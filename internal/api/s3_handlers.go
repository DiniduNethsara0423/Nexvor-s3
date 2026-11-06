package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/storage"
)

// MaxUploadSize limits single PUT payload to 5GB (standard AWS S3 single-PUT limit)
const MaxUploadSize = 5 * 1024 * 1024 * 1024

func init() {
	// Register RFC 8216 HLS & adaptive bitrate streaming MIME types
	_ = mime.AddExtensionType(".m3u8", "application/vnd.apple.mpegurl")
	_ = mime.AddExtensionType(".ts", "video/mp2t")
	_ = mime.AddExtensionType(".m4s", "video/iso.segment")
	_ = mime.AddExtensionType(".mpd", "application/dash+xml")
	_ = mime.AddExtensionType(".mp4", "video/mp4")
	_ = mime.AddExtensionType(".webm", "video/webm")
	_ = mime.AddExtensionType(".mov", "video/quicktime")
}

// S3Handler handles incoming S3 REST protocol requests
type S3Handler struct {
	storage     *storage.DiskEngine
	auth        *auth.Authenticator
	webhookURL  string
	consolePort string
}

// NewS3Handler constructs a new S3Handler with optional MinIO-style webhook notifications
func NewS3Handler(storage *storage.DiskEngine, auth *auth.Authenticator, webhookURL string, consolePort ...string) *S3Handler {
	cp := "9001"
	if len(consolePort) > 0 && consolePort[0] != "" {
		cp = consolePort[0]
	}
	return &S3Handler{
		storage:     storage,
		auth:        auth,
		webhookURL:  webhookURL,
		consolePort: cp,
	}
}

// WriteXML writes an XML response with S3 headers
func (h *S3Handler) WriteXML(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Server", "My-S3/1.0")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

// WriteError writes standard S3 XML error format
func (h *S3Handler) WriteError(w http.ResponseWriter, status int, code, message, resource string) {
	resp := ErrorResponse{
		Code:      code,
		Message:   message,
		Resource:  resource,
		RequestId: fmt.Sprintf("%x", time.Now().UnixNano()),
	}
	h.WriteXML(w, status, resp)
}

// ServeHTTP routes incoming S3 requests
func (h *S3Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security headers & CORS for web apps & modern frontends
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length, Content-MD5, x-amz-date, x-amz-content-sha256, x-amz-security-token, x-amz-user-agent, Range")
	w.Header().Set("Access-Control-Expose-Headers", "ETag, Content-Length, Content-Type, x-amz-request-id, x-amz-version-id")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := strings.Trim(r.URL.Path, "/")

	// Health check endpoints (Kubernetes / MinIO probe compatibility)
	if path == "minio/health/live" || path == "minio/health/ready" || path == "healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// Authenticate request
	ok, errCode := h.auth.Authenticate(r)
	if !ok {
		h.WriteError(w, http.StatusForbidden, errCode, "Authentication failed or access denied", r.URL.Path)
		return
	}

	if path == "" {
		if r.Method == http.MethodGet {
			// If request is from a web browser visiting root, redirect to the MinIO-style Console UI
			accept := r.Header.Get("Accept")
			if strings.Contains(accept, "text/html") && r.Header.Get("Authorization") == "" {
				host := r.Host
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				proto := "http"
				if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
					proto = "https"
				}
				target := fmt.Sprintf("%s://%s:%s", proto, host, h.consolePort)
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
				return
			}
			h.handleListBuckets(w, r)
			return
		}
		h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on root", "/")
		return
	}

	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]
	var key string
	if len(parts) > 1 {
		key = parts[1]
	}

	// Bucket operations
	if key == "" {
		switch r.Method {
		case http.MethodGet:
			h.handleListObjects(w, r, bucket)
		case http.MethodPut:
			h.handleCreateBucket(w, r, bucket)
		case http.MethodDelete:
			h.handleDeleteBucket(w, r, bucket)
		case http.MethodHead:
			h.handleHeadBucket(w, r, bucket)
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on bucket", bucket)
		}
		return
	}

	// Object operations
	q := r.URL.Query()
	uploadID := q.Get("uploadId")

	// Multipart Upload S3 API routing
	if _, hasUploads := q["uploads"]; hasUploads && r.Method == http.MethodPost {
		h.handleInitiateMultipartUpload(w, r, bucket, key)
		return
	}
	if uploadID != "" {
		switch r.Method {
		case http.MethodPut:
			h.handleUploadPart(w, r, bucket, key, uploadID)
		case http.MethodPost:
			h.handleCompleteMultipartUpload(w, r, bucket, key, uploadID)
		case http.MethodDelete:
			h.handleAbortMultipartUpload(w, r, bucket, key, uploadID)
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed for multipart", key)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetObject(w, r, bucket, key)
	case http.MethodPut:
		h.handlePutObject(w, r, bucket, key)
	case http.MethodHead:
		h.handleHeadObject(w, r, bucket, key)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, bucket, key)
	default:
		h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on object", key)
	}
}

func (h *S3Handler) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	buckets, err := h.storage.ListBuckets()
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), "/")
		return
	}

	resp := ListAllMyBucketsResult{
		Xmlns: S3Namespace,
		Owner: Owner{
			ID:          "my-s3-owner",
			DisplayName: "my-s3",
		},
	}

	for _, b := range buckets {
		resp.Buckets.Bucket = append(resp.Buckets.Bucket, BucketXML{
			Name:         b.Name,
			CreationDate: FormatTime(b.CreationDate),
		})
	}

	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	err := h.storage.CreateBucket(bucket)
	if err != nil {
		if err == storage.ErrBucketAlreadyExists {
			h.WriteError(w, http.StatusConflict, "BucketAlreadyOwnedByYou", "The bucket already exists", bucket)
			return
		}
		if err == storage.ErrInvalidBucketName {
			h.WriteError(w, http.StatusBadRequest, "InvalidBucketName", "The bucket name is invalid", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	err := h.storage.DeleteBucket(bucket)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrBucketNotEmpty {
			h.WriteError(w, http.StatusConflict, "BucketNotEmpty", "The bucket you tried to delete is not empty", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	marker := q.Get("marker")
	if marker == "" {
		marker = q.Get("continuation-token")
	}
	maxKeys := 1000
	if mkStr := q.Get("max-keys"); mkStr != "" {
		if parsed, err := strconv.Atoi(mkStr); err == nil {
			maxKeys = parsed
		}
	}

	res, err := h.storage.ListObjects(bucket, prefix, delimiter, marker, maxKeys)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	resp := ListBucketResult{
		Xmlns:                 S3Namespace,
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		Marker:                marker,
		ContinuationToken:     q.Get("continuation-token"),
		MaxKeys:               maxKeys,
		KeyCount:              len(res.Objects),
		IsTruncated:           res.IsTruncated,
		NextMarker:            res.NextMarker,
		NextContinuationToken: res.NextMarker,
	}

	for _, obj := range res.Objects {
		resp.Contents = append(resp.Contents, ObjectXML{
			Key:          obj.Key,
			LastModified: FormatTime(obj.LastModified),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
			Owner: Owner{
				ID:          "my-s3-owner",
				DisplayName: "my-s3",
			},
		})
	}

	for _, cp := range res.CommonPrefixes {
		resp.CommonPrefixes = append(resp.CommonPrefixes, CommonPrefixXML{Prefix: cp})
	}

	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/octet-stream" {
		ext := filepath.Ext(key)
		if mimeType := mime.TypeByExtension(ext); mimeType != "" {
			contentType = mimeType
		} else {
			contentType = "application/octet-stream"
		}
	}

	userMeta := make(map[string]string)
	for hdrKey, hdrVal := range r.Header {
		lower := strings.ToLower(hdrKey)
		if strings.HasPrefix(lower, "x-amz-meta-") {
			metaKey := strings.TrimPrefix(lower, "x-amz-meta-")
			if len(hdrVal) > 0 {
				userMeta[metaKey] = hdrVal[0]
			}
		}
	}

	// Limit body reader to prevent memory exhaustion / DoS
	limitedBody := http.MaxBytesReader(w, r.Body, MaxUploadSize)

	info, err := h.storage.PutObject(bucket, key, limitedBody, r.ContentLength, contentType, userMeta)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.WriteError(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size", key)
			return
		}
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrInvalidObjectKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidObjectName", "Object key is invalid or contains forbidden path characters", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	w.Header().Set("ETag", info.ETag)
	w.WriteHeader(http.StatusOK)

	// Dispatch MinIO-style event notification (e.g. triggers HLS transcoding)
	h.dispatchEvent("s3:ObjectCreated:Put", bucket, key, info)
}

// dispatchEvent emits asynchronous MinIO-style webhook notifications
func (h *S3Handler) dispatchEvent(eventName, bucket, key string, info *storage.ObjectInfo) {
	if h.webhookURL == "" {
		return
	}
	go func() {
		payload := map[string]interface{}{
			"EventName":    eventName,
			"Bucket":       bucket,
			"Key":          key,
			"Size":         info.Size,
			"ContentType":  info.ContentType,
			"ETag":         info.ETag,
			"LastModified": info.LastModified,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(h.webhookURL, "application/json", bytes.NewReader(data))
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}()
}

func (h *S3Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rc, info, err := h.storage.GetObject(bucket, key)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrObjectNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist", key)
			return
		}
		if err == storage.ErrInvalidObjectKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidObjectName", "Object key is invalid", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}
	defer rc.Close()

	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))

	for k, v := range info.UserMetadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	// http.ServeContent handles HTTP Range requests for video/media streaming
	http.ServeContent(w, r, filepath.Base(key), info.LastModified, rc)
}

func (h *S3Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	info, err := h.storage.HeadObject(bucket, key)
	if err != nil {
		if err == storage.ErrBucketNotFound || err == storage.ErrObjectNotFound || err == storage.ErrInvalidObjectKey {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))

	for k, v := range info.UserMetadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	err := h.storage.DeleteObject(bucket, key)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrInvalidObjectKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidObjectName", "Object key is invalid", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}


func (h *S3Handler) handleInitiateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	uploadID, err := h.storage.InitiateMultipartUpload(bucket, key)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrInvalidObjectKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidObjectName", "Object key is invalid", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	resp := InitiateMultipartUploadResult{
		Xmlns:    S3Namespace,
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}
	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	partNumStr := r.URL.Query().Get("partNumber")
	partNum, err := strconv.Atoi(partNumStr)
	if err != nil || partNum < 1 {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid partNumber specified", key)
		return
	}

	etag, err := h.storage.UploadPart(bucket, key, uploadID, partNum, r.Body)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist", uploadID)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	var req CompleteMultipartUploadRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Failed to parse XML body", key)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/xml" {
		ext := filepath.Ext(key)
		contentType = mime.TypeByExtension(ext)
	}

	info, err := h.storage.CompleteMultipartUpload(bucket, key, uploadID, req.Part, contentType)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist", uploadID)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	resp := CompleteMultipartUploadResult{
		Xmlns:    S3Namespace,
		Location: "/" + bucket + "/" + key,
		Bucket:   bucket,
		Key:      key,
		ETag:     info.ETag,
	}
	h.WriteXML(w, http.StatusOK, resp)

	h.dispatchEvent("s3:ObjectCreated:CompleteMultipartUpload", bucket, key, info)
}

func (h *S3Handler) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	_ = h.storage.AbortMultipartUpload(bucket, key, uploadID)
	w.WriteHeader(http.StatusNoContent)
}
