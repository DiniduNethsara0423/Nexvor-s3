package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/crypto"
	"my-s3/internal/replication"
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
	policies    *auth.PolicyEngine
	replicator  *replication.Replicator
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

// SetReplicator attaches an asynchronous cross-site S3 replicator
func (h *S3Handler) SetReplicator(r *replication.Replicator) {
	h.replicator = r
}

// SetPolicyEngine attaches an AWS IAM JSON policy evaluator
func (h *S3Handler) SetPolicyEngine(pe *auth.PolicyEngine) {
	h.policies = pe
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

	// Health check & Prometheus metrics endpoints (Kubernetes / MinIO probe compatibility)
	if path == "minio/health/live" || path == "minio/health/ready" || path == "healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}
	if path == "healthz/replication" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(h.replicator.Stats())
		return
	}
	if path == "minio/v2/metrics/cluster" || path == "metrics" {
		h.handleMetrics(w, r)
		return
	}

	// Support both Path-Style (host:9000/bucket/key) and Virtual-Hosted-Style (bucket.localhost:9000/key)
	var bucket, key string
	if vhostBucket := extractVirtualHostBucket(r.Host); vhostBucket != "" {
		bucket = vhostBucket
		key = path
	} else if path != "" {
		parts := strings.SplitN(path, "/", 2)
		bucket = parts[0]
		if len(parts) > 1 {
			key = parts[1]
		}
	}

	// Authenticate request + Evaluate AWS IAM JSON Bucket & User Policies
	ok, errCode := h.auth.Authenticate(r)
	isAnon := errCode == "anonymous"
	if ok && !isAnon {
		if h.policies != nil && bucket != "" {
			principal := h.auth.ExtractAccessKey(r)
			action := auth.MapRequestToS3Action(r, bucket, key)
			if !h.policies.Evaluate(bucket, key, principal, action, true, false) {
				h.WriteError(w, http.StatusForbidden, "AccessDenied", "Explicitly denied by IAM policy", r.URL.Path)
				return
			}
		}
	} else if isAnon || !ok {
		// Check if anonymous public-read Bucket Policy explicitly grants access (e.g. Allow Principal="*" on public/*)
		policyGranted := false
		if errCode == "MissingSecurityHeader" || isAnon {
			if h.policies != nil && bucket != "" {
				action := auth.MapRequestToS3Action(r, bucket, key)
				if h.policies.Evaluate(bucket, key, "*", action, false, true) {
					policyGranted = true
				} else if isAnon {
					// Even when AllowAnon=true globally, explicit Deny inside Bucket Policy must still block!
					if !h.policies.Evaluate(bucket, key, "*", action, true, false) {
						h.WriteError(w, http.StatusForbidden, "AccessDenied", "Denied by bucket policy", r.URL.Path)
						return
					}
				}
			}
		}
		if !ok && !policyGranted {
			h.WriteError(w, http.StatusForbidden, errCode, "Authentication failed or access denied", r.URL.Path)
			return
		}
	}

	if bucket == "" {
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

	q := r.URL.Query()

	// Bucket operations
	if key == "" {
		switch r.Method {
		case http.MethodGet:
			if _, hasLoc := q["location"]; hasLoc {
				h.WriteXML(w, http.StatusOK, LocationConstraintResult{Xmlns: S3Namespace, Location: "us-east-1"})
				return
			}
			if _, hasVer := q["versioning"]; hasVer {
				h.handleGetBucketVersioning(w, r, bucket)
				return
			}
			if _, hasVers := q["versions"]; hasVers {
				h.handleListObjectVersions(w, r, bucket)
				return
			}
			if _, hasLock := q["object-lock"]; hasLock {
				h.handleGetObjectLockConfig(w, r, bucket)
				return
			}
			if _, hasLC := q["lifecycle"]; hasLC {
				h.handleGetBucketLifecycle(w, r, bucket)
				return
			}
			if _, hasPol := q["policy"]; hasPol {
				h.handleGetBucketPolicy(w, r, bucket)
				return
			}
			if _, hasACL := q["acl"]; hasACL {
				h.handleGetACL(w, r)
				return
			}
			if _, hasUploads := q["uploads"]; hasUploads {
				h.handleListMultipartUploads(w, r, bucket)
				return
			}
			h.handleListObjects(w, r, bucket)
		case http.MethodPost:
			if _, hasDel := q["delete"]; hasDel {
				h.handleDeleteObjects(w, r, bucket)
				return
			}
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST requires ?delete on bucket", bucket)
		case http.MethodPut:
			if _, hasVer := q["versioning"]; hasVer {
				h.handlePutBucketVersioning(w, r, bucket)
				return
			}
			if _, hasLock := q["object-lock"]; hasLock {
				h.handlePutObjectLockConfig(w, r, bucket)
				return
			}
			if _, hasLC := q["lifecycle"]; hasLC {
				h.handlePutBucketLifecycle(w, r, bucket)
				return
			}
			if _, hasPol := q["policy"]; hasPol {
				h.handlePutBucketPolicy(w, r, bucket)
				return
			}
			h.handleCreateBucket(w, r, bucket)
		case http.MethodDelete:
			if _, hasLC := q["lifecycle"]; hasLC {
				h.handleDeleteBucketLifecycle(w, r, bucket)
				return
			}
			if _, hasPol := q["policy"]; hasPol {
				h.handleDeleteBucketPolicy(w, r, bucket)
				return
			}
			h.handleDeleteBucket(w, r, bucket)
		case http.MethodHead:
			h.handleHeadBucket(w, r, bucket)
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on bucket", bucket)
		}
		return
	}

	// Object operations
	uploadID := q.Get("uploadId")

	// Multipart Upload S3 API routing
	if _, hasUploads := q["uploads"]; hasUploads && r.Method == http.MethodPost {
		h.handleInitiateMultipartUpload(w, r, bucket, key)
		return
	}
	if uploadID != "" {
		switch r.Method {
		case http.MethodGet:
			h.handleListParts(w, r, bucket, key, uploadID)
		case http.MethodPut:
			if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
				h.handleUploadPartCopy(w, r, bucket, key, uploadID, copySource)
				return
			}
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

	// Object ACL, Tagging & WORM Object Lock subresources
	if _, hasACL := q["acl"]; hasACL && r.Method == http.MethodGet {
		h.handleGetACL(w, r)
		return
	}
	if _, hasRet := q["retention"]; hasRet {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectRetention(w, r, bucket, key, q.Get("versionId"))
		case http.MethodPut:
			h.handlePutObjectRetention(w, r, bucket, key, q.Get("versionId"))
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on retention", key)
		}
		return
	}
	if _, hasLH := q["legal-hold"]; hasLH {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectLegalHold(w, r, bucket, key, q.Get("versionId"))
		case http.MethodPut:
			h.handlePutObjectLegalHold(w, r, bucket, key, q.Get("versionId"))
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on legal-hold", key)
		}
		return
	}
	if _, hasTagging := q["tagging"]; hasTagging {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectTagging(w, r, bucket, key)
		case http.MethodPut:
			h.handlePutObjectTagging(w, r, bucket, key)
		case http.MethodDelete:
			h.handleDeleteObjectTagging(w, r, bucket, key)
		default:
			h.WriteError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed on tagging", key)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetObject(w, r, bucket, key)
	case http.MethodPut:
		if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
			h.handleCopyObject(w, r, bucket, key, copySource)
			return
		}
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

	if strings.EqualFold(r.Header.Get("x-amz-bucket-object-lock-enabled"), "true") {
		_ = h.storage.EnableBucketObjectLock(bucket)
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
	isV2 := q.Get("list-type") == "2"
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	marker := q.Get("marker")
	continuationToken := q.Get("continuation-token")
	startAfter := q.Get("start-after")

	effectiveMarker := marker
	if isV2 {
		if continuationToken != "" {
			effectiveMarker = continuationToken
		} else if startAfter != "" {
			effectiveMarker = startAfter
		}
	} else if continuationToken != "" {
		effectiveMarker = continuationToken
	}

	maxKeys := 1000
	if mkStr := q.Get("max-keys"); mkStr != "" {
		if parsed, err := strconv.Atoi(mkStr); err == nil && parsed > 0 {
			maxKeys = parsed
		}
	}

	res, err := h.storage.ListObjects(bucket, prefix, delimiter, effectiveMarker, maxKeys)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	resp := ListBucketResult{
		Xmlns:       S3Namespace,
		Name:        bucket,
		Prefix:      prefix,
		Delimiter:   delimiter,
		MaxKeys:     maxKeys,
		KeyCount:    res.KeyCount,
		IsTruncated: res.IsTruncated,
	}

	if isV2 {
		resp.ContinuationToken = continuationToken
		if res.IsTruncated {
			resp.NextContinuationToken = res.NextMarker
		}
	} else {
		resp.Marker = marker
		if res.IsTruncated {
			resp.NextMarker = res.NextMarker
		}
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

func unwrapPayloadReader(r *http.Request) (io.Reader, int64) {
	if strings.EqualFold(r.Header.Get("x-amz-content-sha256"), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		return auth.NewAWSChunkedReader(r.Body), -1
	}
	return r.Body, r.ContentLength
}

func extractUserMeta(r *http.Request) map[string]string {
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
	return userMeta
}

func parseSSEHeaders(r *http.Request) (storage.SSEOptions, error) {
	var opts storage.SSEOptions
	if custAlgo := r.Header.Get("x-amz-server-side-encryption-customer-algorithm"); custAlgo != "" {
		custKeyB64 := r.Header.Get("x-amz-server-side-encryption-customer-key")
		custMD5B64 := r.Header.Get("x-amz-server-side-encryption-customer-key-MD5")
		rawKey, actualMD5, err := crypto.ParseCustomerKey(custAlgo, custKeyB64, custMD5B64)
		if err != nil {
			return opts, err
		}
		opts.CustomerAlgorithm = "AES256"
		opts.CustomerKey = rawKey
		opts.CustomerKeyMD5 = actualMD5
		return opts, nil
	}
	if sse := r.Header.Get("x-amz-server-side-encryption"); sse != "" {
		opts.ServerSideEncryption = sse
	}
	return opts, nil
}

func (h *S3Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	sseOpts, err := parseSSEHeaders(r)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error(), key)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/octet-stream" {
		ext := filepath.Ext(key)
		if mimeType := mime.TypeByExtension(ext); mimeType != "" {
			contentType = mimeType
		} else {
			contentType = "application/octet-stream"
		}
	}

	userMeta := extractUserMeta(r)

	// Limit body reader to prevent memory exhaustion / DoS & unwrap AWS SigV4 chunked payloads transparently
	limitedBody := http.MaxBytesReader(w, r.Body, MaxUploadSize)
	payloadReader := io.Reader(limitedBody)
	expectedSize := r.ContentLength
	if strings.EqualFold(r.Header.Get("x-amz-content-sha256"), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		payloadReader = auth.NewAWSChunkedReader(limitedBody)
		expectedSize = -1
	}

	info, err := h.storage.PutObjectWithSSE(bucket, key, payloadReader, expectedSize, contentType, userMeta, sseOpts)
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
		if errors.Is(err, storage.ErrObjectLocked) {
			h.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error(), key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	w.Header().Set("ETag", info.ETag)
	if info.VersionID != "" {
		w.Header().Set("x-amz-version-id", info.VersionID)
	}
	if info.Encrypted {
		if info.SSEAlgorithm == "AES256-C" {
			w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
			w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", info.SSEKeyMD5)
		} else {
			w.Header().Set("x-amz-server-side-encryption", info.SSEAlgorithm)
		}
	}
	w.WriteHeader(http.StatusOK)

	// Async cross-site replication (Cloud -> Local) + webhook notifications
	h.replicator.EnqueuePut(bucket, key)
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
	sseOpts, err := parseSSEHeaders(r)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", err.Error(), key)
		return
	}
	versionID := r.URL.Query().Get("versionId")
	rc, info, err := h.storage.GetObjectVersionWithSSE(bucket, key, versionID, sseOpts)
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
		if err == crypto.ErrMissingCustomerKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidRequest", err.Error(), key)
			return
		}
		if err == crypto.ErrWrongCustomerKey || err == crypto.ErrTamperedCiphertext {
			h.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error(), key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}
	defer rc.Close()

	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))
	if info.VersionID != "" {
		w.Header().Set("x-amz-version-id", info.VersionID)
	}
	if info.Encrypted {
		if info.SSEAlgorithm == "AES256-C" {
			w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
			w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", info.SSEKeyMD5)
		} else {
			w.Header().Set("x-amz-server-side-encryption", info.SSEAlgorithm)
		}
	}

	for k, v := range info.UserMetadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	// http.ServeContent handles HTTP Range requests for video/media streaming
	http.ServeContent(w, r, filepath.Base(key), info.LastModified, rc)
}

func (h *S3Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	versionID := r.URL.Query().Get("versionId")
	info, err := h.storage.HeadObjectVersion(bucket, key, versionID)
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
	if info.VersionID != "" {
		w.Header().Set("x-amz-version-id", info.VersionID)
	}

	for k, v := range info.UserMetadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	versionID := r.URL.Query().Get("versionId")
	bypass := strings.EqualFold(r.Header.Get("x-amz-bypass-governance-retention"), "true")

	delVerID, isDM, err := h.storage.DeleteObjectVersion(bucket, key, versionID, bypass)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		if err == storage.ErrInvalidObjectKey {
			h.WriteError(w, http.StatusBadRequest, "InvalidObjectName", "Object key is invalid", key)
			return
		}
		if errors.Is(err, storage.ErrObjectLocked) {
			h.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error(), key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	if delVerID != "" {
		w.Header().Set("x-amz-version-id", delVerID)
	}
	if isDM {
		w.Header().Set("x-amz-delete-marker", "true")
	}

	h.replicator.EnqueueDelete(bucket, key)
	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleInitiateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = mime.TypeByExtension(filepath.Ext(key))
	}
	userMeta := extractUserMeta(r)

	uploadID, err := h.storage.InitiateMultipartUploadWithMeta(bucket, key, contentType, userMeta)
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

	payloadReader, _ := unwrapPayloadReader(r)
	expectedMD5 := r.Header.Get("Content-MD5")

	etag, err := h.storage.UploadPartWithMD5(bucket, key, uploadID, partNum, payloadReader, expectedMD5)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist", uploadID)
			return
		}
		if err == storage.ErrBadDigest {
			h.WriteError(w, http.StatusBadRequest, "BadDigest", err.Error(), key)
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
	if contentType == "" || strings.Contains(contentType, "xml") {
		contentType = mime.TypeByExtension(filepath.Ext(key))
	}

	info, err := h.storage.CompleteMultipartUpload(bucket, key, uploadID, req.Part, contentType)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist", uploadID)
			return
		}
		if errors.Is(err, storage.ErrInvalidPart) {
			h.WriteError(w, http.StatusBadRequest, "InvalidPart", err.Error(), key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	w.Header().Set("ETag", info.ETag)
	resp := CompleteMultipartUploadResult{
		Xmlns:    S3Namespace,
		Location: "/" + bucket + "/" + key,
		Bucket:   bucket,
		Key:      key,
		ETag:     info.ETag,
	}
	h.WriteXML(w, http.StatusOK, resp)

	h.replicator.EnqueuePut(bucket, key)
	h.dispatchEvent("s3:ObjectCreated:CompleteMultipartUpload", bucket, key, info)
}

func (h *S3Handler) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	_ = h.storage.AbortMultipartUpload(bucket, key, uploadID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	parts, err := h.storage.ListParts(bucket, key, uploadID)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist", uploadID)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}

	resp := ListPartsResult{
		Xmlns:        S3Namespace,
		Bucket:       bucket,
		Key:          key,
		UploadId:     uploadID,
		StorageClass: "STANDARD",
		MaxParts:     1000,
	}
	for _, p := range parts {
		resp.Part = append(resp.Part, PartXML{
			PartNumber:   p.PartNumber,
			LastModified: FormatTime(p.LastModified),
			ETag:         p.ETag,
			Size:         p.Size,
		})
	}
	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	uploads, err := h.storage.ListMultipartUploads(bucket)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	resp := ListMultipartUploadsResult{
		Xmlns:      S3Namespace,
		Bucket:     bucket,
		MaxUploads: 1000,
	}
	for _, u := range uploads {
		resp.Upload = append(resp.Upload, UploadXML{
			Key:          u.Key,
			UploadId:     u.UploadID,
			StorageClass: "STANDARD",
			Initiated:    FormatTime(u.CreatedAt),
		})
	}
	h.WriteXML(w, http.StatusOK, resp)
}

func extractVirtualHostBucket(hostHeader string) string {
	host := hostHeader
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	if strings.HasSuffix(host, ".localhost") {
		sub := strings.TrimSuffix(host, ".localhost")
		if sub != "" && !strings.Contains(sub, ".") && storage.IsValidBucketName(sub) {
			return sub
		}
	}
	return ""
}

func parseCopySource(copySource string) (string, string, bool) {
	decoded, err := url.PathUnescape(strings.TrimSpace(copySource))
	if err != nil {
		decoded = copySource
	}
	decoded = strings.TrimPrefix(decoded, "/")
	parts := strings.SplitN(decoded, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (h *S3Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey, copySource string) {
	srcBucket, srcKey, ok := parseCopySource(copySource)
	if !ok {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid x-amz-copy-source header", dstKey)
		return
	}

	var overrideCT string
	var overrideMeta map[string]string
	if strings.EqualFold(r.Header.Get("x-amz-metadata-directive"), "REPLACE") {
		overrideCT = r.Header.Get("Content-Type")
		overrideMeta = extractUserMeta(r)
	}

	info, err := h.storage.CopyObject(srcBucket, srcKey, dstBucket, dstKey, overrideCT, overrideMeta)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", srcBucket)
			return
		}
		if err == storage.ErrObjectNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "Source key does not exist", srcKey)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), dstKey)
		return
	}

	h.replicator.EnqueuePut(dstBucket, dstKey)
	h.dispatchEvent("s3:ObjectCreated:Copy", dstBucket, dstKey, info)

	w.Header().Set("ETag", info.ETag)
	h.WriteXML(w, http.StatusOK, CopyObjectResult{
		Xmlns:        S3Namespace,
		LastModified: FormatTime(info.LastModified),
		ETag:         info.ETag,
	})
}

func (h *S3Handler) handleUploadPartCopy(w http.ResponseWriter, r *http.Request, dstBucket, dstKey, uploadID, copySource string) {
	partNum, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
	if err != nil || partNum < 1 {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid partNumber specified", dstKey)
		return
	}
	srcBucket, srcKey, ok := parseCopySource(copySource)
	if !ok {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid x-amz-copy-source header", dstKey)
		return
	}

	startOffset, endOffset := int64(-1), int64(-1)
	if rangeHdr := r.Header.Get("x-amz-copy-source-range"); strings.HasPrefix(rangeHdr, "bytes=") {
		spec := strings.TrimPrefix(rangeHdr, "bytes=")
		bounds := strings.SplitN(spec, "-", 2)
		if len(bounds) == 2 {
			startOffset, _ = strconv.ParseInt(bounds[0], 10, 64)
			endOffset, _ = strconv.ParseInt(bounds[1], 10, 64)
		}
	}

	etag, err := h.storage.CopyPart(srcBucket, srcKey, dstBucket, dstKey, uploadID, partNum, startOffset, endOffset)
	if err != nil {
		if err == storage.ErrUploadNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchUpload", "Multipart upload not found", uploadID)
			return
		}
		if err == storage.ErrObjectNotFound || err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "Source object not found", srcKey)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), dstKey)
		return
	}

	w.Header().Set("ETag", etag)
	h.WriteXML(w, http.StatusOK, CopyPartResult{
		Xmlns:        S3Namespace,
		LastModified: FormatTime(time.Now().UTC()),
		ETag:         etag,
	})
}

func (h *S3Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
		return
	}

	var req DeleteObjectsRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid batch delete XML body", bucket)
		return
	}

	res := DeleteResult{Xmlns: S3Namespace}
	for _, obj := range req.Object {
		if err := h.storage.DeleteObject(bucket, obj.Key); err != nil {
			res.Error = append(res.Error, DeleteErrorXML{
				Key:     obj.Key,
				Code:    "InternalError",
				Message: err.Error(),
			})
			continue
		}
		h.replicator.EnqueueDelete(bucket, obj.Key)
		if !req.Quiet {
			res.Deleted = append(res.Deleted, DeletedObjectXML{Key: obj.Key})
		}
	}

	h.WriteXML(w, http.StatusOK, res)
}

func (h *S3Handler) handleGetACL(w http.ResponseWriter, r *http.Request) {
	h.WriteXML(w, http.StatusOK, AccessControlPolicy{
		Xmlns: S3Namespace,
		Owner: Owner{ID: "my-s3-owner", DisplayName: "my-s3"},
		AccessControlList: []GrantXML{
			{
				Grantee: GranteeXML{
					Xmlns:       "http://www.w3.org/2001/XMLSchema-instance",
					Type:        "CanonicalUser",
					ID:          "my-s3-owner",
					DisplayName: "my-s3",
				},
				Permission: "FULL_CONTROL",
			},
		},
	})
}

func (h *S3Handler) handleGetObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	tags, err := h.storage.GetObjectTags(bucket, key)
	if err != nil {
		if err == storage.ErrObjectNotFound || err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}
	resp := TaggingXML{Xmlns: S3Namespace}
	for k, v := range tags {
		resp.TagSet.Tag = append(resp.TagSet.Tag, TagXML{Key: k, Value: v})
	}
	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handlePutObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	var req TaggingXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid tagging XML", key)
		return
	}
	tags := make(map[string]string, len(req.TagSet.Tag))
	for _, t := range req.TagSet.Tag {
		tags[t.Key] = t.Value
	}
	if err := h.storage.PutObjectTags(bucket, key, tags); err != nil {
		if err == storage.ErrObjectNotFound || err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if err := h.storage.DeleteObjectTags(bucket, key); err != nil {
		if err == storage.ErrObjectNotFound || err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist", key)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), key)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	buckets, objects, totalBytes, _ := h.storage.TotalUsage()
	repStats := h.replicator.Stats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w,
		"# HELP nexvors3_buckets_total Total number of buckets\n"+
			"# TYPE nexvors3_buckets_total gauge\n"+
			"nexvors3_buckets_total %d\n"+
			"# HELP nexvors3_objects_total Total number of stored objects\n"+
			"# TYPE nexvors3_objects_total gauge\n"+
			"nexvors3_objects_total %d\n"+
			"# HELP nexvors3_storage_bytes Total bytes stored on disk\n"+
			"# TYPE nexvors3_storage_bytes gauge\n"+
			"nexvors3_storage_bytes %d\n"+
			"# HELP nexvors3_replication_success_total Total replicated objects\n"+
			"# TYPE nexvors3_replication_success_total counter\n"+
			"nexvors3_replication_success_total %d\n"+
			"# HELP nexvors3_replication_errors_total Total replication failures\n"+
			"# TYPE nexvors3_replication_errors_total counter\n"+
			"nexvors3_replication_errors_total %d\n",
		buckets, objects, totalBytes, repStats.ReplicatedTotal, repStats.FailedTotal,
	)
}

func (h *S3Handler) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	cfg, err := h.storage.GetBucketConfig(bucket)
	if err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket)
		return
	}
	h.WriteXML(w, http.StatusOK, VersioningConfiguration{Xmlns: S3Namespace, Status: cfg.Versioning})
}

func (h *S3Handler) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	var req VersioningConfiguration
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid versioning XML", bucket)
		return
	}
	if err := h.storage.SetBucketVersioning(bucket, req.Status); err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
			return
		}
		if errors.Is(err, storage.ErrObjectLocked) {
			h.WriteError(w, http.StatusConflict, "InvalidBucketState", err.Error(), bucket)
			return
		}
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", err.Error(), bucket)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	entries, err := h.storage.ListObjectVersions(bucket, prefix)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}

	resp := ListVersionsResult{
		Xmlns:   S3Namespace,
		Name:    bucket,
		Prefix:  prefix,
		MaxKeys: 1000,
	}
	owner := Owner{ID: "my-s3-owner", DisplayName: "my-s3"}
	for _, ent := range entries {
		if ent.IsDeleteMarker {
			resp.DeleteMarker = append(resp.DeleteMarker, DeleteMarkerXML{
				Key:          ent.Key,
				VersionId:    ent.VersionID,
				IsLatest:     ent.IsLatest,
				LastModified: FormatTime(ent.LastModified),
				Owner:        owner,
			})
		} else {
			resp.Version = append(resp.Version, VersionXML{
				Key:          ent.Key,
				VersionId:    ent.VersionID,
				IsLatest:     ent.IsLatest,
				LastModified: FormatTime(ent.LastModified),
				ETag:         ent.ETag,
				Size:         ent.Size,
				StorageClass: "STANDARD",
				Owner:        owner,
			})
		}
	}
	h.WriteXML(w, http.StatusOK, resp)
}

func (h *S3Handler) handleGetObjectLockConfig(w http.ResponseWriter, r *http.Request, bucket string) {
	cfg, err := h.storage.GetBucketConfig(bucket)
	if err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
		return
	}
	if !cfg.ObjectLockEnabled {
		h.WriteError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket", bucket)
		return
	}
	h.WriteXML(w, http.StatusOK, ObjectLockConfigurationXML{Xmlns: S3Namespace, ObjectLockEnabled: "Enabled"})
}

func (h *S3Handler) handlePutObjectLockConfig(w http.ResponseWriter, r *http.Request, bucket string) {
	var req ObjectLockConfigurationXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid object lock XML", bucket)
		return
	}
	if !strings.EqualFold(req.ObjectLockEnabled, "Enabled") {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "ObjectLockEnabled must be Enabled", bucket)
		return
	}
	if err := h.storage.EnableBucketObjectLock(bucket); err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", err.Error(), bucket)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleGetObjectRetention(w http.ResponseWriter, r *http.Request, bucket, key, versionID string) {
	info, err := h.storage.HeadObjectVersion(bucket, key, versionID)
	if err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchKey", "Key or version not found", key)
		return
	}
	if info.RetentionMode == "" || info.RetainUntilDate == nil {
		h.WriteError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "No retention policy on object", key)
		return
	}
	h.WriteXML(w, http.StatusOK, ObjectRetentionXML{
		Xmlns:           S3Namespace,
		Mode:            info.RetentionMode,
		RetainUntilDate: info.RetainUntilDate.UTC().Format(time.RFC3339),
	})
}

func (h *S3Handler) handlePutObjectRetention(w http.ResponseWriter, r *http.Request, bucket, key, versionID string) {
	var req ObjectRetentionXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid retention XML", key)
		return
	}
	retainUntil, err := time.Parse(time.RFC3339, strings.TrimSpace(req.RetainUntilDate))
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid RetainUntilDate (RFC3339 required)", key)
		return
	}
	if err := h.storage.SetObjectRetention(bucket, key, versionID, req.Mode, retainUntil); err != nil {
		if errors.Is(err, storage.ErrObjectLocked) {
			h.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error(), key)
			return
		}
		h.WriteError(w, http.StatusBadRequest, "InvalidRequest", err.Error(), key)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleGetObjectLegalHold(w http.ResponseWriter, r *http.Request, bucket, key, versionID string) {
	info, err := h.storage.HeadObjectVersion(bucket, key, versionID)
	if err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchKey", "Key or version not found", key)
		return
	}
	status := info.LegalHoldStatus
	if status == "" {
		status = "OFF"
	}
	h.WriteXML(w, http.StatusOK, ObjectLegalHoldXML{Xmlns: S3Namespace, Status: status})
}

func (h *S3Handler) handlePutObjectLegalHold(w http.ResponseWriter, r *http.Request, bucket, key, versionID string) {
	var req ObjectLegalHoldXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid legal hold XML", key)
		return
	}
	if err := h.storage.SetObjectLegalHold(bucket, key, versionID, req.Status); err != nil {
		h.WriteError(w, http.StatusBadRequest, "InvalidRequest", err.Error(), key)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	rules, err := h.storage.GetBucketLifecycle(bucket)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
			return
		}
		if err == storage.ErrLifecycleNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}
	h.WriteXML(w, http.StatusOK, storage.LifecycleConfigurationXML{
		Xmlns: S3Namespace,
		Rule:  rules,
	})
}

func (h *S3Handler) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	var req storage.LifecycleConfigurationXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedXML", "Invalid lifecycle XML", bucket)
		return
	}
	if err := h.storage.SetBucketLifecycle(bucket, req.Rule); err != nil {
		if err == storage.ErrBucketNotFound {
			h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error(), bucket)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *S3Handler) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := h.storage.DeleteBucketLifecycle(bucket); err != nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", err.Error(), bucket)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleGetBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
		return
	}
	if h.policies == nil {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucketPolicy", "The bucket policy does not exist", bucket)
		return
	}
	raw, ok := h.policies.GetBucketPolicy(bucket)
	if !ok {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucketPolicy", "The bucket policy does not exist", bucket)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *S3Handler) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
		return
	}
	if h.policies == nil {
		h.WriteError(w, http.StatusInternalServerError, "InternalError", "Policy engine unavailable", bucket)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedPolicy", "Unable to read policy body", bucket)
		return
	}
	if err := h.policies.SetBucketPolicy(bucket, body); err != nil {
		h.WriteError(w, http.StatusBadRequest, "MalformedPolicy", err.Error(), bucket)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *S3Handler) handleDeleteBucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	if !h.storage.BucketExists(bucket) {
		h.WriteError(w, http.StatusNotFound, "NoSuchBucket", "Bucket does not exist", bucket)
		return
	}
	if h.policies != nil {
		h.policies.DeleteBucketPolicy(bucket)
	}
	w.WriteHeader(http.StatusNoContent)
}
