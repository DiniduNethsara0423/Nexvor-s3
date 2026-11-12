package storage

import (
	"archive/zip"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"my-s3/internal/crypto"
	"my-s3/internal/erasure"
)

var (
	ErrBucketAlreadyExists = errors.New("bucket already exists")
	ErrBucketNotFound      = errors.New("bucket does not exist")
	ErrObjectNotFound      = errors.New("object does not exist")
	ErrBucketNotEmpty      = errors.New("bucket not empty")
	ErrInvalidBucketName   = errors.New("invalid bucket name")
	ErrInvalidObjectKey    = errors.New("invalid object key or path traversal detected")
	ErrUploadNotFound      = errors.New("multipart upload not found")
	ErrInvalidPart         = errors.New("invalid multipart part or etag mismatch")
	ErrBadDigest           = errors.New("the content-md5 you specified did not match what we received")
	ErrObjectLocked        = errors.New("object version is locked under WORM retention or legal hold")
)

// Zero-allocation 128KB buffer pool for high throughput transfer
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 128*1024)
		return &b
	},
}

// CompletePart represents a part in an S3 CompleteMultipartUpload request
type CompletePart struct {
	PartNumber int    `xml:"PartNumber" json:"part_number"`
	ETag       string `xml:"ETag" json:"etag"`
}

// ObjectInfo holds file metadata
type ObjectInfo struct {
	Bucket          string            `json:"bucket"`
	Key             string            `json:"key"`
	VersionID       string            `json:"version_id,omitempty"`
	IsDeleteMarker  bool              `json:"is_delete_marker,omitempty"`
	Size            int64             `json:"size"`
	ETag            string            `json:"etag"`
	Sha256          string            `json:"sha256,omitempty"`
	ContentType     string            `json:"content_type"`
	LastModified    time.Time         `json:"last_modified"`
	UserMetadata    map[string]string `json:"user_metadata,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	RetentionMode   string            `json:"retention_mode,omitempty"` // "GOVERNANCE" or "COMPLIANCE"
	RetainUntilDate *time.Time        `json:"retain_until_date,omitempty"`
	LegalHoldStatus string            `json:"legal_hold_status,omitempty"` // "ON" or "OFF"
	Encrypted       bool              `json:"encrypted,omitempty"`
	SSEAlgorithm    string            `json:"sse_algorithm,omitempty"` // "AES256" or "aws:kms" or "AES256-C"
	SSEKeyMD5       string            `json:"sse_key_md5,omitempty"`
}

// BucketInfo represents bucket metadata
type BucketInfo struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
}

// SSEOptions configures Server-Side Encryption at Rest (SSE-S3, SSE-KMS, SSE-C)
type SSEOptions struct {
	ServerSideEncryption string // "", "AES256", "aws:kms"
	CustomerAlgorithm    string // "AES256"
	CustomerKey          []byte // 32 bytes (never persisted on disk)
	CustomerKeyMD5       string
}

// DiskEngine implements high-concurrency, sharded-lock local disk storage
type DiskEngine struct {
	bucketMu     sync.RWMutex
	keyLocks     [256]sync.RWMutex
	baseDir      string
	masterKMSKey string
	erasureStore *erasure.MultiDriveStore
}

// SetMasterKMSKey configures default/KMS master secret for SSE-S3 / SSE-KMS encryption at rest
func (e *DiskEngine) SetMasterKMSKey(secret string) {
	e.bucketMu.Lock()
	e.masterKMSKey = strings.TrimSpace(secret)
	e.bucketMu.Unlock()
}

// SetErasureStore attaches a multi-drive GF(2^8) Reed-Solomon erasure coding pool
func (e *DiskEngine) SetErasureStore(store *erasure.MultiDriveStore) {
	e.bucketMu.Lock()
	e.erasureStore = store
	e.bucketMu.Unlock()
}

// NewDiskEngine initializes the storage directory structure safely
func NewDiskEngine(baseDir string) (*DiskEngine, error) {
	absPath, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	bucketsDir := filepath.Join(absPath, "buckets")
	if err := os.MkdirAll(bucketsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create buckets directory: %w", err)
	}
	return &DiskEngine{baseDir: absPath}, nil
}

// getLock returns the striped lock for a specific bucket and key
func (e *DiskEngine) getLock(bucket, key string) *sync.RWMutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(bucket))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(key))
	idx := h.Sum32() % 256
	return &e.keyLocks[idx]
}

func (e *DiskEngine) bucketPath(bucket string) string {
	return filepath.Join(e.baseDir, "buckets", bucket)
}

// IsValidBucketName checks AWS S3 naming constraints (3-63 chars, lowercase, numbers, hyphen, dot)
func IsValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	if name[0] == '-' || name[0] == '.' || name[len(name)-1] == '-' || name[len(name)-1] == '.' {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// sanitizeKey verifies and resolves safe paths, strictly blocking Path Traversal (CWE-22)
func (e *DiskEngine) sanitizeKey(bucket, key, subDir string) (string, error) {
	if !IsValidBucketName(bucket) {
		return "", ErrInvalidBucketName
	}
	if strings.HasPrefix(key, "/") || strings.HasPrefix(key, "~") || strings.Contains(key, "\\") || strings.Contains(key, ":") || strings.Contains(key, "\x00") || strings.Contains(key, "%00") {
		return "", ErrInvalidObjectKey
	}

	cleanKey := filepath.Clean(filepath.FromSlash(key))
	if cleanKey == "." || cleanKey == ".." || strings.HasPrefix(cleanKey, ".."+string(filepath.Separator)) {
		return "", ErrInvalidObjectKey
	}

	baseSubDir := filepath.Clean(filepath.Join(e.bucketPath(bucket), subDir))
	fullPath := filepath.Clean(filepath.Join(baseSubDir, cleanKey))

	rel, err := filepath.Rel(baseSubDir, fullPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", ErrInvalidObjectKey
	}

	return fullPath, nil
}

func sanitizeUploadID(uploadID string) error {
	if len(uploadID) < 16 || len(uploadID) > 64 {
		return ErrUploadNotFound
	}
	for i := 0; i < len(uploadID); i++ {
		c := uploadID[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrUploadNotFound
		}
	}
	return nil
}

func (e *DiskEngine) bucketExistsLocked(bucket string) bool {
	if !IsValidBucketName(bucket) {
		return false
	}
	info, err := os.Stat(e.bucketPath(bucket))
	return err == nil && info.IsDir()
}

// BucketExists checks if bucket directory exists
func (e *DiskEngine) BucketExists(bucket string) bool {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()
	return e.bucketExistsLocked(bucket)
}

// CreateBucket creates a new bucket if not already present
func (e *DiskEngine) CreateBucket(bucket string) error {
	if !IsValidBucketName(bucket) {
		return ErrInvalidBucketName
	}

	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	bPath := e.bucketPath(bucket)
	if e.bucketExistsLocked(bucket) {
		return ErrBucketAlreadyExists
	}

	if err := os.MkdirAll(filepath.Join(bPath, "data"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(bPath, "meta"), 0755); err != nil {
		return err
	}

	meta := BucketInfo{
		Name:         bucket,
		CreationDate: time.Now().UTC(),
	}
	data, _ := json.Marshal(meta)
	return os.WriteFile(filepath.Join(bPath, "bucket.json"), data, 0644)
}

// DeleteBucket deletes an empty bucket
func (e *DiskEngine) DeleteBucket(bucket string) error {
	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}

	bPath := e.bucketPath(bucket)
	dataPath := filepath.Join(bPath, "data")

	hasFiles := false
	_ = filepath.Walk(dataPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			hasFiles = true
			return io.EOF
		}
		return nil
	})

	if hasFiles {
		return ErrBucketNotEmpty
	}

	return os.RemoveAll(bPath)
}

// ListBuckets lists all buckets
func (e *DiskEngine) ListBuckets() ([]BucketInfo, error) {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	bucketsDir := filepath.Join(e.baseDir, "buckets")
	entries, err := os.ReadDir(bucketsDir)
	if err != nil {
		return nil, err
	}

	var buckets []BucketInfo
	for _, entry := range entries {
		if entry.IsDir() {
			metaFile := filepath.Join(bucketsDir, entry.Name(), "bucket.json")
			var b BucketInfo
			data, err := os.ReadFile(metaFile)
			if err == nil {
				_ = json.Unmarshal(data, &b)
			}
			if b.Name == "" {
				b.Name = entry.Name()
				if fi, err := entry.Info(); err == nil {
					b.CreationDate = fi.ModTime().UTC()
				}
			}
			buckets = append(buckets, b)
		}
	}
	return buckets, nil
}

func (e *DiskEngine) resolveMasterSecret() string {
	e.bucketMu.RLock()
	kms := e.masterKMSKey
	e.bucketMu.RUnlock()
	if kms != "" {
		return kms
	}
	kmsPath := filepath.Join(e.baseDir, ".nexvor_kms.key")
	if b, err := os.ReadFile(kmsPath); err == nil && len(b) > 0 {
		return string(b)
	}
	rb := make([]byte, 32)
	_, _ = rand.Read(rb)
	secret := hex.EncodeToString(rb)
	_ = os.WriteFile(kmsPath, []byte(secret), 0600)
	return secret
}

// PutObject streams data with sharded lock and zero-allocation pooled 128KB buffer
func (e *DiskEngine) PutObject(bucket, key string, r io.Reader, size int64, contentType string, userMeta map[string]string) (*ObjectInfo, error) {
	return e.PutObjectWithSSE(bucket, key, r, size, contentType, userMeta, SSEOptions{})
}

// PutObjectWithSSE streams data with optional Server-Side Encryption at Rest (SSE-S3, SSE-KMS, or SSE-C)
func (e *DiskEngine) PutObjectWithSSE(bucket, key string, r io.Reader, size int64, contentType string, userMeta map[string]string, sse SSEOptions) (*ObjectInfo, error) {
	dataPath, err := e.sanitizeKey(bucket, key, "data")
	if err != nil {
		return nil, err
	}
	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return nil, err
	}
	metaPath += ".json"

	if !e.BucketExists(bucket) {
		return nil, ErrBucketNotFound
	}

	// Determine effective encryption key & metadata
	var encKey []byte
	var sseAlgo, sseKeyMD5 string
	if len(sse.CustomerKey) == 32 {
		encKey = sse.CustomerKey
		sseAlgo = "AES256-C"
		sseKeyMD5 = sse.CustomerKeyMD5
	} else if sse.ServerSideEncryption != "" || e.masterKMSKey != "" {
		sseAlgo = sse.ServerSideEncryption
		if sseAlgo == "" {
			sseAlgo = "AES256"
		}
		encKey = crypto.DeriveMasterObjectKey(e.resolveMasterSecret(), bucket, key)
	}

	// Sharded key-level lock: parallel writes to other keys are completely non-blocking
	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	if err := os.MkdirAll(filepath.Dir(dataPath), 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
		return nil, err
	}

	tempFile := dataPath + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return nil, err
	}

	hasherMD5 := md5.New()
	hasherSHA := sha256.New()
	var written int64

	if len(encKey) > 0 {
		// Compute plaintext MD5 & SHA-256 on the fly before 64KB chunked AES-256-GCM encryption
		hashTee := io.TeeReader(r, io.MultiWriter(hasherMD5, hasherSHA))
		written, err = crypto.EncryptStream(f, hashTee, encKey)
	} else {
		mw := io.MultiWriter(f, hasherMD5, hasherSHA)
		bufPtr := bufPool.Get().(*[]byte)
		written, err = io.CopyBuffer(mw, r, *bufPtr)
		bufPool.Put(bufPtr)
	}

	f.Close()
	if err != nil {
		_ = os.Remove(tempFile)
		return nil, err
	}

	cfg := e.getBucketConfigLocked(bucket)
	versionID := ""
	if cfg.Versioning == "Enabled" {
		_ = e.archiveCurrentVersionLocked(bucket, key, dataPath, metaPath)
		versionID = generateVersionID()
	} else {
		if active, err := e.headObjectLocked(bucket, key); err == nil {
			if lockErr := checkObjectLockLocked(active, false); lockErr != nil {
				_ = os.Remove(tempFile)
				return nil, lockErr
			}
		}
	}

	if err := os.Rename(tempFile, dataPath); err != nil {
		_ = os.Remove(tempFile)
		return nil, err
	}

	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hasherMD5.Sum(nil)))
	sha := hex.EncodeToString(hasherSHA.Sum(nil))

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	info := &ObjectInfo{
		Bucket:       bucket,
		Key:          key,
		VersionID:    versionID,
		Size:         written,
		ETag:         etag,
		Sha256:       sha,
		ContentType:  contentType,
		LastModified: time.Now().UTC(),
		UserMetadata: userMeta,
		Encrypted:    len(encKey) > 0,
		SSEAlgorithm: sseAlgo,
		SSEKeyMD5:    sseKeyMD5,
	}

	metaBytes, _ := json.Marshal(info)
	if err := os.WriteFile(metaPath, metaBytes, 0644); err != nil {
		return nil, err
	}

	// If Multi-Drive GF(2^8) Reed-Solomon Erasure Coding is attached, distribute N+M parity shards
	if e.erasureStore != nil && written <= 64*1024*1024 {
		if rawDiskBytes, readErr := os.ReadFile(dataPath); readErr == nil {
			_ = e.erasureStore.PutObject(bucket, key, rawDiskBytes)
		}
	}

	return info, nil
}

func (e *DiskEngine) headObjectLocked(bucket, key string) (*ObjectInfo, error) {
	if !e.bucketExistsLocked(bucket) {
		return nil, ErrBucketNotFound
	}

	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return nil, err
	}
	metaPath += ".json"

	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrObjectNotFound
		}
		return nil, err
	}

	var info ObjectInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// HeadObject reads object metadata safely using sharded lock
func (e *DiskEngine) HeadObject(bucket, key string) (*ObjectInfo, error) {
	keyLock := e.getLock(bucket, key)
	keyLock.RLock()
	defer keyLock.RUnlock()

	info, err := e.headObjectLocked(bucket, key)
	if err != nil {
		return nil, err
	}
	if info.IsDeleteMarker {
		return nil, ErrObjectNotFound
	}
	return info, nil
}

// GetObject returns an io.ReadSeekCloser using sharded read lock
func (e *DiskEngine) GetObject(bucket, key string) (io.ReadSeekCloser, *ObjectInfo, error) {
	keyLock := e.getLock(bucket, key)
	keyLock.RLock()
	defer keyLock.RUnlock()

	info, err := e.headObjectLocked(bucket, key)
	if err != nil {
		return nil, nil, err
	}
	if info.IsDeleteMarker {
		return nil, nil, ErrObjectNotFound
	}

	dataPath, err := e.sanitizeKey(bucket, key, "data")
	if err != nil {
		return nil, nil, err
	}

	f, err := os.Open(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrObjectNotFound
		}
		return nil, nil, err
	}

	return f, info, nil
}

func cleanEmptyParentDirs(startPath, stopPath string) {
	curr := filepath.Dir(startPath)
	for curr != stopPath && len(curr) > len(stopPath) {
		entries, err := os.ReadDir(curr)
		if err != nil || len(entries) > 0 {
			break
		}
		_ = os.Remove(curr)
		curr = filepath.Dir(curr)
	}
}

// DeleteObject removes the object data (or inserts a DeleteMarker when bucket versioning is Enabled)
func (e *DiskEngine) DeleteObject(bucket, key string) error {
	_, _, err := e.DeleteObjectVersion(bucket, key, "", false)
	return err
}

// ListObjectsResult holds objects and common prefixes for S3 ListObjects
type ListObjectsResult struct {
	Objects        []ObjectInfo
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string
	KeyCount       int
}

type listEntry struct {
	sortKey      string
	isPrefix     bool
	obj          ObjectInfo
	commonPrefix string
}

// MultipartUploadMeta describes an active in-progress multipart upload
type MultipartUploadMeta struct {
	UploadID     string            `json:"upload_id"`
	Key          string            `json:"key"`
	ContentType  string            `json:"content_type,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// PartInfo describes an uploaded multipart chunk
type PartInfo struct {
	PartNumber   int       `json:"part_number"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
}

// ListObjects lists objects with S3-compliant lexicographical prefix, delimiter, marker/continuation-token, and maxKeys pagination
func (e *DiskEngine) ListObjects(bucket, prefix, delimiter, marker string, maxKeys int) (*ListObjectsResult, error) {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return nil, ErrBucketNotFound
	}

	if maxKeys <= 0 {
		maxKeys = 1000
	}

	metaBase := filepath.Join(e.bucketPath(bucket), "meta")
	var allObjects []ObjectInfo

	_ = filepath.Walk(metaBase, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil {
			var obj ObjectInfo
			if err := json.Unmarshal(data, &obj); err == nil && !obj.IsDeleteMarker {
				allObjects = append(allObjects, obj)
			}
		}
		return nil
	})

	sort.Slice(allObjects, func(i, j int) bool {
		return allObjects[i].Key < allObjects[j].Key
	})

	// Build unified lexicographically ordered entry stream of Contents + deduplicated CommonPrefixes
	prefixesSeen := make(map[string]bool)
	var entries []listEntry
	for _, obj := range allObjects {
		if prefix != "" && !strings.HasPrefix(obj.Key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := strings.TrimPrefix(obj.Key, prefix)
			if idx := strings.Index(rest, delimiter); idx >= 0 {
				cp := prefix + rest[:idx+len(delimiter)]
				if !prefixesSeen[cp] {
					prefixesSeen[cp] = true
					entries = append(entries, listEntry{
						sortKey:      cp,
						isPrefix:     true,
						commonPrefix: cp,
					})
				}
				continue
			}
		}
		entries = append(entries, listEntry{
			sortKey: obj.Key,
			obj:     obj,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].sortKey < entries[j].sortKey
	})

	// Filter by exclusive marker / continuation-token, then paginate accurately up to maxKeys
	result := &ListObjectsResult{}
	var filtered []listEntry
	for _, ent := range entries {
		if marker != "" && ent.sortKey <= marker {
			continue
		}
		filtered = append(filtered, ent)
	}

	var lastReturnedKey string
	for i, ent := range filtered {
		if i >= maxKeys {
			result.IsTruncated = true
			result.NextMarker = lastReturnedKey
			break
		}
		if ent.isPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, ent.commonPrefix)
		} else {
			result.Objects = append(result.Objects, ent.obj)
		}
		lastReturnedKey = ent.sortKey
		result.KeyCount++
	}

	return result, nil
}

// InitiateMultipartUpload prepares temporary directory for chunked upload
func (e *DiskEngine) InitiateMultipartUpload(bucket, key string) (string, error) {
	return e.InitiateMultipartUploadWithMeta(bucket, key, "", nil)
}

// InitiateMultipartUploadWithMeta prepares temporary directory and saves Content-Type and user metadata
func (e *DiskEngine) InitiateMultipartUploadWithMeta(bucket, key, contentType string, userMeta map[string]string) (string, error) {
	if _, err := e.sanitizeKey(bucket, key, "data"); err != nil {
		return "", err
	}

	if !e.BucketExists(bucket) {
		return "", ErrBucketNotFound
	}

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	uploadID := hex.EncodeToString(b)

	uploadDir := filepath.Join(e.bucketPath(bucket), "uploads", uploadID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", err
	}

	meta := MultipartUploadMeta{
		UploadID:     uploadID,
		Key:          key,
		ContentType:  contentType,
		UserMetadata: userMeta,
		CreatedAt:    time.Now().UTC(),
	}
	data, _ := json.Marshal(meta)
	_ = os.WriteFile(filepath.Join(uploadDir, "meta.json"), data, 0644)

	return uploadID, nil
}

// UploadPart streams an individual multipart chunk to disk using pooled buffer
func (e *DiskEngine) UploadPart(bucket, key, uploadID string, partNumber int, r io.Reader) (string, error) {
	return e.UploadPartWithMD5(bucket, key, uploadID, partNumber, r, "")
}

// UploadPartWithMD5 streams a multipart chunk, verifies optional base64 Content-MD5, and stores its MD5 sidecar
func (e *DiskEngine) UploadPartWithMD5(bucket, key, uploadID string, partNumber int, r io.Reader, expectedMD5Base64 string) (string, error) {
	if !IsValidBucketName(bucket) {
		return "", ErrInvalidBucketName
	}
	if err := sanitizeUploadID(uploadID); err != nil {
		return "", err
	}
	if partNumber < 1 || partNumber > 10000 {
		return "", ErrInvalidPart
	}
	uploadDir := filepath.Join(e.bucketPath(bucket), "uploads", uploadID)
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		return "", ErrUploadNotFound
	}

	partPath := filepath.Join(uploadDir, fmt.Sprintf("part_%05d", partNumber))
	f, err := os.Create(partPath)
	if err != nil {
		return "", err
	}

	hasher := md5.New()
	mw := io.MultiWriter(f, hasher)

	bufPtr := bufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(mw, r, *bufPtr)
	bufPool.Put(bufPtr)

	f.Close()
	if err != nil {
		_ = os.Remove(partPath)
		return "", err
	}

	rawSum := hasher.Sum(nil)
	if expectedMD5Base64 != "" {
		actualB64 := base64.StdEncoding.EncodeToString(rawSum)
		if actualB64 != strings.TrimSpace(expectedMD5Base64) {
			_ = os.Remove(partPath)
			return "", ErrBadDigest
		}
	}

	etagHex := hex.EncodeToString(rawSum)
	etag := fmt.Sprintf("\"%s\"", etagHex)

	partMeta := PartInfo{
		PartNumber:   partNumber,
		Size:         n,
		ETag:         etag,
		LastModified: time.Now().UTC(),
	}
	pmBytes, _ := json.Marshal(partMeta)
	_ = os.WriteFile(partPath+".json", pmBytes, 0644)

	return etag, nil
}

// CompleteMultipartUpload stitches all parts in ascending PartNumber order, verifies part ETags, and emits standard AWS S3 multipart ETag
func (e *DiskEngine) CompleteMultipartUpload(bucket, key, uploadID string, parts []CompletePart, contentType string) (*ObjectInfo, error) {
	if err := sanitizeUploadID(uploadID); err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, ErrInvalidPart
	}

	dataPath, err := e.sanitizeKey(bucket, key, "data")
	if err != nil {
		return nil, err
	}
	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return nil, err
	}
	metaPath += ".json"

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	uploadDir := filepath.Join(e.bucketPath(bucket), "uploads", uploadID)
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		return nil, ErrUploadNotFound
	}

	// Load upload metadata saved during InitiateMultipartUpload
	var upMeta MultipartUploadMeta
	if metaBytes, err := os.ReadFile(filepath.Join(uploadDir, "meta.json")); err == nil {
		_ = json.Unmarshal(metaBytes, &upMeta)
	}

	if err := os.MkdirAll(filepath.Dir(dataPath), 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
		return nil, err
	}

	tempFinal := dataPath + ".tmp"
	f, err := os.Create(tempFinal)
	if err != nil {
		return nil, err
	}

	hasherSHA := sha256.New()
	mw := io.MultiWriter(f, hasherSHA)

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)

	var totalSize int64
	var concatPartMD5 []byte

	for _, part := range parts {
		partPath := filepath.Join(uploadDir, fmt.Sprintf("part_%05d", part.PartNumber))
		pf, err := os.Open(partPath)
		if err != nil {
			f.Close()
			_ = os.Remove(tempFinal)
			return nil, fmt.Errorf("%w: part %d missing or inaccessible", ErrInvalidPart, part.PartNumber)
		}

		partHasher := md5.New()
		tee := io.TeeReader(pf, partHasher)
		n, err := io.CopyBuffer(mw, tee, *bufPtr)
		pf.Close()
		if err != nil {
			f.Close()
			_ = os.Remove(tempFinal)
			return nil, err
		}

		rawPartMD5 := partHasher.Sum(nil)
		actualHex := hex.EncodeToString(rawPartMD5)
		requestedHex := strings.Trim(strings.TrimSpace(part.ETag), "\"")
		if requestedHex != "" && !strings.EqualFold(requestedHex, actualHex) {
			f.Close()
			_ = os.Remove(tempFinal)
			return nil, fmt.Errorf("%w: part %d ETag mismatch (expected %s, got %s)", ErrInvalidPart, part.PartNumber, actualHex, requestedHex)
		}

		concatPartMD5 = append(concatPartMD5, rawPartMD5...)
		totalSize += n
	}
	f.Close()

	if err := os.Rename(tempFinal, dataPath); err != nil {
		_ = os.Remove(tempFinal)
		return nil, err
	}

	_ = os.RemoveAll(uploadDir)

	if contentType == "" {
		contentType = upMeta.ContentType
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Standard AWS S3 Multipart ETag: MD5(concat of raw part MD5 bytes)-PartCount
	finalMD5 := md5.Sum(concatPartMD5)
	s3MultipartETag := fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(finalMD5[:]), len(parts))

	info := &ObjectInfo{
		Bucket:       bucket,
		Key:          key,
		Size:         totalSize,
		ETag:         s3MultipartETag,
		Sha256:       hex.EncodeToString(hasherSHA.Sum(nil)),
		ContentType:  contentType,
		LastModified: time.Now().UTC(),
		UserMetadata: upMeta.UserMetadata,
	}

	metaBytes, _ := json.Marshal(info)
	_ = os.WriteFile(metaPath, metaBytes, 0644)

	return info, nil
}

// ListParts lists uploaded chunks for an in-progress multipart upload
func (e *DiskEngine) ListParts(bucket, key, uploadID string) ([]PartInfo, error) {
	if !IsValidBucketName(bucket) {
		return nil, ErrInvalidBucketName
	}
	if err := sanitizeUploadID(uploadID); err != nil {
		return nil, err
	}
	uploadDir := filepath.Join(e.bucketPath(bucket), "uploads", uploadID)
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		return nil, ErrUploadNotFound
	}
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		return nil, err
	}
	var parts []PartInfo
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasPrefix(ent.Name(), "part_") || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(uploadDir, ent.Name())); err == nil {
			var pi PartInfo
			if json.Unmarshal(b, &pi) == nil {
				parts = append(parts, pi)
			}
		}
	}
	// Fallback if part sidecar missing
	if len(parts) == 0 {
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasPrefix(ent.Name(), "part_") || strings.HasSuffix(ent.Name(), ".json") {
				continue
			}
			numStr := strings.TrimPrefix(ent.Name(), "part_")
			num, _ := strconv.Atoi(numStr)
			fi, err := ent.Info()
			if err == nil && num > 0 {
				parts = append(parts, PartInfo{PartNumber: num, Size: fi.Size(), LastModified: fi.ModTime().UTC()})
			}
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	return parts, nil
}

// ListMultipartUploads lists active in-progress multipart uploads in a bucket
func (e *DiskEngine) ListMultipartUploads(bucket string) ([]MultipartUploadMeta, error) {
	if !e.BucketExists(bucket) {
		return nil, ErrBucketNotFound
	}
	uploadsDir := filepath.Join(e.bucketPath(bucket), "uploads")
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var uploads []MultipartUploadMeta
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(uploadsDir, ent.Name(), "meta.json")); err == nil {
			var m MultipartUploadMeta
			if json.Unmarshal(b, &m) == nil {
				uploads = append(uploads, m)
			}
		}
	}
	return uploads, nil
}

// AbortMultipartUpload cleans up temporary parts safely
func (e *DiskEngine) AbortMultipartUpload(bucket, key, uploadID string) error {
	if !IsValidBucketName(bucket) {
		return ErrInvalidBucketName
	}
	if err := sanitizeUploadID(uploadID); err != nil {
		return err
	}

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	uploadDir := filepath.Join(e.bucketPath(bucket), "uploads", uploadID)
	return os.RemoveAll(uploadDir)
}

// ExportBucketZip packages an entire bucket into a compressed ZIP stream for backups
func (e *DiskEngine) ExportBucketZip(bucket string, w io.Writer) error {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	dataPath := filepath.Join(e.bucketPath(bucket), "data")
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)

	return filepath.Walk(dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(dataPath, path)
		if err != nil {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		zw, err := zipWriter.CreateHeader(header)
		if err != nil {
			return nil
		}

		_, _ = io.CopyBuffer(zw, f, *bufPtr)
		return nil
	})
}

// CopyObject copies an object cleanly (server-side) between buckets or keys without client re-upload
func (e *DiskEngine) CopyObject(srcBucket, srcKey, dstBucket, dstKey string, overrideContentType string, overrideMeta map[string]string) (*ObjectInfo, error) {
	rc, srcInfo, err := e.GetObject(srcBucket, srcKey)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	ct := srcInfo.ContentType
	if overrideContentType != "" {
		ct = overrideContentType
	}
	meta := srcInfo.UserMetadata
	if len(overrideMeta) > 0 {
		meta = overrideMeta
	}

	return e.PutObject(dstBucket, dstKey, rc, srcInfo.Size, ct, meta)
}

// CopyPart copies a full or byte-ranged slice of an existing object into a multipart upload chunk (UploadPartCopy)
func (e *DiskEngine) CopyPart(srcBucket, srcKey, dstBucket, dstKey, uploadID string, partNumber int, startOffset, endOffset int64) (string, error) {
	rc, srcInfo, err := e.GetObject(srcBucket, srcKey)
	if err != nil {
		return "", err
	}
	defer rc.Close()

	var reader io.Reader = rc
	if startOffset >= 0 {
		if endOffset < startOffset || endOffset >= srcInfo.Size {
			endOffset = srcInfo.Size - 1
		}
		if startOffset < srcInfo.Size {
			if _, err := rc.Seek(startOffset, io.SeekStart); err != nil {
				return "", err
			}
			reader = io.LimitReader(rc, endOffset-startOffset+1)
		}
	}

	return e.UploadPartWithMD5(dstBucket, dstKey, uploadID, partNumber, reader, "")
}

// GetObjectTags reads S3 key-value tags stored alongside an object
func (e *DiskEngine) GetObjectTags(bucket, key string) (map[string]string, error) {
	info, err := e.HeadObject(bucket, key)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(info.Tags))
	for k, v := range info.Tags {
		tags[k] = v
	}
	return tags, nil
}

// PutObjectTags updates S3 object tags atomically under sharded key lock
func (e *DiskEngine) PutObjectTags(bucket, key string, tags map[string]string) error {
	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	info, err := e.headObjectLocked(bucket, key)
	if err != nil {
		return err
	}
	info.Tags = tags

	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return err
	}
	metaBytes, _ := json.Marshal(info)
	return os.WriteFile(metaPath+".json", metaBytes, 0644)
}

// DeleteObjectTags removes all S3 tags from an object
func (e *DiskEngine) DeleteObjectTags(bucket, key string) error {
	return e.PutObjectTags(bucket, key, nil)
}

// TotalUsage computes total buckets, objects, and storage bytes across the engine
func (e *DiskEngine) TotalUsage() (int, int, int64, error) {
	buckets, err := e.ListBuckets()
	if err != nil {
		return 0, 0, 0, err
	}
	var totalObjects int
	var totalBytes int64
	for _, b := range buckets {
		res, err := e.ListObjects(b.Name, "", "", "", 100000)
		if err != nil {
			continue
		}
		totalObjects += len(res.Objects)
		for _, obj := range res.Objects {
			totalBytes += obj.Size
		}
	}
	return len(buckets), totalObjects, totalBytes, nil
}
