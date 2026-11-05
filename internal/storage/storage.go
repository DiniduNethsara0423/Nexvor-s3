package storage

import (
	"archive/zip"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrBucketAlreadyExists = errors.New("bucket already exists")
	ErrBucketNotFound      = errors.New("bucket does not exist")
	ErrObjectNotFound      = errors.New("object does not exist")
	ErrBucketNotEmpty      = errors.New("bucket not empty")
	ErrInvalidBucketName   = errors.New("invalid bucket name")
	ErrInvalidObjectKey    = errors.New("invalid object key or path traversal detected")
	ErrUploadNotFound      = errors.New("multipart upload not found")
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
	Bucket       string            `json:"bucket"`
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	Sha256       string            `json:"sha256,omitempty"`
	ContentType  string            `json:"content_type"`
	LastModified time.Time         `json:"last_modified"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
}

// BucketInfo represents bucket metadata
type BucketInfo struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
}

// DiskEngine implements high-concurrency, sharded-lock local disk storage
type DiskEngine struct {
	bucketMu sync.RWMutex
	keyLocks [256]sync.RWMutex
	baseDir  string
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

func (e *DiskEngine) bucketExistsLocked(bucket string) bool {
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

// PutObject streams data with sharded lock and zero-allocation pooled 128KB buffer
func (e *DiskEngine) PutObject(bucket, key string, r io.Reader, size int64, contentType string, userMeta map[string]string) (*ObjectInfo, error) {
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
	mw := io.MultiWriter(f, hasherMD5, hasherSHA)

	// Fetch recycled 128KB buffer from sync.Pool (zero allocations!)
	bufPtr := bufPool.Get().(*[]byte)
	written, err := io.CopyBuffer(mw, r, *bufPtr)
	bufPool.Put(bufPtr)

	f.Close()
	if err != nil {
		_ = os.Remove(tempFile)
		return nil, err
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
		Size:         written,
		ETag:         etag,
		Sha256:       sha,
		ContentType:  contentType,
		LastModified: time.Now().UTC(),
		UserMetadata: userMeta,
	}

	metaBytes, _ := json.Marshal(info)
	if err := os.WriteFile(metaPath, metaBytes, 0644); err != nil {
		return nil, err
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

	return e.headObjectLocked(bucket, key)
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

// DeleteObject removes the object data and cleans up empty parent directories
func (e *DiskEngine) DeleteObject(bucket, key string) error {
	dataPath, err := e.sanitizeKey(bucket, key, "data")
	if err != nil {
		return err
	}
	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return err
	}
	metaPath += ".json"

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	if !e.BucketExists(bucket) {
		return ErrBucketNotFound
	}

	_ = os.Remove(dataPath)
	_ = os.Remove(metaPath)

	cleanEmptyParentDirs(dataPath, filepath.Join(e.bucketPath(bucket), "data"))
	cleanEmptyParentDirs(metaPath, filepath.Join(e.bucketPath(bucket), "meta"))

	return nil
}

// ListObjectsResult holds objects and common prefixes for S3 ListObjects
type ListObjectsResult struct {
	Objects        []ObjectInfo
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string
}

// ListObjects lists objects with prefix, delimiter, marker, and maxKeys support
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
			if err := json.Unmarshal(data, &obj); err == nil {
				allObjects = append(allObjects, obj)
			}
		}
		return nil
	})

	sort.Slice(allObjects, func(i, j int) bool {
		return allObjects[i].Key < allObjects[j].Key
	})

	result := &ListObjectsResult{}
	prefixesSeen := make(map[string]bool)

	count := 0
	for _, obj := range allObjects {
		if marker != "" && obj.Key <= marker {
			continue
		}
		if prefix != "" && !strings.HasPrefix(obj.Key, prefix) {
			continue
		}

		if delimiter != "" {
			rest := strings.TrimPrefix(obj.Key, prefix)
			if idx := strings.Index(rest, delimiter); idx >= 0 {
				commonPrefix := prefix + rest[:idx+len(delimiter)]
				if !prefixesSeen[commonPrefix] {
					prefixesSeen[commonPrefix] = true
					result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix)
				}
				continue
			}
		}

		if count >= maxKeys {
			result.IsTruncated = true
			result.NextMarker = obj.Key
			break
		}

		result.Objects = append(result.Objects, obj)
		count++
	}

	sort.Strings(result.CommonPrefixes)
	return result, nil
}

// InitiateMultipartUpload prepares temporary directory for chunked upload
func (e *DiskEngine) InitiateMultipartUpload(bucket, key string) (string, error) {
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

	meta := struct {
		Key       string    `json:"key"`
		CreatedAt time.Time `json:"created_at"`
	}{
		Key:       key,
		CreatedAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(meta)
	_ = os.WriteFile(filepath.Join(uploadDir, "meta.json"), data, 0644)

	return uploadID, nil
}

// UploadPart streams an individual multipart chunk to disk using pooled buffer
func (e *DiskEngine) UploadPart(bucket, key, uploadID string, partNumber int, r io.Reader) (string, error) {
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
	_, err = io.CopyBuffer(mw, r, *bufPtr)
	bufPool.Put(bufPtr)

	f.Close()
	if err != nil {
		_ = os.Remove(partPath)
		return "", err
	}

	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hasher.Sum(nil)))
	return etag, nil
}

// CompleteMultipartUpload stitches together all uploaded parts into the final object
func (e *DiskEngine) CompleteMultipartUpload(bucket, key, uploadID string, parts []CompletePart, contentType string) (*ObjectInfo, error) {
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

	hasherMD5 := md5.New()
	hasherSHA := sha256.New()
	mw := io.MultiWriter(f, hasherMD5, hasherSHA)

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)

	var totalSize int64
	for _, part := range parts {
		partPath := filepath.Join(uploadDir, fmt.Sprintf("part_%05d", part.PartNumber))
		pf, err := os.Open(partPath)
		if err != nil {
			f.Close()
			_ = os.Remove(tempFinal)
			return nil, fmt.Errorf("part %d missing or inaccessible: %w", part.PartNumber, err)
		}
		n, err := io.CopyBuffer(mw, pf, *bufPtr)
		pf.Close()
		if err != nil {
			f.Close()
			_ = os.Remove(tempFinal)
			return nil, err
		}
		totalSize += n
	}
	f.Close()

	if err := os.Rename(tempFinal, dataPath); err != nil {
		_ = os.Remove(tempFinal)
		return nil, err
	}

	_ = os.RemoveAll(uploadDir)

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	info := &ObjectInfo{
		Bucket:       bucket,
		Key:          key,
		Size:         totalSize,
		ETag:         fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(hasherMD5.Sum(nil)), len(parts)),
		Sha256:       hex.EncodeToString(hasherSHA.Sum(nil)),
		ContentType:  contentType,
		LastModified: time.Now().UTC(),
	}

	metaBytes, _ := json.Marshal(info)
	_ = os.WriteFile(metaPath, metaBytes, 0644)

	return info, nil
}

// AbortMultipartUpload cleans up temporary parts
func (e *DiskEngine) AbortMultipartUpload(bucket, key, uploadID string) error {
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
