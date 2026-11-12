package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"my-s3/internal/crypto"
)

// BucketConfig stores bucket-level governance settings (Versioning, Object Lock)
type BucketConfig struct {
	Versioning        string `json:"versioning,omitempty"` // "", "Enabled", "Suspended"
	ObjectLockEnabled bool   `json:"object_lock_enabled,omitempty"`
}

// ObjectVersionEntry describes an item inside ListObjectVersions
type ObjectVersionEntry struct {
	ObjectInfo
	IsLatest bool `json:"is_latest"`
}

func (e *DiskEngine) bucketConfigPath(bucket string) string {
	return filepath.Join(e.bucketPath(bucket), "bucket_config.json")
}

// GetBucketConfig reads the bucket's versioning and object-lock settings
func (e *DiskEngine) GetBucketConfig(bucket string) (BucketConfig, error) {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return BucketConfig{}, ErrBucketNotFound
	}
	return e.getBucketConfigLocked(bucket), nil
}

func (e *DiskEngine) getBucketConfigLocked(bucket string) BucketConfig {
	var cfg BucketConfig
	data, err := os.ReadFile(e.bucketConfigPath(bucket))
	if err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	return cfg
}

func (e *DiskEngine) saveBucketConfigLocked(bucket string, cfg BucketConfig) error {
	data, _ := json.Marshal(cfg)
	return os.WriteFile(e.bucketConfigPath(bucket), data, 0644)
}

// SetBucketVersioning sets bucket versioning to "Enabled" or "Suspended"
func (e *DiskEngine) SetBucketVersioning(bucket, status string) error {
	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}
	cfg := e.getBucketConfigLocked(bucket)
	if cfg.ObjectLockEnabled && status == "Suspended" {
		return fmt.Errorf("%w: cannot suspend versioning on an Object Lock enabled bucket", ErrObjectLocked)
	}
	if status != "Enabled" && status != "Suspended" {
		return fmt.Errorf("invalid versioning status %q", status)
	}
	cfg.Versioning = status
	return e.saveBucketConfigLocked(bucket, cfg)
}

// EnableBucketObjectLock turns on WORM Object Lock (automatically enables versioning per S3 spec)
func (e *DiskEngine) EnableBucketObjectLock(bucket string) error {
	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}
	cfg := e.getBucketConfigLocked(bucket)
	cfg.ObjectLockEnabled = true
	cfg.Versioning = "Enabled"
	return e.saveBucketConfigLocked(bucket, cfg)
}

func generateVersionID() string {
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	// Fixed-width descending or chronological ID + random suffix
	return fmt.Sprintf("v%019d_%s", time.Now().UTC().UnixNano(), hex.EncodeToString(rb))
}

func (e *DiskEngine) versionDataDir(bucket, key string) string {
	return filepath.Join(e.bucketPath(bucket), "versions", "data", filepath.FromSlash(key))
}

func (e *DiskEngine) versionMetaDir(bucket, key string) string {
	return filepath.Join(e.bucketPath(bucket), "versions", "meta", filepath.FromSlash(key))
}

func checkObjectLockLocked(info *ObjectInfo, bypassGovernance bool) error {
	if info == nil || info.IsDeleteMarker {
		return nil
	}
	if strings.EqualFold(info.LegalHoldStatus, "ON") {
		return fmt.Errorf("%w: legal hold is active on version %s", ErrObjectLocked, info.VersionID)
	}
	if info.RetainUntilDate != nil && time.Now().UTC().Before(*info.RetainUntilDate) {
		mode := strings.ToUpper(info.RetentionMode)
		if mode == "COMPLIANCE" {
			return fmt.Errorf("%w: COMPLIANCE retention active until %s", ErrObjectLocked, info.RetainUntilDate.Format(time.RFC3339))
		}
		if mode == "GOVERNANCE" && !bypassGovernance {
			return fmt.Errorf("%w: GOVERNANCE retention active until %s", ErrObjectLocked, info.RetainUntilDate.Format(time.RFC3339))
		}
	}
	return nil
}

// archiveCurrentVersionLocked moves the active data/meta into versions/ before overwriting or creating a delete marker
func (e *DiskEngine) archiveCurrentVersionLocked(bucket, key, dataPath, metaPath string) error {
	prevInfo, err := e.headObjectLocked(bucket, key)
	if err != nil {
		return nil // No previous version exists
	}

	verID := prevInfo.VersionID
	if verID == "" {
		verID = generateVersionID()
		prevInfo.VersionID = verID
	}

	vDataDir := e.versionDataDir(bucket, key)
	vMetaDir := e.versionMetaDir(bucket, key)
	if err := os.MkdirAll(vDataDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(vMetaDir, 0755); err != nil {
		return err
	}

	if !prevInfo.IsDeleteMarker {
		if _, err := os.Stat(dataPath); err == nil {
			if err := os.Rename(dataPath, filepath.Join(vDataDir, verID)); err != nil {
				return err
			}
		}
	}

	b, _ := json.Marshal(prevInfo)
	if err := os.WriteFile(filepath.Join(vMetaDir, verID+".json"), b, 0644); err != nil {
		return err
	}
	_ = os.Remove(metaPath)
	return nil
}

func sanitizeVersionID(versionID string) error {
	if versionID == "" {
		return nil
	}
	if versionID == "." || versionID == ".." || strings.Contains(versionID, "..") || strings.ContainsAny(versionID, "/\\:\x00") {
		return ErrObjectNotFound
	}
	return nil
}

// HeadObjectVersion reads metadata for a specific versionID (or latest if versionID == "")
func (e *DiskEngine) HeadObjectVersion(bucket, key, versionID string) (*ObjectInfo, error) {
	if err := sanitizeVersionID(versionID); err != nil {
		return nil, err
	}
	if _, err := e.sanitizeKey(bucket, key, "meta"); err != nil {
		return nil, err
	}
	keyLock := e.getLock(bucket, key)
	keyLock.RLock()
	defer keyLock.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return nil, ErrBucketNotFound
	}

	// Check active head first
	active, err := e.headObjectLocked(bucket, key)
	if versionID == "" {
		if err != nil {
			return nil, err
		}
		if active.IsDeleteMarker {
			return nil, ErrObjectNotFound
		}
		return active, nil
	}

	if err == nil && active.VersionID == versionID {
		return active, nil
	}

	vMetaPath := filepath.Join(e.versionMetaDir(bucket, key), filepath.Base(versionID)+".json")
	b, err := os.ReadFile(vMetaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrObjectNotFound
		}
		return nil, err
	}
	var info ObjectInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (e *DiskEngine) wrapDecryptReader(f *os.File, info *ObjectInfo, bucket, key string, sse SSEOptions) (io.ReadSeekCloser, error) {
	if !info.Encrypted {
		return f, nil
	}
	var decKey []byte
	if info.SSEAlgorithm == "AES256-C" {
		if len(sse.CustomerKey) != 32 {
			_ = f.Close()
			return nil, crypto.ErrMissingCustomerKey
		}
		if info.SSEKeyMD5 != "" && sse.CustomerKeyMD5 != info.SSEKeyMD5 {
			_ = f.Close()
			return nil, crypto.ErrWrongCustomerKey
		}
		decKey = sse.CustomerKey
	} else {
		decKey = crypto.DeriveMasterObjectKey(e.resolveMasterSecret(), bucket, key)
	}
	decReader, err := crypto.NewChunkedDecryptReadSeeker(f, decKey, info.Size)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return decReader, nil
}

// GetObjectVersion opens a specific version stream (or latest if versionID == "")
func (e *DiskEngine) GetObjectVersion(bucket, key, versionID string) (io.ReadSeekCloser, *ObjectInfo, error) {
	return e.GetObjectVersionWithSSE(bucket, key, versionID, SSEOptions{})
}

// GetObjectVersionWithSSE opens and transparently decrypts an encrypted or plaintext version stream
func (e *DiskEngine) GetObjectVersionWithSSE(bucket, key, versionID string, sse SSEOptions) (io.ReadSeekCloser, *ObjectInfo, error) {
	if err := sanitizeVersionID(versionID); err != nil {
		return nil, nil, err
	}
	if _, err := e.sanitizeKey(bucket, key, "data"); err != nil {
		return nil, nil, err
	}
	keyLock := e.getLock(bucket, key)
	keyLock.RLock()
	defer keyLock.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return nil, nil, ErrBucketNotFound
	}

	active, err := e.headObjectLocked(bucket, key)
	if versionID == "" {
		if err != nil {
			return nil, nil, err
		}
		if active.IsDeleteMarker {
			return nil, nil, ErrObjectNotFound
		}
		dataPath, _ := e.sanitizeKey(bucket, key, "data")
		f, err := os.Open(dataPath)
		if err != nil {
			if os.IsNotExist(err) && e.erasureStore != nil {
				if recovered, _, ecErr := e.erasureStore.GetObjectAndHeal(bucket, key); ecErr == nil {
					_ = os.MkdirAll(filepath.Dir(dataPath), 0755)
					_ = os.WriteFile(dataPath, recovered, 0644)
					f, err = os.Open(dataPath)
				}
			}
			if err != nil {
				if os.IsNotExist(err) {
					return nil, nil, ErrObjectNotFound
				}
				return nil, nil, err
			}
		}
		rc, decErr := e.wrapDecryptReader(f, active, bucket, key, sse)
		if decErr != nil {
			return nil, nil, decErr
		}
		return rc, active, nil
	}

	if err == nil && active.VersionID == versionID {
		if active.IsDeleteMarker {
			return nil, active, ErrObjectNotFound
		}
		dataPath, _ := e.sanitizeKey(bucket, key, "data")
		f, err := os.Open(dataPath)
		if err != nil {
			return nil, nil, err
		}
		rc, decErr := e.wrapDecryptReader(f, active, bucket, key, sse)
		if decErr != nil {
			return nil, nil, decErr
		}
		return rc, active, nil
	}

	vMetaPath := filepath.Join(e.versionMetaDir(bucket, key), filepath.Base(versionID)+".json")
	b, err := os.ReadFile(vMetaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrObjectNotFound
		}
		return nil, nil, err
	}
	var info ObjectInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, nil, err
	}
	if info.IsDeleteMarker {
		return nil, &info, ErrObjectNotFound
	}

	vDataPath := filepath.Join(e.versionDataDir(bucket, key), filepath.Base(versionID))
	f, err := os.Open(vDataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrObjectNotFound
		}
		return nil, nil, err
	}
	rc, decErr := e.wrapDecryptReader(f, &info, bucket, key, sse)
	if decErr != nil {
		return nil, nil, decErr
	}
	return rc, &info, nil
}

// SetObjectRetention configures WORM retention mode (GOVERNANCE/COMPLIANCE) and RetainUntilDate
func (e *DiskEngine) SetObjectRetention(bucket, key, versionID, mode string, retainUntil time.Time) error {
	if err := sanitizeVersionID(versionID); err != nil {
		return err
	}
	if _, err := e.sanitizeKey(bucket, key, "meta"); err != nil {
		return err
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
		return fmt.Errorf("invalid retention mode %q", mode)
	}

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	targetPath, info, err := e.locateVersionMetaLocked(bucket, key, versionID)
	if err != nil {
		return err
	}
	// Cannot shorten active COMPLIANCE retention per AWS S3 WORM spec
	if strings.EqualFold(info.RetentionMode, "COMPLIANCE") && info.RetainUntilDate != nil && retainUntil.Before(*info.RetainUntilDate) {
		return fmt.Errorf("%w: cannot shorten existing COMPLIANCE retention date", ErrObjectLocked)
	}
	t := retainUntil.UTC()
	info.RetentionMode = mode
	info.RetainUntilDate = &t

	b, _ := json.Marshal(info)
	return os.WriteFile(targetPath, b, 0644)
}

// SetObjectLegalHold turns WORM Legal Hold ON or OFF
func (e *DiskEngine) SetObjectLegalHold(bucket, key, versionID, status string) error {
	if err := sanitizeVersionID(versionID); err != nil {
		return err
	}
	if _, err := e.sanitizeKey(bucket, key, "meta"); err != nil {
		return err
	}
	status = strings.ToUpper(strings.TrimSpace(status))
	if status != "ON" && status != "OFF" {
		return fmt.Errorf("invalid legal hold status %q", status)
	}

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	targetPath, info, err := e.locateVersionMetaLocked(bucket, key, versionID)
	if err != nil {
		return err
	}
	info.LegalHoldStatus = status

	b, _ := json.Marshal(info)
	return os.WriteFile(targetPath, b, 0644)
}

func (e *DiskEngine) locateVersionMetaLocked(bucket, key, versionID string) (string, *ObjectInfo, error) {
	if !e.bucketExistsLocked(bucket) {
		return "", nil, ErrBucketNotFound
	}
	metaPath, _ := e.sanitizeKey(bucket, key, "meta")
	metaPath += ".json"

	active, err := e.headObjectLocked(bucket, key)
	if versionID == "" || (err == nil && active.VersionID == versionID) {
		if err != nil {
			return "", nil, err
		}
		if active.IsDeleteMarker {
			return "", nil, ErrObjectNotFound
		}
		return metaPath, active, nil
	}

	vMetaPath := filepath.Join(e.versionMetaDir(bucket, key), filepath.Base(versionID)+".json")
	b, err := os.ReadFile(vMetaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, ErrObjectNotFound
		}
		return "", nil, err
	}
	var info ObjectInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return "", nil, err
	}
	if info.IsDeleteMarker {
		return "", nil, ErrObjectNotFound
	}
	return vMetaPath, &info, nil
}

// DeleteObjectVersion deletes either a specific version (enforcing WORM locks) or creates a DeleteMarker when versioning is enabled
func (e *DiskEngine) DeleteObjectVersion(bucket, key, versionID string, bypassGovernance bool) (deletedVersionID string, isDeleteMarker bool, err error) {
	if err := sanitizeVersionID(versionID); err != nil {
		return "", false, err
	}
	dataPath, err := e.sanitizeKey(bucket, key, "data")
	if err != nil {
		return "", false, err
	}
	metaPath, err := e.sanitizeKey(bucket, key, "meta")
	if err != nil {
		return "", false, err
	}
	metaPath += ".json"

	keyLock := e.getLock(bucket, key)
	keyLock.Lock()
	defer keyLock.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return "", false, ErrBucketNotFound
	}

	cfg := e.getBucketConfigLocked(bucket)

	// Case 1: Deleting without explicit versionId
	if versionID == "" {
		if cfg.Versioning == "Enabled" {
			_ = e.archiveCurrentVersionLocked(bucket, key, dataPath, metaPath)
			dmVerID := generateVersionID()
			dm := &ObjectInfo{
				Bucket:         bucket,
				Key:            key,
				VersionID:      dmVerID,
				IsDeleteMarker: true,
				LastModified:   time.Now().UTC(),
			}
			if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
				return "", false, err
			}
			b, _ := json.Marshal(dm)
			_ = os.WriteFile(metaPath, b, 0644)
			return dmVerID, true, nil
		}

		// Non-versioned delete: enforce lock on active head if present
		if active, err := e.headObjectLocked(bucket, key); err == nil {
			if lockErr := checkObjectLockLocked(active, bypassGovernance); lockErr != nil {
				return "", false, lockErr
			}
		}
		_ = os.Remove(dataPath)
		_ = os.Remove(metaPath)
		cleanEmptyParentDirs(dataPath, filepath.Join(e.bucketPath(bucket), "data"))
		cleanEmptyParentDirs(metaPath, filepath.Join(e.bucketPath(bucket), "meta"))
		return "", false, nil
	}

	// Case 2: Deleting a specific VersionID
	active, activeErr := e.headObjectLocked(bucket, key)
	if activeErr == nil && active.VersionID == versionID {
		if lockErr := checkObjectLockLocked(active, bypassGovernance); lockErr != nil {
			return "", false, lockErr
		}
		wasDM := active.IsDeleteMarker
		_ = os.Remove(dataPath)
		_ = os.Remove(metaPath)
		e.promoteLatestArchiveLocked(bucket, key, dataPath, metaPath)
		return versionID, wasDM, nil
	}

	vMetaPath := filepath.Join(e.versionMetaDir(bucket, key), filepath.Base(versionID)+".json")
	b, err := os.ReadFile(vMetaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return versionID, false, nil // S3 idempotent delete
		}
		return "", false, err
	}
	var info ObjectInfo
	if err := json.Unmarshal(b, &info); err == nil {
		if lockErr := checkObjectLockLocked(&info, bypassGovernance); lockErr != nil {
			return "", false, lockErr
		}
	}
	_ = os.Remove(vMetaPath)
	_ = os.Remove(filepath.Join(e.versionDataDir(bucket, key), filepath.Base(versionID)))
	cleanEmptyParentDirs(vMetaPath, filepath.Join(e.bucketPath(bucket), "versions", "meta"))
	cleanEmptyParentDirs(filepath.Join(e.versionDataDir(bucket, key), filepath.Base(versionID)), filepath.Join(e.bucketPath(bucket), "versions", "data"))
	return versionID, info.IsDeleteMarker, nil
}

// promoteLatestArchiveLocked restores the newest archived revision into active data/meta if the head version was permanently deleted
func (e *DiskEngine) promoteLatestArchiveLocked(bucket, key, dataPath, metaPath string) {
	vMetaDir := e.versionMetaDir(bucket, key)
	entries, err := os.ReadDir(vMetaDir)
	if err != nil || len(entries) == 0 {
		cleanEmptyParentDirs(dataPath, filepath.Join(e.bucketPath(bucket), "data"))
		cleanEmptyParentDirs(metaPath, filepath.Join(e.bucketPath(bucket), "meta"))
		return
	}
	var latestInfo *ObjectInfo
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(vMetaDir, ent.Name()))
		if err != nil {
			continue
		}
		var cand ObjectInfo
		if json.Unmarshal(b, &cand) == nil {
			if latestInfo == nil || cand.VersionID > latestInfo.VersionID {
				copyCand := cand
				latestInfo = &copyCand
			}
		}
	}
	if latestInfo == nil {
		return
	}
	if !latestInfo.IsDeleteMarker {
		vData := filepath.Join(e.versionDataDir(bucket, key), latestInfo.VersionID)
		_ = os.MkdirAll(filepath.Dir(dataPath), 0755)
		_ = os.Rename(vData, dataPath)
	}
	_ = os.MkdirAll(filepath.Dir(metaPath), 0755)
	b, _ := json.Marshal(latestInfo)
	_ = os.WriteFile(metaPath, b, 0644)
	_ = os.Remove(filepath.Join(vMetaDir, latestInfo.VersionID+".json"))
}

// ListObjectVersions returns active and historical versions (plus delete markers) sorted newest-first per key
func (e *DiskEngine) ListObjectVersions(bucket, prefix string) ([]ObjectVersionEntry, error) {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return nil, ErrBucketNotFound
	}

	var results []ObjectVersionEntry

	// 1. Walk active heads
	metaBase := filepath.Join(e.bucketPath(bucket), "meta")
	_ = filepath.Walk(metaBase, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(fi.Name(), ".json") {
			return nil
		}
		if b, err := os.ReadFile(path); err == nil {
			var obj ObjectInfo
			if json.Unmarshal(b, &obj) == nil {
				if prefix == "" || strings.HasPrefix(obj.Key, prefix) {
					if obj.VersionID == "" {
						obj.VersionID = "null"
					}
					results = append(results, ObjectVersionEntry{ObjectInfo: obj, IsLatest: true})
				}
			}
		}
		return nil
	})

	// 2. Walk archived versions
	vMetaBase := filepath.Join(e.bucketPath(bucket), "versions", "meta")
	_ = filepath.Walk(vMetaBase, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(fi.Name(), ".json") {
			return nil
		}
		if b, err := os.ReadFile(path); err == nil {
			var obj ObjectInfo
			if json.Unmarshal(b, &obj) == nil {
				if prefix == "" || strings.HasPrefix(obj.Key, prefix) {
					results = append(results, ObjectVersionEntry{ObjectInfo: obj, IsLatest: false})
				}
			}
		}
		return nil
	})

	sort.Slice(results, func(i, j int) bool {
		if results[i].Key != results[j].Key {
			return results[i].Key < results[j].Key
		}
		if results[i].IsLatest != results[j].IsLatest {
			return results[i].IsLatest
		}
		return results[i].VersionID > results[j].VersionID
	})

	return results, nil
}
