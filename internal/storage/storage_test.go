package storage

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
)

func TestDiskEngine(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, err := NewDiskEngine(tempDir)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	// 1. Create Bucket
	bucketName := "test-bucket"
	err = engine.CreateBucket(bucketName)
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	if !engine.BucketExists(bucketName) {
		t.Fatalf("expected bucket to exist")
	}

	// 2. Put Object
	objKey := "photos/avatar.png"
	content := []byte("fake-png-image-bytes-12345")
	info, err := engine.PutObject(bucketName, objKey, bytes.NewReader(content), int64(len(content)), "image/png", map[string]string{"user": "dinidu"})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	if info.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), info.Size)
	}
	if info.ContentType != "image/png" {
		t.Errorf("expected image/png, got %s", info.ContentType)
	}

	// 3. Head Object
	head, err := engine.HeadObject(bucketName, objKey)
	if err != nil {
		t.Fatalf("HeadObject failed: %v", err)
	}
	if head.ETag != info.ETag {
		t.Errorf("ETag mismatch: %s vs %s", head.ETag, info.ETag)
	}

	// 4. Get Object
	rc, _, err := engine.GetObject(bucketName, objKey)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}

	readBytes, err := io.ReadAll(rc)
	_ = rc.Close() // Explicitly close file handle immediately for Windows compatibility
	if err != nil {
		t.Fatalf("failed to read data: %v", err)
	}
	if !bytes.Equal(readBytes, content) {
		t.Fatalf("read content mismatch")
	}

	// 5. List Objects
	res, err := engine.ListObjects(bucketName, "", "", "", 10)
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}
	if len(res.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(res.Objects))
	}
	if res.Objects[0].Key != objKey {
		t.Errorf("expected key %s, got %s", objKey, res.Objects[0].Key)
	}

	// 6. Delete Object & verify clean parent removal
	err = engine.DeleteObject(bucketName, objKey)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	_, _, err = engine.GetObject(bucketName, objKey)
	if err != ErrObjectNotFound {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	// 7. Delete Bucket
	err = engine.DeleteBucket(bucketName)
	if err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}
	if engine.BucketExists(bucketName) {
		t.Fatalf("expected bucket to be gone")
	}
}

func TestSecurityPathTraversalPrevention(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-security-*")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, err := NewDiskEngine(tempDir)
	if err != nil {
		t.Fatalf("engine init err: %v", err)
	}

	_ = engine.CreateBucket("safe-bucket")

	maliciousKeys := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32\\cmd.exe",
		"/etc/shadow",
		"sub/../../../secret.txt",
		"..",
	}

	for _, badKey := range maliciousKeys {
		_, err := engine.PutObject("safe-bucket", badKey, bytes.NewReader([]byte("hacked")), 6, "text/plain", nil)
		if err == nil {
			t.Errorf("security flaw: allowed malicious path traversal key %q", badKey)
		}
	}
}

func TestConcurrencyStress(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-stress-*")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, _ := NewDiskEngine(tempDir)
	_ = engine.CreateBucket("stress-bucket")

	var wg sync.WaitGroup
	// 50 parallel writers and readers to verify deadlock-free operation
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "item-" + string(rune('a'+(id%26))) + ".txt"
			data := []byte("parallel data payload")
			_, _ = engine.PutObject("stress-bucket", key, bytes.NewReader(data), int64(len(data)), "text/plain", nil)
			rc, _, err := engine.GetObject("stress-bucket", key)
			if err == nil && rc != nil {
				_ = rc.Close()
			}
		}(i)
	}
	wg.Wait()
}


func TestBucketNamingValidation(t *testing.T) {
	validBuckets := []string{
		"my-bucket",
		"fitbook-media",
		"syncspace-attachments",
		"artist-assets",
		"data.2026.storage",
	}

	invalidBuckets := []string{
		"ab",                          // too short (<3)
		"-startwithhyphen",           // starts with hyphen
		"endwithhyphen-",             // ends with hyphen
		"UPPERCASE",                  // uppercase not allowed in S3
		"space in bucket",            // spaces
		"bucket..double-dot",         // double dot
		"bucket_with_underscore",     // underscores not allowed in DNS S3
		"bucket/traversal",           // slash
	}

	for _, b := range validBuckets {
		if !IsValidBucketName(b) {
			t.Errorf("expected valid bucket name for %q", b)
		}
	}

	for _, b := range invalidBuckets {
		if IsValidBucketName(b) {
			t.Errorf("expected invalid bucket name for %q", b)
		}
	}
}

func TestNullByteInjectionPrevention(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-nullbyte-*")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, _ := NewDiskEngine(tempDir)
	_ = engine.CreateBucket("nullbyte-bucket")

	_, err = engine.PutObject("nullbyte-bucket", "safe.txt\x00.exe", bytes.NewReader([]byte("payload")), 7, "text/plain", nil)
	if err != ErrInvalidObjectKey {
		t.Fatalf("expected ErrInvalidObjectKey on null byte injection, got: %v", err)
	}
}


func TestMultipartUploadWorkflow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-mp-*")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, _ := NewDiskEngine(tempDir)
	_ = engine.CreateBucket("media-bucket")

	objKey := "videos/conference.mp4"

	// 1. Initiate
	uploadID, err := engine.InitiateMultipartUpload("media-bucket", objKey)
	if err != nil {
		t.Fatalf("InitiateMultipartUpload failed: %v", err)
	}
	if uploadID == "" {
		t.Fatalf("expected non-empty uploadID")
	}

	// 2. Upload Part 1
	chunk1 := []byte("Chunk 1: First 5MB of high-definition video...")
	etag1, err := engine.UploadPart("media-bucket", objKey, uploadID, 1, bytes.NewReader(chunk1))
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}

	// 3. Upload Part 2
	chunk2 := []byte("Chunk 2: Second 5MB of high-definition video...")
	etag2, err := engine.UploadPart("media-bucket", objKey, uploadID, 2, bytes.NewReader(chunk2))
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	// 4. Complete
	parts := []CompletePart{
		{PartNumber: 1, ETag: etag1},
		{PartNumber: 2, ETag: etag2},
	}
	info, err := engine.CompleteMultipartUpload("media-bucket", objKey, uploadID, parts, "video/mp4")
	if err != nil {
		t.Fatalf("CompleteMultipartUpload failed: %v", err)
	}

	expectedLen := int64(len(chunk1) + len(chunk2))
	if info.Size != expectedLen {
		t.Errorf("expected size %d, got %d", expectedLen, info.Size)
	}

	// 5. Verify stitched content
	rc, _, err := engine.GetObject("media-bucket", objKey)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	fullData, _ := io.ReadAll(rc)
	_ = rc.Close()

	expectedData := append(chunk1, chunk2...)
	if !bytes.Equal(fullData, expectedData) {
		t.Fatalf("stitched video content does not match expected chunks")
	}
}

func TestBucketZipBackup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "my-s3-zip-*")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine, _ := NewDiskEngine(tempDir)
	_ = engine.CreateBucket("backup-bucket")

	_, _ = engine.PutObject("backup-bucket", "image1.jpg", bytes.NewReader([]byte("jpeg-data")), 9, "image/jpeg", nil)
	_, _ = engine.PutObject("backup-bucket", "folder/doc.pdf", bytes.NewReader([]byte("pdf-data")), 8, "application/pdf", nil)

	var zipBuf bytes.Buffer
	err = engine.ExportBucketZip("backup-bucket", &zipBuf)
	if err != nil {
		t.Fatalf("ExportBucketZip failed: %v", err)
	}

	if zipBuf.Len() == 0 {
		t.Fatalf("expected non-empty ZIP archive")
	}
}
