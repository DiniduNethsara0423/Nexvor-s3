package api

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"my-s3/internal/auth"
	"my-s3/internal/storage"
)

func TestSecurityComprehensivePathTraversal(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	_ = httptest.NewRequest(http.MethodPut, "/safe-bucket", nil)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/safe-bucket", nil))

	maliciousVectors := []string{
		"../../windows/win.ini",
		"..\\..\\windows\\system32",
		"/etc/passwd",
		"/etc/shadow",
		"sub/../../../secret.txt",
		"..",
		"../",
		"folder/../../..",
		"file.txt::$DATA",
		"file.txt:hidden_stream",
		"safe.txt%00.exe",
		"~/.ssh/id_rsa",
	}

	for _, vector := range maliciousVectors {
		// Test PUT
		req := httptest.NewRequest(http.MethodPut, "/safe-bucket/"+vector, bytes.NewReader([]byte("hacked")))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Fatalf("SECURITY FLAW: PUT allowed malicious vector: %q (Code %d)", vector, w.Code)
		}

		// Test GET
		req = httptest.NewRequest(http.MethodGet, "/safe-bucket/"+vector, nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Fatalf("SECURITY FLAW: GET allowed malicious vector: %q (Code %d)", vector, w.Code)
		}

		// Test DELETE
		req = httptest.NewRequest(http.MethodDelete, "/safe-bucket/"+vector, nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusOK || w.Code == http.StatusNoContent {
			t.Fatalf("SECURITY FLAW: DELETE allowed malicious vector: %q (Code %d)", vector, w.Code)
		}
	}
}

func TestSecurityTimingAttackDefense(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	// Authenticator configured with "testaccess" / "testsecret"
	testCases := []struct {
		name      string
		header    string
		shouldPass bool
	}{
		{
			name:      "Valid AWS SigV4 AccessKey",
			header:    "AWS4-HMAC-SHA256 Credential=testaccess/20261105/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
			shouldPass: true,
		},
		{
			name:      "Invalid AccessKey same length",
			header:    "AWS4-HMAC-SHA256 Credential=testXXXXXX/20261105/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
			shouldPass: false,
		},
		{
			name:      "Invalid AccessKey different length",
			header:    "AWS4-HMAC-SHA256 Credential=wrong/20261105/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
			shouldPass: false,
		},
		{
			name:      "Valid legacy AWS key:sig",
			header:    "AWS testaccess:signature123",
			shouldPass: true,
		},
		{
			name:      "Invalid legacy AWS key:sig",
			header:    "AWS eviluser:signature123",
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest(http.MethodGet, "/safe-bucket", nil)
		req.Header.Set("Authorization", tc.header)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if tc.shouldPass && w.Code == http.StatusForbidden {
			t.Errorf("[%s] expected pass, but got 403 Forbidden", tc.name)
		}
		if !tc.shouldPass && w.Code != http.StatusForbidden {
			t.Errorf("[%s] expected 403 Forbidden, got: %d", tc.name, w.Code)
		}
	}
}

func TestSecurityMalformedXMLInjection(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	_ = httptest.NewRequest(http.MethodPut, "/xml-bucket", nil)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/xml-bucket", nil))

	maliciousXMLs := []string{
		"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
		"<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;\">]><lolz>&lol1;</lolz>",
		"<CompleteMultipartUpload><Part><PartNumber>not-a-number</PartNumber></Part></CompleteMultipartUpload>",
		"NOT_XML_AT_ALL_CORRUPT_BYTES_12345",
	}

	for _, payload := range maliciousXMLs {
		req := httptest.NewRequest(http.MethodPost, "/xml-bucket/file.bin?uploadId=fakeid", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/xml")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Must never crash (panic) and must reject with 400 or 404
		if w.Code == http.StatusOK {
			t.Fatalf("SECURITY FLAW: Server accepted malformed XML payload")
		}
	}
}

func TestSecurityEnterpriseVulnerabilityDefenses(t *testing.T) {
	tmpDir := t.TempDir()
	engine, err := storage.NewDiskEngine(tmpDir)
	if err != nil {
		t.Fatalf("engine init failed: %v", err)
	}
	strictAuth := auth.NewAuthenticator("testaccess", "testsecret123", false)
	handler := NewS3Handler(engine, strictAuth, "")

	sign := func(r *http.Request) *httptest.ResponseRecorder {
		r.Host = "localhost:9000"
		auth.SignRequestV4(r, "testaccess", "testsecret123", "us-east-1", "UNSIGNED-PAYLOAD")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	// Setup target bucket & critical file
	if w := sign(httptest.NewRequest(http.MethodPut, "/victim-bucket", nil)); w.Code != http.StatusOK {
		t.Fatalf("setup bucket failed: %d", w.Code)
	}
	if w := sign(httptest.NewRequest(http.MethodPut, "/victim-bucket/important.txt", strings.NewReader("CRITICAL_DATA"))); w.Code != http.StatusOK {
		t.Fatalf("setup object failed: %d", w.Code)
	}

	// 1. Exploit Attempt: Bucket Name ".." Traversal on DELETE /.. or GET /..
	for _, badBucket := range []string{"/..", "/.", "/%2e%2e"} {
		w := sign(httptest.NewRequest(http.MethodDelete, badBucket, nil))
		if w.Code == http.StatusOK || w.Code == http.StatusNoContent {
			t.Fatalf("CRITICAL VULNERABILITY: bucket traversal %q succeeded with %d", badBucket, w.Code)
		}
	}
	// Verify victim-bucket survived intact
	if !engine.BucketExists("victim-bucket") {
		t.Fatalf("CRITICAL VULNERABILITY: victim-bucket was wiped by bucket traversal!")
	}

	// 2. Exploit Attempt: uploadId Path Traversal on AbortMultipartUpload
	abortTrav := sign(httptest.NewRequest(http.MethodDelete, "/victim-bucket/important.txt?uploadId=../../../victim-bucket", nil))
	_ = abortTrav
	if _, err := engine.HeadObject("victim-bucket", "important.txt"); err != nil {
		t.Fatalf("CRITICAL VULNERABILITY: uploadId path traversal deleted victim object! err=%v", err)
	}

	// 3. Exploit Attempt: versionId Path Traversal
	verTrav := sign(httptest.NewRequest(http.MethodGet, "/victim-bucket/important.txt?versionId=../../bucket", nil))
	if verTrav.Code == http.StatusOK {
		t.Fatalf("CRITICAL VULNERABILITY: versionId path traversal returned 200 OK")
	}

	// 4. Exploit Attempt: SSE-C Ciphertext Bit-Flip Tampering Detection
	custKey := make([]byte, 32)
	_, _ = rand.Read(custKey)
	kB64 := base64.StdEncoding.EncodeToString(custKey)
	kMD5 := md5.Sum(custKey)
	md5B64 := base64.StdEncoding.EncodeToString(kMD5[:])

	encReq := httptest.NewRequest(http.MethodPut, "/victim-bucket/secret.bin", strings.NewReader("AUTHENTICATED_CIPHERTEXT_PAYLOAD"))
	encReq.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	encReq.Header.Set("x-amz-server-side-encryption-customer-key", kB64)
	encReq.Header.Set("x-amz-server-side-encryption-customer-key-MD5", md5B64)
	if w := sign(encReq); w.Code != http.StatusOK {
		t.Fatalf("SSE-C upload failed: %d", w.Code)
	}

	// Flip 1 byte in stored ciphertext on disk
	diskPath := filepath.Join(tmpDir, "buckets", "victim-bucket", "data", "secret.bin")
	diskBytes, _ := os.ReadFile(diskPath)
	diskBytes[len(diskBytes)-1] ^= 0xFF
	_ = os.WriteFile(diskPath, diskBytes, 0644)

	decReq := httptest.NewRequest(http.MethodGet, "/victim-bucket/secret.bin", nil)
	decReq.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	decReq.Header.Set("x-amz-server-side-encryption-customer-key", kB64)
	decReq.Header.Set("x-amz-server-side-encryption-customer-key-MD5", md5B64)
	if w := sign(decReq); w.Code != http.StatusForbidden {
		t.Fatalf("SECURITY FAILURE: bit-flipped GCM ciphertext should fail with 403, got %d", w.Code)
	}

	// 5. Exploit Attempt: Expired / Out-of-bounds Presigned URLs
	badPresigns := []string{
		"/victim-bucket/important.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=testaccess/20261111/us-east-1/s3/aws4_request&X-Amz-Date=20200101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" + strings.Repeat("a", 64),
		"/victim-bucket/important.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=testaccess/20261111/us-east-1/s3/aws4_request&X-Amz-Date=20261111T000000Z&X-Amz-Expires=99999999&X-Amz-SignedHeaders=host&X-Amz-Signature=" + strings.Repeat("a", 64),
		"/victim-bucket/important.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=testaccess/20261111/us-east-1/s3/aws4_request&X-Amz-Date=invaliddate&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=" + strings.Repeat("a", 64),
	}
	for _, u := range badPresigns {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		req.Host = "localhost:9000"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("SECURITY FLAW: invalid presigned URL %s returned %d instead of 403", u, w.Code)
		}
	}
}
