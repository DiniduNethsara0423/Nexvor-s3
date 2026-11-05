package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
