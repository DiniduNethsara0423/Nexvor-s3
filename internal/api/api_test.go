package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"my-s3/internal/auth"
	"my-s3/internal/storage"
)

func setupTestServer(t *testing.T) (*S3Handler, func()) {
	tempDir, err := os.MkdirTemp("", "my-s3-api-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	engine, err := storage.NewDiskEngine(tempDir)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	authenticator := auth.NewAuthenticator("testaccess", "testsecret", true)
	handler := NewS3Handler(engine, authenticator, "")

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return handler, cleanup
}

func TestS3APIWorkflow(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Health check
	req := httptest.NewRequest(http.MethodGet, "/minio/health/live", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health check failed: got %d", w.Code)
	}

	// 2. Create Bucket
	req = httptest.NewRequest(http.MethodPut, "/my-bucket", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("create bucket failed: got %d, body: %s", w.Code, w.Body.String())
	}

	// 3. Put Object
	bodyContent := []byte("Hello Enterprise S3 Storage!")
	req = httptest.NewRequest(http.MethodPut, "/my-bucket/docs/hello.txt", bytes.NewReader(bodyContent))
	req.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("put object failed: got %d, body: %s", w.Code, w.Body.String())
	}

	// 4. Head Object
	req = httptest.NewRequest(http.MethodHead, "/my-bucket/docs/hello.txt", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("head object failed: got %d", w.Code)
	}
	if w.Header().Get("ETag") == "" {
		t.Errorf("missing ETag in Head response")
	}

	// 5. Get Object
	req = httptest.NewRequest(http.MethodGet, "/my-bucket/docs/hello.txt", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("get object failed: got %d", w.Code)
	}
	if w.Body.String() != string(bodyContent) {
		t.Errorf("expected body %q, got %q", string(bodyContent), w.Body.String())
	}

	// 6. Range Request (Bytes 0-4 -> "Hello")
	req = httptest.NewRequest(http.MethodGet, "/my-bucket/docs/hello.txt", nil)
	req.Header.Set("Range", "bytes=0-4")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent {
		t.Errorf("expected 206 Partial Content, got %d", w.Code)
	}
	if w.Body.String() != "Hello" {
		t.Errorf("expected 'Hello', got %q", w.Body.String())
	}

	// 7. List Objects
	req = httptest.NewRequest(http.MethodGet, "/my-bucket", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("list objects failed: got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<Key>docs/hello.txt</Key>")) {
		t.Errorf("list objects XML missing key: %s", w.Body.String())
	}

	// 8. Delete Object
	req = httptest.NewRequest(http.MethodDelete, "/my-bucket/docs/hello.txt", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("delete object failed: got %d", w.Code)
	}

	// 9. Delete Bucket
	req = httptest.NewRequest(http.MethodDelete, "/my-bucket", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("delete bucket failed: got %d", w.Code)
	}
}

func TestS3APISecurityPathTraversal(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	_ = httptest.NewRequest(http.MethodPut, "/safe-bucket", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/safe-bucket", nil))

	// Attempt path traversal via REST URL
	req := httptest.NewRequest(http.MethodPut, "/safe-bucket/../../windows/win.ini", bytes.NewReader([]byte("malicious")))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Must be rejected (either 400 or 404 or 403, but never 200)
	if w.Code == http.StatusOK {
		t.Fatalf("SECURITY VULNERABILITY: Path traversal was accepted by S3 API handler!")
	}
}


func TestHLSStreamingAndMime(t *testing.T) {
	handler, cleanup := setupTestServer(t)
	defer cleanup()

	_ = httptest.NewRequest(http.MethodPut, "/video-bucket", nil)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/video-bucket", nil))

	// 1. Upload HLS Master Playlist (.m3u8)
	m3u8Content := []byte("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360\n360p.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\n1080p.m3u8\n")
	req := httptest.NewRequest(http.MethodPut, "/video-bucket/hls/master.m3u8", bytes.NewReader(m3u8Content))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to upload master.m3u8: %d", w.Code)
	}

	// 2. Fetch HLS Master Playlist & verify MIME type
	req = httptest.NewRequest(http.MethodGet, "/video-bucket/hls/master.m3u8", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get master.m3u8: %d", w.Code)
	}
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "mpegurl") {
		t.Errorf("expected mpegurl MIME type for .m3u8, got: %s", contentType)
	}

	// 3. Upload and fetch .ts video segment
	tsChunk := []byte("fake-h264-ts-stream-chunk-bytes")
	req = httptest.NewRequest(http.MethodPut, "/video-bucket/hls/segment_001.ts", bytes.NewReader(tsChunk))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to upload .ts segment: %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/video-bucket/hls/segment_001.ts", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get .ts segment: %d", w.Code)
	}
	tsContentType := w.Header().Get("Content-Type")
	if !strings.Contains(tsContentType, "mp2t") {
		t.Errorf("expected video/mp2t MIME type for .ts, got: %s", tsContentType)
	}
}
