package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"my-s3/internal/storage"
)

func setupTestConsole(t *testing.T) (*ConsoleHandler, func()) {
	tempDir, err := os.MkdirTemp("", "console-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	engine, err := storage.NewDiskEngine(tempDir)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	handler := NewConsoleHandler(engine, "admin", "secret123", "9000")

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return handler, cleanup
}

func TestConsoleAuthentication(t *testing.T) {
	handler, cleanup := setupTestConsole(t)
	defer cleanup()

	// 1. Invalid login
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for wrong password, got %d", w.Code)
	}

	// 2. Valid login
	body, _ = json.Marshal(map[string]string{
		"username": "admin",
		"password": "secret123",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid login, got %d", w.Code)
	}
}

func TestConsoleBucketAndObjectWorkflow(t *testing.T) {
	handler, cleanup := setupTestConsole(t)
	defer cleanup()

	// 1. Create Bucket
	createBody, _ := json.Marshal(map[string]string{"name": "test-web-bucket"})
	req := httptest.NewRequest(http.MethodPost, "/api/buckets", bytes.NewReader(createBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create bucket failed: code %d, body: %s", w.Code, w.Body.String())
	}

	// 2. Upload file via multipart
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)
	part, err := writer.CreateFormFile("file", "sample-video.mp4")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write([]byte("fake-mp4-data-content-stream"))
	_ = writer.Close()

	req = httptest.NewRequest(http.MethodPost, "/api/buckets/test-web-bucket/objects", bodyBuf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: code %d, body: %s", w.Code, w.Body.String())
	}

	// 3. View / Stream file
	req = httptest.NewRequest(http.MethodGet, "/api/buckets/test-web-bucket/view?key=sample-video.mp4", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("view failed: code %d", w.Code)
	}
	if w.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("expected Accept-Ranges: bytes, got %s", w.Header().Get("Accept-Ranges"))
	}

	// 4. Delete object
	req = httptest.NewRequest(http.MethodDelete, "/api/buckets/test-web-bucket/objects/sample-video.mp4", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete object failed: code %d", w.Code)
	}

	// 5. Delete bucket
	req = httptest.NewRequest(http.MethodDelete, "/api/buckets/test-web-bucket", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete bucket failed: code %d", w.Code)
	}
}
