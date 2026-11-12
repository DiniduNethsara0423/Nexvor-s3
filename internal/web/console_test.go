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

func loginTestConsole(t *testing.T, handler *ConsoleHandler) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "secret123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || resp.Token == "" {
		t.Fatalf("expected non-empty HMAC session token")
	}
	return resp.Token
}

func TestConsoleAuthenticationAndSecurityGuard(t *testing.T) {
	handler, cleanup := setupTestConsole(t)
	defer cleanup()

	// 1. Unauthenticated requests to sensitive APIs MUST fail with 401
	protectedEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/buckets"},
		{http.MethodGet, "/api/stats"},
		{http.MethodPost, "/api/presign"},
		{http.MethodGet, "/api/buckets/any/export"},
		{http.MethodDelete, "/api/buckets/any"},
	}
	for _, ep := range protectedEndpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("SECURITY FLAW: unauthenticated %s %s returned %d instead of 401", ep.method, ep.path, w.Code)
		}
	}

	// 2. Forged static or tampered bearer token MUST fail with 401
	for _, badTok := range []string{"nexvor-auth-token-valid", "forged.token", "abc"} {
		req := httptest.NewRequest(http.MethodGet, "/api/buckets", nil)
		req.Header.Set("Authorization", "Bearer "+badTok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("SECURITY FLAW: forged token %q accepted with status %d", badTok, w.Code)
		}
	}

	// 3. Wrong password returns 401
	badCreds, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(badCreds))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for wrong password, got %d", w.Code)
	}

	// 4. Valid login returns HMAC token that unlocks /api/buckets
	tok := loginTestConsole(t, handler)
	reqOK := httptest.NewRequest(http.MethodGet, "/api/buckets", nil)
	reqOK.Header.Set("Authorization", "Bearer "+tok)
	wOK := httptest.NewRecorder()
	handler.ServeHTTP(wOK, reqOK)
	if wOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid session token, got %d", wOK.Code)
	}
}

func TestConsoleBucketAndObjectWorkflow(t *testing.T) {
	handler, cleanup := setupTestConsole(t)
	defer cleanup()

	token := loginTestConsole(t, handler)

	// 1. Create Bucket
	createBody, _ := json.Marshal(map[string]string{"name": "test-web-bucket"})
	req := httptest.NewRequest(http.MethodPost, "/api/buckets", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+token)
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
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload failed: code %d, body: %s", w.Code, w.Body.String())
	}

	// 3. View / Stream file (using ?token= like <video src=...>)
	req = httptest.NewRequest(http.MethodGet, "/api/buckets/test-web-bucket/view?key=sample-video.mp4&token="+token, nil)
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
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete object failed: code %d", w.Code)
	}

	// 5. Delete bucket
	req = httptest.NewRequest(http.MethodDelete, "/api/buckets/test-web-bucket", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete bucket failed: code %d", w.Code)
	}
}
