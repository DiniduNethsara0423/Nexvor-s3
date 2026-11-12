package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/storage"
)

// ConsoleHandler serves the MinIO-style Web Management UI with HMAC-SHA256 session authentication
type ConsoleHandler struct {
	storage       *storage.DiskEngine
	accessKey     string
	secretKey     string
	s3Port        string
	sessionSecret []byte
}

// NewConsoleHandler returns a new ConsoleHandler with credential, port, and random HMAC session secret
func NewConsoleHandler(storage *storage.DiskEngine, opts ...string) *ConsoleHandler {
	accessKey := "minioadmin"
	secretKey := "minioadmin"
	s3Port := "9000"
	if len(opts) > 0 && opts[0] != "" {
		accessKey = opts[0]
	}
	if len(opts) > 1 && opts[1] != "" {
		secretKey = opts[1]
	}
	if len(opts) > 2 && opts[2] != "" {
		s3Port = opts[2]
	}
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	return &ConsoleHandler{
		storage:       storage,
		accessKey:     accessKey,
		secretKey:     secretKey,
		s3Port:        s3Port,
		sessionSecret: sec,
	}
}

func (c *ConsoleHandler) issueSessionToken(username string) string {
	exp := time.Now().UTC().Add(24 * time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%d", username, exp)))
	mac := hmac.New(sha256.New, c.sessionSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func (c *ConsoleHandler) verifySessionToken(token string) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	mac := hmac.New(sha256.New, c.sessionSecret)
	mac.Write([]byte(parts[0]))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSig)) != 1 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	fields := strings.Split(string(raw), "|")
	if len(fields) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().UTC().Unix() > exp {
		return false
	}
	return true
}

func (c *ConsoleHandler) authenticateSession(r *http.Request) bool {
	if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		if c.verifySessionToken(strings.TrimPrefix(authHdr, "Bearer ")) {
			return true
		}
	}
	if cookie, err := r.Cookie("nexvor_session"); err == nil && cookie.Value != "" {
		if c.verifySessionToken(cookie.Value) {
			return true
		}
	}
	if qTok := r.URL.Query().Get("token"); qTok != "" {
		if c.verifySessionToken(qTok) {
			return true
		}
	}
	return false
}

func (c *ConsoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")

	// API endpoints for the console UI
	if strings.HasPrefix(path, "api/") {
		w.Header().Set("Cache-Control", "no-store")
		c.handleAPI(w, r, strings.TrimPrefix(path, "api/"))
		return
	}

	// Serve the embedded MinIO-like Single Page Application
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(htmlConsole))
}

type BucketSummary struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
	ObjectCount  int       `json:"object_count"`
	TotalSize    int64     `json:"total_size"`
}

func ioLimitBody(r *http.Request) io.Reader {
	return io.LimitReader(r.Body, 1<<20)
}

func (c *ConsoleHandler) handleAPI(w http.ResponseWriter, r *http.Request, endpoint string) {
	w.Header().Set("Content-Type", "application/json")

	// 1. Authentication Login & Logout (public endpoints)
	if endpoint == "login" && r.Method == http.MethodPost {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(ioLimitBody(r)).Decode(&creds); err != nil {
			http.Error(w, `{"error":"invalid request format"}`, http.StatusBadRequest)
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(c.accessKey)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(c.secretKey)) == 1
		if userOK && passOK {
			tok := c.issueSessionToken(creds.Username)
			http.SetCookie(w, &http.Cookie{
				Name:     "nexvor_session",
				Value:    tok,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400,
			})
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "ok",
				"token":    tok,
				"username": creds.Username,
				"s3Port":   c.s3Port,
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Access Key or Secret Key"})
		return
	}

	if endpoint == "logout" && r.Method == http.MethodPost {
		http.SetCookie(w, &http.Cookie{Name: "nexvor_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
		return
	}

	// Enforce authenticated HMAC session on ALL remaining Console API endpoints!
	if !c.authenticateSession(r) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}

	if endpoint == "session" && r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"username":      c.accessKey,
			"s3Port":        c.s3Port,
		})
		return
	}

	// Presigned Expiring S3 URL Generator (SigV4)
	if endpoint == "presign" && r.Method == http.MethodPost {
		var body struct {
			Bucket  string `json:"bucket"`
			Key     string `json:"key"`
			Expires int64  `json:"expires_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Bucket == "" || body.Key == "" {
			http.Error(w, `{"error":"bucket and key are required"}`, http.StatusBadRequest)
			return
		}
		if body.Expires <= 0 {
			body.Expires = 86400 // Default 24 hours
		}
		host := r.Host
		if idx := strings.IndexByte(host, ':'); idx != -1 {
			host = host[:idx]
		}
		proto := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			proto = "https"
		}
		s3Endpoint := fmt.Sprintf("%s://%s:%s", proto, host, c.s3Port)
		signedURL, err := auth.GeneratePresignedURL(s3Endpoint, body.Bucket, body.Key, c.accessKey, c.secretKey, "us-east-1", http.MethodGet, body.Expires)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"url":        signedURL,
			"expires_in": body.Expires,
		})
		return
	}

	// 2. Global Server Statistics
	if endpoint == "stats" && r.Method == http.MethodGet {
		buckets, err := c.storage.ListBuckets()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var totalObjects int
		var totalBytes int64
		for _, b := range buckets {
			res, err := c.storage.ListObjects(b.Name, "", "", "", 10000)
			if err == nil {
				totalObjects += len(res.Objects)
				for _, obj := range res.Objects {
					totalBytes += obj.Size
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"buckets_count": len(buckets),
			"objects_count": totalObjects,
			"total_bytes":   totalBytes,
			"version":       "v1.0.0-production",
			"s3_port":       c.s3Port,
		})
		return
	}

	// 3. Bucket List & Creation
	if endpoint == "buckets" {
		if r.Method == http.MethodGet {
			rawBuckets, err := c.storage.ListBuckets()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var summaries []BucketSummary
			for _, b := range rawBuckets {
				res, err := c.storage.ListObjects(b.Name, "", "", "", 10000)
				var count int
				var size int64
				if err == nil {
					count = len(res.Objects)
					for _, obj := range res.Objects {
						size += obj.Size
					}
				}
				summaries = append(summaries, BucketSummary{
					Name:         b.Name,
					CreationDate: b.CreationDate,
					ObjectCount:  count,
					TotalSize:    size,
				})
			}
			_ = json.NewEncoder(w).Encode(summaries)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
				return
			}
			name := strings.TrimSpace(body.Name)
			if err := c.storage.CreateBucket(name); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "created", "bucket": name})
			return
		}
	}

	// 4. Nested Bucket Operations
	parts := strings.Split(endpoint, "/")
	if len(parts) >= 2 && parts[0] == "buckets" {
		bucket := parts[1]

		// Delete bucket
		if len(parts) == 2 && r.Method == http.MethodDelete {
			if err := c.storage.DeleteBucket(bucket); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}

		// Export backup zip
		if len(parts) == 3 && parts[2] == "export" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-backup.zip\"", bucket))
			if err := c.storage.ExportBucketZip(bucket, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		// Stream / View Object Media (Range-supported for videos/audio/images)
		if len(parts) == 3 && (parts[2] == "view" || parts[2] == "download") && r.Method == http.MethodGet {
			key := r.URL.Query().Get("key")
			if key == "" {
				http.Error(w, "missing key query parameter", http.StatusBadRequest)
				return
			}
			rc, info, err := c.storage.GetObject(bucket, key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			defer rc.Close()

			if parts[2] == "download" {
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(key)))
			}

			mimeType := info.ContentType
			if mimeType == "" || mimeType == "application/octet-stream" {
				ext := strings.ToLower(filepath.Ext(key))
				if extMime := mime.TypeByExtension(ext); extMime != "" {
					mimeType = extMime
				} else {
					mimeType = "application/octet-stream"
				}
			}

			w.Header().Set("Content-Type", mimeType)
			w.Header().Set("Accept-Ranges", "bytes")
			http.ServeContent(w, r, info.Key, info.LastModified, rc)
			return
		}

		// List or Upload Objects
		if len(parts) >= 3 && parts[2] == "objects" {
			if r.Method == http.MethodGet {
				res, err := c.storage.ListObjects(bucket, "", "", "", 1000)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(res.Objects)
				return
			}

			if r.Method == http.MethodPost {
				// File upload from Web UI (up to 2GB)
				err := r.ParseMultipartForm(2048 << 20)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				file, header, err := r.FormFile("file")
				if err != nil {
					http.Error(w, "missing file in form", http.StatusBadRequest)
					return
				}
				defer file.Close()

				key := header.Filename
				if customKey := r.FormValue("key"); customKey != "" {
					key = customKey
				}

				contentType := header.Header.Get("Content-Type")
				if contentType == "" || contentType == "application/octet-stream" {
					ext := strings.ToLower(filepath.Ext(key))
					if m := mime.TypeByExtension(ext); m != "" {
						contentType = m
					}
				}

				info, err := c.storage.PutObject(bucket, key, file, header.Size, contentType, nil)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(info)
				return
			}

			if r.Method == http.MethodDelete && len(parts) > 3 {
				key := strings.Join(parts[3:], "/")
				if err := c.storage.DeleteObject(bucket, key); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "key": key})
				return
			}
		}
	}

	http.NotFound(w, r)
}

const htmlConsole = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NexvorS3 — High-Performance Storage Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #090d16;
      --sidebar: #0f172a;
      --surface: #1e293b;
      --surface-hover: #334155;
      --border: #243047;
      --primary: #0284c7;
      --primary-hover: #0369a1;
      --primary-light: #38bdf8;
      --accent: #6366f1;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --danger: #ef4444;
      --danger-hover: #dc2626;
      --success: #10b981;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }

    /* Top Navigation */
    header { background-color: var(--sidebar); padding: 0.85rem 1.75rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; z-index: 20; }
    .brand { display: flex; align-items: center; gap: 0.85rem; }
    .brand-logo { width: 34px; height: 34px; background: linear-gradient(135deg, #0284c7, #6366f1); border-radius: 8px; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 16px rgba(2, 132, 199, 0.4); }
    .brand-title { font-weight: 700; font-size: 1.25rem; letter-spacing: -0.02em; display: flex; align-items: center; gap: 0.5rem; }
    .badge { padding: 0.2rem 0.55rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge-primary { background: rgba(2, 132, 199, 0.2); color: #38bdf8; border: 1px solid rgba(2, 132, 199, 0.4); }
    .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .header-right { display: flex; align-items: center; gap: 1.25rem; }
    .server-status { font-size: 0.82rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.5rem; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 8px var(--success); }
    .user-pill { background: var(--surface); border: 1px solid var(--border); padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.82rem; display: flex; align-items: center; gap: 0.45rem; }

    /* Layout */
    .app-body { display: flex; flex: 1; height: calc(100vh - 65px); }

    /* Sidebar */
    .sidebar { width: 310px; background: var(--sidebar); border-right: 1px solid var(--border); display: flex; flex-direction: column; overflow-y: auto; }
    .sidebar-section { padding: 1.25rem; border-bottom: 1px solid var(--border); }
    .stats-card { background: rgba(30, 41, 59, 0.5); border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.85rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.25rem; }
    .stat-label { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .stat-val { font-size: 1.15rem; font-weight: 700; color: #fff; margin-top: 0.2rem; }
    
    .sidebar-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .sidebar-title { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; font-weight: 600; }
    
    .search-input { width: 100%; background: #090d16; border: 1px solid var(--border); color: #fff; padding: 0.5rem 0.75rem; border-radius: 0.375rem; font-size: 0.85rem; outline: none; margin-bottom: 0.75rem; }
    .search-input:focus { border-color: var(--primary); }

    .bucket-list { list-style: none; display: flex; flex-direction: column; gap: 0.35rem; padding: 0 1.25rem 1.25rem 1.25rem; flex: 1; }
    .bucket-item { padding: 0.75rem 0.85rem; border-radius: 0.45rem; cursor: pointer; color: var(--text); display: flex; justify-content: space-between; align-items: center; transition: all 0.15s ease; border: 1px solid transparent; }
    .bucket-item:hover { background: var(--surface-hover); border-color: var(--border); }
    .bucket-item.active { background: #0369a1; color: #fff; font-weight: 600; border-color: #38bdf8; box-shadow: 0 2px 8px rgba(2, 132, 199, 0.25); }
    .bucket-meta { font-size: 0.75rem; opacity: 0.75; }

    /* Content Area */
    .content { flex: 1; padding: 2rem; overflow-y: auto; background: var(--bg); display: flex; flex-direction: column; gap: 1.5rem; }
    .welcome-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 3rem 2rem; text-align: center; max-width: 650px; margin: 3rem auto; }
    .welcome-card h2 { font-size: 1.6rem; margin-bottom: 0.75rem; font-weight: 700; }
    .welcome-card p { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 1.5rem; line-height: 1.5; }

    /* Bucket View */
    .bucket-view-header { background: var(--surface); border: 1px solid var(--border); border-radius: 0.65rem; padding: 1.25rem 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
    .bucket-heading { display: flex; flex-direction: column; gap: 0.25rem; }
    .bucket-name-title { font-size: 1.35rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
    .bucket-details { font-size: 0.82rem; color: var(--text-muted); }
    .bucket-actions { display: flex; gap: 0.6rem; }

    /* Buttons */
    .btn { background: var(--primary); color: white; border: none; padding: 0.55rem 1rem; border-radius: 0.375rem; cursor: pointer; font-size: 0.85rem; font-weight: 500; display: inline-flex; align-items: center; gap: 0.45rem; transition: background 0.15s, transform 0.05s; }
    .btn:hover { background: var(--primary-hover); }
    .btn:active { transform: scale(0.98); }
    .btn-secondary { background: #334155; }
    .btn-secondary:hover { background: #475569; }
    .btn-success { background: #059669; }
    .btn-success:hover { background: #047857; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: var(--danger-hover); }
    .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
    .btn-outline:hover { background: var(--surface-hover); border-color: var(--text-muted); }

    /* Dropzone & Upload */
    .upload-zone { border: 2px dashed #334155; border-radius: 0.65rem; padding: 2rem 1.5rem; text-align: center; cursor: pointer; transition: all 0.2s; background: rgba(30, 41, 59, 0.3); }
    .upload-zone:hover, .upload-zone.dragover { border-color: var(--primary-light); background: rgba(2, 132, 199, 0.08); }
    .upload-zone h4 { font-size: 1rem; margin-bottom: 0.25rem; }
    .upload-zone p { color: var(--text-muted); font-size: 0.82rem; }

    .progress-box { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem 1.25rem; display: none; flex-direction: column; gap: 0.5rem; }
    .progress-bar-bg { width: 100%; height: 8px; background: #334155; border-radius: 9999px; overflow: hidden; }
    .progress-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #0284c7, #38bdf8); transition: width 0.15s ease; }
    .progress-info { display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted); }

    /* Objects Table */
    .table-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.65rem; overflow: hidden; }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { background: #131d31; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.85rem 1.25rem; border-bottom: 1px solid var(--border); }
    td { padding: 0.9rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.88rem; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .file-icon { font-size: 1.15rem; margin-right: 0.4rem; vertical-align: -2px; }
    .object-name { font-weight: 500; color: #fff; }
    .action-btn { padding: 0.35rem 0.65rem; font-size: 0.78rem; border-radius: 0.3rem; }

    /* Modals */
    .modal-backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(4px); display: none; align-items: center; justify-content: center; z-index: 50; }
    .modal { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; width: 92%; max-width: 520px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6); overflow: hidden; }
    .modal-header { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .modal-header h3 { font-size: 1.15rem; font-weight: 600; }
    .modal-close { background: none; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; }
    .modal-body { padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
    .modal-footer { padding: 1rem 1.5rem; background: rgba(15, 23, 42, 0.5); border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 0.75rem; }
    .form-group { display: flex; flex-direction: column; gap: 0.4rem; }
    .form-group label { font-size: 0.82rem; color: var(--text-muted); font-weight: 500; }
    .form-control { background: #090d16; border: 1px solid var(--border); color: #fff; padding: 0.65rem 0.85rem; border-radius: 0.375rem; font-size: 0.9rem; outline: none; }
    .form-control:focus { border-color: var(--primary); }

    /* Media Preview Modal */
    .preview-modal { max-width: 850px; width: 95%; }
    .preview-player-container { width: 100%; background: #000; border-radius: 0.5rem; overflow: hidden; display: flex; align-items: center; justify-content: center; min-height: 250px; max-height: 550px; }
    .preview-player-container video { width: 100%; max-height: 520px; outline: none; }
    .preview-player-container img { max-width: 100%; max-height: 520px; object-fit: contain; }
    .preview-text { width: 100%; max-height: 400px; overflow: auto; background: #090d16; padding: 1rem; border-radius: 0.375rem; font-family: monospace; font-size: 0.85rem; color: #38bdf8; white-space: pre-wrap; }

    /* Login Overlay */
    .login-overlay { position: fixed; inset: 0; background: var(--bg); display: none; align-items: center; justify-content: center; z-index: 100; }
    .login-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.85rem; width: 92%; max-width: 420px; padding: 2.25rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7); display: flex; flex-direction: column; gap: 1.25rem; }
    .login-logo { display: flex; flex-direction: column; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; text-align: center; }
  </style>
</head>
<body>

  <!-- Top Navigation -->
  <header>
    <div class="brand">
      <div class="brand-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242M12 12v9m-4-4 4 4 4-4"/></svg>
      </div>
      <div>
        <div class="brand-title">
          <span>NexvorS3</span>
          <span class="badge badge-primary">Console</span>
        </div>
      </div>
    </div>
    <div class="header-right">
      <div class="server-status">
        <span class="status-dot"></span>
        <span>Online (API: <strong>:9000</strong>)</span>
      </div>
      <div class="user-pill">
        <span>👤</span>
        <span id="activeUserLabel">admin</span>
      </div>
      <button class="btn btn-outline" style="padding: 0.35rem 0.65rem; font-size: 0.8rem;" onclick="logout()">Sign Out</button>
    </div>
  </header>

  <div class="app-body">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="sidebar-section">
        <div class="stats-card">
          <div>
            <div class="stat-label">Buckets</div>
            <div class="stat-val" id="statBuckets">0</div>
          </div>
          <div>
            <div class="stat-label">Total Data</div>
            <div class="stat-val" id="statSize">0 B</div>
          </div>
        </div>
      </div>

      <div class="sidebar-section" style="padding-bottom: 0.5rem;">
        <div class="sidebar-header">
          <span class="sidebar-title">Buckets</span>
          <button class="btn" style="padding: 0.25rem 0.6rem; font-size: 0.78rem;" onclick="openCreateBucketModal()">+ Create</button>
        </div>
        <input type="text" class="search-input" id="bucketSearch" placeholder="Filter buckets..." oninput="renderBucketList()" />
      </div>

      <ul class="bucket-list" id="bucketListContainer">
        <!-- Rendered via JS -->
      </ul>
    </aside>

    <!-- Main Content -->
    <main class="content">
      <!-- Welcome Empty State (when no bucket is active) -->
      <div id="welcomeView" class="welcome-card">
        <div class="brand-logo" style="width: 56px; height: 56px; margin: 0 auto 1.25rem auto;">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242M12 12v9m-4-4 4 4 4-4"/></svg>
        </div>
        <h2>NexvorS3 Storage Console</h2>
        <p>Ultra-fast, MinIO-compatible S3 object storage with HLS video streaming, automated replication, and zero GC overhead.</p>
        <button class="btn" style="padding: 0.75rem 1.5rem; font-size: 0.95rem;" onclick="openCreateBucketModal()">+ Create New Bucket</button>
      </div>

      <!-- Active Bucket View -->
      <div id="bucketView" style="display: none; flex-direction: column; gap: 1.25rem;">
        <div class="bucket-view-header">
          <div class="bucket-heading">
            <div class="bucket-name-title">
              <span>🗂️</span>
              <span id="activeBucketName">bucket-name</span>
            </div>
            <div class="bucket-details" id="activeBucketDetails">
              0 objects • 0 B
            </div>
          </div>
          <div class="bucket-actions">
            <button class="btn" onclick="triggerFileInput()">📤 Upload File</button>
            <button class="btn btn-success" onclick="exportBucketBackup()">💾 Backup (ZIP)</button>
            <button class="btn btn-danger" onclick="confirmDeleteBucket()">🗑️ Delete Bucket</button>
            <input type="file" id="mainFileInput" style="display:none;" onchange="handleFileUpload(event)" />
          </div>
        </div>

        <!-- Drag & Drop Upload Zone -->
        <div class="upload-zone" id="dropZone" onclick="triggerFileInput()">
          <h4>Drop files here to upload</h4>
          <p>or click here to select files from your computer</p>
        </div>

        <!-- Progress Bar -->
        <div class="progress-box" id="uploadProgressBox">
          <div class="progress-info">
            <span id="uploadFileName">Uploading file...</span>
            <span id="uploadPercent">0%</span>
          </div>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" id="uploadBarFill"></div>
          </div>
        </div>

        <!-- Search Table Filter -->
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <input type="text" class="search-input" id="objectSearch" style="max-width: 320px; margin-bottom: 0;" placeholder="Search files in bucket..." oninput="renderObjectList()" />
          <span style="font-size: 0.8rem; color: var(--text-muted);" id="objectCounterLabel">0 items</span>
        </div>

        <!-- Objects Table -->
        <div class="table-card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Content-Type</th>
                <th>Last Modified</th>
                <th style="text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody id="objectsTableBody">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>
    </main>
  </div>

  <!-- Create Bucket Modal -->
  <div class="modal-backdrop" id="createBucketModal">
    <div class="modal">
      <div class="modal-header">
        <h3>Create New Bucket</h3>
        <button class="modal-close" onclick="closeModal('createBucketModal')">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>Bucket Name</label>
          <input type="text" id="newBucketNameInput" class="form-control" placeholder="my-awesome-bucket" />
          <small style="color: var(--text-muted); font-size: 0.75rem;">Must be 3-63 characters, lowercase letters, numbers, and dashes.</small>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="closeModal('createBucketModal')">Cancel</button>
        <button class="btn" onclick="submitCreateBucket()">Create Bucket</button>
      </div>
    </div>
  </div>

  <!-- Media Preview / Video Stream Modal -->
  <div class="modal-backdrop" id="previewModal">
    <div class="modal preview-modal">
      <div class="modal-header">
        <h3 id="previewTitle">File Preview</h3>
        <button class="modal-close" onclick="closePreviewModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div class="preview-player-container" id="previewMediaContainer">
          <!-- Injected dynamically -->
        </div>
        <div style="display:flex; justify-content: space-between; align-items:center; font-size: 0.82rem; color: var(--text-muted);">
          <span id="previewDetails"></span>
          <button class="btn btn-outline" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="copyPreviewLink()">Copy S3 URL</button>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="closePreviewModal()">Close</button>
        <a id="previewDownloadBtn" class="btn btn-success" download style="text-decoration:none;">Download File</a>
      </div>
    </div>
  </div>

  <!-- Login Modal Overlay -->
  <div class="login-overlay" id="loginOverlay">
    <div class="login-card">
      <div class="login-logo">
        <div class="brand-logo" style="width: 48px; height: 48px;">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242M12 12v9m-4-4 4 4 4-4"/></svg>
        </div>
        <h2 style="font-size: 1.4rem;">Sign in to NexvorS3</h2>
        <p style="font-size: 0.82rem; color: var(--text-muted);">High-Performance S3 Compatible Engine</p>
      </div>
      <div class="form-group">
        <label>Access Key / Username</label>
        <input type="text" id="loginUser" class="form-control" placeholder="minioadmin" value="minioadmin" />
      </div>
      <div class="form-group">
        <label>Secret Key / Password</label>
        <input type="password" id="loginPass" class="form-control" placeholder="minioadmin" value="minioadmin" />
      </div>
      <div id="loginError" style="color: var(--danger); font-size: 0.8rem; display: none;"></div>
      <button class="btn" style="padding: 0.7rem; justify-content: center; font-size: 0.95rem;" onclick="performLogin()">Sign In</button>
      <div style="text-align: center; font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">
        Default credentials: <code>minioadmin</code> / <code>minioadmin</code>
      </div>
    </div>
  </div>

  <script>
    let allBuckets = [];
    let currentBucket = null;
    let currentObjects = [];
    let previewUrl = '';

    // Initialize UI on load
    window.addEventListener('DOMContentLoaded', () => {
      setupDropzone();
      checkSession();
    });

    function checkSession() {
      const token = localStorage.getItem('nexvor_session');
      const user = localStorage.getItem('nexvor_user') || 'minioadmin';
      if (!token) {
        document.getElementById('loginOverlay').style.display = 'flex';
      } else {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('activeUserLabel').textContent = user;
        loadAllData();
      }
    }

    async function performLogin() {
      const username = document.getElementById('loginUser').value.trim();
      const password = document.getElementById('loginPass').value.trim();
      const errBox = document.getElementById('loginError');
      errBox.style.display = 'none';

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        if (res.ok) {
          const data = await res.json();
          localStorage.setItem('nexvor_session', data.token);
          localStorage.setItem('nexvor_user', data.username);
          document.getElementById('loginOverlay').style.display = 'none';
          document.getElementById('activeUserLabel').textContent = data.username;
          loadAllData();
        } else {
          const err = await res.json();
          errBox.textContent = err.error || 'Authentication failed';
          errBox.style.display = 'block';
        }
      } catch (e) {
        errBox.textContent = 'Server unreachable';
        errBox.style.display = 'block';
      }
    }

    function getToken() { return localStorage.getItem('nexvor_session') || ''; }

    async function apiFetch(url, options = {}) {
      const hdrs = Object.assign({}, options.headers || {});
      const tok = getToken();
      if (tok) hdrs['Authorization'] = 'Bearer ' + tok;
      const res = await fetch(url, Object.assign({}, options, { headers: hdrs }));
      if (res.status === 401) {
        localStorage.removeItem('nexvor_session');
        document.getElementById('loginOverlay').style.display = 'flex';
      }
      return res;
    }

    function logout() {
      apiFetch('/api/logout', { method: 'POST' }).catch(() => {});
      localStorage.removeItem('nexvor_session');
      localStorage.removeItem('nexvor_user');
      location.reload();
    }

    async function loadAllData() {
      await loadStats();
      await loadBuckets();
    }

    async function loadStats() {
      try {
        const res = await apiFetch('/api/stats');
        if (res.ok) {
          const stats = await res.json();
          document.getElementById('statBuckets').textContent = stats.buckets_count || 0;
          document.getElementById('statSize').textContent = formatBytes(stats.total_bytes || 0);
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function loadBuckets() {
      try {
        const res = await apiFetch('/api/buckets');
        if (res.ok) {
          allBuckets = await res.json() || [];
          renderBucketList();
          if (currentBucket) {
            const found = allBuckets.find(b => b.name === currentBucket);
            if (found) selectBucket(found.name);
          }
        }
      } catch (e) {
        console.error(e);
      }
    }

    function renderBucketList() {
      const container = document.getElementById('bucketListContainer');
      const filter = document.getElementById('bucketSearch').value.toLowerCase();
      container.innerHTML = '';

      const filtered = allBuckets.filter(b => b.name.toLowerCase().includes(filter));

      if (filtered.length === 0) {
        container.innerHTML = '<li style="padding: 1rem 0; text-align: center; color: var(--text-muted); font-size: 0.82rem;">No buckets found</li>';
        return;
      }

      filtered.forEach(b => {
        const li = document.createElement('li');
        li.className = 'bucket-item' + (currentBucket === b.name ? ' active' : '');
        li.onclick = () => selectBucket(b.name);
        li.innerHTML = 
          '<div>' +
            '<div style="font-weight: 500;">📁 ' + escapeHtml(b.name) + '</div>' +
            '<div class="bucket-meta">' + (b.object_count || 0) + ' items (' + formatBytes(b.total_size || 0) + ')</div>' +
          '</div>' +
          '<span style="font-size: 0.8rem; opacity: 0.6;">›</span>';
        container.appendChild(li);
      });
    }

    async function selectBucket(name) {
      currentBucket = name;
      document.getElementById('welcomeView').style.display = 'none';
      document.getElementById('bucketView').style.display = 'flex';
      document.getElementById('activeBucketName').textContent = name;
      renderBucketList();

      const bucketInfo = allBuckets.find(b => b.name === name);
      if (bucketInfo) {
        document.getElementById('activeBucketDetails').textContent = 
          (bucketInfo.object_count || 0) + ' objects • ' + formatBytes(bucketInfo.total_size || 0) + ' • S3: http://localhost:9000/' + name;
      }

      await loadObjects();
    }

    async function loadObjects() {
      if (!currentBucket) return;
      try {
        const res = await apiFetch('/api/buckets/' + encodeURIComponent(currentBucket) + '/objects');
        if (res.ok) {
          currentObjects = await res.json() || [];
          renderObjectList();
        }
      } catch (e) {
        console.error(e);
      }
    }

    function renderObjectList() {
      const tbody = document.getElementById('objectsTableBody');
      const filter = document.getElementById('objectSearch').value.toLowerCase();
      tbody.innerHTML = '';

      const filtered = currentObjects.filter(obj => obj.key.toLowerCase().includes(filter));
      document.getElementById('objectCounterLabel').textContent = filtered.length + ' item' + (filtered.length === 1 ? '' : 's');

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">No objects in this bucket. Drop files above to upload!</td></tr>';
        return;
      }

      filtered.forEach(obj => {
        const tr = document.createElement('tr');
        const icon = getFileIcon(obj.key, obj.content_type);
        const encodedKey = encodeURIComponent(obj.key);
        const viewUrl = '/api/buckets/' + encodeURIComponent(currentBucket) + '/view?key=' + encodedKey;
        const s3Url = 'http://localhost:9000/' + encodeURIComponent(currentBucket) + '/' + encodeURI(obj.key);

        tr.innerHTML = 
          '<td>' +
            '<span class="file-icon">' + icon + '</span>' +
            '<span class="object-name">' + escapeHtml(obj.key) + '</span>' +
          '</td>' +
          '<td>' + formatBytes(obj.size) + '</td>' +
          '<td><span class="badge" style="background:#1e293b; color:#94a3b8; border:1px solid #334155;">' + escapeHtml(obj.content_type) + '</span></td>' +
          '<td>' + new Date(obj.last_modified).toLocaleString() + '</td>' +
          '<td style="text-align: right;">' +
            '<button class="btn btn-outline action-btn" style="margin-right: 0.35rem;" onclick="openPreview(\'' + escapeJs(obj.key) + '\', \'' + escapeJs(obj.content_type) + '\', ' + obj.size + ')">👁️ Preview</button>' +
            '<a href="/api/buckets/' + encodeURIComponent(currentBucket) + '/download?key=' + encodedKey + '&token=' + encodeURIComponent(getToken()) + '" class="btn btn-secondary action-btn" style="text-decoration:none; margin-right: 0.35rem;" download>⬇️ Download</a>' +
            '<button class="btn btn-outline action-btn" style="margin-right: 0.35rem;" onclick="copyToClipboard(\'' + s3Url + '\', \'S3 URL\')">📋 URL</button>' +
            '<button class="btn btn-danger action-btn" onclick="deleteObject(\'' + escapeJs(obj.key) + '\')">🗑️</button>' +
          '</td>';
        tbody.appendChild(tr);
      });
    }

    function getFileIcon(key, mime) {
      const ext = key.split('.').pop().toLowerCase();
      if (['mp4', 'webm', 'mov', 'mkv', 'm3u8', 'ts'].includes(ext) || mime.startsWith('video/')) return '🎬';
      if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico'].includes(ext) || mime.startsWith('image/')) return '🖼️';
      if (['mp3', 'wav', 'ogg', 'flac', 'aac'].includes(ext) || mime.startsWith('audio/')) return '🎵';
      if (['zip', 'tar', 'gz', 'bz2', '7z', 'rar'].includes(ext)) return '📦';
      if (['js', 'ts', 'go', 'py', 'json', 'html', 'css', 'xml'].includes(ext)) return '💻';
      if (['pdf', 'txt', 'md', 'doc', 'docx'].includes(ext)) return '📄';
      return '📁';
    }

    // Upload Handlers
    function triggerFileInput() {
      document.getElementById('mainFileInput').click();
    }

    function setupDropzone() {
      const dropzone = document.getElementById('dropZone');
      ['dragenter', 'dragover'].forEach(name => {
        window.addEventListener(name, (e) => {
          e.preventDefault();
          if (currentBucket) dropzone.classList.add('dragover');
        });
      });
      ['dragleave', 'drop'].forEach(name => {
        window.addEventListener(name, (e) => {
          e.preventDefault();
          dropzone.classList.remove('dragover');
        });
      });
      window.addEventListener('drop', (e) => {
        if (!currentBucket) return;
        const files = e.dataTransfer.files;
        if (files.length > 0) uploadFile(files[0]);
      });
    }

    function handleFileUpload(event) {
      const file = event.target.files[0];
      if (file) uploadFile(file);
      event.target.value = '';
    }

    function uploadFile(file) {
      if (!currentBucket) return;
      const progressBox = document.getElementById('uploadProgressBox');
      const barFill = document.getElementById('uploadBarFill');
      const fileNameLabel = document.getElementById('uploadFileName');
      const percentLabel = document.getElementById('uploadPercent');

      progressBox.style.display = 'flex';
      fileNameLabel.textContent = 'Uploading ' + file.name + ' (' + formatBytes(file.size) + ')...';
      barFill.style.width = '0%';
      percentLabel.textContent = '0%';

      const formData = new FormData();
      formData.append('file', file);
      formData.append('key', file.name);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/buckets/' + encodeURIComponent(currentBucket) + '/objects');
      if (getToken()) xhr.setRequestHeader('Authorization', 'Bearer ' + getToken());

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          barFill.style.width = pct + '%';
          percentLabel.textContent = pct + '%';
        }
      };

      xhr.onload = async () => {
        setTimeout(() => { progressBox.style.display = 'none'; }, 800);
        if (xhr.status >= 200 && xhr.status < 300) {
          await loadAllData();
          await loadObjects();
        } else {
          alert('Upload failed: ' + xhr.responseText);
        }
      };

      xhr.onerror = () => {
        progressBox.style.display = 'none';
        alert('Network error while uploading');
      };

      xhr.send(formData);
    }

    // Modal & Preview
    function openCreateBucketModal() {
      document.getElementById('newBucketNameInput').value = '';
      document.getElementById('createBucketModal').style.display = 'flex';
      setTimeout(() => document.getElementById('newBucketNameInput').focus(), 50);
    }

    function closeModal(id) {
      document.getElementById(id).style.display = 'none';
    }

    async function submitCreateBucket() {
      const name = document.getElementById('newBucketNameInput').value.trim();
      if (!name) return;
      try {
        const res = await apiFetch('/api/buckets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name })
        });
        if (res.ok) {
          closeModal('createBucketModal');
          await loadAllData();
          selectBucket(name);
        } else {
          const err = await res.json();
          alert('Could not create bucket: ' + (err.error || 'Invalid name'));
        }
      } catch (e) {
        alert('Failed to create bucket');
      }
    }

    async function confirmDeleteBucket() {
      if (!currentBucket) return;
      if (!confirm('Are you sure you want to delete bucket "' + currentBucket + '"?\nIt must be completely empty first.')) return;
      try {
        const res = await apiFetch('/api/buckets/' + encodeURIComponent(currentBucket), { method: 'DELETE' });
        if (res.ok) {
          currentBucket = null;
          document.getElementById('bucketView').style.display = 'none';
          document.getElementById('welcomeView').style.display = 'block';
          await loadAllData();
        } else {
          const err = await res.json();
          alert('Delete failed: ' + (err.error || 'Bucket not empty'));
        }
      } catch (e) {
        alert('Failed to delete bucket');
      }
    }

    async function deleteObject(key) {
      if (!confirm('Delete object "' + key + '" permanently?')) return;
      try {
        const res = await apiFetch('/api/buckets/' + encodeURIComponent(currentBucket) + '/objects/' + encodeURIComponent(key), {
          method: 'DELETE'
        });
        if (res.ok) {
          await loadAllData();
          await loadObjects();
        } else {
          alert('Failed to delete object');
        }
      } catch (e) {
        alert('Error deleting object');
      }
    }

    function openPreview(key, mime, size) {
      const container = document.getElementById('previewMediaContainer');
      const title = document.getElementById('previewTitle');
      const details = document.getElementById('previewDetails');
      const downloadBtn = document.getElementById('previewDownloadBtn');

      const encodedKey = encodeURIComponent(key);
      const tokParam = '&token=' + encodeURIComponent(getToken());
      const viewUrl = '/api/buckets/' + encodeURIComponent(currentBucket) + '/view?key=' + encodedKey + tokParam;
      const downloadUrl = '/api/buckets/' + encodeURIComponent(currentBucket) + '/download?key=' + encodedKey + tokParam;
      previewUrl = 'http://localhost:9000/' + encodeURIComponent(currentBucket) + '/' + encodeURI(key);

      title.textContent = key;
      details.textContent = formatBytes(size) + ' • ' + mime;
      downloadBtn.href = downloadUrl;
      container.innerHTML = '';

      const ext = key.split('.').pop().toLowerCase();

      if (['mp4', 'webm', 'mov', 'm3u8'].includes(ext) || mime.startsWith('video/')) {
        const video = document.createElement('video');
        video.controls = true;
        video.autoplay = true;
        video.src = viewUrl;
        container.appendChild(video);
      } else if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'].includes(ext) || mime.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = viewUrl;
        container.appendChild(img);
      } else if (['mp3', 'wav', 'ogg'].includes(ext) || mime.startsWith('audio/')) {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.autoplay = true;
        audio.src = viewUrl;
        container.appendChild(audio);
      } else {
        // Fetch text preview
        const pre = document.createElement('pre');
        pre.className = 'preview-text';
        pre.textContent = 'Loading text preview...';
        container.appendChild(pre);
        apiFetch('/api/buckets/' + encodeURIComponent(currentBucket) + '/view?key=' + encodedKey)
          .then(r => r.text())
          .then(t => { pre.textContent = t.slice(0, 10000); })
          .catch(() => { pre.textContent = 'Binary file (preview unavailable). Download above to view.'; });
      }

      document.getElementById('previewModal').style.display = 'flex';
    }

    function closePreviewModal() {
      const container = document.getElementById('previewMediaContainer');
      container.innerHTML = '';
      document.getElementById('previewModal').style.display = 'none';
    }

    function copyPreviewLink() {
      copyToClipboard(previewUrl, 'S3 URL');
    }

    function exportBucketBackup() {
      if (!currentBucket) return;
      window.open('/api/buckets/' + encodeURIComponent(currentBucket) + '/export?token=' + encodeURIComponent(getToken()), '_blank');
    }

    function copyToClipboard(text, label) {
      navigator.clipboard.writeText(text).then(() => {
        alert(label + ' copied to clipboard:\n' + text);
      }).catch(() => {
        prompt('Copy ' + label + ':', text);
      });
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    function escapeJs(str) {
      if (!str) return '';
      return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
    }
  </script>
</body>
</html>`
