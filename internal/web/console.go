package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"my-s3/internal/storage"
)

// ConsoleHandler serves the embedded Web Management UI
type ConsoleHandler struct {
	storage *storage.DiskEngine
}

// NewConsoleHandler returns a new ConsoleHandler
func NewConsoleHandler(storage *storage.DiskEngine) *ConsoleHandler {
	return &ConsoleHandler{storage: storage}
}

func (c *ConsoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")

	// API endpoints for the console UI
	if strings.HasPrefix(path, "api/") {
		c.handleAPI(w, r, strings.TrimPrefix(path, "api/"))
		return
	}

	// Serve the embedded Single Page Application
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(htmlConsole))
}

func (c *ConsoleHandler) handleAPI(w http.ResponseWriter, r *http.Request, endpoint string) {
	w.Header().Set("Content-Type", "application/json")

	if endpoint == "buckets" {
		if r.Method == http.MethodGet {
			buckets, err := c.storage.ListBuckets()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(buckets)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := c.storage.CreateBucket(body.Name); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "created", "bucket": body.Name})
			return
		}
	}

	parts := strings.Split(endpoint, "/")
	if len(parts) >= 2 && parts[0] == "buckets" {
		bucket := parts[1]
		if len(parts) == 2 && r.Method == http.MethodDelete {
			if err := c.storage.DeleteBucket(bucket); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}

		if len(parts) == 3 && parts[2] == "export" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-backup.zip\"", bucket))
			if err := c.storage.ExportBucketZip(bucket, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

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
				// File upload from Web UI
				err := r.ParseMultipartForm(500 << 20) // 500MB max
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

				info, err := c.storage.PutObject(bucket, key, file, header.Size, header.Header.Get("Content-Type"), nil)
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
  <title>My-S3 Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0f172a;
      --surface: #1e293b;
      --surface-hover: #334155;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --danger: #ef4444;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    header { background-color: var(--surface); padding: 1rem 2rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    .brand { display: flex; align-items: center; gap: 0.75rem; font-weight: bold; font-size: 1.25rem; }
    .badge { background: #1e3a8a; color: #93c5fd; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .container { display: flex; flex: 1; }
    .sidebar { width: 280px; background: var(--surface); border-right: 1px solid var(--border); padding: 1.5rem 1rem; display: flex; flex-direction: column; gap: 1rem; }
    .sidebar-title { font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center; }
    .bucket-list { list-style: none; display: flex; flex-direction: column; gap: 0.35rem; }
    .bucket-item { padding: 0.65rem 0.85rem; border-radius: 0.375rem; cursor: pointer; color: var(--text); display: flex; justify-content: space-between; align-items: center; transition: all 0.15s; }
    .bucket-item:hover { background: var(--surface-hover); }
    .bucket-item.active { background: var(--primary); color: #fff; font-weight: 600; }
    .content { flex: 1; padding: 2rem; }
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
    .btn { background: var(--primary); color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.375rem; cursor: pointer; font-size: 0.875rem; font-weight: 500; display: inline-flex; align-items: center; gap: 0.5rem; }
    .btn:hover { background: var(--primary-hover); }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 0.5rem; overflow: hidden; border: 1px solid var(--border); }
    th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { background: #131d31; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .empty-state { text-align: center; padding: 4rem 1rem; color: var(--text-muted); }
    .upload-area { border: 2px dashed var(--border); border-radius: 0.5rem; padding: 2rem; text-align: center; cursor: pointer; margin-bottom: 1.5rem; background: rgba(30, 41, 59, 0.5); }
    .upload-area:hover { border-color: var(--primary); }
    input[type="file"] { display: none; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242M12 12v9m-4-4 4 4 4-4"/></svg>
      <span>NexvorS3</span>
      <span class="badge" style="background: #0284c7; color: #ffffff;">NexvorCodeLabs</span>
    </div>
    <div style="font-size: 0.85rem; color: var(--text-muted);">
      REST API: <strong>:9000</strong> | Console: <strong>:9001</strong>
    </div>
  </header>

  <div class="container">
    <aside class="sidebar">
      <div class="sidebar-title">
        <span>Buckets</span>
        <button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="promptNewBucket()">+ New</button>
      </div>
      <ul class="bucket-list" id="bucketList">
        <li class="empty-state" style="padding: 1rem 0;">Loading buckets...</li>
      </ul>
    </aside>

    <main class="content">
      <div class="toolbar">
        <div>
          <h2 id="activeBucketTitle">Select a Bucket</h2>
          <p id="activeBucketSub" style="color: var(--text-muted); font-size: 0.85rem;"></p>
        </div>
        <div id="bucketActions" style="display: none; gap: 0.5rem;">
          <button class="btn" onclick="document.getElementById('fileInput').click()">Upload File</button>
          <button class="btn" style="background:#10b981;" onclick="exportBucketZip()">Backup (ZIP)</button>
          <button class="btn btn-danger" onclick="deleteActiveBucket()">Delete Bucket</button>
          <input type="file" id="fileInput" onchange="uploadSelectedFile(event)" />
        </div>
      </div>

      <div id="dropZone" class="upload-area" style="display: none;" onclick="document.getElementById('fileInput').click()">
        <p>Drag and drop files here, or click to browse</p>
      </div>

      <div id="tableContainer">
        <div class="empty-state">Select a bucket from the sidebar to view objects.</div>
      </div>
    </main>
  </div>

  <script>
    let activeBucket = null;

    async function loadBuckets() {
      try {
        const res = await fetch('/api/buckets');
        const buckets = await res.json() || [];
        const list = document.getElementById('bucketList');
        list.innerHTML = '';
        if (buckets.length === 0) {
          list.innerHTML = '<li style="color: var(--text-muted); font-size: 0.85rem; padding: 0.5rem;">No buckets yet</li>';
          return;
        }
        buckets.forEach(b => {
          const li = document.createElement('li');
          li.className = 'bucket-item' + (activeBucket === b.name ? ' active' : '');
          li.innerHTML = '<span>📁 ' + b.name + '</span>';
          li.onclick = () => selectBucket(b.name);
          list.appendChild(li);
        });
      } catch (err) {
        console.error(err);
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function getS3BaseUrl() {
      return window.location.protocol + '//' + window.location.hostname + ':9000';
    }

    async function selectBucket(name) {
      activeBucket = name;
      document.getElementById('activeBucketTitle').textContent = 'Bucket: ' + name;
      document.getElementById('activeBucketSub').textContent = 'S3 Endpoint: ' + getS3BaseUrl() + '/' + name;
      document.getElementById('bucketActions').style.display = 'flex';
      document.getElementById('dropZone').style.display = 'block';
      loadBuckets();
      loadObjects();
    }

    async function loadObjects() {
      if (!activeBucket) return;
      try {
        const res = await fetch('/api/buckets/' + encodeURIComponent(activeBucket) + '/objects');
        const objects = await res.json() || [];
        const container = document.getElementById('tableContainer');
        if (objects.length === 0) {
          container.innerHTML = '<div class="empty-state">This bucket is empty. Upload your first file!</div>';
          return;
        }

        let html = '<table><thead><tr><th>Object Key</th><th>Size</th><th>Content Type</th><th>Last Modified</th><th>Actions</th></tr></thead><tbody>';
        objects.forEach(obj => {
          const downloadUrl = getS3BaseUrl() + '/' + encodeURIComponent(activeBucket) + '/' + encodeURI(obj.key);
          const safeKey = escapeHtml(obj.key);
          const safeType = escapeHtml(obj.content_type);
          const encodedKey = encodeURIComponent(obj.key);

          html += '<tr>' +
            '<td><strong>' + safeKey + '</strong></td>' +
            '<td>' + formatBytes(obj.size) + '</td>' +
            '<td><span class="badge" style="background:#334155;color:#f8fafc;">' + safeType + '</span></td>' +
            '<td>' + new Date(obj.last_modified).toLocaleString() + '</td>' +
            '<td>' +
              '<a href="' + downloadUrl + '" target="_blank" class="btn" style="padding: 0.25rem 0.5rem; text-decoration: none; font-size: 0.75rem; margin-right: 0.35rem;">Open</a>' +
              '<button class="btn" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; margin-right: 0.35rem; background:#6366f1;" onclick="copyShareLink(\'' + downloadUrl + '\')">Share Link</button>' +
              '<button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="deleteObject(\'' + encodedKey + '\')">Delete</button>' +
            '</td>' +
          '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (err) {
        console.error(err);
      }
    }

    async function promptNewBucket() {
      const name = prompt('Enter new bucket name (lowercase, no spaces):');
      if (!name) return;
      const res = await fetch('/api/buckets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim() })
      });
      if (res.ok) {
        selectBucket(name.trim());
      } else {
        const err = await res.text();
        alert('Error creating bucket: ' + err);
      }
    }

    async function deleteActiveBucket() {
      if (!confirm('Are you sure you want to delete bucket "' + activeBucket + '"? It must be empty.')) return;
      const res = await fetch('/api/buckets/' + activeBucket, { method: 'DELETE' });
      if (res.ok) {
        activeBucket = null;
        document.getElementById('activeBucketTitle').textContent = 'Select a Bucket';
        document.getElementById('activeBucketSub').textContent = '';
        document.getElementById('bucketActions').style.display = 'none';
        document.getElementById('dropZone').style.display = 'none';
        document.getElementById('tableContainer').innerHTML = '<div class="empty-state">Select a bucket to view objects.</div>';
        loadBuckets();
      } else {
        const err = await res.text();
        alert('Could not delete bucket: ' + err);
      }
    }

    async function uploadSelectedFile(event) {
      const file = event.target.files[0];
      if (!file || !activeBucket) return;
      const formData = new FormData();
      formData.append('file', file);
      formData.append('key', file.name);

      const res = await fetch('/api/buckets/' + activeBucket + '/objects', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        event.target.value = '';
        loadObjects();
      } else {
        const err = await res.text();
        alert('Upload failed: ' + err);
      }
    }

    async function deleteObject(encodedKey) {
      const key = decodeURIComponent(encodedKey);
      if (!confirm('Delete object "' + key + '"?')) return;
      const res = await fetch('/api/buckets/' + encodeURIComponent(activeBucket) + '/objects/' + encodedKey, { method: 'DELETE' });
      if (res.ok) {
        loadObjects();
      } else {
        const err = await res.text();
        alert('Delete failed: ' + err);
      }
    }

    function formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function exportBucketZip() {
      if (!activeBucket) return;
      window.open('/api/buckets/' + encodeURIComponent(activeBucket) + '/export', '_blank');
    }

    function copyShareLink(url) {
      navigator.clipboard.writeText(url).then(() => {
        alert('Public Share Link copied to clipboard:\n' + url);
      }).catch(() => {
        prompt('Copy this link:', url);
      });
    }

    loadBuckets();
  </script>
</body>
</html>`
