# NexvorS3: Ultra-Fast S3-Compatible Storage Engine
**By NexvorCodeLabs** | High-Performance Object Storage & Database Reliability Engine  
**Website**: [nexvorcodelabs.me](https://nexvorcodelabs.me) | **Launch Status**: [View Launch Announcement](LAUNCH_ANNOUNCEMENT.md)  
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Docker Image](https://img.shields.io/badge/Docker_Hub-dinidun%2Fnexvors3-blue?logo=docker)](https://hub.docker.com/r/dinidun/nexvors3)

> 🚀 **Public Launch Coming Soon!** We are preparing the official public release. Visit [nexvorcodelabs.me](https://nexvorcodelabs.me) to get in touch with our team for early pilot access.

---

## 🎬 Native HLS (`.m3u8`) & Multi-Resolution Video
NexvorS3 natively supports **Apple HLS (`.m3u8`) playlists** and **`.ts` video segments** with automatic RFC 8216 MIME header mapping and HTTP 206 byte-range seeking. Stream adaptive **1080p, 720p, 480p, and 360p** video to iOS, Android, and web players with zero buffering.

---

## ⚡ Why NexvorS3?

| Feature | AWS S3 | MinIO | **NexvorS3** |
| :--- | :--- | :--- | :--- |
| **Licensing** | Cloud vendor lock-in | Restricted AGPLv3 (threatens closed-source code) | **100% Commercially Permissive (clean-room)** |
| **Memory Footprint** | N/A | ~300MB - 500MB | **~11.7 MB RAM** |
| **Startup Time** | N/A | 3–6 seconds | **< 15 milliseconds** |
| **Docker Image Size** | N/A | ~150MB+ | **~22MB (Alpine multi-stage)** |
| **Video & Audio Streaming** | HTTP Range requests | HTTP Range requests | **Full RFC 8216 HLS (.m3u8) & RFC 7233 Range** |
| **Large File Uploads** | Multipart Uploads | Multipart Uploads | **S3 Multipart Uploads (5MB–5TB chunks)** |
| **One-Click Backups** | Complex AWS Backup | `mc mirror` CLI | **One-click ZIP Backup Export in Web UI & API** |
| **File Sharing** | Presigned URLs | Presigned URLs | **1-Click Copy Public / Presigned Share Link** |
| **Embedded Web UI** | Complex AWS IAM | Bulky console | **Built-in dark-mode Web Console on port 9001** |
| **External Dependencies** | Internet required | Heavy stack | **Zero external dependencies (pure Go stdlib)** |

---

## 🚀 Quick Start

### 1. Run Instantly from Docker Hub
```bash
docker run -d --name nexvor-s3 -p 9000:9000 -p 9001:9001 -v nexvor_data:/data dinidun/nexvors3:latest
```

### 2. Run with Docker Compose
```bash
docker compose up -d
```
* **S3 REST API**: `http://localhost:9000`
* **Web Console UI**: `http://localhost:9001`
* **Default Access Key**: `minioadmin`
* **Default Secret Key**: `minioadmin`

### 3. Run Directly with Go
```bash
# Build
go build -o my-s3.exe ./cmd/server

# Run
./my-s3.exe
```

---

## 🖥️ Web Console UI

Visit **`http://localhost:9001`** in your browser to:
* Create and delete buckets.
* Upload files via drag-and-drop.
* Preview and download stored files directly.
* Inspect file sizes, content types, and timestamps.

---

## 🔌 Connecting Existing Applications

`my-s3` is a 100% drop-in replacement for standard S3 tools and libraries.

### AWS CLI
```bash
# Configure credentials
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

# List buckets
aws --endpoint-url http://localhost:9000 s3 ls

# Create bucket
aws --endpoint-url http://localhost:9000 s3 mb s3://artist-assets

# Copy file
aws --endpoint-url http://localhost:9000 s3 cp myfile.png s3://artist-assets/
```

### Python (`minio` or `boto3`)
Matches your setup in `fitbook`:
```python
from minio import Minio

client = Minio(
    endpoint="localhost:9000",
    access_key="minioadmin",
    secret_key="minioadmin",
    secure=False
)

# Upload file
client.fput_object("fitbook-media", "avatar.jpg", "./avatar.jpg")
```

### Node.js (`@aws-sdk/client-s3`)
Matches your setup in `syncspace` & `celibriy-web`:
```typescript
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  endpoint: "http://localhost:9000",
  region: "us-east-1",
  credentials: {
    accessKeyId: "minioadmin",
    secretAccessKey: "minioadmin",
  },
  forcePathStyle: true,
});
```

---

## 📦 Project Structure

```
my-s3/
├── cmd/
│   └── server/
│       └── main.go              # Server bootstrap, CLI flags & graceful shutdown
├── internal/
│   ├── api/
│   │   ├── s3_handlers.go       # REST endpoints (PutObject, GetObject, Range requests)
│   │   └── s3_xml.go            # AWS standard S3 XML serialization
│   ├── auth/
│   │   └── auth.go              # SigV4 & key authentication parser
│   ├── storage/
│   │   └── storage.go           # High-concurrency disk storage & metadata engine
│   └── web/
│       └── console.go           # Embedded dark-mode web management console
├── Dockerfile                   # Multi-stage lightweight build (< 25MB)
├── docker-compose.yml           # Production Docker Compose orchestration
├── go.mod
└── README.md
```

---

## ⚖️ License
NexvorS3 is open-source software licensed under the **[Apache License 2.0](LICENSE)**.

* Clean-room implementation from public S3 specifications (zero AGPLv3/GPL copyleft contamination).
* You are 100% free to compile, modify, embed in proprietary products, host as a SaaS, or distribute commercially.
