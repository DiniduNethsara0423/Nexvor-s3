package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/replication"
	"my-s3/internal/storage"
)

func signedDo(t *testing.T, client *http.Client, method, rawURL string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	auth.SignRequestV4(req, "prod-ak", "prod-sk-super-secret", "us-east-1", "UNSIGNED-PAYLOAD")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s failed: %v", method, rawURL, err)
	}
	return resp
}

func TestPhase4BarmanCNPGDrillAndReplication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup Replica (Local k3s cluster S3) with strict SigV4 (AllowAnon=false)
	replicaDir := t.TempDir()
	replicaStorage, err := storage.NewDiskEngine(replicaDir)
	if err != nil {
		t.Fatalf("replica storage init failed: %v", err)
	}
	replicaAuth := auth.NewAuthenticator("prod-ak", "prod-sk-super-secret", false)
	replicaHandler := NewS3Handler(replicaStorage, replicaAuth, "")
	replicaSrv := httptest.NewServer(replicaHandler)
	defer replicaSrv.Close()

	// 2. Setup Primary (Cloud S3) with strict SigV4 + Native Async Cross-Site Replicator -> Replica
	primaryDir := t.TempDir()
	primaryStorage, err := storage.NewDiskEngine(primaryDir)
	if err != nil {
		t.Fatalf("primary storage init failed: %v", err)
	}
	primaryAuth := auth.NewAuthenticator("prod-ak", "prod-sk-super-secret", false)
	primaryHandler := NewS3Handler(primaryStorage, primaryAuth, "")
	rep := replication.NewReplicator(primaryStorage, replicaSrv.URL, "prod-ak", "prod-sk-super-secret", "us-east-1")
	rep.Start(ctx, 2)
	primaryHandler.SetReplicator(rep)

	primarySrv := httptest.NewServer(primaryHandler)
	defer primarySrv.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	// --- TEST A: Strict AWS SigV4 Auth Defense ---
	unauthReq, _ := http.NewRequest(http.MethodGet, primarySrv.URL+"/", nil)
	unauthResp, err := client.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauth request error: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unauthenticated request in strict SigV4 mode, got %d", unauthResp.StatusCode)
	}

	// Forged signature must fail with 403
	forgedReq, _ := http.NewRequest(http.MethodGet, primarySrv.URL+"/", nil)
	auth.SignRequestV4(forgedReq, "prod-ak", "wrong-secret-key", "us-east-1", "UNSIGNED-PAYLOAD")
	forgedResp, _ := client.Do(forgedReq)
	forgedResp.Body.Close()
	if forgedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 SignatureDoesNotMatch for wrong SigV4 key, got %d", forgedResp.StatusCode)
	}

	// --- TEST B: Create Bucket via Path-Style URL + Valid SigV4 ---
	bucket := "arrakapay-wallet-dr"
	resp := signedDo(t, client, http.MethodPut, primarySrv.URL+"/"+bucket, nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 creating bucket, got %d", resp.StatusCode)
	}

	// --- TEST C: Full S3 Multipart Upload (CloudNativePG Barman Base Backup Simulation) ---
	baseKey := "pg-wallet/base/20261111T150000/data.tar.gz"
	initResp := signedDo(t, client, http.MethodPost, primarySrv.URL+"/"+bucket+"/"+baseKey+"?uploads", nil, map[string]string{
		"Content-Type":       "application/gzip",
		"x-amz-meta-cluster": "wallet-pg-prod",
	})
	var initResult InitiateMultipartUploadResult
	_ = xml.NewDecoder(initResp.Body).Decode(&initResult)
	initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK || initResult.UploadId == "" {
		t.Fatalf("InitiateMultipartUpload failed: code=%d uploadId=%q", initResp.StatusCode, initResult.UploadId)
	}

	// Verify ListMultipartUploads reports active upload
	lmuResp := signedDo(t, client, http.MethodGet, primarySrv.URL+"/"+bucket+"?uploads", nil, nil)
	var lmuResult ListMultipartUploadsResult
	_ = xml.NewDecoder(lmuResp.Body).Decode(&lmuResult)
	lmuResp.Body.Close()
	if len(lmuResult.Upload) != 1 || lmuResult.Upload[0].UploadId != initResult.UploadId {
		t.Fatalf("ListMultipartUploads mismatch: %+v", lmuResult)
	}

	// Upload 3 parts (testing Content-MD5 validation + corrupted digest rejection)
	p1 := bytes.Repeat([]byte("PGDATA_BLOCK_1_"), 1024)
	p2 := bytes.Repeat([]byte("PGDATA_BLOCK_2_"), 1024)
	p3 := bytes.Repeat([]byte("PGDATA_BLOCK_3_"), 512)
	fullBaseBackup := append(append([]byte{}, p1...), p2...)
	fullBaseBackup = append(fullBaseBackup, p3...)
	expectedFullSHA := sha256.Sum256(fullBaseBackup)

	// Negative check: bad Content-MD5 must be rejected with 400 BadDigest
	badMD5 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	badPartResp := signedDo(t, client, http.MethodPut, fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", primarySrv.URL, bucket, baseKey, initResult.UploadId), p1, map[string]string{
		"Content-MD5": badMD5,
	})
	badPartResp.Body.Close()
	if badPartResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 BadDigest for mismatched Content-MD5, got %d", badPartResp.StatusCode)
	}

	var completedParts []storage.CompletePart
	var concatRawPartMD5 []byte
	for idx, chunk := range [][]byte{p1, p2, p3} {
		partNum := idx + 1
		sum := md5.Sum(chunk)
		concatRawPartMD5 = append(concatRawPartMD5, sum[:]...)
		b64 := base64.StdEncoding.EncodeToString(sum[:])

		uResp := signedDo(t, client, http.MethodPut, fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s", primarySrv.URL, bucket, baseKey, partNum, initResult.UploadId), chunk, map[string]string{
			"Content-MD5": b64,
		})
		etag := uResp.Header.Get("ETag")
		uResp.Body.Close()
		if uResp.StatusCode != http.StatusOK || etag == "" {
			t.Fatalf("UploadPart %d failed: code=%d etag=%q", partNum, uResp.StatusCode, etag)
		}
		completedParts = append(completedParts, storage.CompletePart{PartNumber: partNum, ETag: etag})
	}

	// Verify ListParts returns all 3 chunks
	lpResp := signedDo(t, client, http.MethodGet, fmt.Sprintf("%s/%s/%s?uploadId=%s", primarySrv.URL, bucket, baseKey, initResult.UploadId), nil, nil)
	var lpResult ListPartsResult
	_ = xml.NewDecoder(lpResp.Body).Decode(&lpResult)
	lpResp.Body.Close()
	if len(lpResult.Part) != 3 {
		t.Fatalf("expected 3 parts in ListParts, got %d", len(lpResult.Part))
	}

	// Complete Multipart Upload and verify standard AWS S3 Multipart ETag (<md5-of-md5s>-3)
	compXML, _ := xml.Marshal(CompleteMultipartUploadRequest{Part: completedParts})
	compResp := signedDo(t, client, http.MethodPost, fmt.Sprintf("%s/%s/%s?uploadId=%s", primarySrv.URL, bucket, baseKey, initResult.UploadId), compXML, map[string]string{
		"Content-Type": "application/xml",
	})
	var compResult CompleteMultipartUploadResult
	_ = xml.NewDecoder(compResp.Body).Decode(&compResult)
	compResp.Body.Close()

	expectedS3Sum := md5.Sum(concatRawPartMD5)
	expectedMultipartETag := fmt.Sprintf("\"%s-3\"", hex.EncodeToString(expectedS3Sum[:]))
	if compResp.StatusCode != http.StatusOK {
		t.Fatalf("CompleteMultipartUpload failed: %d", compResp.StatusCode)
	}
	if compResp.Header.Get("ETag") != expectedMultipartETag || compResult.ETag != expectedMultipartETag {
		t.Fatalf("expected AWS standard multipart ETag %s, got header=%s xml=%s", expectedMultipartETag, compResp.Header.Get("ETag"), compResult.ETag)
	}

	// --- TEST D: AWS Chunked SigV4 Framing (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) ---
	walManifestData := []byte("START WAL LOCATION: 0/1000028 (file 000000010000000000000001)\nCHECKPOINT LOCATION: 0/1000060\n")
	chunkFramed := fmt.Sprintf("%x;chunk-signature=deadbeef\r\n%s\r\n0;chunk-signature=deadbeef\r\n\r\n", len(walManifestData), string(walManifestData))
	manifestKey := "pg-wallet/wals/0000000100000000/000000010000000000000001.backup"
	reqFramed, _ := http.NewRequest(http.MethodPut, primarySrv.URL+"/"+bucket+"/"+manifestKey, strings.NewReader(chunkFramed))
	auth.SignRequestV4(reqFramed, "prod-ak", "prod-sk-super-secret", "us-east-1", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	framedResp, err := client.Do(reqFramed)
	if err != nil {
		t.Fatalf("framed upload failed: %v", err)
	}
	framedResp.Body.Close()
	if framedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for AWS chunked upload, got %d", framedResp.StatusCode)
	}

	// --- TEST E: Upload 12 Continuous WAL Segments & KYC Docs + Paginated ListObjectsV2 ---
	for i := 1; i <= 12; i++ {
		walKey := fmt.Sprintf("pg-wallet/wals/0000000100000000/0000000100000000%08x", i)
		walBody := []byte(fmt.Sprintf("WAL_SEGMENT_DATA_%04d", i))
		r := signedDo(t, client, http.MethodPut, primarySrv.URL+"/"+bucket+"/"+walKey, walBody, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("failed uploading WAL %d: %d", i, r.StatusCode)
		}
	}

	// Paginate ListObjectsV2 across 13 objects (12 WALs + 1 .backup) using max-keys=3
	var collectedKeys []string
	token := ""
	pages := 0
	for {
		pages++
		u := fmt.Sprintf("%s/%s?list-type=2&prefix=%s&max-keys=3", primarySrv.URL, bucket, "pg-wallet/wals/0000000100000000/")
		if token != "" {
			u += "&continuation-token=" + token
		}
		lResp := signedDo(t, client, http.MethodGet, u, nil, nil)
		var lr ListBucketResult
		_ = xml.NewDecoder(lResp.Body).Decode(&lr)
		lResp.Body.Close()

		if lResp.StatusCode != http.StatusOK {
			t.Fatalf("ListObjectsV2 failed on page %d: %d", pages, lResp.StatusCode)
		}
		if lr.KeyCount != len(lr.Contents)+len(lr.CommonPrefixes) {
			t.Fatalf("KeyCount mismatch: got %d, want %d", lr.KeyCount, len(lr.Contents)+len(lr.CommonPrefixes))
		}
		for _, obj := range lr.Contents {
			collectedKeys = append(collectedKeys, obj.Key)
		}
		if !lr.IsTruncated {
			break
		}
		token = lr.NextContinuationToken
	}

	// Must have ZERO skipped and ZERO duplicate keys across all 5 pages!
	if len(collectedKeys) != 13 {
		t.Fatalf("Barman ListObjectsV2 pagination lost/duplicated WALs! expected 13, got %d (%v)", len(collectedKeys), collectedKeys)
	}

	// Also verify Delimiter="/" pagination (pg-wallet/ -> CommonPrefixes: base/, wals/)
	delimResp1 := signedDo(t, client, http.MethodGet, primarySrv.URL+"/"+bucket+"?list-type=2&prefix=pg-wallet/&delimiter=/&max-keys=1", nil, nil)
	var dr1 ListBucketResult
	_ = xml.NewDecoder(delimResp1.Body).Decode(&dr1)
	delimResp1.Body.Close()
	if !dr1.IsTruncated || len(dr1.CommonPrefixes) != 1 || dr1.CommonPrefixes[0].Prefix != "pg-wallet/base/" {
		t.Fatalf("expected truncated CommonPrefix pg-wallet/base/ on page 1, got %+v", dr1)
	}

	delimResp2 := signedDo(t, client, http.MethodGet, primarySrv.URL+"/"+bucket+"?list-type=2&prefix=pg-wallet/&delimiter=/&max-keys=1&continuation-token="+dr1.NextContinuationToken, nil, nil)
	var dr2 ListBucketResult
	_ = xml.NewDecoder(delimResp2.Body).Decode(&dr2)
	delimResp2.Body.Close()
	if len(dr2.CommonPrefixes) != 1 || dr2.CommonPrefixes[0].Prefix != "pg-wallet/wals/" {
		t.Fatalf("expected CommonPrefix pg-wallet/wals/ on page 2, got %+v", dr2)
	}

	// --- TEST F: Verify Native Async Cross-Site Replication & Scratch Restore Integrity ---
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rep.Stats().ReplicatedTotal >= 14 && rep.Stats().QueueDepth == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rep.Stats().FailedTotal > 0 || rep.Stats().ReplicatedTotal < 14 {
		t.Fatalf("async replication did not complete cleanly: %+v", rep.Stats())
	}

	// Restore Base Backup from REPLICA server and verify byte-for-byte SHA-256 match!
	restoreResp := signedDo(t, client, http.MethodGet, replicaSrv.URL+"/"+bucket+"/"+baseKey, nil, nil)
	restoredBytes, _ := io.ReadAll(restoreResp.Body)
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusOK {
		t.Fatalf("failed restoring base backup from replica: %d", restoreResp.StatusCode)
	}
	if sha256.Sum256(restoredBytes) != expectedFullSHA {
		t.Fatalf("SCRATCH RESTORE CORRUPTION: restored SHA-256 does not match original backup!")
	}

	// Verify WAL .backup manifest on Replica also matches exact un-framed content
	manifestResp := signedDo(t, client, http.MethodGet, replicaSrv.URL+"/"+bucket+"/"+manifestKey, nil, nil)
	manifestBytes, _ := io.ReadAll(manifestResp.Body)
	manifestResp.Body.Close()
	if !bytes.Equal(manifestBytes, walManifestData) {
		t.Fatalf("manifest mismatch on replica: got %q, want %q", string(manifestBytes), string(walManifestData))
	}
}
