package api

import (
	"bytes"
	"context"
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

func TestMinIOFullFeatureCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	engine, err := storage.NewDiskEngine(tmpDir)
	if err != nil {
		t.Fatalf("engine init failed: %v", err)
	}
	authenticator := auth.NewAuthenticator("minioadmin", "miniosecret123", false)
	handler := NewS3Handler(engine, authenticator, "")
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	sign := func(method, url string, body []byte, hdrs map[string]string) *http.Response {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, _ := http.NewRequest(method, url, r)
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		auth.SignRequestV4(req, "minioadmin", "miniosecret123", "us-east-1", "UNSIGNED-PAYLOAD")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP %s %s failed: %v", method, url, err)
		}
		return resp
	}

	// Create source & destination buckets
	for _, b := range []string{"src-bucket", "dst-bucket"} {
		resp := sign(http.MethodPut, srv.URL+"/"+b, nil, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("create bucket %s failed: %d", b, resp.StatusCode)
		}
	}

	// 1. Bucket metadata queries (?location, ?versioning, ?acl)
	locResp := sign(http.MethodGet, srv.URL+"/src-bucket?location", nil, nil)
	var locXML LocationConstraintResult
	_ = xml.NewDecoder(locResp.Body).Decode(&locXML)
	locResp.Body.Close()
	if locXML.Location != "us-east-1" {
		t.Errorf("expected LocationConstraint us-east-1, got %q", locXML.Location)
	}

	verResp := sign(http.MethodGet, srv.URL+"/src-bucket?versioning", nil, nil)
	verBody, _ := io.ReadAll(verResp.Body)
	verResp.Body.Close()
	if verResp.StatusCode != http.StatusOK || !strings.Contains(string(verBody), "<VersioningConfiguration") {
		t.Errorf("unexpected ?versioning response: %d %s", verResp.StatusCode, string(verBody))
	}

	aclResp := sign(http.MethodGet, srv.URL+"/src-bucket?acl", nil, nil)
	aclBody, _ := io.ReadAll(aclResp.Body)
	aclResp.Body.Close()
	if aclResp.StatusCode != http.StatusOK || !strings.Contains(string(aclBody), "FULL_CONTROL") {
		t.Errorf("unexpected ?acl response: %d %s", aclResp.StatusCode, string(aclBody))
	}

	// 2. Upload object and test Server-Side CopyObject (x-amz-copy-source)
	payload := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	putResp := sign(http.MethodPut, srv.URL+"/src-bucket/folder/origin.bin", payload, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	putResp.Body.Close()

	copyResp := sign(http.MethodPut, srv.URL+"/dst-bucket/copied/target.bin", nil, map[string]string{
		"x-amz-copy-source": "/src-bucket/folder/origin.bin",
	})
	var copyXML CopyObjectResult
	_ = xml.NewDecoder(copyResp.Body).Decode(&copyXML)
	copyResp.Body.Close()
	if copyResp.StatusCode != http.StatusOK || copyXML.ETag == "" {
		t.Fatalf("CopyObject failed: code=%d xml=%+v", copyResp.StatusCode, copyXML)
	}

	// Verify copied bytes match identically
	getCopyResp := sign(http.MethodGet, srv.URL+"/dst-bucket/copied/target.bin", nil, nil)
	gotCopy, _ := io.ReadAll(getCopyResp.Body)
	getCopyResp.Body.Close()
	if !bytes.Equal(gotCopy, payload) {
		t.Fatalf("copied payload mismatch: got %q", string(gotCopy))
	}

	// 3. UploadPartCopy with byte range (bytes=10-19 -> "ABCDEFGHIJ")
	initResp := sign(http.MethodPost, srv.URL+"/dst-bucket/slice.bin?uploads", nil, nil)
	var initXML InitiateMultipartUploadResult
	_ = xml.NewDecoder(initResp.Body).Decode(&initXML)
	initResp.Body.Close()

	partCopyResp := sign(http.MethodPut, fmt.Sprintf("%s/dst-bucket/slice.bin?partNumber=1&uploadId=%s", srv.URL, initXML.UploadId), nil, map[string]string{
		"x-amz-copy-source":       "/src-bucket/folder/origin.bin",
		"x-amz-copy-source-range": "bytes=10-19",
	})
	var cpXML CopyPartResult
	_ = xml.NewDecoder(partCopyResp.Body).Decode(&cpXML)
	partCopyResp.Body.Close()
	if partCopyResp.StatusCode != http.StatusOK || cpXML.ETag == "" {
		t.Fatalf("UploadPartCopy failed: %d", partCopyResp.StatusCode)
	}

	compBody, _ := xml.Marshal(CompleteMultipartUploadRequest{
		Part: []storage.CompletePart{{PartNumber: 1, ETag: cpXML.ETag}},
	})
	compResp := sign(http.MethodPost, fmt.Sprintf("%s/dst-bucket/slice.bin?uploadId=%s", srv.URL, initXML.UploadId), compBody, nil)
	compResp.Body.Close()

	sliceResp := sign(http.MethodGet, srv.URL+"/dst-bucket/slice.bin", nil, nil)
	sliceBytes, _ := io.ReadAll(sliceResp.Body)
	sliceResp.Body.Close()
	if string(sliceBytes) != "ABCDEFGHIJ" {
		t.Fatalf("UploadPartCopy range mismatch: got %q, want ABCDEFGHIJ", string(sliceBytes))
	}

	// 4. Object Tagging (?tagging PUT -> GET -> DELETE)
	tagReqXML, _ := xml.Marshal(TaggingXML{
		TagSet: TagSetXML{Tag: []TagXML{{Key: "env", Value: "prod"}, {Key: "compliance", Value: "kyc"}}},
	})
	putTagResp := sign(http.MethodPut, srv.URL+"/src-bucket/folder/origin.bin?tagging", tagReqXML, nil)
	putTagResp.Body.Close()
	if putTagResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT ?tagging failed: %d", putTagResp.StatusCode)
	}

	getTagResp := sign(http.MethodGet, srv.URL+"/src-bucket/folder/origin.bin?tagging", nil, nil)
	var gotTags TaggingXML
	_ = xml.NewDecoder(getTagResp.Body).Decode(&gotTags)
	getTagResp.Body.Close()
	if len(gotTags.TagSet.Tag) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(gotTags.TagSet.Tag))
	}

	delTagResp := sign(http.MethodDelete, srv.URL+"/src-bucket/folder/origin.bin?tagging", nil, nil)
	delTagResp.Body.Close()
	if delTagResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE ?tagging failed: %d", delTagResp.StatusCode)
	}

	// 5. Presigned SigV4 URL (GET succeeds without auth header when valid signature in query string!)
	presignedURL, err := auth.GeneratePresignedURL(srv.URL, "src-bucket", "folder/origin.bin", "minioadmin", "miniosecret123", "us-east-1", http.MethodGet, 3600)
	if err != nil {
		t.Fatalf("GeneratePresignedURL failed: %v", err)
	}
	preResp, err := client.Get(presignedURL)
	if err != nil {
		t.Fatalf("presigned GET failed: %v", err)
	}
	preBytes, _ := io.ReadAll(preResp.Body)
	preResp.Body.Close()
	if preResp.StatusCode != http.StatusOK || !bytes.Equal(preBytes, payload) {
		t.Fatalf("presigned URL fetch failed: status=%d len=%d", preResp.StatusCode, len(preBytes))
	}

	// Tampered presigned URL must fail with 403
	tamperedURL := presignedURL[:len(presignedURL)-2] + "ff"
	if tamperedURL == presignedURL {
		tamperedURL = presignedURL[:len(presignedURL)-2] + "aa"
	}
	badPreResp, _ := client.Get(tamperedURL)
	badPreResp.Body.Close()
	if badPreResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered presigned URL, got %d", badPreResp.StatusCode)
	}

	// 6. Batch Multi-Object Delete (POST /{bucket}?delete)
	delBatchXML, _ := xml.Marshal(DeleteObjectsRequest{
		Object: []DeleteObjectIdentifierXML{
			{Key: "copied/target.bin"},
			{Key: "slice.bin"},
		},
	})
	delBatchResp := sign(http.MethodPost, srv.URL+"/dst-bucket?delete", delBatchXML, nil)
	var delRes DeleteResult
	_ = xml.NewDecoder(delBatchResp.Body).Decode(&delRes)
	delBatchResp.Body.Close()
	if delBatchResp.StatusCode != http.StatusOK || len(delRes.Deleted) != 2 {
		t.Fatalf("batch delete failed: code=%d deleted=%+v err=%+v", delBatchResp.StatusCode, delRes.Deleted, delRes.Error)
	}

	// 7. Virtual-Hosted-Style Request (src-bucket.localhost -> src-bucket)
	vhostReq := httptest.NewRequest(http.MethodGet, "/folder/origin.bin", nil)
	vhostReq.Host = "src-bucket.localhost:9000"
	auth.SignRequestV4(vhostReq, "minioadmin", "miniosecret123", "us-east-1", "UNSIGNED-PAYLOAD")
	vw := httptest.NewRecorder()
	handler.ServeHTTP(vw, vhostReq)
	if vw.Code != http.StatusOK || !bytes.Equal(vw.Body.Bytes(), payload) {
		t.Fatalf("virtual-host bucket routing failed: code=%d", vw.Code)
	}

	// 8. Prometheus Cluster Metrics Endpoint (/minio/v2/metrics/cluster)
	metricsReq := httptest.NewRequest(http.MethodGet, "/minio/v2/metrics/cluster", nil)
	mw := httptest.NewRecorder()
	handler.ServeHTTP(mw, metricsReq)
	if mw.Code != http.StatusOK || !strings.Contains(mw.Body.String(), "nexvors3_objects_total 1") {
		t.Fatalf("unexpected Prometheus metrics output: code=%d body=%s", mw.Code, mw.Body.String())
	}
}

func TestReplicaOfflineCatchupReconciliation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Primary creates bucket & files BEFORE replica catches up
	primaryStorage, _ := storage.NewDiskEngine(t.TempDir())
	_ = primaryStorage.CreateBucket("kyc-docs")
	_, _ = primaryStorage.PutObject("kyc-docs", "passport-001.jpg", strings.NewReader("kyc-image-bytes"), 15, "image/jpeg", nil)

	// Start empty Replica
	replicaStorage, _ := storage.NewDiskEngine(t.TempDir())
	replicaHandler := NewS3Handler(replicaStorage, auth.NewAuthenticator("ak", "sk", false), "")
	replicaSrv := httptest.NewServer(replicaHandler)
	defer replicaSrv.Close()

	// Start Replicator -> ReconcileExisting should automatically backfill missed objects!
	rep := replication.NewReplicator(primaryStorage, replicaSrv.URL, "ak", "sk", "us-east-1")
	rep.Start(ctx, 2)

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if rep.Stats().ReplicatedTotal >= 1 && rep.Stats().QueueDepth == 0 {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	rc, info, err := replicaStorage.GetObject("kyc-docs", "passport-001.jpg")
	if err != nil {
		t.Fatalf("expected missed object to be backfilled on replica: %v", err)
	}
	rc.Close()
	if info.Size != 15 {
		t.Fatalf("expected backfilled size 15, got %d", info.Size)
	}
}
