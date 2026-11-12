package api

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/erasure"
	"my-s3/internal/storage"
)

func TestEnterpriseVersioningAndWORMLock(t *testing.T) {
	tmpDir := t.TempDir()
	engine, err := storage.NewDiskEngine(tmpDir)
	if err != nil {
		t.Fatalf("engine init failed: %v", err)
	}
	handler := NewS3Handler(engine, auth.NewAuthenticator("ak", "sk", true), "")

	// 1. Create bucket with Object Lock enabled (auto-enables Versioning)
	createReq := httptest.NewRequest(http.MethodPut, "/compliance-vault", nil)
	createReq.Header.Set("x-amz-bucket-object-lock-enabled", "true")
	cw := httptest.NewRecorder()
	handler.ServeHTTP(cw, createReq)
	if cw.Code != http.StatusOK {
		t.Fatalf("create object-lock bucket failed: %d", cw.Code)
	}

	// Verify GET ?versioning & GET ?object-lock
	verW := httptest.NewRecorder()
	handler.ServeHTTP(verW, httptest.NewRequest(http.MethodGet, "/compliance-vault?versioning", nil))
	if !strings.Contains(verW.Body.String(), "<Status>Enabled</Status>") {
		t.Fatalf("expected versioning Enabled, got: %s", verW.Body.String())
	}

	// 2. Upload v1 & v2
	r1 := httptest.NewRecorder()
	handler.ServeHTTP(r1, httptest.NewRequest(http.MethodPut, "/compliance-vault/ledger.json", strings.NewReader(`{"v":1}`)))
	v1 := r1.Header().Get("x-amz-version-id")

	r2 := httptest.NewRecorder()
	handler.ServeHTTP(r2, httptest.NewRequest(http.MethodPut, "/compliance-vault/ledger.json", strings.NewReader(`{"v":2}`)))
	v2 := r2.Header().Get("x-amz-version-id")

	if v1 == "" || v2 == "" || v1 == v2 {
		t.Fatalf("expected distinct version IDs, got v1=%q v2=%q", v1, v2)
	}

	// Point-in-time read of v1
	getV1 := httptest.NewRecorder()
	handler.ServeHTTP(getV1, httptest.NewRequest(http.MethodGet, "/compliance-vault/ledger.json?versionId="+v1, nil))
	if getV1.Body.String() != `{"v":1}` {
		t.Fatalf("expected v1 content, got %q", getV1.Body.String())
	}

	// 3. Soft delete creates DeleteMarker; reading without versionId returns 404
	delSoft := httptest.NewRecorder()
	handler.ServeHTTP(delSoft, httptest.NewRequest(http.MethodDelete, "/compliance-vault/ledger.json", nil))
	dmVer := delSoft.Header().Get("x-amz-version-id")
	if delSoft.Header().Get("x-amz-delete-marker") != "true" {
		t.Fatalf("expected delete marker header")
	}

	getAfterDel := httptest.NewRecorder()
	handler.ServeHTTP(getAfterDel, httptest.NewRequest(http.MethodGet, "/compliance-vault/ledger.json", nil))
	if getAfterDel.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete marker, got %d", getAfterDel.Code)
	}

	// Delete DeleteMarker -> v2 becomes active again!
	delDM := httptest.NewRecorder()
	handler.ServeHTTP(delDM, httptest.NewRequest(http.MethodDelete, "/compliance-vault/ledger.json?versionId="+dmVer, nil))
	if delDM.Code != http.StatusNoContent {
		t.Fatalf("expected 204 deleting delete marker, got %d", delDM.Code)
	}

	getRestored := httptest.NewRecorder()
	handler.ServeHTTP(getRestored, httptest.NewRequest(http.MethodGet, "/compliance-vault/ledger.json", nil))
	if getRestored.Body.String() != `{"v":2}` {
		t.Fatalf("expected v2 restored after removing delete marker, got %q", getRestored.Body.String())
	}

	// 4. List ?versions shows both v2 (IsLatest=true) and v1 (IsLatest=false)
	lvW := httptest.NewRecorder()
	handler.ServeHTTP(lvW, httptest.NewRequest(http.MethodGet, "/compliance-vault?versions", nil))
	var lvRes ListVersionsResult
	_ = xml.NewDecoder(lvW.Body).Decode(&lvRes)
	if len(lvRes.Version) != 2 {
		t.Fatalf("expected 2 versions in ?versions, got %d", len(lvRes.Version))
	}

	// 5. Apply COMPLIANCE WORM Lock to v2 & verify deletion is strictly blocked (even with bypass header!)
	until := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	retXML, _ := xml.Marshal(ObjectRetentionXML{Mode: "COMPLIANCE", RetainUntilDate: until})
	retReq := httptest.NewRequest(http.MethodPut, "/compliance-vault/ledger.json?retention&versionId="+v2, bytes.NewReader(retXML))
	retW := httptest.NewRecorder()
	handler.ServeHTTP(retW, retReq)
	if retW.Code != http.StatusOK {
		t.Fatalf("set retention failed: %d (%s)", retW.Code, retW.Body.String())
	}

	lockedDelReq := httptest.NewRequest(http.MethodDelete, "/compliance-vault/ledger.json?versionId="+v2, nil)
	lockedDelReq.Header.Set("x-amz-bypass-governance-retention", "true")
	lockedDelW := httptest.NewRecorder()
	handler.ServeHTTP(lockedDelW, lockedDelReq)
	if lockedDelW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 AccessDenied deleting COMPLIANCE locked version, got %d", lockedDelW.Code)
	}

	// 6. Apply GOVERNANCE lock on v1: blocked normally, allowed with bypass header
	govXML, _ := xml.Marshal(ObjectRetentionXML{Mode: "GOVERNANCE", RetainUntilDate: until})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/compliance-vault/ledger.json?retention&versionId="+v1, bytes.NewReader(govXML)))

	govBlocked := httptest.NewRecorder()
	handler.ServeHTTP(govBlocked, httptest.NewRequest(http.MethodDelete, "/compliance-vault/ledger.json?versionId="+v1, nil))
	if govBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 deleting GOVERNANCE version without bypass, got %d", govBlocked.Code)
	}

	govBypassReq := httptest.NewRequest(http.MethodDelete, "/compliance-vault/ledger.json?versionId="+v1, nil)
	govBypassReq.Header.Set("x-amz-bypass-governance-retention", "true")
	govBypassW := httptest.NewRecorder()
	handler.ServeHTTP(govBypassW, govBypassReq)
	if govBypassW.Code != http.StatusNoContent {
		t.Fatalf("expected 204 deleting GOVERNANCE version with bypass header, got %d", govBypassW.Code)
	}
}

func TestEnterpriseServerSideEncryptionAndRangeSeek(t *testing.T) {
	tmpDir := t.TempDir()
	engine, _ := storage.NewDiskEngine(tmpDir)
	engine.SetMasterKMSKey("nexvor-super-kms-master-secret-2026")
	handler := NewS3Handler(engine, auth.NewAuthenticator("ak", "sk", true), "")

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/kms-vault", nil))

	// 1. Upload 160 KB payload (> 2 chunks of 64KB) -> encrypted transparently with AES-256-GCM
	plain := make([]byte, 160*1024)
	for i := range plain {
		plain[i] = byte('A' + (i % 26))
	}
	copy(plain[70000:70020], []byte("ENCRYPTED_RANGE_SEEK"))

	putReq := httptest.NewRequest(http.MethodPut, "/kms-vault/video.bin", bytes.NewReader(plain))
	putW := httptest.NewRecorder()
	handler.ServeHTTP(putW, putReq)
	if putW.Code != http.StatusOK || putW.Header().Get("x-amz-server-side-encryption") != "AES256" {
		t.Fatalf("expected encrypted upload 200 with SSE header, got %d", putW.Code)
	}

	// Verify raw file on disk does NOT contain plaintext marker!
	rawDiskBytes, err := os.ReadFile(filepath.Join(tmpDir, "buckets", "kms-vault", "data", "video.bin"))
	if err != nil {
		t.Fatalf("failed reading raw encrypted file: %v", err)
	}
	if bytes.Contains(rawDiskBytes, []byte("ENCRYPTED_RANGE_SEEK")) {
		t.Fatalf("SECURITY FAILURE: plaintext found on encrypted disk file!")
	}

	// Verify HTTP 206 Range Seek across 64KB chunk boundary (bytes 70000-70019)
	rangeReq := httptest.NewRequest(http.MethodGet, "/kms-vault/video.bin", nil)
	rangeReq.Header.Set("Range", "bytes=70000-70019")
	rangeW := httptest.NewRecorder()
	handler.ServeHTTP(rangeW, rangeReq)
	if rangeW.Code != http.StatusPartialContent || rangeW.Body.String() != "ENCRYPTED_RANGE_SEEK" {
		t.Fatalf("expected 206 ENCRYPTED_RANGE_SEEK, got %d (%q)", rangeW.Code, rangeW.Body.String())
	}

	// 2. SSE-C Customer-Provided Key test
	custKey := make([]byte, 32)
	_, _ = rand.Read(custKey)
	custKeyB64 := base64.StdEncoding.EncodeToString(custKey)
	md5Sum := md5.Sum(custKey)
	custMD5B64 := base64.StdEncoding.EncodeToString(md5Sum[:])

	ssecPut := httptest.NewRequest(http.MethodPut, "/kms-vault/kyc.txt", strings.NewReader("top-secret-passport"))
	ssecPut.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	ssecPut.Header.Set("x-amz-server-side-encryption-customer-key", custKeyB64)
	ssecPut.Header.Set("x-amz-server-side-encryption-customer-key-MD5", custMD5B64)
	ssecPutW := httptest.NewRecorder()
	handler.ServeHTTP(ssecPutW, ssecPut)
	if ssecPutW.Code != http.StatusOK {
		t.Fatalf("SSE-C upload failed: %d (%s)", ssecPutW.Code, ssecPutW.Body.String())
	}

	// Reading SSE-C object without key fails (400 InvalidRequest)
	noKeyW := httptest.NewRecorder()
	handler.ServeHTTP(noKeyW, httptest.NewRequest(http.MethodGet, "/kms-vault/kyc.txt", nil))
	if noKeyW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when reading SSE-C object without customer key, got %d", noKeyW.Code)
	}

	// Reading with correct key succeeds!
	ssecGet := httptest.NewRequest(http.MethodGet, "/kms-vault/kyc.txt", nil)
	ssecGet.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	ssecGet.Header.Set("x-amz-server-side-encryption-customer-key", custKeyB64)
	ssecGet.Header.Set("x-amz-server-side-encryption-customer-key-MD5", custMD5B64)
	ssecGetW := httptest.NewRecorder()
	handler.ServeHTTP(ssecGetW, ssecGet)
	if ssecGetW.Code != http.StatusOK || ssecGetW.Body.String() != "top-secret-passport" {
		t.Fatalf("SSE-C decrypt failed: %d (%q)", ssecGetW.Code, ssecGetW.Body.String())
	}
}

func TestEnterpriseLifecycleExpiryAndIAMPolicies(t *testing.T) {
	tmpDir := t.TempDir()
	engine, _ := storage.NewDiskEngine(tmpDir)
	policies := auth.NewPolicyEngine(tmpDir)
	handler := NewS3Handler(engine, auth.NewAuthenticator("root-ak", "root-sk", false), "")
	handler.SetPolicyEngine(policies)

	// Helper to make SigV4 request
	signed := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Host = "localhost:9000"
		auth.SignRequestV4(req, "root-ak", "root-sk", "us-east-1", "UNSIGNED-PAYLOAD")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	if w := signed(http.MethodPut, "/policy-bucket", nil); w.Code != http.StatusOK {
		t.Fatalf("create bucket failed: %d", w.Code)
	}

	signed(http.MethodPut, "/policy-bucket/public/logo.png", []byte("PNG_DATA"))
	signed(http.MethodPut, "/policy-bucket/public/protected.txt", []byte("IMMUTABLE_BY_POLICY"))
	signed(http.MethodPut, "/policy-bucket/private/wallet.db", []byte("PRIVATE_WALLET"))

	// 1. Attach AWS IAM JSON Bucket Policy:
	//    Allow anonymous GET on public/*
	//    Explicitly DENY DeleteObject on public/protected.txt (even for root!)
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "PublicRead",
				"Effect": "Allow",
				"Principal": "*",
				"Action": ["s3:GetObject"],
				"Resource": ["arn:aws:s3:::policy-bucket/public/*"]
			},
			{
				"Sid": "ProtectCriticalFile",
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:DeleteObject",
				"Resource": "arn:aws:s3:::policy-bucket/public/protected.txt"
			}
		]
	}`
	if w := signed(http.MethodPut, "/policy-bucket?policy", []byte(policyJSON)); w.Code != http.StatusNoContent {
		t.Fatalf("PUT ?policy failed: %d (%s)", w.Code, w.Body.String())
	}

	// Anonymous GET on public/logo.png succeeds even though AllowAnon=false!
	anonPub := httptest.NewRecorder()
	handler.ServeHTTP(anonPub, httptest.NewRequest(http.MethodGet, "/policy-bucket/public/logo.png", nil))
	if anonPub.Code != http.StatusOK || anonPub.Body.String() != "PNG_DATA" {
		t.Fatalf("expected anonymous public read 200, got %d", anonPub.Code)
	}

	// Anonymous GET on private/wallet.db blocked (403)
	anonPriv := httptest.NewRecorder()
	handler.ServeHTTP(anonPriv, httptest.NewRequest(http.MethodGet, "/policy-bucket/private/wallet.db", nil))
	if anonPriv.Code != http.StatusForbidden {
		t.Fatalf("expected anonymous private read 403, got %d", anonPriv.Code)
	}

	// Authenticated root DELETE on protected.txt blocked by explicit Deny!
	if w := signed(http.MethodDelete, "/policy-bucket/public/protected.txt", nil); w.Code != http.StatusForbidden {
		t.Fatalf("expected explicit Deny to block delete even for root, got %d", w.Code)
	}

	// 2. Lifecycle Auto-Expiry rule (?lifecycle)
	lcXML, _ := xml.Marshal(storage.LifecycleConfigurationXML{
		Rule: []storage.LifecycleRule{
			{
				ID:         "expire-public",
				Prefix:     "public/",
				Status:     "Enabled",
				Expiration: &storage.LifecycleExpiration{Days: 7},
			},
		},
	})
	if w := signed(http.MethodPut, "/policy-bucket?lifecycle", lcXML); w.Code != http.StatusOK {
		t.Fatalf("PUT ?lifecycle failed: %d (%s)", w.Code, w.Body.String())
	}

	// Set Legal Hold on protected.txt so lifecycle skips it, while logo.png expires
	_ = engine.SetObjectLegalHold("policy-bucket", "public/protected.txt", "", "ON")

	purged := engine.SweepExpiredObjects(time.Now().UTC().Add(8 * 24 * time.Hour))
	if purged != 1 {
		t.Fatalf("expected exactly 1 object (logo.png) expired by lifecycle while skipping legal-hold protected.txt, got %d", purged)
	}

	if _, err := engine.HeadObject("policy-bucket", "public/logo.png"); err != storage.ErrObjectNotFound {
		t.Errorf("expected expired logo.png to be deleted")
	}
	if _, err := engine.HeadObject("policy-bucket", "public/protected.txt"); err != nil {
		t.Errorf("expected legal-hold protected.txt to survive lifecycle sweep, got %v", err)
	}
}

func TestEnterpriseReedSolomonErasureAndSelfHeal(t *testing.T) {
	tmpDir := t.TempDir()
	drives := make([]string, 6)
	for i := 0; i < 6; i++ {
		drives[i] = filepath.Join(tmpDir, "disk", string(rune('0'+i)))
	}

	// 4 Data + 2 Parity = survives losing ANY 2 drives simultaneously!
	ecStore, err := erasure.NewMultiDriveStore(drives, 4, 2)
	if err != nil {
		t.Fatalf("failed to create MultiDriveStore: %v", err)
	}

	engine, _ := storage.NewDiskEngine(tmpDir)
	engine.SetErasureStore(ecStore)
	handler := NewS3Handler(engine, auth.NewAuthenticator("ak", "sk", true), "")

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/ec-bucket", nil))

	original := bytes.Repeat([]byte("ARRAKAPAY_EC_LEDGER_BLOCK_"), 500)
	putW := httptest.NewRecorder()
	handler.ServeHTTP(putW, httptest.NewRequest(http.MethodPut, "/ec-bucket/ledger.dat", bytes.NewReader(original)))
	if putW.Code != http.StatusOK {
		t.Fatalf("PUT failed: %d", putW.Code)
	}

	// Simulate catastrophic failure:
	// 1. Delete primary data file (forces erasure recovery)
	_ = os.Remove(filepath.Join(tmpDir, "buckets", "ec-bucket", "data", "ledger.dat"))
	// 2. Wipe Drive 0 completely AND corrupt Drive 2 with bit-rot!
	_ = os.RemoveAll(drives[0])
	_ = os.WriteFile(filepath.Join(drives[2], "ec-bucket", "ledger.dat", "part.2"), []byte("CORRUPTED_BITROT"), 0644)

	// GET reconstructs original bytes identically via GF(2^8) Reed-Solomon & self-heals drives!
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, httptest.NewRequest(http.MethodGet, "/ec-bucket/ledger.dat", nil))
	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK recovered from RS erasure parity, got %d (%s)", getW.Code, getW.Body.String())
	}
	if !bytes.Equal(getW.Body.Bytes(), original) {
		t.Fatalf("Reed-Solomon reconstructed bytes do not match original!")
	}

	// Verify Drive 0 shard was self-healed back onto disk
	if _, err := os.Stat(filepath.Join(drives[0], "ec-bucket", "ledger.dat", "part.0")); err != nil {
		t.Errorf("expected Drive 0 shard to be self-healed automatically, got %v", err)
	}
}
