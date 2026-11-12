package replication

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"my-s3/internal/auth"
	"my-s3/internal/storage"
)

type opType string

const (
	opPut    opType = "PUT"
	opDelete opType = "DELETE"
)

type event struct {
	op     opType
	bucket string
	key    string
}

// Stats holds real-time replication health metrics
type Stats struct {
	Enabled         bool   `json:"enabled"`
	TargetEndpoint  string `json:"target_endpoint,omitempty"`
	QueueDepth      int    `json:"queue_depth"`
	ReplicatedTotal int64  `json:"replicated_total"`
	DeletedTotal    int64  `json:"deleted_total"`
	FailedTotal     int64  `json:"failed_total"`
	LastError       string `json:"last_error,omitempty"`
}

// Replicator performs asynchronous S3-to-S3 cross-site replication (e.g., Cloud -> Local replica)
type Replicator struct {
	storage        *storage.DiskEngine
	targetEndpoint string
	accessKey      string
	secretKey      string
	region         string
	client         *http.Client
	queue          chan event
	maxRetries     int

	bucketsCreated sync.Map
	replicatedCnt  atomic.Int64
	deletedCnt     atomic.Int64
	failedCnt      atomic.Int64

	errMu   sync.RWMutex
	lastErr string
}

// NewReplicator creates an async replication engine; if targetEndpoint is empty, returns nil (disabled)
func NewReplicator(storage *storage.DiskEngine, targetEndpoint, accessKey, secretKey, region string) *Replicator {
	targetEndpoint = strings.TrimRight(strings.TrimSpace(targetEndpoint), "/")
	if targetEndpoint == "" {
		return nil
	}
	if region == "" {
		region = "us-east-1"
	}
	return &Replicator{
		storage:        storage,
		targetEndpoint: targetEndpoint,
		accessKey:      accessKey,
		secretKey:      secretKey,
		region:         region,
		client:         &http.Client{Timeout: 60 * time.Second},
		queue:          make(chan event, 4096),
		maxRetries:     4,
	}
}

// Start launches background worker goroutines for async non-blocking replication
// plus an initial background catch-up reconciliation pass for objects created while offline
func (r *Replicator) Start(ctx context.Context, workers int) {
	if r == nil {
		return
	}
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		go r.worker(ctx)
	}
	go r.ReconcileExisting(ctx)
}

// ReconcileExisting checks all existing local buckets/objects against the target replica
// and schedules puts for any missing or mismatched objects (disaster recovery backfill)
func (r *Replicator) ReconcileExisting(ctx context.Context) {
	if r == nil {
		return
	}
	buckets, err := r.storage.ListBuckets()
	if err != nil {
		return
	}
	for _, b := range buckets {
		if ctx.Err() != nil {
			return
		}
		res, err := r.storage.ListObjects(b.Name, "", "", "", 100000)
		if err != nil {
			continue
		}
		for _, obj := range res.Objects {
			if ctx.Err() != nil {
				return
			}
			if !r.targetHasMatchingObject(ctx, b.Name, obj.Key, obj.ETag) {
				r.EnqueuePut(b.Name, obj.Key)
			}
		}
	}
}

func (r *Replicator) targetHasMatchingObject(ctx context.Context, bucket, key, expectedETag string) bool {
	targetURL := r.targetEndpoint + "/" + url.PathEscape(bucket) + "/" + encodeS3KeyPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		return false
	}
	auth.SignRequestV4(req, r.accessKey, r.secretKey, r.region, "UNSIGNED-PAYLOAD")

	resp, err := r.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return strings.Trim(resp.Header.Get("ETag"), "\"") == strings.Trim(expectedETag, "\"")
}

// EnqueuePut schedules an uploaded or completed multipart object for async replication
func (r *Replicator) EnqueuePut(bucket, key string) {
	if r == nil {
		return
	}
	select {
	case r.queue <- event{op: opPut, bucket: bucket, key: key}:
	default:
		r.failedCnt.Add(1)
		r.setError("replication queue full; dropped put for " + bucket + "/" + key)
	}
}

// EnqueueDelete schedules an object deletion for async replication
func (r *Replicator) EnqueueDelete(bucket, key string) {
	if r == nil {
		return
	}
	select {
	case r.queue <- event{op: opDelete, bucket: bucket, key: key}:
	default:
		r.failedCnt.Add(1)
		r.setError("replication queue full; dropped delete for " + bucket + "/" + key)
	}
}

// Stats returns live replication throughput and error metrics
func (r *Replicator) Stats() Stats {
	if r == nil {
		return Stats{Enabled: false}
	}
	r.errMu.RLock()
	le := r.lastErr
	r.errMu.RUnlock()
	return Stats{
		Enabled:         true,
		TargetEndpoint:  r.targetEndpoint,
		QueueDepth:      len(r.queue),
		ReplicatedTotal: r.replicatedCnt.Load(),
		DeletedTotal:    r.deletedCnt.Load(),
		FailedTotal:     r.failedCnt.Load(),
		LastError:       le,
	}
}

func (r *Replicator) setError(msg string) {
	r.errMu.Lock()
	r.lastErr = msg
	r.errMu.Unlock()
}

func (r *Replicator) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.queue:
			r.processWithRetry(ctx, ev)
		}
	}
}

func (r *Replicator) processWithRetry(ctx context.Context, ev event) {
	backoff := 250 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return
		}
		if ev.op == opPut {
			lastErr = r.replicatePut(ctx, ev.bucket, ev.key)
		} else {
			lastErr = r.replicateDelete(ctx, ev.bucket, ev.key)
		}
		if lastErr == nil {
			if ev.op == opPut {
				r.replicatedCnt.Add(1)
			} else {
				r.deletedCnt.Add(1)
			}
			return
		}
		if attempt < r.maxRetries {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	r.failedCnt.Add(1)
	r.setError(fmt.Sprintf("%s %s/%s failed: %v", ev.op, ev.bucket, ev.key, lastErr))
	log.Printf("[Replication] ERROR: %s %s/%s failed after retries: %v", ev.op, ev.bucket, ev.key, lastErr)
}

func (r *Replicator) ensureTargetBucket(ctx context.Context, bucket string) error {
	if _, ok := r.bucketsCreated.Load(bucket); ok {
		return nil
	}
	targetURL := r.targetEndpoint + "/" + url.PathEscape(bucket)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, nil)
	if err != nil {
		return err
	}
	auth.SignRequestV4(req, r.accessKey, r.secretKey, r.region, "UNSIGNED-PAYLOAD")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		r.bucketsCreated.Store(bucket, true)
		return nil
	}
	return fmt.Errorf("create target bucket returned %d", resp.StatusCode)
}

func encodeS3KeyPath(key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func (r *Replicator) replicatePut(ctx context.Context, bucket, key string) error {
	if err := r.ensureTargetBucket(ctx, bucket); err != nil {
		return err
	}

	rc, info, err := r.storage.GetObject(bucket, key)
	if err != nil {
		return err
	}
	defer rc.Close()

	targetURL := r.targetEndpoint + "/" + url.PathEscape(bucket) + "/" + encodeS3KeyPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, rc)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size
	if info.ContentType != "" {
		req.Header.Set("Content-Type", info.ContentType)
	}
	for k, v := range info.UserMetadata {
		req.Header.Set("x-amz-meta-"+k, v)
	}

	auth.SignRequestV4(req, r.accessKey, r.secretKey, r.region, "UNSIGNED-PAYLOAD")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("target PUT returned status %d", resp.StatusCode)
	}
	return nil
}

func (r *Replicator) replicateDelete(ctx context.Context, bucket, key string) error {
	targetURL := r.targetEndpoint + "/" + url.PathEscape(bucket) + "/" + encodeS3KeyPath(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, targetURL, nil)
	if err != nil {
		return err
	}
	auth.SignRequestV4(req, r.accessKey, r.secretKey, r.region, "UNSIGNED-PAYLOAD")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("target DELETE returned status %d", resp.StatusCode)
	}
	return nil
}
