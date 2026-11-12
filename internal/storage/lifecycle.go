package storage

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrLifecycleNotFound = errors.New("the lifecycle configuration does not exist")

// LifecycleFilter supports modern S3 <Filter><Prefix>...</Prefix></Filter> XML
type LifecycleFilter struct {
	Prefix string `xml:"Prefix,omitempty" json:"prefix,omitempty"`
}

// LifecycleExpiration specifies days until current object expiration
type LifecycleExpiration struct {
	Days int `xml:"Days,omitempty" json:"days,omitempty"`
}

// NoncurrentExpiration specifies days until historical versions expire
type NoncurrentExpiration struct {
	NoncurrentDays int `xml:"NoncurrentDays,omitempty" json:"noncurrent_days,omitempty"`
}

// LifecycleRule represents a single S3 bucket ILM auto-expiry rule
type LifecycleRule struct {
	ID                         string                `xml:"ID,omitempty" json:"id,omitempty"`
	Prefix                     string                `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Filter                     *LifecycleFilter      `xml:"Filter,omitempty" json:"filter,omitempty"`
	Status                     string                `xml:"Status" json:"status"` // "Enabled" or "Disabled"
	Expiration                 *LifecycleExpiration  `xml:"Expiration,omitempty" json:"expiration,omitempty"`
	NoncurrentVersionExpiration *NoncurrentExpiration `xml:"NoncurrentVersionExpiration,omitempty" json:"noncurrent_version_expiration,omitempty"`
}

// EffectivePrefix normalizes legacy <Prefix> and modern <Filter><Prefix>
func (r LifecycleRule) EffectivePrefix() string {
	if r.Filter != nil && r.Filter.Prefix != "" {
		return r.Filter.Prefix
	}
	return r.Prefix
}

// LifecycleConfigurationXML models AWS S3 <LifecycleConfiguration> XML
type LifecycleConfigurationXML struct {
	XMLName xml.Name        `xml:"LifecycleConfiguration"`
	Xmlns   string          `xml:"xmlns,attr,omitempty"`
	Rule    []LifecycleRule `xml:"Rule"`
}

func (e *DiskEngine) lifecyclePath(bucket string) string {
	return filepath.Join(e.bucketPath(bucket), "lifecycle.json")
}

// GetBucketLifecycle loads a bucket's ILM rules
func (e *DiskEngine) GetBucketLifecycle(bucket string) ([]LifecycleRule, error) {
	e.bucketMu.RLock()
	defer e.bucketMu.RUnlock()

	if !e.bucketExistsLocked(bucket) {
		return nil, ErrBucketNotFound
	}
	b, err := os.ReadFile(e.lifecyclePath(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrLifecycleNotFound
		}
		return nil, err
	}
	var rules []LifecycleRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// SetBucketLifecycle persists S3 lifecycle auto-expiry rules
func (e *DiskEngine) SetBucketLifecycle(bucket string, rules []LifecycleRule) error {
	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}
	b, _ := json.MarshalIndent(rules, "", "  ")
	return os.WriteFile(e.lifecyclePath(bucket), b, 0644)
}

// DeleteBucketLifecycle removes lifecycle rules from a bucket
func (e *DiskEngine) DeleteBucketLifecycle(bucket string) error {
	e.bucketMu.Lock()
	defer e.bucketMu.Unlock()

	if !e.bucketExistsLocked(bucket) {
		return ErrBucketNotFound
	}
	_ = os.Remove(e.lifecyclePath(bucket))
	return nil
}

// SweepExpiredObjects evaluates all Enabled lifecycle rules against current time `now`
// and safely removes expired items (respecting WORM retention & legal hold locks)
func (e *DiskEngine) SweepExpiredObjects(now time.Time) int {
	buckets, err := e.ListBuckets()
	if err != nil {
		return 0
	}

	purged := 0
	for _, b := range buckets {
		rules, err := e.GetBucketLifecycle(b.Name)
		if err != nil || len(rules) == 0 {
			continue
		}

		versions, err := e.ListObjectVersions(b.Name, "")
		if err != nil {
			continue
		}

		for _, ver := range versions {
			for _, rule := range rules {
				if !strings.EqualFold(rule.Status, "Enabled") {
					continue
				}
				pfx := rule.EffectivePrefix()
				if pfx != "" && !strings.HasPrefix(ver.Key, pfx) {
					continue
				}

				shouldDelete := false
				if ver.IsLatest && !ver.IsDeleteMarker && rule.Expiration != nil && rule.Expiration.Days > 0 {
					cutoff := now.Add(-time.Duration(rule.Expiration.Days) * 24 * time.Hour)
					if !ver.LastModified.After(cutoff) {
						shouldDelete = true
					}
				} else if !ver.IsLatest && rule.NoncurrentVersionExpiration != nil && rule.NoncurrentVersionExpiration.NoncurrentDays > 0 {
					cutoff := now.Add(-time.Duration(rule.NoncurrentVersionExpiration.NoncurrentDays) * 24 * time.Hour)
					if !ver.LastModified.After(cutoff) {
						shouldDelete = true
					}
				}

				if shouldDelete {
					vID := ver.VersionID
					if vID == "null" {
						vID = ""
					}
					if _, _, delErr := e.DeleteObjectVersion(b.Name, ver.Key, vID, false); delErr == nil {
						purged++
					}
					break
				}
			}
		}
	}
	return purged
}

// StartLifecycleSweeper launches a background goroutine to periodically expire old objects
func (e *DiskEngine) StartLifecycleSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.SweepExpiredObjects(time.Now().UTC())
			}
		}
	}()
}
