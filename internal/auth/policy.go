package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// StringOrSlice unmarshals an AWS IAM field that may be either a single string or a JSON string array
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringOrSlice{single}
		return nil
	}
	var slice []string
	if err := json.Unmarshal(data, &slice); err == nil {
		*s = slice
		return nil
	}
	// Handle {"AWS": "..."} Principal object form
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err == nil {
		for _, rawVal := range obj {
			var inner StringOrSlice
			if err := json.Unmarshal(rawVal, &inner); err == nil {
				*s = append(*s, inner...)
			}
		}
		return nil
	}
	return errors.New("expected string, string array, or Principal map")
}

// Statement represents a single AWS IAM policy statement
type Statement struct {
	Sid       string        `json:"Sid,omitempty"`
	Effect    string        `json:"Effect"` // "Allow" or "Deny"
	Principal StringOrSlice `json:"Principal,omitempty"`
	Action    StringOrSlice `json:"Action"`
	Resource  StringOrSlice `json:"Resource"`
}

// IAMPolicy represents a standard AWS IAM JSON Policy Document
type IAMPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// PolicyEngine persists and evaluates AWS IAM JSON bucket & user policies
type PolicyEngine struct {
	mu             sync.RWMutex
	baseDir        string
	bucketPolicies map[string]*IAMPolicy
	userPolicies   map[string]*IAMPolicy
}

// NewPolicyEngine initializes IAM JSON policy storage
func NewPolicyEngine(baseDir string) *PolicyEngine {
	pe := &PolicyEngine{
		baseDir:        baseDir,
		bucketPolicies: make(map[string]*IAMPolicy),
		userPolicies:   make(map[string]*IAMPolicy),
	}
	pe.loadExisting()
	return pe
}

func (pe *PolicyEngine) loadExisting() {
	if pe.baseDir == "" {
		return
	}
	bucketsDir := filepath.Join(pe.baseDir, "buckets")
	entries, err := os.ReadDir(bucketsDir)
	if err == nil {
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			pPath := filepath.Join(bucketsDir, ent.Name(), "policy.json")
			if b, err := os.ReadFile(pPath); err == nil {
				var pol IAMPolicy
				if json.Unmarshal(b, &pol) == nil {
					pe.bucketPolicies[ent.Name()] = &pol
				}
			}
		}
	}
	usersPath := filepath.Join(pe.baseDir, "user_policies.json")
	if b, err := os.ReadFile(usersPath); err == nil {
		_ = json.Unmarshal(b, &pe.userPolicies)
	}
}

// SetBucketPolicy parses, validates, and stores an AWS IAM JSON Bucket Policy
func (pe *PolicyEngine) SetBucketPolicy(bucket string, rawJSON []byte) error {
	var pol IAMPolicy
	if err := json.Unmarshal(rawJSON, &pol); err != nil {
		return fmt.Errorf("malformed policy JSON: %w", err)
	}
	if len(pol.Statement) == 0 {
		return errors.New("policy must contain at least one Statement")
	}
	for i, st := range pol.Statement {
		if !strings.EqualFold(st.Effect, "Allow") && !strings.EqualFold(st.Effect, "Deny") {
			return fmt.Errorf("statement %d has invalid Effect %q", i, st.Effect)
		}
		if len(st.Action) == 0 || len(st.Resource) == 0 {
			return fmt.Errorf("statement %d must specify Action and Resource", i)
		}
	}

	pe.mu.Lock()
	pe.bucketPolicies[bucket] = &pol
	pe.mu.Unlock()

	if pe.baseDir != "" {
		pPath := filepath.Join(pe.baseDir, "buckets", bucket, "policy.json")
		_ = os.MkdirAll(filepath.Dir(pPath), 0755)
		b, _ := json.MarshalIndent(pol, "", "  ")
		return os.WriteFile(pPath, b, 0644)
	}
	return nil
}

// GetBucketPolicy retrieves raw JSON of a bucket policy
func (pe *PolicyEngine) GetBucketPolicy(bucket string) ([]byte, bool) {
	pe.mu.RLock()
	pol, ok := pe.bucketPolicies[bucket]
	pe.mu.RUnlock()
	if !ok || pol == nil {
		return nil, false
	}
	b, _ := json.MarshalIndent(pol, "", "  ")
	return b, true
}

// DeleteBucketPolicy removes a bucket policy
func (pe *PolicyEngine) DeleteBucketPolicy(bucket string) {
	pe.mu.Lock()
	delete(pe.bucketPolicies, bucket)
	pe.mu.Unlock()
	if pe.baseDir != "" {
		_ = os.Remove(filepath.Join(pe.baseDir, "buckets", bucket, "policy.json"))
	}
}

// SetUserPolicy attaches an IAM JSON policy to a non-root AccessKey
func (pe *PolicyEngine) SetUserPolicy(accessKey string, pol *IAMPolicy) {
	pe.mu.Lock()
	pe.userPolicies[accessKey] = pol
	if pe.baseDir != "" {
		b, _ := json.MarshalIndent(pe.userPolicies, "", "  ")
		_ = os.WriteFile(filepath.Join(pe.baseDir, "user_policies.json"), b, 0600)
	}
	pe.mu.Unlock()
}

// matchGlob supports AWS IAM `*` and `?` wildcards
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	pi, vi := 0, 0
	starIdx, matchIdx := -1, 0
	for vi < len(value) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]) {
			pi++
			vi++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = vi
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			vi = matchIdx
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if matchGlob(p, value) {
			return true
		}
	}
	return false
}

// MapRequestToS3Action converts an HTTP method/path/query into standard AWS S3 Action string
func MapRequestToS3Action(r *http.Request, bucket, key string) string {
	q := r.URL.Query()
	if key == "" {
		if _, ok := q["policy"]; ok {
			switch r.Method {
			case http.MethodGet:
				return "s3:GetBucketPolicy"
			case http.MethodPut:
				return "s3:PutBucketPolicy"
			case http.MethodDelete:
				return "s3:DeleteBucketPolicy"
			}
		}
		if _, ok := q["lifecycle"]; ok {
			switch r.Method {
			case http.MethodGet:
				return "s3:GetLifecycleConfiguration"
			case http.MethodPut, http.MethodDelete:
				return "s3:PutLifecycleConfiguration"
			}
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return "s3:ListBucket"
		case http.MethodPut:
			return "s3:CreateBucket"
		case http.MethodDelete:
			return "s3:DeleteBucket"
		case http.MethodPost:
			return "s3:DeleteObject"
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return "s3:GetObject"
	case http.MethodPut, http.MethodPost:
		return "s3:PutObject"
	case http.MethodDelete:
		return "s3:DeleteObject"
	}
	return "s3:*"
}

// Evaluate determines if (principal, action, resourceARN) is allowed.
// Explicit Deny ALWAYS overrides Allow.
// If isRoot=true, allowed unless an explicit Deny matches.
// If isAnonymous=true, allowed only if BucketPolicy has a matching Allow with Principal="*".
func (pe *PolicyEngine) Evaluate(bucket, key, principal, action string, isRoot, isAnonymous bool) bool {
	if pe == nil {
		return !isAnonymous
	}

	resourceARN := "arn:aws:s3:::" + bucket
	if key != "" {
		resourceARN += "/" + key
	}

	pe.mu.RLock()
	bPol := pe.bucketPolicies[bucket]
	uPol := pe.userPolicies[principal]
	pe.mu.RUnlock()

	explicitAllow := false

	checkPol := func(pol *IAMPolicy, checkPrincipal bool) (denied bool, allowed bool) {
		if pol == nil {
			return false, false
		}
		for _, st := range pol.Statement {
			if checkPrincipal && len(st.Principal) > 0 {
				if !matchAny(st.Principal, principal) {
					continue
				}
			}
			if !matchAny(st.Action, action) || !matchAny(st.Resource, resourceARN) {
				continue
			}
			if strings.EqualFold(st.Effect, "Deny") {
				return true, false
			}
			if strings.EqualFold(st.Effect, "Allow") {
				allowed = true
			}
		}
		return false, allowed
	}

	if denied, allow := checkPol(bPol, true); denied {
		return false
	} else if allow {
		explicitAllow = true
	}

	if denied, allow := checkPol(uPol, false); denied {
		return false
	} else if allow {
		explicitAllow = true
	}

	if isRoot {
		return true
	}
	if isAnonymous {
		return explicitAllow
	}
	if uPol != nil {
		return explicitAllow
	}
	return true
}
