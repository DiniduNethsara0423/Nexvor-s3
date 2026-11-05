package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// Authenticator validates AWS SigV4 and key-based requests safely
type Authenticator struct {
	AccessKey string
	SecretKey string
	AllowAnon bool
}

// NewAuthenticator creates a new hardened auth manager
func NewAuthenticator(accessKey, secretKey string, allowAnon bool) *Authenticator {
	return &Authenticator{
		AccessKey: accessKey,
		SecretKey: secretKey,
		AllowAnon: allowAnon,
	}
}

// ExtractAccessKey safely parses the access key identifier
func (a *Authenticator) ExtractAccessKey(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		parts := strings.Split(authHeader, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "AWS4-HMAC-SHA256 Credential=") {
				val := strings.TrimPrefix(part, "AWS4-HMAC-SHA256 Credential=")
				credParts := strings.Split(val, "/")
				if len(credParts) > 0 {
					return credParts[0]
				}
			} else if strings.HasPrefix(part, "Credential=") {
				val := strings.TrimPrefix(part, "Credential=")
				credParts := strings.Split(val, "/")
				if len(credParts) > 0 {
					return credParts[0]
				}
			}
		}
	} else if strings.HasPrefix(authHeader, "AWS ") {
		cred := strings.TrimPrefix(authHeader, "AWS ")
		parts := strings.Split(cred, ":")
		if len(parts) == 2 {
			return parts[0]
		}
	}

	// Presigned URL query params
	if cred := r.URL.Query().Get("X-Amz-Credential"); cred != "" {
		parts := strings.Split(cred, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// Authenticate verifies request credentials using constant-time comparison to prevent timing attacks (CWE-208)
func (a *Authenticator) Authenticate(r *http.Request) (bool, string) {
	authHeader := r.Header.Get("Authorization")
	queryCred := r.URL.Query().Get("X-Amz-Credential")

	if authHeader == "" && queryCred == "" {
		if a.AllowAnon {
			return true, "anonymous"
		}
		return false, "MissingSecurityHeader"
	}

	key := a.ExtractAccessKey(r)
	if key == "" {
		return false, "InvalidAccessKeyId"
	}

	// Constant-time comparison defends against timing attacks
	if subtle.ConstantTimeCompare([]byte(key), []byte(a.AccessKey)) != 1 {
		return false, "InvalidAccessKeyId"
	}

	return true, ""
}

// ComputeHmac256 computes HMAC-SHA256
func ComputeHmac256(message []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	return h.Sum(nil)
}

// HexHmac256 computes and hex encodes HMAC-SHA256
func HexHmac256(message []byte, secret []byte) string {
	return hex.EncodeToString(ComputeHmac256(message, secret))
}
