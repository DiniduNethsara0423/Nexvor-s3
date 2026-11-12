package auth

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Authenticator validates AWS SigV4 (header & presigned URL) and legacy key-based requests
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

type sigV4Params struct {
	AccessKey     string
	DateStamp     string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	AmzDate       string
	IsPresigned   bool
	Expires       int64
}

func parseSigV4Header(r *http.Request) (*sigV4Params, bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		rest := strings.TrimSpace(strings.TrimPrefix(authHeader, "AWS4-HMAC-SHA256"))
		parts := strings.Split(rest, ",")
		p := &sigV4Params{
			AmzDate: r.Header.Get("x-amz-date"),
		}
		if p.AmzDate == "" {
			p.AmzDate = r.Header.Get("Date")
		}
		for _, part := range parts {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "Credential":
				credParts := strings.Split(kv[1], "/")
				if len(credParts) >= 4 {
					p.AccessKey = credParts[0]
					p.DateStamp = credParts[1]
					p.Region = credParts[2]
					p.Service = credParts[3]
				}
			case "SignedHeaders":
				for _, h := range strings.Split(kv[1], ";") {
					if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
						p.SignedHeaders = append(p.SignedHeaders, trimmed)
					}
				}
			case "Signature":
				p.Signature = strings.TrimSpace(kv[1])
			}
		}
		return p, p.AccessKey != ""
	}

	// Check Presigned URL query parameters
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" && q.Get("X-Amz-Credential") != "" {
		credParts := strings.Split(q.Get("X-Amz-Credential"), "/")
		if len(credParts) >= 4 {
			exp, _ := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
			var sh []string
			for _, h := range strings.Split(q.Get("X-Amz-SignedHeaders"), ";") {
				if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
					sh = append(sh, trimmed)
				}
			}
			return &sigV4Params{
				AccessKey:     credParts[0],
				DateStamp:     credParts[1],
				Region:        credParts[2],
				Service:       credParts[3],
				SignedHeaders: sh,
				Signature:     strings.TrimSpace(q.Get("X-Amz-Signature")),
				AmzDate:       q.Get("X-Amz-Date"),
				IsPresigned:   true,
				Expires:       exp,
			}, true
		}
	}

	return nil, false
}

// ExtractAccessKey safely parses the access key identifier
func (a *Authenticator) ExtractAccessKey(r *http.Request) string {
	if p, ok := parseSigV4Header(r); ok {
		return p.AccessKey
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS ") {
		cred := strings.TrimPrefix(authHeader, "AWS ")
		parts := strings.Split(cred, ":")
		if len(parts) == 2 {
			return parts[0]
		}
	}
	if cred := r.URL.Query().Get("X-Amz-Credential"); cred != "" {
		parts := strings.Split(cred, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

// VerifySigV4 performs full cryptographic AWS Signature V4 validation (AWS4-HMAC-SHA256)
func (a *Authenticator) VerifySigV4(r *http.Request) (bool, string) {
	p, ok := parseSigV4Header(r)
	if !ok {
		return false, "InvalidAccessKeyId"
	}
	if subtle.ConstantTimeCompare([]byte(p.AccessKey), []byte(a.AccessKey)) != 1 {
		return false, "InvalidAccessKeyId"
	}

	// Enforce strict presigned URL bounds (max 7 days per AWS S3 spec, valid ISO8601 timestamp)
	if p.IsPresigned {
		if p.Expires <= 0 || p.Expires > 604800 || p.AmzDate == "" {
			return false, "AccessDenied"
		}
		signedAt, err := time.Parse("20060102T150405Z", p.AmzDate)
		if err != nil {
			return false, "AccessDenied"
		}
		if time.Now().UTC().After(signedAt.Add(time.Duration(p.Expires) * time.Second)) {
			return false, "AccessDenied"
		}
	}

	if len(p.Signature) != 64 {
		return false, "SignatureDoesNotMatch"
	}

	expectedSig := computeExpectedSigV4(r, p, a.SecretKey)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(p.Signature)), []byte(expectedSig)) != 1 {
		return false, "SignatureDoesNotMatch"
	}
	return true, ""
}

func computeExpectedSigV4(r *http.Request, p *sigV4Params, secretKey string) string {
	canonicalURI := r.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string (exclude X-Amz-Signature for presigned URLs, sort by parameter name)
	q := r.URL.Query()
	var keys []string
	for k := range q {
		if p.IsPresigned && k == "X-Amz-Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qp []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		ek := awsURIEncode(k, true)
		for _, v := range vals {
			qp = append(qp, ek+"="+awsURIEncode(v, true))
		}
	}
	canonicalQuery := strings.Join(qp, "&")

	// Canonical headers & signed headers
	sort.Strings(p.SignedHeaders)
	var canonHeaders strings.Builder
	for _, h := range p.SignedHeaders {
		var val string
		if h == "host" {
			val = r.Host
		} else {
			val = strings.Join(r.Header.Values(h), ",")
		}
		canonHeaders.WriteString(h)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(strings.TrimSpace(val))
		canonHeaders.WriteByte('\n')
	}
	signedHeadersStr := strings.Join(p.SignedHeaders, ";")

	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	crHash := sha256.Sum256([]byte(canonicalRequest))
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", p.DateStamp, p.Region, p.Service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		p.AmzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	kDate := ComputeHmac256([]byte(p.DateStamp), []byte("AWS4"+secretKey))
	kRegion := ComputeHmac256([]byte(p.Region), kDate)
	kService := ComputeHmac256([]byte(p.Service), kRegion)
	kSigning := ComputeHmac256([]byte("aws4_request"), kService)

	return HexHmac256([]byte(stringToSign), kSigning)
}

func awsURIEncode(s string, encodeSlash bool) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	if !encodeSlash {
		escaped = strings.ReplaceAll(escaped, "%2F", "/")
	}
	return escaped
}

// SignRequestV4 adds valid AWS4-HMAC-SHA256 authorization headers to an outgoing HTTP request (used by Async Replicator & tests)
func SignRequestV4(req *http.Request, accessKey, secretKey, region, payloadHash string) {
	if region == "" {
		region = "us-east-1"
	}
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	p := &sigV4Params{
		AccessKey:     accessKey,
		DateStamp:     dateStamp,
		Region:        region,
		Service:       "s3",
		SignedHeaders: signedHeaders,
		AmzDate:       amzDate,
	}

	sig := computeExpectedSigV4(req, p, secretKey)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request, SignedHeaders=%s, Signature=%s",
		accessKey, dateStamp, region, strings.Join(signedHeaders, ";"), sig,
	))
}

// GeneratePresignedURL builds an AWS SigV4 expiring presigned URL for secure private-bucket sharing
func GeneratePresignedURL(endpointURL, bucket, key, accessKey, secretKey, region, method string, expirySeconds int64) (string, error) {
	if region == "" {
		region = "us-east-1"
	}
	if method == "" {
		method = http.MethodGet
	}
	if expirySeconds <= 0 {
		expirySeconds = 3600
	}
	base := strings.TrimRight(endpointURL, "/")
	keySegs := strings.Split(strings.TrimPrefix(key, "/"), "/")
	for i, s := range keySegs {
		keySegs[i] = url.PathEscape(s)
	}
	rawURL := fmt.Sprintf("%s/%s/%s", base, url.PathEscape(bucket), strings.Join(keySegs, "/"))
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, dateStamp, region)

	q := parsed.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", credential)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", strconv.FormatInt(expirySeconds, 10))
	q.Set("X-Amz-SignedHeaders", "host")
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequest(method, parsed.String(), nil)
	if err != nil {
		return "", err
	}

	p := &sigV4Params{
		AccessKey:     accessKey,
		DateStamp:     dateStamp,
		Region:        region,
		Service:       "s3",
		SignedHeaders: []string{"host"},
		AmzDate:       amzDate,
		IsPresigned:   true,
		Expires:       expirySeconds,
	}
	sig := computeExpectedSigV4(req, p, secretKey)
	q.Set("X-Amz-Signature", sig)
	parsed.RawQuery = q.Encode()

	return parsed.String(), nil
}

// Authenticate verifies request credentials; enforces cryptographic SigV4 verification when AllowAnon is false
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

	// Enforce full cryptographic SigV4 verification when running in strict production mode (AllowAnon=false)
	if !a.AllowAnon {
		return a.VerifySigV4(r)
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

// AWSChunkedReader strips STREAMING-AWS4-HMAC-SHA256-PAYLOAD chunk framing transparently so boto3/Barman payloads never corrupt
type AWSChunkedReader struct {
	br        *bufio.Reader
	remaining int64
	eof       bool
}

// NewAWSChunkedReader wraps an HTTP request body using AWS chunked transfer encoding
func NewAWSChunkedReader(r io.Reader) *AWSChunkedReader {
	return &AWSChunkedReader{br: bufio.NewReaderSize(r, 64*1024)}
}

func (c *AWSChunkedReader) Read(p []byte) (int, error) {
	if c.eof {
		return 0, io.EOF
	}
	if c.remaining == 0 {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		chunkSize, err := strconv.ParseInt(line, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid aws chunk size %q: %w", line, err)
		}
		if chunkSize == 0 {
			c.eof = true
			return 0, io.EOF
		}
		c.remaining = chunkSize
	}

	toRead := int64(len(p))
	if toRead > c.remaining {
		toRead = c.remaining
	}
	n, err := c.br.Read(p[:toRead])
	c.remaining -= int64(n)

	if c.remaining == 0 && err == nil {
		// Consume trailing \r\n after chunk data
		_, _ = c.br.ReadString('\n')
	}
	return n, err
}
