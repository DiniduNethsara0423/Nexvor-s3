package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// PlainBlockSize is 64 KB per chunk, matching high-throughput streaming while keeping Range seeks O(1)
	PlainBlockSize = 64 * 1024
	NonceSize      = 12
	TagSize        = 16
	EncBlockSize   = NonceSize + PlainBlockSize + TagSize
)

var (
	ErrWrongCustomerKey  = errors.New("the customer-provided encryption key does not match")
	ErrMissingCustomerKey = errors.New("object is encrypted with SSE-C: customer key required")
	ErrTamperedCiphertext = errors.New("aes-256-gcm authentication failed: ciphertext corrupted or tampered")
)

// DeriveMasterObjectKey derives a unique 32-byte AES-256 key per object from a KMS master secret and object metadata
func DeriveMasterObjectKey(masterSecret, bucket, key string) []byte {
	h := hmac.New(sha256.New, []byte(masterSecret))
	h.Write([]byte("nexvor-sse-s3-v1:"))
	h.Write([]byte(bucket))
	h.Write([]byte("/"))
	h.Write([]byte(key))
	return h.Sum(nil) // 32 bytes (AES-256)
}

// ParseCustomerKey validates and decodes base64 SSE-C headers (returns raw 32-byte key + expected base64 MD5)
func ParseCustomerKey(algo, keyB64, md5B64 string) ([]byte, string, error) {
	if !strings.EqualFold(strings.TrimSpace(algo), "AES256") {
		return nil, "", errors.New("unsupported SSE-C algorithm (must be AES256)")
	}
	rawKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil || len(rawKey) != 32 {
		return nil, "", errors.New("SSE-C key must be base64-encoded 32 bytes (256-bit AES)")
	}
	actualSum := md5.Sum(rawKey)
	actualMD5B64 := base64.StdEncoding.EncodeToString(actualSum[:])
	if md5B64 != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(md5B64)), []byte(actualMD5B64)) != 1 {
		return nil, "", errors.New("SSE-C customer key MD5 mismatch")
	}
	return rawKey, actualMD5B64, nil
}

// EncryptStream seals plaintext into 64KB chunked AES-256-GCM frames, returning total plaintext bytes written
func EncryptStream(dst io.Writer, src io.Reader, key []byte) (int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	plainBuf := make([]byte, PlainBlockSize)
	aad := make([]byte, 8)
	var totalPlain int64
	var blockIndex uint64

	for {
		n, readErr := io.ReadFull(src, plainBuf)
		if n > 0 {
			nonce := make([]byte, NonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return totalPlain, err
			}
			binary.BigEndian.PutUint64(aad, blockIndex)

			sealed := gcm.Seal(nil, nonce, plainBuf[:n], aad)
			if _, err := dst.Write(nonce); err != nil {
				return totalPlain, err
			}
			if _, err := dst.Write(sealed); err != nil {
				return totalPlain, err
			}
			totalPlain += int64(n)
			blockIndex++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return totalPlain, readErr
		}
	}
	return totalPlain, nil
}

// ChunkedDecryptReadSeeker provides O(1) random-access Seek() & HTTP 206 Range streaming over 64KB AES-256-GCM encrypted files
type ChunkedDecryptReadSeeker struct {
	file      *os.File
	gcm       cipher.AEAD
	plainSize int64
	encSize   int64
	pos       int64

	cachedIdx int64
	cachedBuf []byte
}

// NewChunkedDecryptReadSeeker wraps an encrypted os.File for seekable AES-256-GCM decryption
func NewChunkedDecryptReadSeeker(f *os.File, key []byte, plainSize int64) (*ChunkedDecryptReadSeeker, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	rs := &ChunkedDecryptReadSeeker{
		file:      f,
		gcm:       gcm,
		plainSize: plainSize,
		encSize:   fi.Size(),
		cachedIdx: -1,
	}
	if plainSize > 0 {
		// Pre-authenticate and warm-cache block 0 so wrong SSE keys or corrupted headers fail before HTTP 200 is sent
		if _, err := rs.loadBlock(0); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

func (r *ChunkedDecryptReadSeeker) loadBlock(blockIdx int64) ([]byte, error) {
	if r.cachedIdx == blockIdx && r.cachedBuf != nil {
		return r.cachedBuf, nil
	}

	diskOffset := blockIdx * EncBlockSize
	if diskOffset >= r.encSize {
		return nil, io.EOF
	}
	toRead := EncBlockSize
	if diskOffset+int64(toRead) > r.encSize {
		toRead = int(r.encSize - diskOffset)
	}
	if toRead <= NonceSize+TagSize {
		return nil, ErrTamperedCiphertext
	}

	frame := make([]byte, toRead)
	if _, err := r.file.ReadAt(frame, diskOffset); err != nil && err != io.EOF {
		return nil, err
	}

	nonce := frame[:NonceSize]
	ciphertext := frame[NonceSize:]
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(blockIdx))

	plain, err := r.gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrTamperedCiphertext
	}

	r.cachedIdx = blockIdx
	r.cachedBuf = plain
	return plain, nil
}

func (r *ChunkedDecryptReadSeeker) Read(p []byte) (int, error) {
	if r.pos >= r.plainSize {
		return 0, io.EOF
	}

	totalRead := 0
	for totalRead < len(p) && r.pos < r.plainSize {
		blockIdx := r.pos / PlainBlockSize
		blockOff := int(r.pos % PlainBlockSize)

		plain, err := r.loadBlock(blockIdx)
		if err != nil {
			if totalRead > 0 && err == io.EOF {
				return totalRead, nil
			}
			return totalRead, err
		}

		avail := len(plain) - blockOff
		if avail <= 0 {
			return totalRead, io.EOF
		}
		n := copy(p[totalRead:], plain[blockOff:])
		totalRead += n
		r.pos += int64(n)
	}
	return totalRead, nil
}

func (r *ChunkedDecryptReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = r.pos + offset
	case io.SeekEnd:
		target = r.plainSize + offset
	default:
		return 0, fmt.Errorf("invalid seek whence %d", whence)
	}
	if target < 0 {
		return 0, errors.New("negative seek position")
	}
	r.pos = target
	return r.pos, nil
}

func (r *ChunkedDecryptReadSeeker) Close() error {
	return r.file.Close()
}
