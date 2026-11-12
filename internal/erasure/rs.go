package erasure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrTooFewShards    = errors.New("insufficient healthy shards to reconstruct data")
	ErrInvalidECConfig = errors.New("dataShards and parityShards must be > 0 and total <= 255")
)

// GF(2^8) primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("gf256 division by zero")
	}
	if a == 0 {
		return 0
	}
	diff := int(gfLog[a]) - int(gfLog[b])
	if diff < 0 {
		diff += 255
	}
	return gfExp[diff]
}

// buildEncodingMatrix constructs an (D+P)xD systematic matrix whose top D rows form the Identity matrix
// and bottom P rows form a Cauchy matrix over GF(2^8) (guarantees every DxD submatrix is invertible!).
func buildEncodingMatrix(d, p int) ([][]byte, error) {
	if d <= 0 || p <= 0 || d+p > 255 {
		return nil, ErrInvalidECConfig
	}
	total := d + p
	mat := make([][]byte, total)
	for r := 0; r < d; r++ {
		mat[r] = make([]byte, d)
		mat[r][r] = 1
	}
	// Systematic Cauchy parity rows: A[r][c] = 1 / (x_r ^ y_c) where x_r in [0..p-1], y_c in [p..p+d-1]
	for r := 0; r < p; r++ {
		row := make([]byte, d)
		for c := 0; c < d; c++ {
			xr := byte(r)
			yc := byte(p + c)
			row[c] = gfDiv(1, xr^yc)
		}
		mat[d+r] = row
	}
	return mat, nil
}

func invertMatrixGF(m [][]byte) ([][]byte, error) {
	n := len(m)
	aug := make([][]byte, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]byte, 2*n)
		copy(aug[i][:n], m[i])
		aug[i][n+i] = 1
	}

	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if aug[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot == -1 {
			return nil, errors.New("singular matrix")
		}
		if pivot != col {
			aug[col], aug[pivot] = aug[pivot], aug[col]
		}

		inv := gfDiv(1, aug[col][col])
		for c := 0; c < 2*n; c++ {
			aug[col][c] = gfMul(aug[col][c], inv)
		}

		for r := 0; r < n; r++ {
			if r == col || aug[r][col] == 0 {
				continue
			}
			factor := aug[r][col]
			for c := 0; c < 2*n; c++ {
				aug[r][c] ^= gfMul(factor, aug[col][c])
			}
		}
	}

	res := make([][]byte, n)
	for i := 0; i < n; i++ {
		res[i] = make([]byte, n)
		copy(res[i], aug[i][n:])
	}
	return res, nil
}

// SplitEncode splits data into D equal data shards and computes P Reed-Solomon parity shards
func SplitEncode(data []byte, dataShards, parityShards int) ([][]byte, int, error) {
	mat, err := buildEncodingMatrix(dataShards, parityShards)
	if err != nil {
		return nil, 0, err
	}

	shardSize := (len(data) + dataShards - 1) / dataShards
	if shardSize == 0 {
		shardSize = 1
	}

	total := dataShards + parityShards
	shards := make([][]byte, total)
	for i := 0; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}

	for i := 0; i < dataShards; i++ {
		start := i * shardSize
		if start < len(data) {
			end := start + shardSize
			if end > len(data) {
				end = len(data)
			}
			copy(shards[i], data[start:end])
		}
	}

	for pIdx := 0; pIdx < parityShards; pIdx++ {
		row := mat[dataShards+pIdx]
		out := shards[dataShards+pIdx]
		for dIdx := 0; dIdx < dataShards; dIdx++ {
			coeff := row[dIdx]
			if coeff == 0 {
				continue
			}
			in := shards[dIdx]
			for b := 0; b < shardSize; b++ {
				out[b] ^= gfMul(coeff, in[b])
			}
		}
	}

	return shards, shardSize, nil
}

// Reconstruct heals missing (nil) shards using any D surviving shards and returns original data truncated to origSize
func Reconstruct(shards [][]byte, dataShards, parityShards int, origSize int64) ([]byte, error) {
	mat, err := buildEncodingMatrix(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	total := dataShards + parityShards
	if len(shards) != total {
		return nil, fmt.Errorf("expected %d shards, got %d", total, len(shards))
	}

	var validIndices []int
	shardSize := 0
	for i, s := range shards {
		if s != nil {
			validIndices = append(validIndices, i)
			if shardSize == 0 {
				shardSize = len(s)
			}
		}
	}
	if len(validIndices) < dataShards || shardSize == 0 {
		return nil, ErrTooFewShards
	}

	// Pick first D healthy shards to invert submatrix
	selected := validIndices[:dataShards]
	subMat := make([][]byte, dataShards)
	for i, idx := range selected {
		subMat[i] = mat[idx]
	}
	invMat, err := invertMatrixGF(subMat)
	if err != nil {
		return nil, err
	}

	// Reconstruct any missing data shards
	for dIdx := 0; dIdx < dataShards; dIdx++ {
		if shards[dIdx] != nil {
			continue
		}
		rebuilt := make([]byte, shardSize)
		row := invMat[dIdx]
		for c, sIdx := range selected {
			coeff := row[c]
			if coeff == 0 {
				continue
			}
			in := shards[sIdx]
			for b := 0; b < shardSize; b++ {
				rebuilt[b] ^= gfMul(coeff, in[b])
			}
		}
		shards[dIdx] = rebuilt
	}

	// Recompute any missing parity shards (self-healing!)
	for pIdx := 0; pIdx < parityShards; pIdx++ {
		idx := dataShards + pIdx
		if shards[idx] != nil {
			continue
		}
		rebuilt := make([]byte, shardSize)
		row := mat[idx]
		for dIdx := 0; dIdx < dataShards; dIdx++ {
			coeff := row[dIdx]
			if coeff == 0 {
				continue
			}
			in := shards[dIdx]
			for b := 0; b < shardSize; b++ {
				rebuilt[b] ^= gfMul(coeff, in[b])
			}
		}
		shards[idx] = rebuilt
	}

	out := make([]byte, 0, int64(dataShards)*int64(shardSize))
	for i := 0; i < dataShards; i++ {
		out = append(out, shards[i]...)
	}
	if origSize >= 0 && int64(len(out)) > origSize {
		out = out[:origSize]
	}
	return out, nil
}

// ShardManifest records per-shard SHA-256 bit-rot checksums
type ShardManifest struct {
	DataShards   int      `json:"data_shards"`
	ParityShards int      `json:"parity_shards"`
	OrigSize     int64    `json:"orig_size"`
	ShardHashes  []string `json:"shard_hashes"`
}

// MultiDriveStore distributes Reed-Solomon shards across multiple disks/directories with bit-rot self-healing
type MultiDriveStore struct {
	mu           sync.RWMutex
	drives       []string
	dataShards   int
	parityShards int
}

// NewMultiDriveStore initializes a RAID/Erasure-coded shard store across drives (len(drives) == dataShards + parityShards)
func NewMultiDriveStore(drives []string, dataShards, parityShards int) (*MultiDriveStore, error) {
	if len(drives) != dataShards+parityShards {
		return nil, fmt.Errorf("drive count (%d) must equal dataShards+parityShards (%d)", len(drives), dataShards+parityShards)
	}
	for _, d := range drives {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}
	return &MultiDriveStore{
		drives:       drives,
		dataShards:   dataShards,
		parityShards: parityShards,
	}, nil
}

func (s *MultiDriveStore) shardPath(driveIdx int, bucket, key string, shardIdx int) string {
	return filepath.Join(s.drives[driveIdx], bucket, filepath.FromSlash(key), fmt.Sprintf("part.%d", shardIdx))
}

func (s *MultiDriveStore) manifestPath(driveIdx int, bucket, key string) string {
	return filepath.Join(s.drives[driveIdx], bucket, filepath.FromSlash(key), "ec.manifest.json")
}

// PutObject encodes data across all drives with per-shard SHA-256 checksums
func (s *MultiDriveStore) PutObject(bucket, key string, data []byte) error {
	shards, _, err := SplitEncode(data, s.dataShards, s.parityShards)
	if err != nil {
		return err
	}

	hashes := make([]string, len(shards))
	for i, sh := range shards {
		sum := sha256.Sum256(sh)
		hashes[i] = hex.EncodeToString(sum[:])
	}

	manifest := ShardManifest{
		DataShards:   s.dataShards,
		ParityShards: s.parityShards,
		OrigSize:     int64(len(data)),
		ShardHashes:  hashes,
	}
	mBytes, _ := json.Marshal(manifest)

	s.mu.Lock()
	defer s.mu.Unlock()

	for i, sh := range shards {
		sp := s.shardPath(i, bucket, key, i)
		_ = os.MkdirAll(filepath.Dir(sp), 0755)
		if err := os.WriteFile(sp, sh, 0644); err != nil {
			return err
		}
		_ = os.WriteFile(s.manifestPath(i, bucket, key), mBytes, 0644)
	}
	return nil
}

// GetObjectAndHeal reads shards, detects bit-rot or lost drives via SHA-256, reconstructs missing shards, and self-heals drives!
func (s *MultiDriveStore) GetObjectAndHeal(bucket, key string) (data []byte, healedCount int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var manifest ShardManifest
	var gotManifest bool
	for i := range s.drives {
		if b, err := os.ReadFile(s.manifestPath(i, bucket, key)); err == nil {
			if json.Unmarshal(b, &manifest) == nil {
				gotManifest = true
				break
			}
		}
	}
	if !gotManifest {
		return nil, 0, os.ErrNotExist
	}

	total := manifest.DataShards + manifest.ParityShards
	shards := make([][]byte, total)
	missing := make([]bool, total)

	for i := 0; i < total; i++ {
		sp := s.shardPath(i, bucket, key, i)
		b, readErr := os.ReadFile(sp)
		if readErr != nil {
			missing[i] = true
			continue
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != manifest.ShardHashes[i] {
			// Bit-rot detected! Discard corrupted shard so RS reconstructs it cleanly
			missing[i] = true
			continue
		}
		shards[i] = b
	}

	out, err := Reconstruct(shards, manifest.DataShards, manifest.ParityShards, manifest.OrigSize)
	if err != nil {
		return nil, 0, err
	}

	// Self-heal missing/corrupted shards & manifests back onto drives that are writable
	mBytes, _ := json.Marshal(manifest)
	for i := 0; i < total; i++ {
		if missing[i] && shards[i] != nil {
			sp := s.shardPath(i, bucket, key, i)
			if err := os.MkdirAll(filepath.Dir(sp), 0755); err == nil {
				if err := os.WriteFile(sp, shards[i], 0644); err == nil {
					_ = os.WriteFile(s.manifestPath(i, bucket, key), mBytes, 0644)
					healedCount++
				}
			}
		}
	}

	return out, healedCount, nil
}
