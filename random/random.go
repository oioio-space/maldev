package random

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// String generates a cryptographically random alphanumeric string of the given length.
func String(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

// Bytes returns n cryptographically random bytes.
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// Int returns a cryptographically random integer in [min, max).
func Int(min, max int) (int, error) {
	if max <= min {
		return 0, fmt.Errorf("max (%d) must be greater than min (%d)", max, min)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + min, nil
}

// Duration returns a cryptographically random duration in [min, max).
func Duration(min, max time.Duration) (time.Duration, error) {
	n, err := Int(int(min), int(max))
	return time.Duration(n), err
}

// Int64 returns a cryptographically random int64 (full range — may
// be negative). Useful as a seed for math/rand.NewSource where the
// caller wants per-build entropy without manually unrolling the
// crypto/rand → uint64 → int64 dance.
func Int64() (int64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("random.Int64: %w", err)
	}
	// Bit-reinterpret the 8 random bytes as int64. Full range
	// (negative + positive) is correct for math/rand.NewSource —
	// it accepts any int64.
	v := int64(buf[0]) | int64(buf[1])<<8 | int64(buf[2])<<16 | int64(buf[3])<<24 |
		int64(buf[4])<<32 | int64(buf[5])<<40 | int64(buf[6])<<48 | int64(buf[7])<<56
	return v, nil
}
