package hash

import (
	"fmt"
	"os"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

// Ssdeep computes the ssdeep fuzzy hash of data.
// ssdeep uses context-triggered piecewise hashing to produce
// locality-sensitive hashes that detect similar content.
func Ssdeep(data []byte) (string, error) {
	return ssdeep.FuzzyBytes(data)
}

// SsdeepFile computes the ssdeep fuzzy hash of a file.
func SsdeepFile(path string) (string, error) {
	return ssdeep.FuzzyFilename(path)
}

// SsdeepCompare returns the similarity score (0-100) between two ssdeep hashes.
// 0 means no similarity, 100 means identical content.
func SsdeepCompare(hash1, hash2 string) (int, error) {
	return ssdeep.Distance(hash1, hash2)
}

// TLSH computes the TLSH (Trend Locality Sensitive Hash) of data.
// Minimum input: 50 bytes (library enforced). Inputs under 256 bytes
// may produce less reliable similarity hashes.
func TLSH(data []byte) (string, error) {
	t, err := tlsh.HashBytes(data)
	if err != nil {
		return "", fmt.Errorf("tlsh hash: %w", err)
	}
	return t.String(), nil
}

// TLSHFile computes the TLSH hash of a file.
func TLSHFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return TLSH(data)
}

// TLSHCompare returns the distance between two TLSH hashes.
// Lower distance means more similar. 0 means identical.
// Typical threshold: <100 for similar files.
func TLSHCompare(hash1, hash2 string) (int, error) {
	t1, err := tlsh.ParseStringToTlsh(hash1)
	if err != nil {
		return 0, fmt.Errorf("parse first hash: %w", err)
	}
	t2, err := tlsh.ParseStringToTlsh(hash2)
	if err != nil {
		return 0, fmt.Errorf("parse second hash: %w", err)
	}
	return t1.Diff(t2), nil
}
