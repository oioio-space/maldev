package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// PayloadPath returns the absolute path to a test payload file in testutil/.
// Skips the test if the file doesn't exist.
func PayloadPath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("payload %q not found: %v", name, err)
	}
	return path
}

// LoadPayload reads a test payload file from testutil/.
// Skips the test if the file doesn't exist.
func LoadPayload(t *testing.T, name string) []byte {
	t.Helper()
	path := PayloadPath(t, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read payload %q: %v", name, err)
	}
	if len(data) == 0 {
		t.Fatalf("payload %q is empty", name)
	}
	return data
}
