package wipe

import (
	"os"
	"testing"
)

func TestFile(t *testing.T) {
	// Create a temp file
	f, err := os.CreateTemp("", "wipe_test_*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Write([]byte("sensitive data here that should be wiped"))
	f.Close()

	// Wipe it
	if err := File(path, 3); err != nil {
		t.Fatal(err)
	}

	// File should not exist anymore
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should have been deleted after wipe")
	}
}

func TestFileSinglePass(t *testing.T) {
	f, err := os.CreateTemp("", "wipe_single_*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Write([]byte("data"))
	f.Close()

	if err := File(path, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should have been deleted after wipe")
	}
}

func TestFileZeroPasses(t *testing.T) {
	// Zero passes should be treated as 1 pass (minimum)
	f, err := os.CreateTemp("", "wipe_zero_*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Write([]byte("data"))
	f.Close()

	if err := File(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should have been deleted after wipe")
	}
}

func TestFileNonExistent(t *testing.T) {
	err := File("/nonexistent/path/to/file.txt", 1)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}
