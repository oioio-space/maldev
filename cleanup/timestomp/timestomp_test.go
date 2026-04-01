package timestomp

import (
	"os"
	"testing"
	"time"
)

func TestSet(t *testing.T) {
	f, err := os.CreateTemp("", "timestomp_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	target := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := Set(f.Name(), target, target); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(f.Name())
	got := info.ModTime().UTC()
	if !got.Equal(target) {
		t.Fatalf("ModTime = %v, want %v", got, target)
	}
}

func TestSetFutureDate(t *testing.T) {
	f, err := os.CreateTemp("", "timestomp_future_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	target := time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC)
	if err := Set(f.Name(), target, target); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(f.Name())
	got := info.ModTime().UTC()
	if !got.Equal(target) {
		t.Fatalf("ModTime = %v, want %v", got, target)
	}
}

func TestCopyFrom(t *testing.T) {
	src, _ := os.CreateTemp("", "ts_src_*")
	dst, _ := os.CreateTemp("", "ts_dst_*")
	defer os.Remove(src.Name())
	defer os.Remove(dst.Name())
	src.Close()
	dst.Close()

	target := time.Date(2019, 6, 15, 12, 0, 0, 0, time.UTC)
	os.Chtimes(src.Name(), target, target)

	if err := CopyFrom(src.Name(), dst.Name()); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(dst.Name())
	got := info.ModTime().UTC()
	if !got.Equal(target) {
		t.Fatalf("dst ModTime = %v, want %v", got, target)
	}
}

func TestSetNonExistent(t *testing.T) {
	target := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	err := Set("/nonexistent/path/file.txt", target, target)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestCopyFromNonExistent(t *testing.T) {
	f, _ := os.CreateTemp("", "ts_exists_*")
	defer os.Remove(f.Name())
	f.Close()

	err := CopyFrom("/nonexistent/path/file.txt", f.Name())
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}
