//go:build windows

package stealthopen

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGetObjectID(t *testing.T) {
	f, err := os.CreateTemp("", "stealthopen-*.txt")
	require.NoError(t, err)
	f.Close()
	defer os.Remove(f.Name())

	oid, err := GetObjectID(f.Name())
	require.NoError(t, err)
	require.NotEqual(t, [16]byte{}, oid, "expected non-zero Object ID")
}

func TestOpenByID(t *testing.T) {
	f, err := os.CreateTemp("", "stealthopen-read-*.txt")
	require.NoError(t, err)
	_, _ = f.WriteString("hello stealthopen")
	f.Close()
	defer os.Remove(f.Name())

	oid, err := GetObjectID(f.Name())
	require.NoError(t, err)

	volume := filepath.VolumeName(f.Name()) + "\\"
	fh, err := OpenByID(volume, oid)
	require.NoError(t, err)
	defer fh.Close()

	buf := make([]byte, 17)
	n, err := fh.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello stealthopen", string(buf[:n]))
}

func TestSetObjectID(t *testing.T) {
	f, err := os.CreateTemp("", "stealthopen-set-*.txt")
	require.NoError(t, err)
	f.Close()
	defer os.Remove(f.Name())

	// FSCTL_SET_OBJECT_ID requires no existing ID; delete any auto-assigned one first.
	err = DeleteObjectID(f.Name())
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
			errors.Is(err, windows.ERROR_REPARSE_TAG_INVALID) {
			t.Skipf("SetObjectID requires admin: %v", err)
		}
		// ERROR_FILE_NOT_FOUND means no Object ID exists — that's fine.
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			require.NoError(t, err)
		}
	}

	var want [16]byte
	for i := range want {
		want[i] = byte(i + 1)
	}
	err = SetObjectID(f.Name(), want)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
			errors.Is(err, windows.ERROR_REPARSE_TAG_INVALID) {
			t.Skipf("SetObjectID requires admin: %v", err)
		}
		require.NoError(t, err) // fail on unexpected errors
	}

	got, err := GetObjectID(f.Name())
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDeleteObjectID(t *testing.T) {
	f, err := os.CreateTemp("", "stealthopen-del-*.txt")
	require.NoError(t, err)
	f.Close()
	defer os.Remove(f.Name())

	err = DeleteObjectID(f.Name())
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
			errors.Is(err, windows.ERROR_REPARSE_TAG_INVALID) {
			t.Skipf("DeleteObjectID requires admin: %v", err)
		}
		// No Object ID to delete is acceptable.
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return
		}
		require.NoError(t, err)
	}
}
