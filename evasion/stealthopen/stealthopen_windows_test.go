//go:build windows

package stealthopen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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

	var want [16]byte
	for i := range want {
		want[i] = byte(i + 1)
	}
	err = SetObjectID(f.Name(), want)
	if err != nil {
		t.Skipf("SetObjectID requires admin: %v", err)
	}

	got, err := GetObjectID(f.Name())
	require.NoError(t, err)
	require.Equal(t, want, got)
}
