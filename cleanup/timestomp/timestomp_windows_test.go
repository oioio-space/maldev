//go:build windows

package timestomp

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// getFileCreationTime reads the creation time via Windows API.
func getFileCreationTime(t *testing.T, path string) time.Time {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	defer windows.CloseHandle(h)

	var ctime, atime, mtime windows.Filetime
	err = windows.GetFileTime(h, &ctime, &atime, &mtime)
	require.NoError(t, err)
	return time.Unix(0, ctime.Nanoseconds())
}

func TestSetFull(t *testing.T) {
	f, err := os.CreateTemp("", "timestomp_setfull_*")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	ctime := time.Date(2010, 3, 15, 10, 30, 0, 0, time.UTC)
	atime := time.Date(2011, 6, 20, 14, 0, 0, 0, time.UTC)
	mtime := time.Date(2012, 9, 25, 18, 45, 0, 0, time.UTC)

	err = SetFull(f.Name(), ctime, atime, mtime)
	require.NoError(t, err)

	// Verify modification time via os.Stat.
	info, err := os.Stat(f.Name())
	require.NoError(t, err)
	assert.Equal(t, mtime.Unix(), info.ModTime().UTC().Unix(), "modification time mismatch")

	// Verify creation time via Windows API.
	gotCtime := getFileCreationTime(t, f.Name())
	assert.Equal(t, ctime.Unix(), gotCtime.UTC().Unix(), "creation time mismatch")
}

func TestSetFullNonExistent(t *testing.T) {
	ts := time.Now()
	err := SetFull(`C:\nonexistent\path\file.txt`, ts, ts, ts)
	assert.Error(t, err)
}

func TestCopyFromFull(t *testing.T) {
	src, err := os.CreateTemp("", "ts_full_src_*")
	require.NoError(t, err)
	defer os.Remove(src.Name())
	src.Close()

	dst, err := os.CreateTemp("", "ts_full_dst_*")
	require.NoError(t, err)
	defer os.Remove(dst.Name())
	dst.Close()

	// Set known timestamps on the source file.
	ctime := time.Date(2008, 1, 1, 0, 0, 0, 0, time.UTC)
	atime := time.Date(2009, 6, 15, 12, 0, 0, 0, time.UTC)
	mtime := time.Date(2010, 12, 31, 23, 59, 0, 0, time.UTC)
	err = SetFull(src.Name(), ctime, atime, mtime)
	require.NoError(t, err)

	// Copy all timestamps from src to dst.
	err = CopyFromFull(src.Name(), dst.Name())
	require.NoError(t, err)

	// Verify modification time matches.
	dstInfo, err := os.Stat(dst.Name())
	require.NoError(t, err)
	assert.Equal(t, mtime.Unix(), dstInfo.ModTime().UTC().Unix(), "dst modification time must match src")

	// Verify creation time matches.
	gotCtime := getFileCreationTime(t, dst.Name())
	assert.Equal(t, ctime.Unix(), gotCtime.UTC().Unix(), "dst creation time must match src")
}

func TestCopyFromFullNonExistentSrc(t *testing.T) {
	dst, err := os.CreateTemp("", "ts_full_dst_*")
	require.NoError(t, err)
	defer os.Remove(dst.Name())
	dst.Close()

	err = CopyFromFull(`C:\nonexistent\src.txt`, dst.Name())
	assert.Error(t, err)
}

func TestCopyFromFullNonExistentDst(t *testing.T) {
	src, err := os.CreateTemp("", "ts_full_src_*")
	require.NoError(t, err)
	defer os.Remove(src.Name())
	src.Close()

	err = CopyFromFull(src.Name(), `C:\nonexistent\dst.txt`)
	assert.Error(t, err)
}
