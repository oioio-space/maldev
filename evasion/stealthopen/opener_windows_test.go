//go:build windows

package stealthopen

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVolumeFromPath_DriveLetter(t *testing.T) {
	got, err := VolumeFromPath(`C:\Windows\System32\ntdll.dll`)
	require.NoError(t, err)
	assert.Equal(t, `C:\`, got)
}

func TestVolumeFromPath_Win32Prefix(t *testing.T) {
	got, err := VolumeFromPath(`\\?\C:\Windows\System32\ntdll.dll`)
	require.NoError(t, err)
	assert.Equal(t, `C:\`, got)
}

func TestVolumeFromPath_UNC(t *testing.T) {
	got, err := VolumeFromPath(`\\server\share\some\file.dat`)
	require.NoError(t, err)
	assert.Equal(t, `\\server\share\`, got)
}

func TestVolumeFromPath_Empty(t *testing.T) {
	_, err := VolumeFromPath("")
	require.Error(t, err)
}

func TestVolumeFromPath_Relative(t *testing.T) {
	// filepath.Abs resolves against cwd. We just assert the result ends in
	// the canonical `<Drive>:\` form — the specific drive depends on cwd.
	got, err := VolumeFromPath(`some\relative\file.txt`)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(got, `:\`), "expected drive-root suffix, got %q", got)
}

func TestStealth_Open_ValidatesState(t *testing.T) {
	// Nil receiver.
	var nilStealth *Stealth
	_, err := nilStealth.Open("anything")
	require.Error(t, err)

	// Empty VolumePath.
	s := &Stealth{ObjectID: [16]byte{0xAA}}
	_, err = s.Open("x")
	require.Error(t, err)

	// Zero ObjectID.
	s = &Stealth{VolumePath: `C:\`}
	_, err = s.Open("x")
	require.Error(t, err)
}

// TestNewStealth_RoundTrip captures the Object ID for a temp file, uses
// the resulting Stealth opener to read the file back via OpenFileById,
// and verifies the bytes round-trip. The path passed to Open is
// deliberately garbage — the opener ignores it and goes via volume
// handle + Object ID.
func TestNewStealth_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	want := []byte("MALDEV_STEALTHOPEN_ROUNDTRIP_OK")
	require.NoError(t, os.WriteFile(path, want, 0o600))

	st, err := NewStealth(path)
	if err != nil {
		t.Skipf("NewStealth unavailable on this volume (likely non-NTFS or missing admin): %v", err)
	}
	require.NotNil(t, st)
	assert.NotEmpty(t, st.VolumePath, "VolumePath must be populated")

	var zero [16]byte
	assert.NotEqual(t, zero, st.ObjectID, "ObjectID must be populated")

	// Read via Stealth (path arg is intentionally garbage).
	f, err := st.Open("ignored-by-stealth-opener")
	require.NoError(t, err)
	defer f.Close()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, want, got, "bytes round-tripped via Object ID must match the original content")
}

// TestStealth_DefeatsPathHookSemantics sanity-checks that Stealth.Open
// does not consult the path argument — two Stealth openers built for
// two different files must return their OWN file regardless of which
// path the caller passes in.
func TestStealth_DefeatsPathHookSemantics(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.bin")
	pathB := filepath.Join(dir, "b.bin")
	dataA := []byte("ALPHA_marker_AAAA")
	dataB := []byte("BRAVO_marker_BBBB")
	require.NoError(t, os.WriteFile(pathA, dataA, 0o600))
	require.NoError(t, os.WriteFile(pathB, dataB, 0o600))

	stA, errA := NewStealth(pathA)
	stB, errB := NewStealth(pathB)
	if errA != nil || errB != nil {
		t.Skipf("NewStealth unavailable: errA=%v errB=%v", errA, errB)
	}

	// Cross-call: stA asked to open pathB still returns pathA's content.
	f, err := stA.Open(pathB)
	require.NoError(t, err)
	got, _ := io.ReadAll(f)
	f.Close()
	assert.Equal(t, dataA, got, "Stealth opener A must return file A regardless of the path argument")

	// Symmetric.
	f, err = stB.Open(pathA)
	require.NoError(t, err)
	got, _ = io.ReadAll(f)
	f.Close()
	assert.Equal(t, dataB, got)
}
