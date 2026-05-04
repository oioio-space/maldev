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

// TestMultiStealth_Open_NilReceiver guards the nil-receiver path so a
// caller wiring `var op stealthopen.Opener = (*MultiStealth)(nil)` by
// mistake gets a clear error instead of a nil-deref panic.
func TestMultiStealth_Open_NilReceiver(t *testing.T) {
	var nilM *MultiStealth
	_, err := nilM.Open("anything")
	require.Error(t, err)
}

// TestMultiStealth_Open_EmptyPath guards the explicit empty-path
// rejection — `os.Open("")` would otherwise surface as ENOENT and
// pollute the cache.
func TestMultiStealth_Open_EmptyPath(t *testing.T) {
	m := &MultiStealth{}
	_, err := m.Open("")
	require.Error(t, err)
}

// TestMultiStealth_Open_ZeroValueWorks captures the zero-value
// usability promise: `var m MultiStealth` is valid, no constructor.
func TestMultiStealth_Open_ZeroValueWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "z.bin")
	require.NoError(t, os.WriteFile(path, []byte("zv"), 0o600))

	var m MultiStealth // zero value
	f, err := m.Open(path)
	require.NoError(t, err)
	defer f.Close()
	got, _ := io.ReadAll(f)
	assert.Equal(t, []byte("zv"), got)
}

// TestMultiStealth_Open_RoundTrip exercises the happy path: write a
// temp file, open it twice via *MultiStealth, verify both reads
// return the same bytes. The second call goes through the cache.
func TestMultiStealth_Open_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "round.bin")
	want := []byte("MULTISTEALTH_ROUNDTRIP_OK")
	require.NoError(t, os.WriteFile(path, want, 0o600))

	m := &MultiStealth{}

	// First call — captures ID + caches.
	f1, err := m.Open(path)
	require.NoError(t, err)
	got1, _ := io.ReadAll(f1)
	f1.Close()
	assert.Equal(t, want, got1)

	// Second call — cache hit, routes through OpenByID.
	f2, err := m.Open(path)
	require.NoError(t, err)
	got2, _ := io.ReadAll(f2)
	f2.Close()
	assert.Equal(t, want, got2)

	// Cache is populated for this abs path (lowercased — Windows paths
	// are case-insensitive, see MultiStealth.Open).
	abs, _ := filepath.Abs(path)
	abs = strings.ToLower(abs)
	m.mu.Lock()
	entry, tried := m.cache[abs]
	m.mu.Unlock()
	require.True(t, tried, "abs path must be in the cache after first call")
	if entry == nil {
		// NewStealth failed (likely non-NTFS temp dir) — round-trip
		// still succeeded via the negative-cache fallback. Skip the
		// stronger Object-ID assertion in that environment.
		t.Skipf("MultiStealth fell back to os.Open (non-NTFS temp dir likely); round-trip still verified")
	}
	var zero [16]byte
	assert.NotEqual(t, zero, entry.ObjectID, "cached Stealth must carry a non-zero ObjectID")
}

// TestMultiStealth_Open_NegativeCacheFallsBack verifies that a
// missing-file open errors out (via os.Open) AND that the
// negative-cache entry is recorded so we don't retry NewStealth on
// the next call for the same path.
func TestMultiStealth_Open_NegativeCacheFallsBack(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "does-not-exist.bin")
	m := &MultiStealth{}

	_, err := m.Open(bogus)
	require.Error(t, err, "missing file must surface as an error")

	abs, _ := filepath.Abs(bogus)
	abs = strings.ToLower(abs)
	m.mu.Lock()
	entry, tried := m.cache[abs]
	m.mu.Unlock()
	require.True(t, tried, "missing-path attempt must populate the cache")
	assert.Nil(t, entry, "negative cache entry must be nil so subsequent calls go straight to os.Open")
}

// TestMultiStealth_Open_DifferentPathsKeptSeparate makes sure the
// per-path cache binds the right ObjectID to the right path —
// different paths must not collide.
func TestMultiStealth_Open_DifferentPathsKeptSeparate(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "alpha.bin")
	pathB := filepath.Join(dir, "bravo.bin")
	dataA := []byte("ALPHA_separate_AAAA")
	dataB := []byte("BRAVO_separate_BBBB")
	require.NoError(t, os.WriteFile(pathA, dataA, 0o600))
	require.NoError(t, os.WriteFile(pathB, dataB, 0o600))

	m := &MultiStealth{}

	// Prime both paths.
	for _, p := range []string{pathA, pathB} {
		f, err := m.Open(p)
		require.NoError(t, err)
		f.Close()
	}

	// Re-read both and assert no path-collision in the cache.
	fA, err := m.Open(pathA)
	require.NoError(t, err)
	gotA, _ := io.ReadAll(fA)
	fA.Close()
	assert.Equal(t, dataA, gotA, "path A must still return file A on cache hit")

	fB, err := m.Open(pathB)
	require.NoError(t, err)
	gotB, _ := io.ReadAll(fB)
	fB.Close()
	assert.Equal(t, dataB, gotB, "path B must still return file B on cache hit")
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
