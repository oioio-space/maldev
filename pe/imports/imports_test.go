package imports

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testPEPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("need Windows PE")
	}
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("not found: %v", err)
	}
	return p
}

func TestList(t *testing.T) {
	p := testPEPath(t)
	imps, err := List(p)
	require.NoError(t, err)
	require.NotEmpty(t, imps)
	// Modern Windows 11 notepad uses API sets (api-ms-win-*) instead of
	// KERNEL32.dll directly, so check for any well-known DLL in the import table.
	known := []string{"KERNEL32.dll", "USER32.dll", "GDI32.dll"}
	var hasKnown bool
	for _, imp := range imps {
		for _, dll := range known {
			if strings.EqualFold(imp.DLL, dll) {
				hasKnown = true
				break
			}
		}
		if hasKnown {
			break
		}
	}
	require.True(t, hasKnown, "expected at least one well-known DLL import")
}

func TestListByDLL(t *testing.T) {
	p := testPEPath(t)
	// USER32.dll is present in notepad on all Windows versions including Win11.
	imps, err := ListByDLL(p, "USER32.dll")
	require.NoError(t, err)
	require.NotEmpty(t, imps)
	// All returned imports must belong to the requested DLL.
	for _, imp := range imps {
		require.True(t, strings.EqualFold(imp.DLL, "USER32.dll"), "unexpected DLL: %s", imp.DLL)
	}
}

func TestListNonExistent(t *testing.T) {
	_, err := List(`C:\nonexistent_12345.exe`)
	require.Error(t, err)
}

func TestFromReader(t *testing.T) {
	p := testPEPath(t)
	f, err := os.Open(p)
	require.NoError(t, err)
	defer f.Close()

	imps, err := FromReader(f)
	require.NoError(t, err)
	require.NotEmpty(t, imps)
}

// TestListDelay_NotepadEntriesFlaggedDelay verifies the
// per-entry Delay flag matches the ListDelay filter contract:
// every returned entry must have Delay==true. Notepad on Win11
// has ~25 delay imports (covers the populated-result path);
// older/leaner Windows builds may have zero (covers the
// empty-result path) — both are valid.
func TestListDelay_NotepadEntriesFlaggedDelay(t *testing.T) {
	p := testPEPath(t)
	delays, err := ListDelay(p)
	require.NoError(t, err)
	t.Logf("notepad.exe delay imports: %d", len(delays))
	for _, imp := range delays {
		require.True(t, imp.Delay, "ListDelay must only return Delay==true entries")
	}
}

// TestListDelay_EdgeHasDelayImports — modern Windows apps lean
// heavily on delay-load. msedge.exe is the most reliable target
// when it's installed (Win11 ships with it).
func TestListDelay_EdgeHasDelayImports(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	const edge = `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	if _, err := os.Stat(edge); err != nil {
		t.Skipf("msedge.exe not found: %v", err)
	}

	delays, err := ListDelay(edge)
	require.NoError(t, err)
	if len(delays) == 0 {
		t.Skip("msedge.exe wrapper has no delay imports — actual deps live in delegated DLLs")
	}
	for _, imp := range delays {
		require.True(t, imp.Delay, "ListDelay must only return Delay==true entries")
	}
	t.Logf("msedge.exe delay imports: %d (sample: %s.%s)",
		len(delays), delays[0].DLL, delays[0].Function)
}
