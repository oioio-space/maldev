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
