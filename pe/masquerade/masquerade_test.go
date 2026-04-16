package masquerade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func testPEPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("need Windows PE for extraction test")
	}
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("notepad.exe not found: %v", err)
	}
	return p
}

func TestExtract(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Manifest)
	require.NotNil(t, res.VersionInfo)
	require.NotEmpty(t, res.Icons)
}

func TestExtractVersionInfo(t *testing.T) {
	pe := testPEPath(t)
	res, err := Extract(pe)
	require.NoError(t, err)
	require.NotEmpty(t, res.VersionInfo.FileDescription)
	require.NotEmpty(t, res.VersionInfo.CompanyName)
	t.Logf("FileDescription: %s", res.VersionInfo.FileDescription)
	t.Logf("CompanyName: %s", res.VersionInfo.CompanyName)
}

func TestExtractNonExistent(t *testing.T) {
	_, err := Extract(`C:\nonexistent_pe_12345.exe`)
	require.Error(t, err)
}

func TestExecLevelString(t *testing.T) {
	require.Equal(t, "asInvoker", AsInvoker.String())
	require.Equal(t, "highestAvailable", HighestAvailable.String())
	require.Equal(t, "requireAdministrator", RequireAdministrator.String())
}
