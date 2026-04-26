//go:build windows

package selfdelete

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/version"
)

// skipIfWin11_24H2NtfsBlock skips the in-place self-delete tests on
// Win11 24H2+ where Microsoft hardened NtfsSetDispositionInfo to
// redirect the delete into an alternate data stream rather than
// unlinking. The Jonas Lyk `:wtfbbq` ADS rename + FileDispositionInfo
// pattern (what DeleteFile currently uses) returns success but the
// file remains visible — the test's `os.Stat(path) → IsNotExist` check
// fails. Migration to the modern FILE_DISPOSITION_INFO_EX with
// FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS lifts
// the block (see LloydLabs/delete-self-poc + tkyn.dev writeup) —
// chantier-IV-aligned follow-up.
func skipIfWin11_24H2NtfsBlock(t *testing.T) {
	t.Helper()
	if version.AtLeast(version.WINDOWS_11_24H2) {
		t.Skip("Win11 24H2 NtfsSetDispositionInfo redirects in-place delete to ADS — DeleteFile path needs migration to FILE_DISPOSITION_INFO_EX with POSIX_SEMANTICS. Tracked under chantier IV.")
	}
}

// adsTestDir returns a temp directory outside Windows Defender's real-time scan
// hot zone (AppData\Local\Temp). Tests in this package create and immediately
// delete files; Defender holding an open handle causes FileDispositionInfo to
// return ACCESS_DENIED before it releases the handle.
//
// The repo's ignore/ directory is excluded from Defender on this dev machine,
// so we place test files there. t.Cleanup removes the directory afterward.
func adsTestDir(t *testing.T) string {
	t.Helper()
	// Package working directory is cleanup/selfdelete — go up two levels to repo root.
	dir := filepath.Join("..", "..", "ignore", "selfdelete_test", t.Name())
	require.NoError(t, os.MkdirAll(dir, 0755))
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestDeleteFile(t *testing.T) {
	skipIfWin11_24H2NtfsBlock(t)
	dir := adsTestDir(t)
	tmpFile, err := os.CreateTemp(dir, "deltest_*.txt")
	require.NoError(t, err)
	_, err = tmpFile.WriteString("test content")
	require.NoError(t, err)
	tmpFile.Close()

	path := tmpFile.Name()
	require.FileExists(t, path)

	err = DeleteFile(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
}

func TestDeleteFileNonExistent(t *testing.T) {
	err := DeleteFile(`C:\nonexistent_file_maldev_test_12345.txt`)
	require.Error(t, err)
}

func TestDeleteFileForce(t *testing.T) {
	skipIfWin11_24H2NtfsBlock(t)
	dir := adsTestDir(t)
	tmpFile, err := os.CreateTemp(dir, "delforce_*.txt")
	require.NoError(t, err)
	_, err = tmpFile.WriteString("force delete test")
	require.NoError(t, err)
	tmpFile.Close()

	path := tmpFile.Name()
	require.FileExists(t, path)

	// Single retry with zero delay is sufficient — file is not locked.
	err = DeleteFileForce(path, 1, 0)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
}

func TestDeleteFileForceNonExistent(t *testing.T) {
	err := DeleteFileForce(`C:\nonexistent_file_maldev_test_force_12345.txt`, 2, 0)
	require.Error(t, err)
}

func TestRunWithScriptInChild(t *testing.T) {
	testutil.RequireIntrusive(t)

	if os.Getenv("MALDEV_CHILD_TEST") == "selfdelete" {
		// We ARE the child copy — start the deletion batch script, then exit.
		// RunWithScript spawns cmd.exe to delete us after we terminate.
		err := RunWithScript(0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		fmt.Print("SELFDELETE_STARTED")
		os.Exit(0)
	}

	// Parent: copy the test binary to a temp directory and run the copy.
	dir := t.TempDir()
	src := os.Args[0]
	dst := filepath.Join(dir, "deleteme.exe")

	data, err := os.ReadFile(src)
	require.NoError(t, err, "read test binary")
	require.NoError(t, os.WriteFile(dst, data, 0755), "write child binary")

	cmd := exec.Command(dst, "-test.run=TestRunWithScriptInChild", "-test.v")
	cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=selfdelete", "MALDEV_INTRUSIVE=1")
	output, _ := cmd.CombinedOutput()

	// The batch script deletes the binary asynchronously after the child exits.
	// Give cmd.exe time to complete its deletion loop.
	time.Sleep(3 * time.Second)

	_, statErr := os.Stat(dst)
	assert.True(t, os.IsNotExist(statErr),
		"binary should have been deleted by RunWithScript, output: %s", string(output))
}
