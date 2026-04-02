//go:build windows

package uacbypass

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// requireManual skips unless MALDEV_MANUAL=1 is set.
func requireManual(t *testing.T) {
	t.Helper()
	if os.Getenv("MALDEV_MANUAL") == "" {
		t.Skip("manual test: set MALDEV_MANUAL=1 (requires non-elevated user + UAC enabled + VM)")
	}
}

// TestFODHelper launches calc.exe via fodhelper UAC bypass.
//
// PREREQUISITES:
//   - Run as non-elevated user (standard user context)
//   - UAC must be enabled (default setting)
//   - Run in a VM
//   - Windows 10 or later
//
// USAGE:
//
//	MALDEV_MANUAL=1 go test ./uacbypass/ -run TestFODHelper -v
//
// VERIFY:
//
//	calc.exe should appear as an elevated process.
//	Check: tasklist /FI "IMAGENAME eq calc.exe" /V — should show High or System integrity.
//
// CLEANUP:
//
//	taskkill /F /IM calc.exe
//	Registry keys are cleaned up automatically by FODHelper's defer blocks.
func TestFODHelper(t *testing.T) {
	requireManual(t)

	err := FODHelper("calc.exe")
	require.NoError(t, err)

	// Give the spawned process time to appear.
	time.Sleep(2 * time.Second)
	t.Log("check for elevated calc.exe process: tasklist /FI \"IMAGENAME eq calc.exe\" /V")
}

// TestEventVwr launches calc.exe via eventvwr UAC bypass.
//
// PREREQUISITES:
//   - Run as non-elevated user (standard user context)
//   - UAC must be enabled (default setting)
//   - Run in a VM
//   - Windows 10 or later
//
// USAGE:
//
//	MALDEV_MANUAL=1 go test ./uacbypass/ -run TestEventVwr -v
//
// VERIFY:
//
//	calc.exe should appear as an elevated process.
//	Check: tasklist /FI "IMAGENAME eq calc.exe" /V — should show High or System integrity.
//
// CLEANUP:
//
//	taskkill /F /IM calc.exe
//	Registry key HKCU\Software\Classes\mscfile\shell\open\command is cleaned by defer.
func TestEventVwr(t *testing.T) {
	requireManual(t)

	err := EventVwr("calc.exe")
	require.NoError(t, err)

	// EventVwr internally sleeps 2s before spawning; add buffer for process visibility.
	time.Sleep(2 * time.Second)
	t.Log("check for elevated calc.exe process: tasklist /FI \"IMAGENAME eq calc.exe\" /V")
}

// TestSilentCleanup launches calc.exe via SilentCleanup scheduled task UAC bypass.
//
// PREREQUISITES:
//   - Run as non-elevated user (standard user context)
//   - UAC must be enabled (default setting)
//   - Run in a VM
//   - Windows 10 or later (SilentCleanup task must be present)
//
// USAGE:
//
//	MALDEV_MANUAL=1 go test ./uacbypass/ -run TestSilentCleanup -v
//
// VERIFY:
//
//	calc.exe should appear as an elevated process.
//	Check: tasklist /FI "IMAGENAME eq calc.exe" /V — should show High or System integrity.
//
// CLEANUP:
//
//	taskkill /F /IM calc.exe
//	HKCU\Environment\windir value is restored by defer DeleteValue.
func TestSilentCleanup(t *testing.T) {
	requireManual(t)

	err := SilentCleanup("calc.exe")
	require.NoError(t, err)

	// SilentCleanup internally sleeps 1s; add buffer for process visibility.
	time.Sleep(2 * time.Second)
	t.Log("check for elevated calc.exe process: tasklist /FI \"IMAGENAME eq calc.exe\" /V")
}

// TestSLUI launches calc.exe via SLUI UAC bypass.
//
// PREREQUISITES:
//   - Run as non-elevated user (standard user context)
//   - UAC must be enabled (default setting)
//   - Run in a VM
//   - Windows 10 or later
//
// USAGE:
//
//	MALDEV_MANUAL=1 go test ./uacbypass/ -run TestSLUI -v
//
// VERIFY:
//
//	calc.exe should appear as an elevated process.
//	Check: tasklist /FI "IMAGENAME eq calc.exe" /V — should show High or System integrity.
//
// CLEANUP:
//
//	taskkill /F /IM calc.exe
//	Registry key HKCU\Software\Classes\exefile\shell\open\command is cleaned by defer.
func TestSLUI(t *testing.T) {
	requireManual(t)

	err := SLUI("calc.exe")
	require.NoError(t, err)

	// SLUI internally sleeps 1s; add buffer for process visibility.
	time.Sleep(2 * time.Second)
	t.Log("check for elevated calc.exe process: tasklist /FI \"IMAGENAME eq calc.exe\" /V")
}
