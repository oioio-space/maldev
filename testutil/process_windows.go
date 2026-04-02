//go:build windows

package testutil

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpawnSacrificial creates a suspended notepad.exe for injection tests.
func SpawnSacrificial(t *testing.T) (pid uint32, threadHandle windows.Handle, cleanup func()) {
	t.Helper()
	argv, err := windows.UTF16PtrFromString("notepad.exe")
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err = windows.CreateProcess(nil, argv, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, &si, &pi)
	if err != nil {
		t.Fatalf("CreateProcess: %v", err)
	}
	cleanup = func() {
		windows.TerminateProcess(pi.Process, 0)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
	}
	return pi.ProcessId, pi.Thread, cleanup
}

// SpawnAndResume creates a running notepad.exe for CRT/APC injection.
func SpawnAndResume(t *testing.T) (pid uint32, cleanup func()) {
	t.Helper()
	p, th, c := SpawnSacrificial(t)
	windows.ResumeThread(th)
	return p, c
}
