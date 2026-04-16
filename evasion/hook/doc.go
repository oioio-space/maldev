// Package hook provides x64 inline function hooking — intercept any exported
// Windows function by patching its prologue with a JMP to a Go callback.
//
// Technique: Inline hooking with relay + trampoline. Automatically analyzes
// the function prologue to determine steal length, generates a trampoline
// for calling the original, and fixes up RIP-relative instructions.
//
// MITRE ATT&CK: T1574.012 — Hijack Execution Flow: Inline Hooking.
// Platform: Windows (x64 only).
// Detection: High — EDR integrity checks detect modified function prologues.
//
// No CGo required — uses syscall.NewCallback for the Go-to-native bridge.
// No x64dbg required — prologue analysis is automatic via x86asm.
//
// Example:
//
//	var h *hook.Hook
//	h, _ = hook.InstallByName("kernel32.dll", "DeleteFileW", func(lpFileName uintptr) uintptr {
//	    name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpFileName)))
//	    log.Printf("DeleteFileW: %s", name)
//	    r, _, _ := syscall.SyscallN(h.Trampoline(), lpFileName)
//	    return r
//	})
//	defer h.Remove()
package hook
