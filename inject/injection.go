// Package inject provides unified shellcode injection techniques
// for Windows and Linux platforms.
package inject

import "errors"

var ErrNotSupported = errors.New("injection method not supported on this platform")

// Method identifies the injection technique.
type Method string

// Windows methods
const (
	MethodCreateRemoteThread  Method = "crt"
	MethodCreateThread        Method = "ct"
	MethodQueueUserAPC        Method = "apc"
	MethodEarlyBirdAPC        Method = "earlybird"
	MethodThreadHijack Method = "threadhijack"

	// MethodProcessHollowing is deprecated: use MethodThreadHijack.
	// This is actually Thread Execution Hijacking (T1055.003), not PE hollowing.
	MethodProcessHollowing = MethodThreadHijack
	MethodRtlCreateUserThread Method = "rtl"
	MethodDirectSyscall       Method = "syscall"
	MethodCreateFiber         Method = "fiber"
)

// Linux methods
const (
	MethodPtrace  Method = "ptrace"
	MethodMemFD   Method = "memfd"
	MethodProcMem Method = "procmem"
)

// Purego methods (Linux/macOS, no CGO)
const (
	MethodPureGoShellcode   Method = "purego"
	MethodPureGoMeterpreter Method = "purego-meter"
)

// Injector performs shellcode injection.
type Injector interface {
	Inject(shellcode []byte) error
}

// Config configures an injection.
type Config struct {
	Method      Method
	PID         int    // target PID (0 = self for procmem/ct/purego)
	ProcessPath string // path to spawn (earlybird, hollow)
	Fallback    bool   // try alternate methods on failure
}
