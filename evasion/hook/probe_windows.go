//go:build windows

package hook

import "syscall"

// ProbeResult holds the captured arguments and return value from a single
// call to a probed function. Up to 18 arguments are captured to cover the
// widest Windows x64 ABI surface without a known signature.
type ProbeResult struct {
	Args [18]uintptr
	Ret  uintptr
}

// NonZeroArgs returns the indices of arguments that were non-zero on this call.
// Useful for narrowing down which parameters a function actually uses.
func (r ProbeResult) NonZeroArgs() []int {
	var indices []int
	for i, a := range r.Args {
		if a != 0 {
			indices = append(indices, i)
		}
	}
	return indices
}

// NonZeroCount returns the number of non-zero arguments observed on this call.
func (r ProbeResult) NonZeroCount() int {
	n := 0
	for _, a := range r.Args {
		if a != 0 {
			n++
		}
	}
	return n
}

// InstallProbe hooks the function at targetAddr without requiring knowledge of
// its signature. onCall is invoked on every call with all 18 argument slots
// captured; the original function is then called transparently via the
// trampoline and its return value is forwarded to the caller.
func InstallProbe(targetAddr uintptr, onCall func(ProbeResult), opts ...HookOption) (*Hook, error) {
	var h *Hook
	handler := func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18 uintptr) uintptr {
		result := ProbeResult{Args: [18]uintptr{a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18}}
		onCall(result)
		r, _, _ := syscall.SyscallN(h.Trampoline(), a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18)
		return r
	}
	var err error
	h, err = Install(targetAddr, handler, opts...)
	return h, err
}

// InstallProbeByName resolves a function by DLL and export name, then installs
// a signature-agnostic probe hook on it.
func InstallProbeByName(dllName, funcName string, onCall func(ProbeResult), opts ...HookOption) (*Hook, error) {
	var h *Hook
	handler := func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18 uintptr) uintptr {
		result := ProbeResult{Args: [18]uintptr{a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18}}
		onCall(result)
		r, _, _ := syscall.SyscallN(h.Trampoline(), a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18)
		return r
	}
	var err error
	h, err = InstallByName(dllName, funcName, handler, opts...)
	return h, err
}
