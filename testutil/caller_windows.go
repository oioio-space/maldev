package testutil

import (
	"testing"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// CallerMethod bundles a Caller with its method enum and a human-readable name
// for table-driven tests. The Method field allows tests to pass it directly to
// WindowsConfig.SyscallMethod without maintaining a separate name→method map.
type CallerMethod struct {
	Name   string
	Method wsyscall.Method
	Caller *wsyscall.Caller
}

// CallerMethods returns the 4 standard Caller configurations for matrix testing.
// Each technique that accepts *wsyscall.Caller should be tested with all 4.
func CallerMethods(t *testing.T) []CallerMethod {
	t.Helper()
	chain := wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate())
	return []CallerMethod{
		{"WinAPI", wsyscall.MethodWinAPI, nil},
		{"NativeAPI", wsyscall.MethodNativeAPI, wsyscall.New(wsyscall.MethodNativeAPI, nil)},
		{"Direct", wsyscall.MethodDirect, wsyscall.New(wsyscall.MethodDirect, chain)},
		{"Indirect", wsyscall.MethodIndirect, wsyscall.New(wsyscall.MethodIndirect, chain)},
	}
}
