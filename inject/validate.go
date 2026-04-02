package inject

import (
	"fmt"
	"runtime"
)

// ValidateMethod checks that an injection method is valid for the current platform.
func ValidateMethod(method Method) error {
	if method == "" {
		return fmt.Errorf("injection method cannot be empty")
	}

	available := AvailableMethods()
	for _, m := range available {
		if m == method {
			return nil
		}
	}

	return fmt.Errorf("injection method '%s' not available on %s/%s, available methods: %v",
		method, runtime.GOOS, runtime.GOARCH, available)
}

// Validate checks the validity of an injection configuration.
func (c *Config) Validate() error {
	if err := ValidateMethod(c.Method); err != nil {
		return err
	}

	// Methods requiring a PID
	remoteMethods := map[Method]bool{
		MethodCreateRemoteThread:  true,
		MethodQueueUserAPC:        true,
		MethodRtlCreateUserThread: true,
		MethodPtrace:              true,
	}

	if remoteMethods[c.Method] && c.PID <= 0 && c.ProcessPath == "" {
		return fmt.Errorf("method '%s' requires a valid PID or process name/path", c.Method)
	}

	// Methods requiring a ProcessPath
	processPathMethods := map[Method]bool{
		MethodThreadHijack: true,
		MethodEarlyBirdAPC:     true,
	}

	if processPathMethods[c.Method] && c.ProcessPath == "" {
		return fmt.Errorf("method '%s' requires a process path", c.Method)
	}

	return nil
}

// AvailableMethods returns the methods available on the current platform.
func AvailableMethods() []Method {
	if runtime.GOOS == "windows" {
		return []Method{
			MethodCreateRemoteThread,
			MethodCreateThread,
			MethodQueueUserAPC,
			MethodEarlyBirdAPC,
			MethodThreadHijack,
			MethodRtlCreateUserThread,
			MethodDirectSyscall,
			MethodCreateFiber,
		}
	} else if runtime.GOOS == "linux" {
		return []Method{
			MethodPtrace,
			MethodMemFD,
			MethodProcMem,
		}
	}
	return []Method{}
}

// DefaultMethod returns the default injection method for the current platform.
func DefaultMethod() Method {
	if runtime.GOOS == "windows" {
		return MethodCreateRemoteThread
	} else if runtime.GOOS == "linux" {
		return MethodPtrace
	}
	return MethodCreateRemoteThread
}

// DefaultMethodForStage returns the default method for staging (self-injection).
func DefaultMethodForStage() Method {
	if runtime.GOOS == "windows" {
		return MethodCreateThread
	} else if runtime.GOOS == "linux" {
		return MethodProcMem
	}
	return MethodCreateThread
}

// NewInjector creates an injector for the given configuration.
func NewInjector(cfg *Config) (Injector, error) {
	return newPlatformInjector(cfg)
}
