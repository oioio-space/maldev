//go:build linux && amd64

package antivm

import (
	"os"

	"golang.org/x/sys/unix"
)

// hasPortIOPrivileges reports whether the current process can issue an
// `IN EAX, DX` against an arbitrary port without faulting. The check
// raises IOPL to 3 (full port I/O) on success; callers MUST invoke
// [dropPortIOPrivileges] after they finish their port-I/O sequence.
//
// Linux requires CAP_SYS_RAWIO + a successful iopl(3) syscall. Effective
// UID 0 is the simplest proxy for the capability; iopl itself returns
// EPERM under seccomp / containerd profiles even with the capability,
// so we attempt the syscall and trust its return.
func hasPortIOPrivileges() bool {
	if os.Geteuid() != 0 {
		return false
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOPL, 3, 0, 0); errno != 0 {
		return false
	}
	return true
}

// dropPortIOPrivileges restores IOPL to 0 — the default user-mode value
// where any IN/OUT instruction faults. Always call after a successful
// [hasPortIOPrivileges] + port-I/O sequence so we don't leave the
// process with elevated I/O privileges across the rest of its lifetime.
func dropPortIOPrivileges() {
	unix.Syscall(unix.SYS_IOPL, 0, 0, 0)
}
