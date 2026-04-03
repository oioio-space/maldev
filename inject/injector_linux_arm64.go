//go:build linux && arm64

package inject

import "fmt"

// sysMemfdCreate is the memfd_create syscall number on ARM64.
const sysMemfdCreate = 279

// injectPtrace is not yet implemented for ARM64.
func (l *linuxInjector) injectPtrace(_ []byte) error {
	return fmt.Errorf("ptrace injection not yet implemented for ARM64 (use procmem or memfd)")
}
