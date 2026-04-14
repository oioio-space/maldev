//go:build !windows

package hideprocess

import (
	"errors"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func PatchProcessMonitor(_ int, _ *wsyscall.Caller) error {
	return errors.New("hideprocess: not supported on this platform")
}
