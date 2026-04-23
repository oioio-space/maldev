//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

// InlineStrategy stub on non-Windows. Cycle always returns an error;
// the struct exists so cross-platform Mask code compiles.
type InlineStrategy struct {
	UseBusyTrig bool
}

func (s *InlineStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: InlineStrategy requires Windows")
}

// Region stub for non-Windows (parallel to the Windows Region in mask_windows.go).
type Region struct {
	Addr uintptr
	Size uintptr
}

// Suppress unused-import warning in case the package ends up importing time
// via other stubs later.
var _ = time.Duration(0)
