//go:build !(windows && amd64)

package sleepmask

import (
	"context"
	"errors"
	"time"
)

// FoliageStrategy on non-(windows+amd64) platforms is a stub; Cycle
// always returns an error. Real implementation lives in
// strategy_foliage_windows.go.
type FoliageStrategy struct {
	ScrubBytes uintptr
}

func (*FoliageStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: FoliageStrategy requires Windows amd64")
}

var _ = time.Duration(0)
