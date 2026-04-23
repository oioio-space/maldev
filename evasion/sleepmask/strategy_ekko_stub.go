//go:build !(windows && amd64)

package sleepmask

import (
	"context"
	"errors"
	"time"
)

// EkkoStrategy on non-(windows+amd64) platforms is a stub; Cycle always
// returns an error. Real implementation lives in strategy_ekko_windows.go.
type EkkoStrategy struct{}

func (*EkkoStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: EkkoStrategy requires Windows amd64")
}

var _ = time.Duration(0)
