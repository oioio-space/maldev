//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

type TimerQueueStrategy struct{}

func (*TimerQueueStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: TimerQueueStrategy requires Windows")
}

var _ = time.Duration(0)
