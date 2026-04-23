//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

type RemoteInlineStrategy struct {
	UseBusyTrig bool
}

func (*RemoteInlineStrategy) Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: RemoteInlineStrategy requires Windows")
}

var _ = time.Duration(0)
