package sleepmask

import (
	"context"
	"time"
)

// Strategy encapsulates the encrypt → wait → decrypt cycle. Different
// strategies differ in WHICH thread does the work and HOW the wait is
// performed. The mask holds a Strategy and dispatches to Cycle each
// time Sleep is called.
//
// Strategies must:
//   - Always run the decrypt phase, even if ctx is cancelled during
//     the wait — otherwise the region stays masked and the caller's
//     next access faults.
//   - Preserve the original page protection of every region (capture
//     on encrypt, restore on decrypt).
//   - Maintain the v0.11.0 invariant that VirtualProtect(RW) runs
//     BEFORE the cipher writes to the page.
//
// See docs/techniques/evasion/sleep-mask.md for the level taxonomy
// (L1 inline, L2 light/full, L3 Foliage, L4 BOF) and which strategies
// this package ships.
type Strategy interface {
	// Cycle runs one encrypt → wait(d) → decrypt cycle on the given
	// regions using cipher and key. Returns ctx.Err() if the wait was
	// cancelled, the underlying syscall error otherwise, or nil on
	// clean completion.
	Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error
}
