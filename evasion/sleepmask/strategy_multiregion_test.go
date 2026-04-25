package sleepmask

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStrategy records every Cycle invocation so tests can assert on
// dispatch shape (regions × duration). Returns a configurable error
// per-call. Cross-platform — does not touch real memory pages.
type fakeStrategy struct {
	mu    sync.Mutex
	calls []fakeCall
	err   error
}

type fakeCall struct {
	regions []Region
	d       time.Duration
}

func (f *fakeStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	f.mu.Lock()
	cp := make([]Region, len(regions))
	copy(cp, regions)
	f.calls = append(f.calls, fakeCall{regions: cp, d: d})
	f.mu.Unlock()
	return f.err
}

// TestMultiRegionRotation_NilInnerErrs ensures the wrapper rejects an
// unset Inner instead of silently no-op'ing.
func TestMultiRegionRotation_NilInnerErrs(t *testing.T) {
	s := &MultiRegionRotation{}
	err := s.Cycle(context.Background(), []Region{{Addr: 1, Size: 1}, {Addr: 2, Size: 1}}, NewXORCipher(), []byte{0}, time.Millisecond)
	if !errors.Is(err, errMultiRegionNoInner) {
		t.Errorf("nil Inner err = %v, want errMultiRegionNoInner", err)
	}
}

// TestMultiRegionRotation_PassThroughSingleRegion verifies that the
// wrapper imposes no overhead for the single-region case — Inner sees
// the original regions slice + the original duration.
func TestMultiRegionRotation_PassThroughSingleRegion(t *testing.T) {
	inner := &fakeStrategy{}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{{Addr: 0x1000, Size: 0x100}}
	err := s.Cycle(context.Background(), regions, NewXORCipher(), []byte{0}, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if got := len(inner.calls); got != 1 {
		t.Fatalf("inner.calls = %d, want 1", got)
	}
	if inner.calls[0].d != 100*time.Millisecond {
		t.Errorf("inner d = %v, want 100ms", inner.calls[0].d)
	}
	if len(inner.calls[0].regions) != 1 || inner.calls[0].regions[0] != regions[0] {
		t.Errorf("inner regions = %+v, want %+v", inner.calls[0].regions, regions)
	}
}

// TestMultiRegionRotation_DispatchesPerRegion is the core contract:
// N regions ⇒ N Inner.Cycle calls, each with one region and d/N.
func TestMultiRegionRotation_DispatchesPerRegion(t *testing.T) {
	inner := &fakeStrategy{}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{
		{Addr: 0x1000, Size: 0x100},
		{Addr: 0x2000, Size: 0x200},
		{Addr: 0x3000, Size: 0x300},
	}
	if err := s.Cycle(context.Background(), regions, NewXORCipher(), []byte{0}, 300*time.Millisecond); err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if got := len(inner.calls); got != 3 {
		t.Fatalf("inner.calls = %d, want 3", got)
	}
	for i, call := range inner.calls {
		if len(call.regions) != 1 {
			t.Errorf("call[%d] regions = %d, want 1", i, len(call.regions))
		} else if call.regions[0] != regions[i] {
			t.Errorf("call[%d] region = %+v, want %+v", i, call.regions[0], regions[i])
		}
		if call.d != 100*time.Millisecond {
			t.Errorf("call[%d] d = %v, want 100ms (300ms/3)", i, call.d)
		}
	}
}

// TestMultiRegionRotation_PropagatesInnerError ensures the wrapper
// surfaces the first inner failure rather than swallowing it.
func TestMultiRegionRotation_PropagatesInnerError(t *testing.T) {
	innerErr := errors.New("boom")
	inner := &fakeStrategy{err: innerErr}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{{Addr: 1, Size: 1}, {Addr: 2, Size: 1}}
	err := s.Cycle(context.Background(), regions, NewXORCipher(), []byte{0}, 10*time.Millisecond)
	if !errors.Is(err, innerErr) {
		t.Errorf("err = %v, want innerErr", err)
	}
	// Should have stopped after the first call's error.
	if len(inner.calls) != 1 {
		t.Errorf("inner.calls = %d, want 1 (early exit on first error)", len(inner.calls))
	}
}

// TestMultiRegionRotation_RespectsCancelledContext ensures a
// cancellation observed between sub-cycles short-circuits the
// remaining iterations.
func TestMultiRegionRotation_RespectsCancelledContext(t *testing.T) {
	inner := &fakeStrategy{}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{{Addr: 1, Size: 1}, {Addr: 2, Size: 1}, {Addr: 3, Size: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Cycle(ctx, regions, NewXORCipher(), []byte{0}, 30*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(inner.calls) > 1 {
		t.Errorf("inner.calls = %d, want <=1 (cancel observed early)", len(inner.calls))
	}
}

// TestMultiRegionRotation_ZeroDurationShortCircuits matches Mask.Sleep's
// d<=0 behavior.
func TestMultiRegionRotation_ZeroDurationShortCircuits(t *testing.T) {
	inner := &fakeStrategy{}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{{Addr: 1, Size: 1}, {Addr: 2, Size: 1}}
	if err := s.Cycle(context.Background(), regions, NewXORCipher(), []byte{0}, 0); err != nil {
		t.Errorf("Cycle d=0 err = %v, want nil", err)
	}
	if len(inner.calls) != 0 {
		t.Errorf("inner.calls = %d, want 0", len(inner.calls))
	}
}

// TestMultiRegionRotation_TooShortDurationFallsBack covers the
// duration-too-small-to-subdivide branch.
func TestMultiRegionRotation_TooShortDurationFallsBack(t *testing.T) {
	inner := &fakeStrategy{}
	s := &MultiRegionRotation{Inner: inner}
	regions := []Region{{Addr: 1, Size: 1}, {Addr: 2, Size: 1}, {Addr: 3, Size: 1}}
	// 1ns / 3 = 0 → fallback to single Cycle on regions[:1].
	if err := s.Cycle(context.Background(), regions, NewXORCipher(), []byte{0}, 1*time.Nanosecond); err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if len(inner.calls) != 1 {
		t.Fatalf("inner.calls = %d, want 1 (fallback)", len(inner.calls))
	}
	if len(inner.calls[0].regions) != 1 || inner.calls[0].regions[0] != regions[0] {
		t.Errorf("fallback region = %+v, want %+v", inner.calls[0].regions, regions[:1])
	}
}
