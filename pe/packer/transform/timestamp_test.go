package transform_test

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// minPE returns a 200-byte synthetic PE buffer just rich enough for
// PatchPETimeDateStamp to walk to the COFF TimeDateStamp field. DOS
// magic + e_lfanew + PE signature + 20-byte COFF header.
func minPE(t *testing.T) []byte {
	t.Helper()
	const peOff = 0x40
	out := make([]byte, 0x100)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:transform.PEELfanewOffset+4], peOff)
	binary.LittleEndian.PutUint32(out[peOff:peOff+4], 0x00004550) // "PE\0\0"
	return out
}

func TestPatchPETimeDateStamp_WritesAtCorrectOffset(t *testing.T) {
	pe := minPE(t)
	if err := transform.PatchPETimeDateStamp(pe, 0xDEADBEEF); err != nil {
		t.Fatalf("PatchPETimeDateStamp: %v", err)
	}
	const peOff = 0x40
	tsOff := peOff + 4 + transform.COFFTimeDateStampOffset
	got := binary.LittleEndian.Uint32(pe[tsOff : tsOff+4])
	if got != 0xDEADBEEF {
		t.Errorf("TimeDateStamp = 0x%X, want 0xDEADBEEF", got)
	}
}

func TestPatchPETimeDateStamp_RejectsTruncated(t *testing.T) {
	if err := transform.PatchPETimeDateStamp([]byte{0x4D, 0x5A}, 0); err == nil {
		t.Error("PatchPETimeDateStamp on 2-byte input: want error, got nil")
	}
}

func TestPatchPETimeDateStamp_RejectsELfanewOverflow(t *testing.T) {
	pe := make([]byte, 0x80)
	pe[0] = 'M'
	pe[1] = 'Z'
	// Point e_lfanew past the buffer end.
	binary.LittleEndian.PutUint32(pe[transform.PEELfanewOffset:transform.PEELfanewOffset+4], 0x1000)
	if err := transform.PatchPETimeDateStamp(pe, 0); err == nil {
		t.Error("PatchPETimeDateStamp with bogus e_lfanew: want error, got nil")
	}
}

func TestRandomTimeDateStamp_WithinRecentFiveYearWindow(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	nowEpoch := uint32(1_700_000_000) // 2023-11-14
	const fiveYears uint32 = 157_680_000

	for i := 0; i < 100; i++ {
		ts := transform.RandomTimeDateStamp(rng, nowEpoch)
		if ts > nowEpoch {
			t.Errorf("ts %d > now %d (future timestamp)", ts, nowEpoch)
		}
		if nowEpoch-ts > fiveYears {
			t.Errorf("ts %d is more than 5 years before now %d (delta = %d s, max = %d s)",
				ts, nowEpoch, nowEpoch-ts, fiveYears)
		}
	}
}

func TestRandomTimeDateStamp_DeterministicGivenSeed(t *testing.T) {
	a := transform.RandomTimeDateStamp(rand.New(rand.NewSource(777)), 1_700_000_000)
	b := transform.RandomTimeDateStamp(rand.New(rand.NewSource(777)), 1_700_000_000)
	if a != b {
		t.Errorf("same seed produced %d vs %d", a, b)
	}
}

func TestRandomTimeDateStamp_DiffersAcrossSeeds(t *testing.T) {
	a := transform.RandomTimeDateStamp(rand.New(rand.NewSource(1)), 1_700_000_000)
	b := transform.RandomTimeDateStamp(rand.New(rand.NewSource(2)), 1_700_000_000)
	if a == b {
		t.Errorf("seeds 1 and 2 collided on %d", a)
	}
}

func TestRandomTimeDateStamp_HandlesZeroNow(t *testing.T) {
	// Edge case: nowEpoch == 0 (caller forgot to thread time.Now)
	// should not crash. Returns any positive uint32.
	got := transform.RandomTimeDateStamp(rand.New(rand.NewSource(1)), 0)
	if got == 0 {
		// Acceptable but rare; the assertion is "doesn't crash".
		_ = got
	}
}

// Placeholder to silence the import-only usage warning when the
// `errors` import is needed by future tests; remove if unused.
var _ = errors.New
