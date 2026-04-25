//go:build windows && amd64

package kcallback

import (
	"encoding/binary"
	"errors"
	"testing"
)

// rwReader extends memoryReader (in kcallback_windows_test.go) with a
// WriteKernel method so the same regions back both the read and write
// paths under tests.
type rwReader struct {
	*memoryReader
}

func (r *rwReader) WriteKernel(addr uintptr, data []byte) (int, error) {
	for base, region := range r.regions {
		if addr >= base && addr+uintptr(len(data)) <= base+uintptr(len(region)) {
			off := addr - base
			n := copy(region[off:], data)
			return n, nil
		}
	}
	return 0, ErrNoKernelReader
}

func newRW(regions map[uintptr][]byte) *rwReader {
	return &rwReader{memoryReader: &memoryReader{regions: regions}}
}

// TestRemoveToken_IsZeroOnDefault keeps the deferred-cleanup idiom
// honest: `var tok RemoveToken` ... `defer Restore(tok, w)` must be a
// no-op until Remove populates it.
func TestRemoveToken_IsZeroOnDefault(t *testing.T) {
	var tok RemoveToken
	if !tok.IsZero() {
		t.Error("zero RemoveToken.IsZero() = false, want true")
	}
}

// TestRemove_NilWriter ensures the public-facing API rejects nil
// writers with the documented sentinel.
func TestRemove_NilWriter(t *testing.T) {
	cb := Callback{Kind: KindCreateProcess, Index: 0, SlotAddr: 0xFFFF000000001000}
	_, err := Remove(cb, nil)
	if !errors.Is(err, ErrNoKernelReader) {
		t.Errorf("Remove(_, nil) err = %v, want ErrNoKernelReader", err)
	}
}

// TestRemove_EmptySlotAddrReturnsErrEmptySlot covers the
// hand-constructed-Callback foot-gun. SlotAddr is populated by
// Enumerate; a literal Callback{} has it zero, and Remove must refuse
// to write at address 0.
func TestRemove_EmptySlotAddrReturnsErrEmptySlot(t *testing.T) {
	w := newRW(nil)
	_, err := Remove(Callback{Kind: KindCreateProcess, Index: 0}, w)
	if !errors.Is(err, ErrEmptySlot) {
		t.Errorf("Remove(SlotAddr=0) err = %v, want ErrEmptySlot", err)
	}
}

// TestRemove_AlreadyZeroSlotReturnsErrEmptySlot covers the race
// window where the slot was zeroed between Enumerate and Remove.
func TestRemove_AlreadyZeroSlotReturnsErrEmptySlot(t *testing.T) {
	const slot uintptr = 0xFFFFF80100000000
	w := newRW(map[uintptr][]byte{slot: make([]byte, 8)})
	cb := Callback{Kind: KindCreateProcess, Index: 0, SlotAddr: slot}
	_, err := Remove(cb, w)
	if !errors.Is(err, ErrEmptySlot) {
		t.Errorf("Remove(zero slot) err = %v, want ErrEmptySlot", err)
	}
}

// TestRemove_ZeroesSlotAndCapturesOriginal is the happy path: Remove
// zeros the slot and the returned token carries enough state for
// Restore to put it back.
func TestRemove_ZeroesSlotAndCapturesOriginal(t *testing.T) {
	const slot uintptr = 0xFFFFF80100000000
	const original uint64 = 0xFFFFF80200000123
	region := make([]byte, 8)
	binary.LittleEndian.PutUint64(region, original)
	w := newRW(map[uintptr][]byte{slot: region})
	cb := Callback{Kind: KindCreateThread, Index: 7, SlotAddr: slot}

	tok, err := Remove(cb, w)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if tok.OriginalSlot != original {
		t.Errorf("token.OriginalSlot = 0x%X, want 0x%X", tok.OriginalSlot, original)
	}
	if tok.SlotAddr != slot {
		t.Errorf("token.SlotAddr = 0x%X, want 0x%X", tok.SlotAddr, slot)
	}
	if tok.Kind != KindCreateThread || tok.Index != 7 {
		t.Errorf("token kind/index = %v/%d, want KindCreateThread/7", tok.Kind, tok.Index)
	}
	if got := binary.LittleEndian.Uint64(region); got != 0 {
		t.Errorf("slot post-Remove = 0x%X, want 0", got)
	}
}

// TestRestore_RoundTrips Remove → Restore must leave the slot exactly
// as Enumerate first observed it.
func TestRestore_RoundTrips(t *testing.T) {
	const slot uintptr = 0xFFFFF80100000010
	const original uint64 = 0xFFFFF80200000ABC
	region := make([]byte, 8)
	binary.LittleEndian.PutUint64(region, original)
	w := newRW(map[uintptr][]byte{slot: region})
	cb := Callback{Kind: KindLoadImage, Index: 3, SlotAddr: slot}

	tok, err := Remove(cb, w)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := Restore(tok, w); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := binary.LittleEndian.Uint64(region); got != original {
		t.Errorf("slot post-Restore = 0x%X, want 0x%X", got, original)
	}
}

// TestRestore_ZeroTokenIsNoOp covers the deferred-cleanup idiom: a
// never-populated token must Restore as a no-op so callers can defer
// it before Remove runs.
func TestRestore_ZeroTokenIsNoOp(t *testing.T) {
	w := newRW(nil)
	if err := Restore(RemoveToken{}, w); err != nil {
		t.Errorf("Restore(zero token) = %v, want nil", err)
	}
}

// TestRestore_NilWriterReturnsErrNoKernelReader keeps Restore symmetric
// with Remove on the nil-writer guard for non-zero tokens.
func TestRestore_NilWriterReturnsErrNoKernelReader(t *testing.T) {
	tok := RemoveToken{Kind: KindCreateProcess, Index: 0, SlotAddr: 0x1000, OriginalSlot: 1}
	if err := Restore(tok, nil); !errors.Is(err, ErrNoKernelReader) {
		t.Errorf("Restore(_, nil) err = %v, want ErrNoKernelReader", err)
	}
}

// TestEnumerate_PopulatesSlotAddr ensures Enumerate reports each
// callback's SlotAddr — the field Remove keys on. Without this,
// Remove would always reject non-Enumerate-derived Callbacks.
func TestEnumerate_PopulatesSlotAddr(t *testing.T) {
	const arrayBase uintptr = 0xFFFFF80100000000
	const blockA uintptr = 0xFFFFF80200000100
	const funcA uintptr = 0xFFFFF80300001000

	arr := make([]byte, 2*8)
	binary.LittleEndian.PutUint64(arr[0:], uint64(blockA)|1)
	bA := make([]byte, 16)
	binary.LittleEndian.PutUint64(bA[8:], uint64(funcA))
	r := &memoryReader{regions: map[uintptr][]byte{arrayBase: arr, blockA: bA}}

	got, err := readCallbackArray(r, arrayBase, 2, KindCreateProcess)
	if err != nil {
		t.Fatalf("readCallbackArray: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d callbacks, want 1", len(got))
	}
	if got[0].SlotAddr != arrayBase {
		t.Errorf("got[0].SlotAddr = 0x%X, want 0x%X", got[0].SlotAddr, arrayBase)
	}
}
