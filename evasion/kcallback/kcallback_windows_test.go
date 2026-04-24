//go:build windows && amd64

package kcallback

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

// memoryReader serves fixed buffers at fixed kernel VAs. Used to
// simulate a driver-backed KernelReader for readCallbackArray tests.
type memoryReader struct {
	regions map[uintptr][]byte
}

func (m *memoryReader) ReadKernel(addr uintptr, buf []byte) (int, error) {
	// Find the region whose base <= addr < base+len.
	for base, data := range m.regions {
		if addr >= base && addr < base+uintptr(len(data)) {
			off := addr - base
			n := copy(buf, data[off:])
			return n, nil
		}
	}
	return 0, ErrNoKernelReader
}

// TestReadCallbackArray_ParsesPopulatedSlots walks a crafted 3-slot
// array with 2 populated entries (one enabled, one disabled) + 1
// empty slot, and asserts the Callback slice matches.
func TestReadCallbackArray_ParsesPopulatedSlots(t *testing.T) {
	const arrayBase uintptr = 0xFFFFF80100000000
	const blockA uintptr = 0xFFFFF80200000100
	const blockB uintptr = 0xFFFFF80200000200
	const funcA uintptr = 0xFFFFF80300001000
	const funcB uintptr = 0xFFFFF80300002000

	// Build the 3-slot array: [enabled-blockA, 0, disabled-blockB].
	// low 4 bits are flags; we set bit 0 on slot 0 (enabled) and
	// leave bit 0 clear on slot 2 (disabled). Block addresses must
	// be 16-byte aligned — both ends match.
	arr := make([]byte, 3*8)
	binary.LittleEndian.PutUint64(arr[0:], uint64(blockA)|1)
	binary.LittleEndian.PutUint64(arr[8:], 0)
	binary.LittleEndian.PutUint64(arr[16:], uint64(blockB))

	// Each block has Function at offset 8 (first 8 bytes are
	// ExRundownProtect we don't care about).
	bA := make([]byte, 16)
	binary.LittleEndian.PutUint64(bA[8:], uint64(funcA))
	bB := make([]byte, 16)
	binary.LittleEndian.PutUint64(bB[8:], uint64(funcB))

	reader := &memoryReader{regions: map[uintptr][]byte{
		arrayBase: arr,
		blockA:    bA,
		blockB:    bB,
	}}

	got, err := readCallbackArray(reader, arrayBase, 3, KindCreateProcess)
	if err != nil {
		t.Fatalf("readCallbackArray: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d callbacks, want 2 (slot 1 is empty)", len(got))
	}
	if got[0].Index != 0 || got[0].Address != funcA || !got[0].Enabled {
		t.Errorf("slot 0: %+v", got[0])
	}
	if got[1].Index != 2 || got[1].Address != funcB || got[1].Enabled {
		t.Errorf("slot 2: %+v", got[1])
	}
	// Both Kinds must be the one we asked for.
	for i, cb := range got {
		if cb.Kind != KindCreateProcess {
			t.Errorf("got[%d].Kind = %v, want KindCreateProcess", i, cb.Kind)
		}
	}
}

// TestNtoskrnlBase_Resolves asserts the user-mode query succeeds and
// yields a non-zero kernel VA. Any BOOT value > 0 is structurally
// valid; kernel addresses live in the canonical high range on x64.
func TestNtoskrnlBase_Resolves(t *testing.T) {
	base, err := NtoskrnlBase()
	if err != nil {
		t.Fatalf("NtoskrnlBase: %v", err)
	}
	if base == 0 {
		t.Fatal("NtoskrnlBase returned zero")
	}
	// x64 kernel VAs start in the canonical high half; low addresses
	// would indicate a usermode mixup.
	if base < 0xFFFF000000000000 {
		t.Fatalf("NtoskrnlBase 0x%X is not in the canonical high half", base)
	}
}

// TestDriverAt_ResolvesNtoskrnl confirms DriverAt resolves a
// known-in-kernel address (ntoskrnl's own base) back to ntoskrnl.exe.
func TestDriverAt_ResolvesNtoskrnl(t *testing.T) {
	base, err := NtoskrnlBase()
	if err != nil {
		t.Fatalf("NtoskrnlBase: %v", err)
	}
	name, err := DriverAt(base)
	if err != nil {
		t.Fatalf("DriverAt(0x%X): %v", base, err)
	}
	if !strings.EqualFold(name, "ntoskrnl.exe") {
		t.Fatalf("DriverAt(ntoskrnl.base) = %q, want ntoskrnl.exe", name)
	}
}

// TestDriverAt_ReturnsEmptyForUsermode asserts a userland address
// (this test's own stack) resolves to "" + nil — no driver should
// cover it.
func TestDriverAt_ReturnsEmptyForUsermode(t *testing.T) {
	var stackLocal int
	name, err := DriverAt(uintptr(unsafe.Pointer(&stackLocal)))
	if err != nil {
		t.Fatalf("DriverAt(stack): %v", err)
	}
	if name != "" {
		t.Fatalf("DriverAt(stack) = %q, want empty", name)
	}
}

// TestEnumerate_NilReaderReturnsErrNoKernelReader covers the happy
// nil-guard path; the real enumeration is exercised via mock reader
// in kcallback_test.go.
func TestEnumerate_NilReaderReturnsErrNoKernelReader(t *testing.T) {
	_, err := Enumerate(nil, OffsetTable{CreateProcessRoutineRVA: 0x100})
	if err == nil {
		t.Fatal("nil reader: want error")
	}
}
