//go:build windows && amd64

package kcallback

import (
	"encoding/binary"
	"fmt"
)

// Enumerate reads the three callback arrays described by tab via
// reader, resolves each callback's owning driver (best effort), and
// returns the concatenated slice. Entries whose high bits address a
// zero-valued slot are skipped; entries whose low bit is 0 are
// included with Enabled=false.
//
// Layout: each array slot is 8 bytes (uint64) holding a PEX_CALLBACK
// (pointer to a ROUTINE_BLOCK with low 4 bits used for flags). The
// real callback function is at offset 8 of the ROUTINE_BLOCK.
//
// Caller must supply tab.*RoutineRVA for the current ntoskrnl build.
// Omitted RVAs (0) skip that array cleanly. tab.ArrayLen defaults to
// 64 when zero (Win10 PspCreateProcessNotifyRoutine capacity).
func Enumerate(reader KernelReader, tab OffsetTable) ([]Callback, error) {
	if reader == nil {
		return nil, ErrNoKernelReader
	}
	base, err := NtoskrnlBase()
	if err != nil {
		return nil, err
	}
	arrLen := tab.ArrayLen
	if arrLen == 0 {
		arrLen = 64
	}

	steps := []struct {
		kind Kind
		rva  uint32
	}{
		{KindCreateProcess, tab.CreateProcessRoutineRVA},
		{KindCreateThread, tab.CreateThreadRoutineRVA},
		{KindLoadImage, tab.LoadImageRoutineRVA},
	}

	var out []Callback
	for _, s := range steps {
		if s.rva == 0 {
			continue
		}
		cb, err := readCallbackArray(reader, base+uintptr(s.rva), arrLen, s.kind)
		if err != nil {
			return out, fmt.Errorf("%s: %w", s.kind, err)
		}
		out = append(out, cb...)
	}
	return out, nil
}

// readCallbackArray reads n 8-byte slots starting at arrayAddr,
// dereferences the masked ROUTINE_BLOCK pointer + 8 for each non-zero
// slot, and returns one Callback per populated entry.
func readCallbackArray(reader KernelReader, arrayAddr uintptr, n int, kind Kind) ([]Callback, error) {
	buf := make([]byte, n*8)
	read, err := reader.ReadKernel(arrayAddr, buf)
	if err != nil {
		return nil, fmt.Errorf("read array @0x%X: %w", arrayAddr, err)
	}
	if read < n*8 {
		return nil, fmt.Errorf("short read: %d/%d", read, n*8)
	}

	var out []Callback
	for i := 0; i < n; i++ {
		slot := binary.LittleEndian.Uint64(buf[i*8:])
		if slot == 0 {
			continue
		}
		block := uintptr(slot &^ 0xF)
		enabled := slot&1 != 0

		fnBuf := make([]byte, 8)
		if _, err := reader.ReadKernel(block+8, fnBuf); err != nil {
			// Can't read the block — record the slot but leave Address zero.
			out = append(out, Callback{
				Kind:    kind,
				Index:   i,
				Enabled: enabled,
			})
			continue
		}
		fn := uintptr(binary.LittleEndian.Uint64(fnBuf))
		mod, _ := DriverAt(fn)
		out = append(out, Callback{
			Kind:    kind,
			Index:   i,
			Address: fn,
			Module:  mod,
			Enabled: enabled,
		})
	}
	return out, nil
}
