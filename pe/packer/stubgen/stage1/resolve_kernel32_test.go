package stage1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"golang.org/x/arch/x86/x86asm"
)

// emitResolveBytes is a thin wrapper that builds + encodes the
// resolver and returns the produced bytes. Used by every test
// below so they share the same compilation surface.
func emitResolveBytes(t *testing.T, exportName string) []byte {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitResolveKernel32Export(b, exportName); err != nil {
		t.Fatalf("EmitResolveKernel32Export(%q): %v", exportName, err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}

// TestEmitResolveKernel32Export_RejectsEmptyExportName — guard
// against hashing the empty string (would produce hash=0 which
// collides with the export-loop's initial accumulator state).
func TestEmitResolveKernel32Export_RejectsEmptyExportName(t *testing.T) {
	b, _ := amd64.New()
	err := stage1.EmitResolveKernel32Export(b, "")
	if !errors.Is(err, stage1.ErrEmptyExportName) {
		t.Errorf("got %v, want ErrEmptyExportName", err)
	}
}

// TestEmitResolveKernel32Export_AssemblesCleanly — the assembled
// bytes must round-trip through golang.org/x/arch/x86/x86asm.Decode
// without errors. Catches malformed encodings, ill-sized operands,
// and accidentally-emitted invalid opcodes.
func TestEmitResolveKernel32Export_AssemblesCleanly(t *testing.T) {
	out := emitResolveBytes(t, "CreateThread")
	if len(out) == 0 {
		t.Fatal("resolver emitted 0 bytes")
	}
	off := 0
	for off < len(out) {
		inst, err := x86asm.Decode(out[off:], 64)
		if err != nil {
			t.Fatalf("decode at offset %d: %v (next bytes %x)", off, err, out[off:min(off+8, len(out))])
		}
		if inst.Len == 0 {
			t.Fatalf("zero-length decode at offset %d", off)
		}
		off += inst.Len
	}
}

// TestEmitResolveKernel32Export_SplicesExportHash — emit the
// resolver for two different exports; the bytes must differ at
// exactly 4 bytes (the spliced export-hash imm32 in the CMPL
// instruction). The rest of the asm template is identical.
func TestEmitResolveKernel32Export_SplicesExportHash(t *testing.T) {
	out1 := emitResolveBytes(t, "CreateThread")
	out2 := emitResolveBytes(t, "ExitProcess")

	if len(out1) != len(out2) {
		t.Fatalf("byte length differs: %d vs %d (export-name length should not affect the asm size)",
			len(out1), len(out2))
	}

	diffs := 0
	for i := range out1 {
		if out1[i] != out2[i] {
			diffs++
		}
	}
	if diffs != 4 {
		t.Errorf("got %d differing bytes, want 4 (the spliced export-hash imm32)", diffs)
	}

	// Confirm one of the two imm32 splices is the expected hash.
	hash1 := stage1.Ror13HashASCII("CreateThread")
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], hash1)
	if !bytes.Contains(out1, want[:]) {
		t.Errorf("hash of %q (%#x) not found in emitted bytes", "CreateThread", hash1)
	}
}

// TestEmitResolveKernel32Export_ContainsKernel32Hash — the
// pre-baked module hash must appear once in the emitted bytes
// (as the imm32 of the `cmp r10d, Kernel32DLLHash` instruction).
func TestEmitResolveKernel32Export_ContainsKernel32Hash(t *testing.T) {
	out := emitResolveBytes(t, "CreateThread")
	var hashBytes [4]byte
	binary.LittleEndian.PutUint32(hashBytes[:], stage1.Kernel32DLLHash)
	if got := bytes.Count(out, hashBytes[:]); got != 1 {
		t.Errorf("Kernel32DLLHash imm32 occurs %d times, want 1", got)
	}
}

// TestEmitResolveKernel32Export_GSPrefixPresent — the first
// instruction must be the GS-prefixed `mov rax, gs:[0x60]` (the
// PEB load). Catches accidental removal of the prefix opcode.
func TestEmitResolveKernel32Export_GSPrefixPresent(t *testing.T) {
	out := emitResolveBytes(t, "CreateThread")
	want := []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}
	if !bytes.HasPrefix(out, want) {
		t.Errorf("first %d bytes = %x, want %x (mov rax, gs:[0x60])",
			len(want), out[:min(len(out), len(want))], want)
	}
}

// TestEmitResolveKernel32Export_PinnedByteCount — the resolver's
// emitted size is invariant under exportName changes (only the
// 4-byte spliced hash differs, which doesn't grow the encoding).
// Pinning the exact byte count catches accidental drift from any
// future tweak to the emitter that quietly changes the asm size —
// would otherwise hide inside the converted-DLL stub's 4 KiB
// budget for 50%+ regressions.
func TestEmitResolveKernel32Export_PinnedByteCount(t *testing.T) {
	const want = 196 // measured 2026-05-11; bump deliberately if asm changes
	out := emitResolveBytes(t, "CreateThread")
	if len(out) != want {
		t.Errorf("resolver size %d B, want %d B (drift from the asm template)", len(out), want)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
