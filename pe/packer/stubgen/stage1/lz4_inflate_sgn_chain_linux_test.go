//go:build linux && maldev_packer_lz4_diagnose

package stage1_test

import (
	"bytes"
	"unsafe"
	"debug/elf"
	"path/filepath"
	"testing"

	"github.com/pierrec/lz4/v4"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// TestLZ4Inflate_SGNChain_RoundTrip is the diagnostic for the C3-stage-2
// SIGSEGV. It exercises the EXACT byte chain the runtime stub does:
//
//	original .text → LZ4 compress → SGN encode → SGN decode → LZ4 inflate (asm)
//
// without going through PackBinary or any binary-layout machinery. If this
// round-trips, the bug is in the in-binary layout (section bounds, page
// protections, kernel RWX refusal). If this CRASHES, the bug is in the
// SGN+LZ4 chain semantics — the SGN-decoded bytes don't match what the
// pure-Go LZ4 inflate expects.
//
// See docs/refactor-2026-doc/KNOWN-ISSUES-1e.md C3-stage-2 hypothesis 1.
func TestLZ4Inflate_SGNChain_RoundTrip(t *testing.T) {
	// Step 1: get a real .text fragment from the Phase 1f fixture.
	fixturePath := filepath.Join("..", "..", "runtime", "testdata", "hello_static_pie")
	fixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	f, err := elf.Open(fixturePath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()
	textSec := f.Section(".text")
	if textSec == nil {
		t.Fatal("no .text section in fixture")
	}
	originalText, err := textSec.Data()
	if err != nil {
		t.Fatalf("read .text data: %v", err)
	}
	originalSize := uint32(len(originalText))
	t.Logf("original .text: %d bytes", originalSize)

	// Step 2: LZ4 compress (Block format), same as stubgen.Generate.
	dst := make([]byte, lz4.CompressBlockBound(len(originalText)))
	var c lz4.Compressor
	n, err := c.CompressBlock(originalText, dst)
	if err != nil {
		t.Fatalf("lz4.CompressBlock: %v", err)
	}
	if n == 0 {
		t.Skip("LZ4 returned 0 (incompressible) — diagnostic doesn't apply")
	}
	compressed := dst[:n]
	compressedSize := uint32(n)
	t.Logf("compressed: %d bytes (ratio %.1f%%)", compressedSize, 100.0*float64(compressedSize)/float64(originalSize))

	// Step 3: build the on-disk payload like stubgen.Generate does:
	// safety_margin zero bytes + compressed bytes.
	safetyMargin := (originalSize+254)/255 + 16
	if safetyMargin < 64 {
		safetyMargin = 64
	}
	payload := make([]byte, safetyMargin+compressedSize) // first safetyMargin bytes are zero
	copy(payload[safetyMargin:], compressed)
	t.Logf("payload: %d bytes (safety_margin=%d + compressed=%d)", len(payload), safetyMargin, compressedSize)

	// Step 4: SGN encode + decode round-trip on the payload (using poly engine
	// the same way stubgen.Generate uses it).
	eng, err := poly.NewEngine(1, 1) // seed=1, rounds=1 — match the failing E2E
	if err != nil {
		t.Fatalf("poly.NewEngine: %v", err)
	}
	encoded, rds, err := eng.EncodePayloadExcluding(payload, stage1.BaseReg)
	if err != nil {
		t.Fatalf("EncodePayloadExcluding: %v", err)
	}

	decoded := append([]byte(nil), encoded...)
	for i := len(rds) - 1; i >= 0; i-- {
		key := rds[i].Key
		for j := range decoded {
			decoded[j] = rds[i].Subst.Decode(decoded[j], key)
		}
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("SGN round-trip diverged from input — bug in SGN engine, not in LZ4 chain")
	}
	t.Log("SGN round-trip OK")

	// Step 5: assert the decoded bytes match the layout we expect:
	// [0..safetyMargin) = zero bytes; [safetyMargin..) = compressed bytes.
	for i := uint32(0); i < safetyMargin; i++ {
		if decoded[i] != 0 {
			t.Errorf("decoded[%d] = %#x, want 0 (zero prefix corrupted by SGN round-trip)",
				i, decoded[i])
			break
		}
	}
	if !bytes.Equal(decoded[safetyMargin:], compressed) {
		t.Errorf("decoded[safetyMargin:] != compressed — SGN round-trip corrupts compressed bytes")
	}
	t.Log("decoded layout matches expected (zero prefix + compressed)")

	// Step 6: run the asm LZ4 decoder on the decoded[safetyMargin:] bytes.
	// Use the same harness pattern as TestEmitLZ4Inflate_RoundTrip_*.
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitLZ4Inflate(b); err != nil {
		t.Fatalf("EmitLZ4Inflate: %v", err)
	}
	asmBytes, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode asm: %v", err)
	}
	decodeFn, cleanup := newDecoder(t, asmBytes)
	defer cleanup()

	// Run the decoder via mmap: src = decoded[safetyMargin:], srcSize = compressedSize,
	// dst is a fresh buffer (NOT in-place). This isolates the LZ4 decoder behavior
	// from any in-place layout concerns.
	out := make([]byte, originalSize)
	decodeFn(unsafe.Pointer(&decoded[safetyMargin]), unsafe.Pointer(&out[0]), uint64(compressedSize))

	if !bytes.Equal(out, originalText) {
		t.Errorf("asm LZ4 inflate of SGN-decoded bytes != original .text — chain semantics broken")
		// Log first divergence
		for i := range originalText {
			if out[i] != originalText[i] {
				t.Logf("first divergence at byte %d: got %#x, want %#x", i, out[i], originalText[i])
				break
			}
		}
		return
	}
	t.Log("FULL CHAIN ROUND-TRIP OK — bug is NOT in SGN+LZ4 semantics, must be in binary layout")
}
