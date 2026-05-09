//go:build linux

package stage1_test

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"testing"
	"unsafe"

	lz4 "github.com/pierrec/lz4/v4"
	"golang.org/x/sys/unix"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// helloStaticPIE is the shared ELF test binary used across the packer suite.
const helloStaticPIE = "../../runtime/testdata/hello_static_pie"

// funcval mirrors the Go runtime's internal funcval layout (runtime/funcval.go).
// A Go func variable is a pointer to a funcval; the first field is the machine
// code address the runtime jumps to when the func is called. This layout is
// stable for amd64 Go across all versions we support (1.21+).
type funcval struct{ code uintptr }

// compressLZ4Block compresses src using LZ4 block format and returns the
// compressed bytes. The destination buffer is pre-allocated using
// lz4.CompressBlockBound to guarantee that even incompressible inputs fit.
func compressLZ4Block(t testing.TB, src []byte) []byte {
	t.Helper()
	dst := make([]byte, lz4.CompressBlockBound(len(src)))
	var c lz4.Compressor
	n, err := c.CompressBlock(src, dst)
	if err != nil {
		t.Fatalf("lz4 CompressBlock: %v", err)
	}
	return dst[:n]
}

// lz4InflateBytes returns the raw machine bytes of the LZ4 inflate decoder
// by emitting them into a fresh amd64.Builder and encoding.
func lz4InflateBytes(t *testing.T) []byte {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitLZ4Inflate(b); err != nil {
		t.Fatalf("EmitLZ4Inflate: %v", err)
	}
	bs, err := b.Encode()
	if err != nil {
		t.Fatalf("Builder.Encode: %v", err)
	}
	return bs
}

// newDecoder mmaps asmBytes as an RX page and returns a callable Go func plus
// a cleanup function. The returned func must not be called after cleanup runs.
//
// Go func values are pointer-to-funcval, where funcval.code is the entry point.
// We heap-allocate a funcval pointing into the mmap'd page so the Go runtime
// calls the asm code via the standard indirect-call path — no cgo required.
//
// The decoder has no GC synchronisation points (no heap allocation, no
// goroutine yields), so calling it from a plain goroutine is safe for short
// inputs. For large inputs (≳100 KB compressed) where the surrounding test
// allocates enough to prime a GC cycle during the asm call, the caller MUST
// guard with runtime.LockOSThread + debug.SetGCPercent(-1); see the SGN chain
// diagnostic for an example. Production stubs never hit this because they run
// on a fresh kernel thread before any Go runtime exists.
func newDecoder(t testing.TB, asmBytes []byte) (fn func(src, dst unsafe.Pointer, srcSize uint64), cleanup func()) {
	t.Helper()

	mem, err := unix.Mmap(-1, 0, len(asmBytes),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	copy(mem, asmBytes)

	fv := &funcval{code: uintptr(unsafe.Pointer(&mem[0]))}

	var f func(src, dst unsafe.Pointer, srcSize uint64)
	*(*uintptr)(unsafe.Pointer(&f)) = uintptr(unsafe.Pointer(fv))

	cleanup = func() {
		if err := unix.Munmap(mem); err != nil {
			t.Errorf("munmap: %v", err)
		}
	}
	return f, cleanup
}

// runLZ4Asm emits a fresh decoder, mmaps it, and runs it on src → dst.
// It is the single-shot helper for tests that don't need to reuse the page.
func runLZ4Asm(t *testing.T, asmBytes []byte, src, dst []byte) {
	t.Helper()
	fn, cleanup := newDecoder(t, asmBytes)
	defer cleanup()

	var srcPtr, dstPtr unsafe.Pointer
	if len(src) > 0 {
		srcPtr = unsafe.Pointer(&src[0])
	}
	if len(dst) > 0 {
		dstPtr = unsafe.Pointer(&dst[0])
	}
	fn(srcPtr, dstPtr, uint64(len(src)))
}

// roundTrip compresses original with LZ4 block format, runs the asm decoder,
// and asserts the decoded output is byte-equal to the original.
func roundTrip(t *testing.T, name string, original []byte) {
	t.Helper()

	compressed := compressLZ4Block(t, original)
	t.Logf("%s: original=%d compressed=%d ratio=%.2f",
		name, len(original), len(compressed),
		float64(len(compressed))/float64(max(len(original), 1)))

	decoded := make([]byte, len(original))
	asmBytes := lz4InflateBytes(t)
	runLZ4Asm(t, asmBytes, compressed, decoded)

	if !bytes.Equal(decoded, original) {
		t.Errorf("%s: decoded output mismatch: got %d bytes, want %d bytes", name, len(decoded), len(original))
		if len(original) <= 64 {
			t.Errorf("  original:  %x", original)
			t.Errorf("  decoded:   %x", decoded)
		}
	}
}

// TestEmitLZ4Inflate_RoundTrip_AllZero verifies that a 4 KiB all-zero
// payload compresses and decompresses correctly. Zero bytes produce
// a highly compressible input with long match runs, exercising the
// match-copy path heavily.
func TestEmitLZ4Inflate_RoundTrip_AllZero(t *testing.T) {
	roundTrip(t, "all-zero-4k", make([]byte, 4096))
}

// TestEmitLZ4Inflate_RoundTrip_AllRandom verifies that a 4 KiB
// cryptographically random payload round-trips. Random bytes are
// incompressible in the entropy sense but LZ4 still emits a valid
// block (literal-only sequences); the test exercises the literal-only path.
func TestEmitLZ4Inflate_RoundTrip_AllRandom(t *testing.T) {
	src := make([]byte, 4096)
	if _, err := rand.Read(src); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	roundTrip(t, "all-random-4k", src)
}

// TestEmitLZ4Inflate_RoundTrip_RLE verifies a 4 KiB single-byte run
// (all 0xAB). LZ4 compresses this to a token + match_offset=1 + long
// length extension. The decoder's explicit byte-by-byte match loop (not
// rep movsb) is required: each output byte is the byte just written,
// so the copy-source pointer must read from already-written output.
func TestEmitLZ4Inflate_RoundTrip_RLE(t *testing.T) {
	roundTrip(t, "rle-4k-0xAB", bytes.Repeat([]byte{0xAB}, 4096))
}

// TestEmitLZ4Inflate_RoundTrip_RealText decompresses a real x86-64 .text
// section to verify the decoder handles realistic instruction-stream bytes
// (high entropy, mixture of repeating patterns and unique bytes).
func TestEmitLZ4Inflate_RoundTrip_RealText(t *testing.T) {
	f, err := elf.Open(helloStaticPIE)
	if err != nil {
		t.Skipf("cannot open %s: %v", helloStaticPIE, err)
	}
	defer f.Close()

	sec := f.Section(".text")
	if sec == nil {
		t.Fatalf(".text section not found in %s", helloStaticPIE)
	}
	raw, err := sec.Data()
	if err != nil {
		t.Fatalf(".text Data(): %v", err)
	}
	// Limit to 64 KiB so we stay within single-block LZ4 territory.
	if len(raw) > 65536 {
		raw = raw[:65536]
	}

	roundTrip(t, "real-text", raw)
}

// TestEmitLZ4Inflate_RoundTrip_EdgeSizes is a table-driven test for
// boundary sizes. It checks that the decoder handles the degenerate cases
// (empty, 1 byte, just under/over the 15-token extension threshold) and
// the 65535/65536-byte sizes that stress the match-offset field width.
func TestEmitLZ4Inflate_RoundTrip_EdgeSizes(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"0-bytes", 0},
		{"1-byte", 1},
		{"15-bytes", 15},
		{"16-bytes", 16},
		{"4095-bytes", 4095},
		{"65535-bytes", 65535},
		{"65536-bytes", 65536},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := make([]byte, tc.size)
			// Pattern that stays compressible at all sizes.
			for i := range src {
				src[i] = byte(i % 17)
			}
			roundTrip(t, tc.name, src)
		})

		// Random sub-test exercises the literal-only path at each boundary;
		// skip size==0 since random and patterned empty inputs are identical.
		if tc.size == 0 {
			continue
		}
		t.Run(tc.name+"-random", func(t *testing.T) {
			src := make([]byte, tc.size)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			roundTrip(t, tc.name+"-random", src)
		})
	}
}

// TestEmitLZ4Inflate_ByteCount verifies the emitted decoder is within the
// documented 200-byte budget. A regression here signals an unintentional
// instruction expansion by the golang-asm lowering pass.
func TestEmitLZ4Inflate_ByteCount(t *testing.T) {
	bs := lz4InflateBytes(t)
	t.Logf("decoder size: %d bytes", len(bs))
	if len(bs) > 200 {
		t.Errorf("decoder too large: %d bytes, budget is 200", len(bs))
	}
}

// TestEmitLZ4Inflate_RoundTrip_ZeroSizeSpecial verifies the 0-byte edge case
// in isolation. LZ4 encodes an empty payload as a single 0x00 token byte;
// the decoder must advance past it, reach src_end, and return without
// writing anything.
func TestEmitLZ4Inflate_RoundTrip_ZeroSizeSpecial(t *testing.T) {
	compressed := compressLZ4Block(t, []byte{})
	t.Logf("compressed-empty: %x (%d bytes)", compressed, len(compressed))

	// Provide a 1-byte scratch as the dst pointer so the pointer is valid;
	// the decoder must not write to it (0-byte original → 0-byte output).
	scratch := []byte{0xFF}
	asmBytes := lz4InflateBytes(t)
	runLZ4Asm(t, asmBytes, compressed, scratch)

	if scratch[0] != 0xFF {
		t.Errorf("decoder wrote to dst for 0-byte payload: scratch[0] = 0x%02x", scratch[0])
	}
}

// BenchmarkEmitLZ4Inflate_4k benchmarks the asm decoder throughput on a
// 4 KiB all-zero payload (maximally compressible) to establish a baseline.
func BenchmarkEmitLZ4Inflate_4k(b *testing.B) {
	src := make([]byte, 4096)
	compressed := compressLZ4Block(b, src)

	asmBytes, err := func() ([]byte, error) {
		bldr, err := amd64.New()
		if err != nil {
			return nil, err
		}
		if err := stage1.EmitLZ4Inflate(bldr); err != nil {
			return nil, err
		}
		return bldr.Encode()
	}()
	if err != nil {
		b.Fatal(err)
	}

	fn, cleanup := newDecoder(b, asmBytes)
	defer cleanup()

	decoded := make([]byte, len(src))
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(unsafe.Pointer(&compressed[0]), unsafe.Pointer(&decoded[0]), uint64(len(compressed)))
	}
}
