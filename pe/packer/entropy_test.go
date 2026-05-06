package packer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"testing"
)

// shannon returns the byte-histogram Shannon entropy of `data`
// in bits/byte. Range [0, 8]. Uniform random data sits at ~8;
// real .text sections sit around 5.5-6; runs of identical bytes
// drop to 0.
func shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var hist [256]int
	for _, b := range data {
		hist[b]++
	}
	total := float64(len(data))
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

func TestEntropyCover_String(t *testing.T) {
	cases := []struct {
		e    EntropyCover
		want string
	}{
		{EntropyCoverInterleave, "interleave"},
		{EntropyCoverCarrier, "carrier"},
		{EntropyCoverHexAlphabet, "hex-alphabet"},
		{EntropyCover(99), "entropy-cover(99)"},
	}
	for _, c := range cases {
		if got := c.e.String(); got != c.want {
			t.Errorf("EntropyCover(%d).String() = %q, want %q", c.e, got, c.want)
		}
	}
}

func TestOpEntropyCover_String(t *testing.T) {
	if got := OpEntropyCover.String(); got != "entropy-cover" {
		t.Errorf("OpEntropyCover.String() = %q, want %q", got, "entropy-cover")
	}
}

// TestInterleave_RoundTrip covers EntropyCoverInterleave with the
// default tuning and a random 64 KiB payload.
func TestInterleave_RoundTrip(t *testing.T) {
	data := make([]byte, 64*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed random: %v", err)
	}
	out, _, err := applyEntropyCover(EntropyCoverInterleave, nil, data)
	if err != nil {
		t.Fatalf("applyEntropyCover: %v", err)
	}
	if len(out) <= len(data) {
		t.Fatalf("expected interleave output > input (defaults insert padding); got %d <= %d",
			len(out), len(data))
	}
	got, err := reverseEntropyCover(EntropyCoverInterleave, nil, out)
	if err != nil {
		t.Fatalf("reverseEntropyCover: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d (first diff search…)", len(got), len(data))
	}
}

// TestInterleave_DropsApparentEntropy verifies the headline claim
// that interleaving with code-like padding lowers Shannon entropy
// of a previously-uniform input.
func TestInterleave_DropsApparentEntropy(t *testing.T) {
	data := make([]byte, 256*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed random: %v", err)
	}
	before := shannon(data)
	if before < 7.9 {
		t.Fatalf("uniform input should be ~8 bits/byte, got %.3f", before)
	}
	out, _, err := applyEntropyCover(EntropyCoverInterleave, nil, data)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	after := shannon(out)
	t.Logf("interleave: %.3f → %.3f bits/byte (input %d → %d)", before, after, len(data), len(out))
	if after >= before {
		t.Fatalf("interleave failed to drop entropy: %.3f → %.3f", before, after)
	}
	// Default 33% padding on uniform random data lands around
	// 7.4 bits/byte (240 non-alphabet bytes share 66.7%, 16
	// alphabet bytes get 33.3% concentrated → Shannon ≈ 7.4).
	// The real <5 target requires stacking with HexAlphabet —
	// see TestEntropyCover_StackedDeepDrop.
	if after >= 7.6 {
		t.Errorf("interleave should land below 7.6 bits/byte with default 33%% padding; got %.3f", after)
	}
}

// TestEntropyCover_StackedDeepDrop demonstrates the operational
// recommendation: stack EntropyCoverHexAlphabet AFTER an inner
// step. HexAlphabet caps apparent entropy at 4 bits/byte —
// Interleave alone caps near 7.4 (math-bound by mix ratio).
func TestEntropyCover_StackedDeepDrop(t *testing.T) {
	data := make([]byte, 32*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	step1, _, err := applyEntropyCover(EntropyCoverInterleave, nil, data)
	if err != nil {
		t.Fatalf("step1: %v", err)
	}
	step2, _, err := applyEntropyCover(EntropyCoverHexAlphabet, nil, step1)
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	stacked := shannon(step2)
	t.Logf("stacked Interleave→HexAlphabet: %.3f bits/byte", stacked)
	if stacked > 4.05 {
		t.Errorf("stacked entropy %.3f exceeds 4 bits/byte ceiling", stacked)
	}
	// Reverse the stack and confirm round-trip.
	rev1, err := reverseEntropyCover(EntropyCoverHexAlphabet, nil, step2)
	if err != nil {
		t.Fatalf("rev1: %v", err)
	}
	rev2, err := reverseEntropyCover(EntropyCoverInterleave, nil, rev1)
	if err != nil {
		t.Fatalf("rev2: %v", err)
	}
	if !bytes.Equal(rev2, data) {
		t.Fatalf("stacked round-trip mismatch")
	}
}

// TestInterleave_AllPadPatterns verifies every pad pattern
// round-trips cleanly.
func TestInterleave_AllPadPatterns(t *testing.T) {
	data := bytes.Repeat([]byte{'A'}, 4096)
	patterns := []PadPattern{PadPatternZeros, PadPatternInt3, PadPatternNOP, PadPatternMixedASM}
	for _, p := range patterns {
		key := []byte{6, 64, byte(p), 0} // chunk=64, pad=64, pattern=p
		out, _, err := applyEntropyCover(EntropyCoverInterleave, key, data)
		if err != nil {
			t.Fatalf("pattern %d apply: %v", p, err)
		}
		got, err := reverseEntropyCover(EntropyCoverInterleave, nil, out)
		if err != nil {
			t.Fatalf("pattern %d reverse: %v", p, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("pattern %d: round-trip mismatch", p)
		}
	}
}

func TestInterleave_RejectsBadKey(t *testing.T) {
	_, _, err := applyEntropyCover(EntropyCoverInterleave, []byte{1, 2, 3}, []byte("hi"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover for short key, got %v", err)
	}
	_, _, err = applyEntropyCover(EntropyCoverInterleave, []byte{0, 0, 0, 0}, []byte("hi"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover for chunkLog2=0, got %v", err)
	}
	_, _, err = applyEntropyCover(EntropyCoverInterleave, []byte{17, 0, 0, 0}, []byte("hi"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover for chunkLog2=17, got %v", err)
	}
	// Out-of-range pattern (closes silent-zero corruption hole).
	_, _, err = applyEntropyCover(EntropyCoverInterleave, []byte{6, 64, 0xFF, 0}, []byte("hi"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover for pattern=0xFF, got %v", err)
	}
}

func TestInterleave_RejectsCorruptBody(t *testing.T) {
	_, err := reverseEntropyCover(EntropyCoverInterleave, nil, []byte{1, 2})
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for short body, got %v", err)
	}
	_, err = reverseEntropyCover(EntropyCoverInterleave, nil, []byte{0, 0, 0, 0, 'x'})
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for chunkLog2=0, got %v", err)
	}
	// Wire-side pattern out of range (defense vs. forged blob).
	_, err = reverseEntropyCover(EntropyCoverInterleave, nil, []byte{6, 64, 0xFF, 0, 'x'})
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for pattern=0xFF, got %v", err)
	}
}

// TestInterleave_TinyAndEmpty exercises edge cases: 0-byte and
// 1-byte inputs (no gap → no padding inserted).
func TestInterleave_TinyAndEmpty(t *testing.T) {
	for _, n := range []int{0, 1, 7, 256} {
		data := bytes.Repeat([]byte{'x'}, n)
		out, _, err := applyEntropyCover(EntropyCoverInterleave, nil, data)
		if err != nil {
			t.Fatalf("n=%d apply: %v", n, err)
		}
		got, err := reverseEntropyCover(EntropyCoverInterleave, nil, out)
		if err != nil {
			t.Fatalf("n=%d reverse: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("n=%d: round-trip mismatch", n)
		}
	}
}

// TestCarrier_RoundTrip + TestCarrier_PrefixIsPNG.
func TestCarrier_RoundTrip(t *testing.T) {
	data := make([]byte, 8192)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _, err := applyEntropyCover(EntropyCoverCarrier, nil, data)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != carrierHeaderSize+len(data) {
		t.Errorf("carrier output %d bytes, want %d", len(out), carrierHeaderSize+len(data))
	}
	got, err := reverseEntropyCover(EntropyCoverCarrier, nil, out)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestCarrier_PrefixIsPNG(t *testing.T) {
	out, _, err := applyEntropyCover(EntropyCoverCarrier, nil, []byte("payload"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(out, pngMagic) {
		t.Errorf("carrier output doesn't start with PNG magic; got % x", out[:8])
	}
}

func TestCarrier_RejectsCorrupt(t *testing.T) {
	out, _, _ := applyEntropyCover(EntropyCoverCarrier, nil, []byte("hi"))
	out[0] ^= 1
	_, err := reverseEntropyCover(EntropyCoverCarrier, nil, out)
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for tampered magic, got %v", err)
	}
	_, err = reverseEntropyCover(EntropyCoverCarrier, nil, []byte{0x89})
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for short body, got %v", err)
	}
}

// TestHexAlphabet_RoundTrip + TestHexAlphabet_HistogramIsCodeLike.
func TestHexAlphabet_RoundTrip(t *testing.T) {
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _, err := applyEntropyCover(EntropyCoverHexAlphabet, nil, data)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != hexAlphabetHeaderSize+2*len(data) {
		t.Errorf("hex-alphabet output %d bytes, want %d", len(out), hexAlphabetHeaderSize+2*len(data))
	}
	got, err := reverseEntropyCover(EntropyCoverHexAlphabet, nil, out)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch")
	}
}

// TestHexAlphabet_HistogramIsCodeLike verifies every byte after
// the header is drawn from [codeLikeAlphabet] — guarantees the
// "looks like .text" property.
func TestHexAlphabet_HistogramIsCodeLike(t *testing.T) {
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _, err := applyEntropyCover(EntropyCoverHexAlphabet, nil, data)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	for i, b := range out[hexAlphabetHeaderSize:] {
		found := false
		for _, a := range codeLikeAlphabet {
			if b == a {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("byte at offset %d (%#x) not in codeLikeAlphabet", i+hexAlphabetHeaderSize, b)
		}
	}
	// And the entropy of the body should top out at 4 bits/byte
	// (16-symbol alphabet → log2(16) = 4 max).
	after := shannon(out[hexAlphabetHeaderSize:])
	t.Logf("hex-alphabet entropy: %.3f bits/byte", after)
	if after > 4.05 {
		t.Errorf("hex-alphabet entropy %.3f exceeds 4 bits/byte ceiling", after)
	}
}

func TestHexAlphabet_RejectsCorrupt(t *testing.T) {
	out, _, _ := applyEntropyCover(EntropyCoverHexAlphabet, nil, []byte("ab"))
	out[0] ^= 1
	_, err := reverseEntropyCover(EntropyCoverHexAlphabet, nil, out)
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for tampered magic, got %v", err)
	}
	_, err = reverseEntropyCover(EntropyCoverHexAlphabet, nil, []byte{1})
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for short body, got %v", err)
	}
	// Body byte not in alphabet.
	out2, _, _ := applyEntropyCover(EntropyCoverHexAlphabet, nil, []byte("ab"))
	out2[hexAlphabetHeaderSize] = 0x37 // not in alphabet
	_, err = reverseEntropyCover(EntropyCoverHexAlphabet, nil, out2)
	if !errors.Is(err, ErrEntropyCoverCorrupt) {
		t.Fatalf("expected ErrEntropyCoverCorrupt for off-alphabet byte, got %v", err)
	}
}

// TestUnsupportedEntropyCover guards the dispatcher.
func TestUnsupportedEntropyCover(t *testing.T) {
	_, _, err := applyEntropyCover(EntropyCover(99), nil, []byte("x"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover, got %v", err)
	}
	_, err = reverseEntropyCover(EntropyCover(99), nil, []byte("x"))
	if !errors.Is(err, ErrUnsupportedEntropyCover) {
		t.Fatalf("expected ErrUnsupportedEntropyCover, got %v", err)
	}
}

// TestEntropyCover_InPipeline verifies OpEntropyCover composes
// correctly with the existing pipeline (cipher → entropy-cover)
// end-to-end. Uses pre-randomized data so compression doesn't
// shrink the body below a stat-stable sample size.
func TestEntropyCover_InPipeline(t *testing.T) {
	data := make([]byte, 64*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pipeline := []PipelineStep{
		{Op: OpCipher, Algo: uint8(CipherAESGCM)},
		{Op: OpEntropyCover, Algo: uint8(EntropyCoverInterleave)},
	}
	packed, keys, err := PackPipeline(data, pipeline)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got, err := UnpackPipeline(packed, keys)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("pipeline round-trip mismatch")
	}

	// The entropy-cover step is the LAST forward op, so its
	// output is the wire body. Measure its entropy and confirm
	// it sits below the entropy of the cipher output (which is
	// what we'd get without the cover step).
	noCover := []PipelineStep{
		{Op: OpCipher, Algo: uint8(CipherAESGCM)},
	}
	packedNoCover, _, err := PackPipeline(data, noCover)
	if err != nil {
		t.Fatalf("pack no-cover: %v", err)
	}
	covered := shannon(packed[headerSizeV2+2*len(pipeline):])
	uncovered := shannon(packedNoCover[headerSizeV2+2*len(noCover):])
	t.Logf("entropy with cover: %.3f / without: %.3f", covered, uncovered)
	if covered >= uncovered {
		t.Errorf("entropy-cover failed to lower entropy: %.3f >= %.3f", covered, uncovered)
	}
}

// TestRandomTuning sanity-checks the test-helper randomTuning so
// future authors don't bake invalid keys into their test pipelines.
func TestRandomTuning(t *testing.T) {
	for i := 0; i < 32; i++ {
		k, err := randomTuning()
		if err != nil {
			t.Fatalf("randomTuning: %v", err)
		}
		if k[0] < 1 || k[0] > 16 {
			t.Errorf("chunkLog2 out of range: %d", k[0])
		}
		if k[1] > 127 {
			t.Errorf("padSize over cap: %d", k[1])
		}
	}
}

// randomTuning returns a random valid tuning for
// [EntropyCoverInterleave]. Test-only — production callers should
// hard-code their own ratio.
func randomTuning() ([]byte, error) {
	out := make([]byte, interleaveHeaderSize)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	out[0] = (out[0] % 8) + 4 // chunkLog2 in 4..11 → chunk 16..2048
	out[1] &= 0x7F             // cap padSize at 128 to bound size growth
	out[2] = byte(PadPatternMixedASM)
	out[3] = 0
	return out, nil
}
