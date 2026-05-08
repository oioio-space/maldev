package packer_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackPipeline_RoundTrip_SingleAESGCM is the simplest
// pipeline shape: one cipher step. Equivalent to the legacy
// Pack but goes through the v2 path.
func TestPackPipeline_RoundTrip_SingleAESGCM(t *testing.T) {
	input := []byte("hello pipeline")
	blob, keys, err := packer.PackPipeline(input, []packer.PipelineStep{
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	})
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	got, err := packer.UnpackPipeline(blob, keys)
	if err != nil {
		t.Fatalf("UnpackPipeline: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("round-trip lost bytes: got %q, want %q", got, input)
	}
}

// TestPackPipeline_RoundTrip_AllCiphers verifies every cipher
// algo round-trips when used standalone.
func TestPackPipeline_RoundTrip_AllCiphers(t *testing.T) {
	cases := []packer.Cipher{
		packer.CipherAESGCM,
		packer.CipherChaCha20,
		packer.CipherRC4,
	}
	input := []byte("the quick brown fox jumps over the lazy dog")
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) {
			blob, keys, err := packer.PackPipeline(input, []packer.PipelineStep{
				{Op: packer.OpCipher, Algo: uint8(c)},
			})
			if err != nil {
				t.Fatalf("PackPipeline(%s): %v", c, err)
			}
			got, err := packer.UnpackPipeline(blob, keys)
			if err != nil {
				t.Fatalf("UnpackPipeline(%s): %v", c, err)
			}
			if !bytes.Equal(got, input) {
				t.Errorf("%s: round-trip lost bytes", c)
			}
		})
	}
}

// TestPackPipeline_RoundTrip_AllPermutations same for permutations.
func TestPackPipeline_RoundTrip_AllPermutations(t *testing.T) {
	cases := []packer.Permutation{
		packer.PermutationXOR,
		packer.PermutationArithShift,
		packer.PermutationSBox,
	}
	input := []byte("permutation round-trip target bytes")
	for _, p := range cases {
		t.Run(p.String(), func(t *testing.T) {
			blob, keys, err := packer.PackPipeline(input, []packer.PipelineStep{
				{Op: packer.OpPermute, Algo: uint8(p)},
			})
			if err != nil {
				t.Fatalf("PackPipeline(%s): %v", p, err)
			}
			got, err := packer.UnpackPipeline(blob, keys)
			if err != nil {
				t.Fatalf("UnpackPipeline(%s): %v", p, err)
			}
			if !bytes.Equal(got, input) {
				t.Errorf("%s: round-trip lost bytes (got %q, want %q)", p, got, input)
			}
		})
	}
}

// TestPackPipeline_RoundTrip_StackedThreeLayers exercises the
// canonical "permutation → permutation → cipher" 3-layer stack
// the design doc recommends for entropy-aware ops.
func TestPackPipeline_RoundTrip_StackedThreeLayers(t *testing.T) {
	input := []byte("multi-layer pipeline test — three orthogonal transforms")
	pipeline := []packer.PipelineStep{
		{Op: packer.OpPermute, Algo: uint8(packer.PermutationXOR)},
		{Op: packer.OpPermute, Algo: uint8(packer.PermutationSBox)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	}
	blob, keys, err := packer.PackPipeline(input, pipeline)
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	got, err := packer.UnpackPipeline(blob, keys)
	if err != nil {
		t.Fatalf("UnpackPipeline: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("3-layer round-trip lost bytes")
	}
}

func TestPackPipeline_RejectsEmpty(t *testing.T) {
	_, _, err := packer.PackPipeline([]byte("x"), nil)
	if !errors.Is(err, packer.ErrEmptyPipeline) {
		t.Errorf("got %v, want ErrEmptyPipeline", err)
	}
}

func TestPackPipeline_RejectsTooLong(t *testing.T) {
	huge := make([]packer.PipelineStep, 256)
	for i := range huge {
		huge[i] = packer.PipelineStep{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)}
	}
	_, _, err := packer.PackPipeline([]byte("x"), huge)
	if !errors.Is(err, packer.ErrPipelineTooLong) {
		t.Errorf("got %v, want ErrPipelineTooLong", err)
	}
}

func TestUnpackPipeline_RejectsKeyCountMismatch(t *testing.T) {
	blob, keys, err := packer.PackPipeline([]byte("test"), []packer.PipelineStep{
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
		{Op: packer.OpPermute, Algo: uint8(packer.PermutationXOR)},
	})
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	// Drop the last key.
	_, err = packer.UnpackPipeline(blob, keys[:1])
	if !errors.Is(err, packer.ErrPipelineKeysMismatch) {
		t.Errorf("got %v, want ErrPipelineKeysMismatch", err)
	}
}

func TestPackPipeline_AcceptsSuppliedKey(t *testing.T) {
	customKey := bytes.Repeat([]byte{0xA5}, 32)
	_, keys, err := packer.PackPipeline([]byte("x"), []packer.PipelineStep{
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM), Key: customKey},
	})
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	if !bytes.Equal(keys[0], customKey) {
		t.Error("supplied key was not echoed back in PipelineKeys[0]")
	}
}

func TestPackPipeline_ProducesUniqueOutputForSameInput(t *testing.T) {
	input := []byte("uniqueness check")
	pipeline := []packer.PipelineStep{
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	}
	a, _, _ := packer.PackPipeline(input, pipeline)
	b, _, _ := packer.PackPipeline(input, pipeline)
	if bytes.Equal(a, b) {
		t.Error("two PackPipeline calls produced identical bytes — nonce reuse?")
	}
}

func TestPipelineOpString(t *testing.T) {
	if got := packer.OpCipher.String(); got != "cipher" {
		t.Errorf("OpCipher.String() = %q, want %q", got, "cipher")
	}
	if got := packer.OpPermute.String(); got != "permute" {
		t.Errorf("OpPermute.String() = %q, want %q", got, "permute")
	}
	if got := packer.PipelineOp(99).String(); got != "op(99)" {
		t.Errorf("op(99).String() = %q, want %q", got, "op(99)")
	}
}

// TestUnpackPipeline_CorruptTruncatedTable confirms a pipeline
// blob whose step table is truncated past the body end surfaces
// ErrCorruptBlob (not the misleading ErrBadMagic the sentinel
// used to wrap before v0.63.x — structural-corruption errors
// belong to a distinct sentinel from "wrong magic at offset 0").
func TestUnpackPipeline_CorruptTruncatedTable(t *testing.T) {
	steps := []packer.PipelineStep{
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	}
	blob, keys, err := packer.PackPipeline([]byte("hello"), steps)
	if err != nil {
		t.Fatalf("PackPipeline: %v", err)
	}
	// Truncate to header + 1 byte: the v2 header (32 bytes)
	// records NumSteps=4, so the step table claims 4*2=8 bytes
	// past the header. The truncated blob has only 1 byte of
	// table — tableEnd > len(packed) fires the structural-
	// corruption check.
	truncated := blob[:33]
	_, err = packer.UnpackPipeline(truncated, keys)
	if !errors.Is(err, packer.ErrCorruptBlob) {
		t.Errorf("got %v, want ErrCorruptBlob", err)
	}
}

func TestPermutationString(t *testing.T) {
	cases := []struct {
		p    packer.Permutation
		want string
	}{
		{packer.PermutationXOR, "xor"},
		{packer.PermutationArithShift, "arith-shift"},
		{packer.PermutationSBox, "sbox"},
		{packer.Permutation(99), "permutation(99)"},
	}
	for _, tc := range cases {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("Permutation(%d).String() = %q, want %q", uint8(tc.p), got, tc.want)
		}
	}
}
