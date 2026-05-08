package stubgen

import (
	"crypto/rand"
	"errors"
	"fmt"

	lz4 "github.com/pierrec/lz4/v4"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/random"
)

// Options drives Generate.
type Options struct {
	// Input is the PE/ELF binary to transform in place.
	Input []byte
	// Rounds is the number of SGN encoding rounds, 1..10; default 3.
	Rounds int
	// Seed drives the poly engine. Zero = crypto-random.
	Seed int64
	// StubMaxSize is the pre-reserved byte count for the appended stub
	// section. Zero defaults to 8192 when Compress is true (the LZ4
	// decoder adds ~160 bytes), 4096 otherwise.
	StubMaxSize uint32
	// CipherKey, when non-nil, is used as the XOR key for .text
	// encryption. When nil a fresh 32-byte key is generated.
	CipherKey []byte
	// AntiDebug, when true, prepends a ~70-byte anti-debug prologue to the
	// Windows PE stub before the CALL+POP+ADD PIC prologue. See
	// [stage1.EmitOptions.AntiDebug] for the full description. ELF stubs
	// ignore this flag.
	AntiDebug bool
	// Compress, when true, LZ4-compresses the .text section before SGN
	// encoding. The stub gains a register-setup sequence + the 136-byte
	// LZ4 block inflate decoder between the last SGN round and the OEP
	// JMP. Plan.TextMemSize is set so the loader maps enough virtual memory
	// for the in-place inflate to expand into. Default false (conservative).
	Compress bool
}

// Sentinels surfaced by Generate.
var (
	// ErrInvalidRounds fires when Options.Rounds is outside [1, 10].
	ErrInvalidRounds = errors.New("stubgen: rounds out of range")
	// ErrNoInput fires when Options.Input is nil or empty.
	ErrNoInput = errors.New("stubgen: no input bytes")
)

// Generate runs the UPX-style transform pipeline:
//
//  1. Detect format (PE vs ELF)
//  2. PlanPE / PlanELF (compute RVAs)
//  3. XOR-encrypt input's .text with CipherKey (or a fresh random key)
//  4. poly.Engine.EncodePayload (SGN N-round)
//  5. stage1.EmitStub (CALL+POP+ADD prologue + N rounds + JMP-OEP)
//  6. stage1.PatchTextDisplacement (post-Encode prologue fixup)
//  7. transform.InjectStubPE / InjectStubELF (write modified binary)
//
// Returns the modified binary and the key used to encrypt .text.
func Generate(opts Options) ([]byte, []byte, error) {
	if len(opts.Input) == 0 {
		return nil, nil, ErrNoInput
	}
	rounds := opts.Rounds
	if rounds == 0 {
		rounds = 3
	}
	if rounds < 1 || rounds > 10 {
		return nil, nil, fmt.Errorf("%w: rounds=%d", ErrInvalidRounds, rounds)
	}
	stubMaxSize := opts.StubMaxSize
	if stubMaxSize == 0 {
		// Compress adds ~160 bytes to the stub (4-insn setup + 136-byte LZ4
		// decoder). 8192 gives comfortable headroom for 10 SGN rounds + decoder.
		if opts.Compress {
			stubMaxSize = 8192
		} else {
			stubMaxSize = 4096
		}
	}
	seed := opts.Seed
	if seed == 0 {
		s, err := random.Int64()
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: seed: %w", err)
		}
		seed = s
	}

	// 1. Detect format + Plan
	format := transform.DetectFormat(opts.Input)
	var plan transform.Plan
	switch format {
	case transform.FormatPE:
		var err error
		plan, err = transform.PlanPE(opts.Input, stubMaxSize)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: PlanPE: %w", err)
		}
	case transform.FormatELF:
		var err error
		plan, err = transform.PlanELF(opts.Input, stubMaxSize)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: PlanELF: %w", err)
		}
	default:
		return nil, nil, transform.ErrUnsupportedInputFormat
	}

	// 2. Extract .text bytes
	originalTextBytes := opts.Input[plan.TextFileOff : plan.TextFileOff+plan.TextSize]
	originalTextSize := plan.TextSize

	// 3. Optionally LZ4-compress .text before SGN encoding.
	//
	// Layout after compression:
	//   payload = [zero_prefix (safetyMargin bytes)] + [lz4_block (compressedSize bytes)]
	//
	// The SGN engine encodes the entire payload (prefix + compressed block).
	// At runtime, after all SGN rounds decode the payload back:
	//   [0, safetyMargin)              = zero bytes   (SGN round decoded zeros)
	//   [safetyMargin, safetyMargin+n) = LZ4 block    (the compressed .text)
	//
	// The stub then runs the LZ4 inflate decoder with:
	//   src = textBase + safetyMargin   (compressed block)
	//   dst = textBase                  (expand in-place; dst < src always)
	//   srcSize = compressedSize
	//
	// safety_margin = ⌈compressedSize/255⌉ + 16 guarantees dst never catches
	// src (LZ4 block spec: each compressed byte expands to ≤255 output bytes).
	//
	// plan.TextSize is updated to len(payload) so InjectStubPE/ELF writes the
	// correct number of bytes on disk. plan.TextMemSize is set to safetyMargin
	// + originalTextSize so the loader maps enough virtual memory for inflate.
	var (
		emitOpts       stage1.EmitOptions
		encodePayload  []byte
		safetyMargin   uint32
		compressedSize uint32
	)
	emitOpts.AntiDebug = opts.AntiDebug

	if opts.Compress {
		dst := make([]byte, lz4.CompressBlockBound(len(originalTextBytes)))
		var c lz4.Compressor
		n, err := c.CompressBlock(originalTextBytes, dst)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: lz4 compress: %w", err)
		}
		compressed := dst[:n]
		compressedSize = uint32(n)

		// safety_margin = ⌈originalTextSize/255⌉ + 16, minimum 64.
		//
		// For in-place LZ4 inflate with dst < src: the write pointer advances
		// from textBase and the read pointer starts at textBase+safetyMargin.
		// Each output byte was produced from at most 1/255 of an input byte
		// (worst case: each 0xFF extension byte yields 255 literals). The gap
		// between write and read shrinks by at most 1-(1/255) per output byte,
		// so the total potential overshoot over the full decompression is
		// ≤ originalSize/255. Using compressedSize/255 underestimates this
		// (since compressedSize ≤ originalSize), which caused dst to overtake src
		// midway through decompression. Correct bound: ⌈originalTextSize/255⌉.
		origSz := uint32(len(originalTextBytes))
		margin := (origSz+254)/255 + 16
		if margin < 64 {
			margin = 64
		}
		safetyMargin = margin

		// Build the on-disk payload: zero prefix + compressed block.
		encodePayload = make([]byte, safetyMargin+compressedSize)
		copy(encodePayload[safetyMargin:], compressed)

		// Update plan so the transform functions know the on-disk and
		// virtual sizes differ (memsz > filesz for the inflate workspace).
		plan.TextSize = uint32(len(encodePayload))
		plan.TextMemSize = safetyMargin + originalTextSize

		emitOpts.Compress = true
		emitOpts.SafetyMargin = safetyMargin
		emitOpts.CompressedSize = compressedSize
	} else {
		// Non-compress path: encode the raw .text bytes directly.
		encodePayload = originalTextBytes
	}

	// 3a. Key is unused in the SGN-only pipeline (no outer XOR cipher today).
	// Retained for API compatibility — callers that pass a key still get it
	// back as the second return value so PackBinary's signature is stable.
	key := opts.CipherKey
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, nil, fmt.Errorf("stubgen: cipher key: %w", err)
		}
	}

	// 4. SGN-encode the payload (raw text bytes or zero-prefix+compressed block).
	eng, err := poly.NewEngine(seed, rounds)
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: NewEngine: %w", err)
	}
	// EncodePayloadExcluding(stage1.BaseReg) keeps R15 out of the
	// per-round register randomisation. R15 holds the runtime
	// TextRVA pointer set by the CALL+POP+ADD prologue and read by
	// every round (`MOV src, r15`); if a round took it as the key
	// or counter register, the address would be clobbered → SIGSEGV
	// on the first decoder dereference. Caught by the seed-3+
	// regression test in stubgen_test.go.
	finalEncoded, polyRounds, err := eng.EncodePayloadExcluding(encodePayload, stage1.BaseReg)
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: EncodePayload: %w", err)
	}

	// 5. Emit stub asm
	b, err := amd64.New()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.New: %w", err)
	}
	if err := stage1.EmitStub(b, plan, polyRounds, emitOpts); err != nil {
		return nil, nil, fmt.Errorf("stubgen: EmitStub: %w", err)
	}

	stubBytes, err := b.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.Encode: %w", err)
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, nil, fmt.Errorf("%w: %d > %d", transform.ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}

	// 6. Patch CALL+POP+ADD prologue: replace sentinel with real displacement
	if _, err := stage1.PatchTextDisplacement(stubBytes, plan); err != nil {
		return nil, nil, fmt.Errorf("stubgen: PatchTextDisplacement: %w", err)
	}

	// 7. Inject into input
	var out []byte
	switch format {
	case transform.FormatPE:
		out, err = transform.InjectStubPE(opts.Input, finalEncoded, stubBytes, plan)
	case transform.FormatELF:
		out, err = transform.InjectStubELF(opts.Input, finalEncoded, stubBytes, plan)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: Inject: %w", err)
	}

	return out, key, nil
}
