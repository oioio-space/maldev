package stubgen

import (
	"crypto/rand"
	"errors"
	"fmt"

	lz4 "github.com/pierrec/lz4/v4"

	"github.com/oioio-space/maldev/encode"
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

	// StubSectionName, when non-zero, names the appended PE stub
	// section. Forwarded into [transform.Plan.StubSectionName]; see
	// that field for the full semantics. Zero-value preserves the
	// canonical ".mldv\x00\x00\x00" name. PE only.
	StubSectionName [8]byte

	// ConvertEXEtoDLL, when true, routes the input EXE through the
	// EXE→DLL conversion pipeline: [transform.PlanConvertedDLL] +
	// [stage1.EmitConvertedDLLStub] +
	// [stage1.PatchConvertedDLLStubDisplacements] +
	// [transform.InjectConvertedDLL]. The output is a DLL whose
	// DllMain decrypts .text and spawns the original EXE entry
	// point on a fresh thread via PEB-walked kernel32!CreateThread.
	//
	// Mutually exclusive with non-PE inputs (silently ignored on
	// ELF) and with `Compress` (slice-5.3 stub doesn't embed the
	// LZ4 inflate path — caught via [ErrConvertEXEtoDLLUnsupported]
	// while that limitation stands).
	//
	// Slice 5.5 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
	ConvertEXEtoDLL bool

	// DiagSkipConvertedPayload, when true alongside ConvertEXEtoDLL,
	// emits a minimal converted-DLL stub: prologue + CALL+POP+ADD +
	// reason check + flag latch + return TRUE. Everything past the
	// flag latch (SGN rounds, kernel32-resolver, CreateThread call)
	// is skipped. Used by slice 5.5.y's bisection to isolate which
	// stage causes the real-loader ERROR_DLL_INIT_FAILED. Production
	// code MUST leave this false.
	DiagSkipConvertedPayload bool

	// DiagSkipConvertedResolver and DiagSkipConvertedSpawn are
	// finer-grained slice-5.5.y bisection gates. The first skips the
	// kernel32 resolver and (transitively) the CreateThread call; the
	// second keeps the resolver but skips the CreateThread call frame.
	// Production code MUST leave both false.
	DiagSkipConvertedResolver bool
	DiagSkipConvertedSpawn    bool

	// ConvertEXEtoDLLDefaultArgs bakes a default command-line into
	// the converted-DLL stub. Ignored when ConvertEXEtoDLL is false
	// (only the converted-DLL stub flavour patches PEB.CommandLine).
	// Empty string preserves prior behaviour: payload sees the host
	// process's existing GetCommandLineW result. See
	// [stage1.EmitOptions.DefaultArgs] for OPSEC trade-offs.
	ConvertEXEtoDLLDefaultArgs string

	// ConvertEXEtoDLLRunWithArgs requests the converted-DLL stub
	// to emit a `RunWithArgs(LPCWSTR args)` exported function and
	// register it in the DLL's export table. Ignored when
	// ConvertEXEtoDLL is false. See [stage1.EmitOptions.RunWithArgs]
	// for the per-call semantics.
	ConvertEXEtoDLLRunWithArgs bool
}

// Sentinels surfaced by Generate.
var (
	// ErrInvalidRounds fires when Options.Rounds is outside [1, 10].
	ErrInvalidRounds = errors.New("stubgen: rounds out of range")
	// ErrNoInput fires when Options.Input is nil or empty.
	ErrNoInput = errors.New("stubgen: no input bytes")
	// ErrCompressDLLUnsupported fires when Options.Compress is true
	// AND the input is a DLL. The DllMain stub layout doesn't yet
	// embed the LZ4 inflate / scratch buffer path the EXE stub uses
	// — slice-4 limitation, tracked in
	// docs/refactor-2026-doc/packer-dll-format-plan.md.
	ErrCompressDLLUnsupported = errors.New("stubgen: Compress=true is not supported on DLL inputs")
	// ErrConvertEXEtoDLLUnsupported fires while the EXE→DLL chantier
	// sub-slices 5.2 (stub emitter), 5.3 (injector), 5.4 (stubgen
	// dispatch) are in flight. Slice 5.1 wired the API surface +
	// admission cross-checks; the conversion pipeline itself lands
	// in 5.2-5.5.
	//
	// See docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
	ErrConvertEXEtoDLLUnsupported = errors.New("stubgen: ConvertEXEtoDLL not yet implemented (slice 5.2-5.5 in flight)")
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

	// 1. Detect format + Plan. PE inputs split three ways:
	//   - native DLL input  → PlanDLL          (slice 2 chantier)
	//   - EXE + ConvertEXEtoDLL=true → PlanConvertedDLL (slice 5)
	//   - plain EXE         → PlanPE
	// The downstream emit/inject branches off the corresponding
	// Plan.IsDLL / Plan.IsConvertedDLL flags.
	format := transform.DetectFormat(opts.Input)
	var plan transform.Plan
	switch format {
	case transform.FormatPE:
		var err error
		switch {
		case transform.IsDLL(opts.Input):
			plan, err = transform.PlanDLL(opts.Input, stubMaxSize)
			if err != nil {
				return nil, nil, fmt.Errorf("stubgen: PlanDLL: %w", err)
			}
			if opts.Compress {
				return nil, nil, ErrCompressDLLUnsupported
			}
		case opts.ConvertEXEtoDLL:
			plan, err = transform.PlanConvertedDLL(opts.Input, stubMaxSize)
			if err != nil {
				return nil, nil, fmt.Errorf("stubgen: PlanConvertedDLL: %w", err)
			}
			// Slice 5.7 ✅ shipped: pack-time LZ4 inflate + memcpy block
			// emitted by EmitConvertedDLLStub between SGN and the kernel32
			// resolver; runtime validated by Win10 VM E2E
			// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_Compress_E2E
			// (3/3 passes, 2.09s avg). The earlier "host wedges in LZ4
			// inflate" failure was resolved upstream — the slice 5.5.y
			// callee-save spill fix + the SizeOfImage scratch-region fix
			// (both already in place by v0.123.0) cleared the underlying
			// register-corruption / loader-rejection conditions.
		default:
			plan, err = transform.PlanPE(opts.Input, stubMaxSize)
			if err != nil {
				return nil, nil, fmt.Errorf("stubgen: PlanPE: %w", err)
			}
		}
		// Forward operator-supplied section name (Phase 2-A). Zero
		// value preserves the canonical ".mldv\x00\x00\x00" default.
		plan.StubSectionName = opts.StubSectionName
	case transform.FormatELF:
		if opts.ConvertEXEtoDLL {
			return nil, nil, fmt.Errorf("%w: ConvertEXEtoDLL requires a PE input", transform.ErrUnsupportedInputFormat)
		}
		var err error
		plan, err = transform.PlanELF(opts.Input, stubMaxSize)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: PlanELF: %w", err)
		}
	default:
		return nil, nil, transform.ErrUnsupportedInputFormat
	}

	// 2. Extract .text bytes (slice; plan.TextSize may be mutated below when Compress=true)
	originalTextBytes := opts.Input[plan.TextFileOff : plan.TextFileOff+plan.TextSize]
	// originalTextSize captures plan.TextSize before the optional mutation in step 3.
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
	emitOpts.DiagSkipConvertedPayload = opts.DiagSkipConvertedPayload
	emitOpts.DiagSkipConvertedResolver = opts.DiagSkipConvertedResolver
	emitOpts.DiagSkipConvertedSpawn = opts.DiagSkipConvertedSpawn
	emitOpts.DefaultArgs = opts.ConvertEXEtoDLLDefaultArgs
	emitOpts.RunWithArgs = opts.ConvertEXEtoDLLRunWithArgs

	if opts.Compress {
		dst := make([]byte, lz4.CompressBlockBound(len(originalTextBytes)))
		var c lz4.Compressor
		n, err := c.CompressBlock(originalTextBytes, dst)
		if err != nil {
			return nil, nil, fmt.Errorf("stubgen: lz4 compress: %w", err)
		}
		compressed := dst[:n]
		compressedSize = uint32(n)

		// LZ4 inflate runs NON-IN-PLACE: src = R15 (compressed bytes after
		// SGN unwrap), dst = scratch buffer in the stub segment's BSS slack.
		// After inflate the stub memcpys plaintext back to R15.
		//
		// Avoids the .text segment-grow blocker (Go static-PIE packs PT_LOADs
		// tightly — .text can't grow past the next read-only segment). The
		// stub segment is appended by us; its memsz is freely sized.
		//
		// On disk: filesz = compressedSize (only compressed bytes ship).
		// Stub segment: memsz = StubMaxSize + originalTextSize, filesz =
		//               StubMaxSize (kernel zero-fills the scratch region).
		// Scratch RVA = StubRVA + StubMaxSize.
		safetyMargin = uint32(originalTextSize>>8) + 32 // informational only
		if safetyMargin < 64 {
			safetyMargin = 64
		}

		encodePayload = compressed

		plan.TextSize = compressedSize
		plan.TextMemSize = compressedSize // no longer needs slack — scratch lives in stub seg
		plan.StubScratchSize = originalTextSize

		// ScratchDispFromText = (StubRVA + StubMaxSize) − TextRVA.
		// int32 fits any practical Go binary; PlanPE/PlanELF cap at 32-bit RVAs.
		scratchRVA := plan.StubRVA + plan.StubMaxSize
		scratchDisp := int32(scratchRVA) - int32(plan.TextRVA)

		emitOpts.Compress = true
		emitOpts.SafetyMargin = safetyMargin
		emitOpts.CompressedSize = compressedSize
		emitOpts.OriginalSize = originalTextSize
		emitOpts.ScratchDispFromText = scratchDisp
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

	// 5. Emit stub asm — DLL inputs use the DllMain-shaped emitter,
	// everything else the EXE emitter.
	b, err := amd64.New()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.New: %w", err)
	}
	switch {
	case plan.IsDLL:
		if err := stage1.EmitDLLStub(b, plan, polyRounds); err != nil {
			return nil, nil, fmt.Errorf("stubgen: EmitDLLStub: %w", err)
		}
	case plan.IsConvertedDLL:
		if err := stage1.EmitConvertedDLLStub(b, plan, polyRounds, emitOpts); err != nil {
			return nil, nil, fmt.Errorf("stubgen: EmitConvertedDLLStub: %w", err)
		}
	default:
		if err := stage1.EmitStub(b, plan, polyRounds, emitOpts); err != nil {
			return nil, nil, fmt.Errorf("stubgen: EmitStub: %w", err)
		}
	}

	stubBytes, err := b.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: amd64.Encode: %w", err)
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, nil, fmt.Errorf("%w: %d > %d", transform.ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}

	// 6. Patch CALL+POP+ADD prologue: replace sentinel with real
	// displacement. Shared between EXE and DLL stub layouts — both
	// use the same emitTextBasePrologue idiom.
	if _, err := stage1.PatchTextDisplacement(stubBytes, plan); err != nil {
		return nil, nil, fmt.Errorf("stubgen: PatchTextDisplacement: %w", err)
	}
	// DLL stubs carry extra R15-relative disp sentinels that the
	// per-flavour patchers rewrite once the trailing-data offsets
	// are known. Native DLL: flag + slot. Converted DLL: flag only
	// (no orig_dllmain slot — there's no tail-call target).
	switch {
	case plan.IsDLL:
		if _, err := stage1.PatchDLLStubDisplacements(stubBytes, plan); err != nil {
			return nil, nil, fmt.Errorf("stubgen: PatchDLLStubDisplacements: %w", err)
		}
	case plan.IsConvertedDLL:
		if _, err := stage1.PatchConvertedDLLStubDisplacements(stubBytes, plan); err != nil {
			return nil, nil, fmt.Errorf("stubgen: PatchConvertedDLLStubDisplacements: %w", err)
		}
		if opts.ConvertEXEtoDLLDefaultArgs != "" {
			argsBytesLen := len(encode.ToUTF16LE(opts.ConvertEXEtoDLLDefaultArgs))
			offFromEnd := stage1.ConvertedDLLStubArgsBufferOffsetFromEnd(argsBytesLen)
			argsBufferOff := uint32(len(stubBytes) - offFromEnd)
			if _, err := stage1.PatchPEBCommandLineDisp(stubBytes, plan.StubRVA, plan.TextRVA, argsBufferOff); err != nil {
				return nil, nil, fmt.Errorf("stubgen: PatchPEBCommandLineDisp: %w", err)
			}
		}
		if opts.ConvertEXEtoDLLRunWithArgs {
			if _, err := stage1.PatchRunWithArgsTextDisplacement(stubBytes, plan); err != nil {
				return nil, nil, fmt.Errorf("stubgen: PatchRunWithArgsTextDisplacement: %w", err)
			}
			// Offset becomes the RunWithArgs export RVA in slice 1.B.1.d;
			// for now we only NOP the sentinel so the entry's first byte
			// is a safe NOP if a stray GetProcAddress lands here before
			// the export table is in place.
			if _, err := stage1.PatchConvertedDLLRunWithArgsEntry(stubBytes); err != nil {
				return nil, nil, fmt.Errorf("stubgen: PatchConvertedDLLRunWithArgsEntry: %w", err)
			}
		}
	}

	// 7. Inject into input. DLL inputs route through InjectStubDLL;
	// EXE+ConvertEXEtoDLL through InjectConvertedDLL (delegate-and-
	// flip); plain EXE/ELF through their format-native injectors.
	var out []byte
	switch {
	case plan.IsDLL:
		out, err = transform.InjectStubDLL(opts.Input, finalEncoded, stubBytes, plan)
	case plan.IsConvertedDLL:
		out, err = transform.InjectConvertedDLL(opts.Input, finalEncoded, stubBytes, plan)
	case format == transform.FormatPE:
		out, err = transform.InjectStubPE(opts.Input, finalEncoded, stubBytes, plan)
	case format == transform.FormatELF:
		out, err = transform.InjectStubELF(opts.Input, finalEncoded, stubBytes, plan)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stubgen: Inject: %w", err)
	}

	return out, key, nil
}
