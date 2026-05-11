package transform

import "errors"

// Format identifies the input binary's container format.
type Format uint8

const (
	FormatUnknown Format = iota
	FormatPE             // Windows PE32+
	FormatELF            // Linux ELF64
)

// String returns the canonical lowercase format name.
func (f Format) String() string {
	switch f {
	case FormatPE:
		return "pe"
	case FormatELF:
		return "elf"
	default:
		return "unknown"
	}
}

// DetectFormat inspects the first few bytes of `input` and returns
// the matching Format, or FormatUnknown when neither magic matches.
func DetectFormat(input []byte) Format {
	if len(input) < 4 {
		return FormatUnknown
	}
	if input[0] == 'M' && input[1] == 'Z' {
		return FormatPE
	}
	if input[0] == 0x7F && input[1] == 'E' && input[2] == 'L' && input[3] == 'F' {
		return FormatELF
	}
	return FormatUnknown
}

// Plan describes the layout decisions InjectStubPE/InjectStubELF
// will apply. Returned by PlanPE/PlanELF before stub generation
// so the stub emitter knows the RVA constants it must bake into
// the asm.
//
// Two-phase design avoids the chicken-and-egg between "stub needs
// section RVAs" and "transform needs stub bytes":
//
//	plan, _   := transform.PlanPE(input, stubMaxSize)
//	stubBytes := stage1.EmitStub(builder, plan, rounds)
//	out, _    := transform.InjectStubPE(input, encryptedText, stubBytes, plan)
type Plan struct {
	Format      Format // PE or ELF
	TextRVA     uint32 // RVA of the section that gets encrypted
	TextFileOff uint32 // file offset where encrypted bytes are written
	TextSize    uint32 // bytes to encrypt + decrypt at runtime
	TextHdrOff  uint32 // PE only: file offset of the .text section header (unused for ELF)
	OEPRVA      uint32 // original entry point — JMP target after decrypt
	StubRVA     uint32 // RVA of the new stub section (= new entry point)
	StubFileOff uint32 // file offset where stub bytes are written
	StubMaxSize uint32 // pre-reserved bytes for the stub

	// TextMemSize, when non-zero and greater than TextSize, requests that
	// the .text section's virtual memory size (VirtualSize in PE, p_memsz
	// in ELF) be set larger than the on-disk file size. The kernel maps the
	// gap between filesz and memsz as zero bytes. Reserved for diagnostic
	// use; the C3 compression scratch buffer now lives in the stub segment
	// (see StubScratchSize) so .text memsz is no longer enlarged.
	TextMemSize uint32

	// StubScratchSize, when non-zero, requests that the stub segment's
	// memsz extend StubScratchSize bytes past StubMaxSize. The kernel
	// zero-fills that BSS region; C3 compression uses it as a non-in-place
	// LZ4 inflate destination, sidestepping the ELF/PE constraint that the
	// .text segment can't grow past adjacent read-only segments.
	//
	// Scratch RVA = StubRVA + StubMaxSize. Stub asm references it via
	// LEA reg, [R15 + (StubRVA + StubMaxSize − TextRVA)].
	StubScratchSize uint32

	// StubSectionName, when non-zero, names the appended stub
	// section. The PE section name field is 8 bytes, NUL-padded.
	// Zero-value leaves InjectStubPE to write the default
	// ".mldv\x00\x00\x00" — preserving backwards-compatible
	// output on callers that don't override.
	//
	// Operators set this (typically via [RandomStubSectionName])
	// to defeat YARA rules keyed on the literal ".mldv" string —
	// Phase 2-A of docs/refactor-2026-doc/packer-design.md.
	//
	// PE only; ELF section names live in .shstrtab and are not
	// load-relevant.
	StubSectionName [8]byte

	// IsDLL is set by [PlanDLL] when the input PE has the
	// IMAGE_FILE_DLL bit in COFF Characteristics. Stub emitters
	// switch to the DllMain prologue/epilogue layout (preserve
	// rcx/edx/r8, decrypt-once sentinel, tail-call to the
	// original DllMain) instead of the EXE CALL+POP+ADD →
	// JMP-OEP → ExitProcess pattern.
	//
	// [PlanPE] never sets this flag (it rejects DLLs with
	// [ErrIsDLL] upfront). PE only.
	IsDLL bool

	// IsConvertedDLL is set by [PlanConvertedDLL] for the EXE→DLL
	// conversion path (PackBinaryOptions.ConvertEXEtoDLL). The input
	// is an EXE; InjectConvertedDLL flips IMAGE_FILE_DLL on the
	// output. Mutually exclusive with [IsDLL].
	//
	// Slice 5 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
	IsConvertedDLL bool
}

// Sentinels surfaced by PlanPE / PlanELF / InjectStubPE / InjectStubELF.
var (
	// ErrUnsupportedInputFormat fires when DetectFormat returns FormatUnknown.
	ErrUnsupportedInputFormat = errors.New("transform: unsupported input format")

	// ErrNoTextSection fires when the input has no .text section
	// (PE) or no R+E PT_LOAD (ELF).
	ErrNoTextSection = errors.New("transform: input lacks an executable section")

	// ErrOEPOutsideText fires when the input's entry point is not
	// within the .text / executable segment we plan to encrypt.
	ErrOEPOutsideText = errors.New("transform: original entry point is not within .text")

	// ErrTLSCallbacks fires when the input declares TLS callbacks
	// (PE only). They run before the entry point and would touch
	// encrypted bytes — out of scope v1.
	ErrTLSCallbacks = errors.New("transform: input has TLS callbacks (out of scope)")

	// ErrIsDLL fires when the input PE carries the
	// IMAGE_FILE_DLL bit in COFF Characteristics. PackBinary's
	// stub follows the EXE entry-point contract (single arg-less
	// call from the loader, then ExitProcess); a DLL's "entry
	// point" is DllMain(HINSTANCE, DWORD, LPVOID) → BOOL invoked
	// multiple times with PROCESS_ATTACH / THREAD_ATTACH /
	// PROCESS_DETACH reasons. The stub would never see PROCESS_DETACH
	// to clean up, and its ExitProcess would tear down the host
	// process instead of returning TRUE. Out of scope for v1 —
	// see HANDOFF-2026-05-11 "DLL packing" open question.
	ErrIsDLL = errors.New("transform: input is a DLL (PackBinary only supports EXE — use PackBinaryBundle to wrap DLLs)")

	// ErrIsEXE is the mirror of [ErrIsDLL]: [PlanDLL] returns it
	// when the input PE lacks the IMAGE_FILE_DLL bit (i.e. it's
	// an EXE). The DLL stub layout requires the loader's DllMain
	// calling convention; an EXE entry point reading rcx/edx/r8
	// would dereference garbage and crash.
	ErrIsEXE = errors.New("transform: input is an EXE (PlanDLL requires IMAGE_FILE_DLL — use PlanPE for EXEs)")

	// ErrStubTooLarge fires when emitted stub bytes exceed
	// Plan.StubMaxSize.
	ErrStubTooLarge = errors.New("transform: emitted stub exceeds reserved size")

	// ErrSectionTableFull fires when the input PE has no headroom
	// for one more section header.
	ErrSectionTableFull = errors.New("transform: cannot append section header (no headroom)")

	// ErrCorruptOutput fires when the modified binary fails the
	// post-injection self-test (debug/pe.NewFile or debug/elf.NewFile).
	ErrCorruptOutput = errors.New("transform: modified binary failed self-test")

	// ErrPlanFormatMismatch fires when InjectStubPE is called with a
	// Plan whose Format field is not FormatPE (or symmetrically for ELF).
	ErrPlanFormatMismatch = errors.New("transform: plan format does not match Inject function")
)
