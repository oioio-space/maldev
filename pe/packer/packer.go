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
	"errors"
	"fmt"
	"math/rand"
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
)

// String returns the canonical lowercase format name.
func (f Format) String() string {
	switch f {
	case FormatWindowsExe:
		return "windows-exe"
	case FormatLinuxELF:
		return "linux-elf"
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
	// When caller specifies a Format, cross-check against magic detection so
	// mismatches are caught before the more expensive planning pass.
	if opts.Format != FormatUnknown {
		detected := transform.DetectFormat(input)
		expected := transformFormatFor(opts.Format)
		if detected != expected {
			return nil, nil, fmt.Errorf("%w: opts.Format=%s but input is %s",
				ErrUnsupportedFormat, opts.Format, detected)
		}
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
		opts.RandomizeExistingSectionNames
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

	return out, key, nil
}

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
)

// transformFormatFor maps the operator-facing packer.Format to the
// transform package's internal Format constant.
func transformFormatFor(f Format) transform.Format {
	switch f {
	case FormatWindowsExe:
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
