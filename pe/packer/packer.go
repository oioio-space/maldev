// Package packer is maldev's custom PE/ELF packer.
//
// [Pack] / [Unpack] handle the encrypt-only pipeline (Phase 1c+).
// [PackBinary] is the operator-facing entry point added in Phase 1e-A/B:
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

	"github.com/oioio-space/maldev/crypto"
	"github.com/oioio-space/maldev/pe/packer/internal/elfgate"
	"github.com/oioio-space/maldev/pe/packer/stubgen"
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
	FormatWindowsExe               // Phase 1e-A: PE32+ Windows executable
	FormatLinuxELF                 // Phase 1e-B: ELF64 Linux static-PIE
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
	// Format selects the host binary shape. FormatUnknown (zero) is
	// always rejected; callers must be explicit.
	Format Format

	// Pipeline is the Phase 1c+ encryption pipeline applied to the
	// inner payload before embedding it in the stage-2 binary.
	// When nil, a single AES-GCM step is used.
	Pipeline []PipelineStep

	// Stage1Rounds is the number of SGN encoding rounds applied to
	// the stage-2 blob. Defaults to 3 when zero. Valid range: 1..10.
	Stage1Rounds int

	// Seed drives the poly engine and the stage-2 variant selector.
	// Zero means crypto-random, producing a fresh variant each call.
	Seed int64
}

// ErrUnsupportedFormat fires when [PackBinary] is asked for an unknown
// or unimplemented format. Phase 1e-C/D/E will extend the Format enum.
var ErrUnsupportedFormat = errors.New("packer: unsupported format")

// PackBinary wraps a target payload in a runnable host binary with a
// polymorphic stage-1 decoder and a reflective stage-2 loader.
// Supported formats: [FormatWindowsExe] (Phase 1e-A) and [FormatLinuxELF]
// (Phase 1e-B).
//
// Pure Go: no go build, no system toolchain at pack-time.
//
// Pipeline:
//  1. [PackPipeline] encrypts the payload (default: single AES-GCM step).
//  2. [stubgen.PickStage2Variant] selects a committed stage-2 binary.
//  3. [stubgen.PatchStage2] appends the encrypted payload + key trailer.
//  4. [stubgen.Generate] runs SGN rounds and emits the host binary.
//
// Sentinels: [ErrUnsupportedFormat], [stubgen.ErrInvalidRounds],
// [stubgen.ErrPayloadTooLarge], [stubgen.ErrEncodingSelfTestFailed].
func PackBinary(payload []byte, opts PackBinaryOptions) (host []byte, key []byte, err error) {
	// Two-layer enum: packer.Format is operator-facing; stubgen.HostFormat is
	// internal. The mapping keeps the public API decoupled from the pipeline.
	var hostFormat stubgen.HostFormat
	switch opts.Format {
	case FormatWindowsExe:
		hostFormat = stubgen.HostFormatPE
	case FormatLinuxELF:
		hostFormat = stubgen.HostFormatELF
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}

	rounds := opts.Stage1Rounds
	if rounds == 0 {
		rounds = 3
	}

	pipeline := opts.Pipeline
	if pipeline == nil {
		// AES-GCM is the safe, well-tested default; operators with
		// entropy-cover or multi-cipher requirements pass Pipeline
		// explicitly.
		pipeline = []PipelineStep{{Op: OpCipher, Algo: uint8(CipherAESGCM)}}
	}
	encryptedPayload, keys, err := PackPipeline(payload, pipeline)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackPipeline: %w", err)
	}
	// PackPipeline returns one key per step; PackBinary exposes the
	// first key. Operators needing per-step keys should call PackPipeline
	// directly.
	key = keys[0]

	stage2, err := stubgen.PickStage2Variant(opts.Seed, hostFormat)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: %w", err)
	}

	inner, err := stubgen.PatchStage2(stage2, encryptedPayload, key)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PatchStage2: %w", err)
	}

	host, err = stubgen.Generate(stubgen.Options{
		Inner:      inner,
		Rounds:     rounds,
		Seed:       opts.Seed,
		HostFormat: hostFormat,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("packer: stubgen.Generate: %w", err)
	}

	return host, key, nil
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
