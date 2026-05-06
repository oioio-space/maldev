// Package packer is maldev's custom PE/ELF packer.
//
// Today the package ships only the encrypt + embed pipeline:
// [Pack] takes any byte buffer and produces a self-describing
// maldev-format blob (header + AEAD-encrypted payload). [Unpack]
// reverses the pipeline given the key. The blob is NOT runnable
// as a PE; the reflective loader stub that wraps the blob into
// a runnable PE/ELF lands in a follow-up phase.
//
// Design + roadmap: docs/refactor-2026-doc/packer-design.md.
package packer

import (
	"fmt"

	"github.com/oioio-space/maldev/crypto"
	"github.com/oioio-space/maldev/pe/packer/internal/elfgate"
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
