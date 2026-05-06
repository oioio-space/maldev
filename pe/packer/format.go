package packer

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Magic identifies a maldev-packed blob. Four bytes at the start
// of every Pack output. Picked to avoid collision with common
// PE/ELF/script magics (MZ, ELF, #!, PK, …).
var Magic = [4]byte{'M', 'L', 'D', 'V'}

// FormatVersion bumps when the on-wire blob layout changes in a
// non-backwards-compatible way. Unpack rejects unknown versions
// to fail loudly rather than misinterpret bytes.
const FormatVersion uint16 = 1

// Cipher selects the AEAD primitive used to encrypt the payload.
// AESGCM is the modern default; ChaCha20 wins on hosts without
// AES-NI; RC4 is legacy / shellcode-loader compatible only.
type Cipher uint8

const (
	CipherAESGCM   Cipher = 0
	CipherChaCha20 Cipher = 1
	CipherRC4      Cipher = 2
)

// String returns the canonical lowercase cipher name.
func (c Cipher) String() string {
	switch c {
	case CipherAESGCM:
		return "aes-gcm"
	case CipherChaCha20:
		return "chacha20-poly1305"
	case CipherRC4:
		return "rc4"
	default:
		return fmt.Sprintf("cipher(%d)", uint8(c))
	}
}

// Compressor selects the compression pass run BEFORE encryption.
type Compressor uint8

const (
	CompressorNone  Compressor = 0
	CompressorAPLib Compressor = 1
	CompressorLZMA  Compressor = 2
	CompressorZstd  Compressor = 3
	CompressorLZ4   Compressor = 4
)

// String returns the canonical lowercase compressor name.
func (c Compressor) String() string {
	switch c {
	case CompressorNone:
		return "none"
	case CompressorAPLib:
		return "aplib"
	case CompressorLZMA:
		return "lzma"
	case CompressorZstd:
		return "zstd"
	case CompressorLZ4:
		return "lz4"
	default:
		return fmt.Sprintf("compressor(%d)", uint8(c))
	}
}

// HeaderSize is the on-wire byte length of the fixed-size blob
// header. Constant across versions; format-version changes that
// extend the header live in a separate "extended header" trailer
// after the magic to preserve backward parsing.
const HeaderSize = 32

// header is the binary-serialized blob preamble. Field ordering
// is wire-stable per FormatVersion. The body that follows is
// crypto.EncryptAESGCM's output (nonce-prefixed ciphertext +
// auth tag) — the nonce isn't broken out here because the AEAD
// layer owns its own framing.
type header struct {
	Magic       [4]byte
	Version     uint16
	Cipher      uint8
	Compressor  uint8
	OrigSize    uint64
	PayloadSize uint64
	_           [8]byte
}

// marshalInto writes the header into dst[:HeaderSize]. dst must
// be at least HeaderSize bytes; reuses the caller's allocation
// so Pack can size the whole blob in one make().
func (h *header) marshalInto(dst []byte) {
	_ = dst[HeaderSize-1]
	copy(dst[0:4], h.Magic[:])
	binary.LittleEndian.PutUint16(dst[4:6], h.Version)
	dst[6] = h.Cipher
	dst[7] = h.Compressor
	binary.LittleEndian.PutUint64(dst[8:16], h.OrigSize)
	binary.LittleEndian.PutUint64(dst[16:24], h.PayloadSize)
	for i := 24; i < HeaderSize; i++ {
		dst[i] = 0
	}
}

// unmarshalHeader parses the first HeaderSize bytes of `data`
// into a header.
func unmarshalHeader(data []byte) (*header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("%w: have %d bytes, need %d", ErrShortBlob, len(data), HeaderSize)
	}
	h := &header{
		Version:     binary.LittleEndian.Uint16(data[4:6]),
		Cipher:      data[6],
		Compressor:  data[7],
		OrigSize:    binary.LittleEndian.Uint64(data[8:16]),
		PayloadSize: binary.LittleEndian.Uint64(data[16:24]),
	}
	copy(h.Magic[:], data[0:4])
	if h.Magic != Magic {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrBadMagic, h.Magic, Magic)
	}
	if h.Version != FormatVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, FormatVersion)
	}
	return h, nil
}

// Sentinel errors surfaced by the format / Unpack layer.
var (
	// ErrShortBlob fires when the input bytes are too small to
	// contain a maldev-packed header.
	ErrShortBlob = errors.New("packer: blob shorter than header")

	// ErrBadMagic fires when the first 4 bytes don't match [Magic].
	ErrBadMagic = errors.New("packer: bad magic")

	// ErrUnsupportedVersion fires when the blob's version field
	// doesn't match this build's [FormatVersion].
	ErrUnsupportedVersion = errors.New("packer: unsupported format version")

	// ErrUnsupportedCipher fires when the blob references a
	// Cipher constant this build doesn't know how to decrypt.
	ErrUnsupportedCipher = errors.New("packer: unsupported cipher")

	// ErrUnsupportedCompressor fires when the blob references a
	// Compressor constant this build doesn't know how to inflate.
	ErrUnsupportedCompressor = errors.New("packer: unsupported compressor")

	// ErrPayloadSizeMismatch fires when the header's PayloadSize
	// disagrees with the actual byte count after the header.
	ErrPayloadSizeMismatch = errors.New("packer: payload size mismatch")
)
