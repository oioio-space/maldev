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
	CompressorAPLib Compressor = 1 // reserved; not yet implemented
	CompressorLZMA  Compressor = 2 // reserved; not yet implemented
	CompressorZstd  Compressor = 3 // reserved; not yet implemented
	CompressorLZ4   Compressor = 4 // reserved; not yet implemented
	CompressorFlate Compressor = 5 // raw DEFLATE (compress/flate)
	CompressorGzip  Compressor = 6 // gzip-framed DEFLATE (compress/gzip)
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
	case CompressorFlate:
		return "flate"
	case CompressorGzip:
		return "gzip"
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

// FormatVersionPipeline is the wire-format version emitted by
// [PackPipeline]. Distinct from [FormatVersion] (used by [Pack])
// so old single-cipher blobs continue to unpack via the v1 path
// and new multi-step blobs route through [UnpackPipeline].
const FormatVersionPipeline uint16 = 2

// headerSizeV2 is the on-wire size of the v2 header. Same 32
// bytes as v1; the Cipher + Compressor fields are repurposed
// as NumSteps + reserved.
const headerSizeV2 = 32

// headerV2 is the v2 wire layout. Same total size as [header]
// (32 bytes) so callers don't need to track size variants.
//
//	+0x00  Magic        [4]byte "MLDV"
//	+0x04  Version      u16 = 2
//	+0x06  NumSteps     u8 (1..255)
//	+0x07  reserved     u8
//	+0x08  OrigSize     u64
//	+0x10  PayloadSize  u64
//	+0x18  reserved     [8]byte
type headerV2 struct {
	Magic       [4]byte
	Version     uint16
	NumSteps    uint8
	OrigSize    uint64
	PayloadSize uint64
}

// marshalInto writes the v2 header into dst[:headerSizeV2].
func (h *headerV2) marshalInto(dst []byte) {
	_ = dst[headerSizeV2-1]
	copy(dst[0:4], h.Magic[:])
	binary.LittleEndian.PutUint16(dst[4:6], h.Version)
	dst[6] = h.NumSteps
	dst[7] = 0
	binary.LittleEndian.PutUint64(dst[8:16], h.OrigSize)
	binary.LittleEndian.PutUint64(dst[16:24], h.PayloadSize)
	for i := 24; i < headerSizeV2; i++ {
		dst[i] = 0
	}
}

// unmarshalHeaderV2 parses the first headerSizeV2 bytes of `data`
// into a v2 header. Rejects v1 blobs with [ErrUnsupportedVersion]
// so callers can route v1 inputs to the legacy [Unpack] path.
func unmarshalHeaderV2(data []byte) (*headerV2, error) {
	if len(data) < headerSizeV2 {
		return nil, fmt.Errorf("%w: have %d bytes, need %d", ErrShortBlob, len(data), headerSizeV2)
	}
	h := &headerV2{
		Version:     binary.LittleEndian.Uint16(data[4:6]),
		NumSteps:    data[6],
		OrigSize:    binary.LittleEndian.Uint64(data[8:16]),
		PayloadSize: binary.LittleEndian.Uint64(data[16:24]),
	}
	copy(h.Magic[:], data[0:4])
	if h.Magic != Magic {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrBadMagic, h.Magic, Magic)
	}
	if h.Version != FormatVersionPipeline {
		return nil, fmt.Errorf("%w: got %d, want %d (pipeline)",
			ErrUnsupportedVersion, h.Version, FormatVersionPipeline)
	}
	if h.NumSteps == 0 {
		return nil, fmt.Errorf("%w: pipeline has zero steps", ErrBadMagic)
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
