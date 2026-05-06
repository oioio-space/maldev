package packer

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// OpEntropyCover is the pipeline op that lowers a blob's apparent
// Shannon entropy. It runs LATE in a pipeline — after compression
// and encryption — because its job is to undo the high-entropy
// signature those stages produce.
//
// Three sub-algorithms ship: [EntropyCoverInterleave] (low-entropy
// padding spliced between ciphertext chunks — the only one that
// drops the actual histogram entropy), [EntropyCoverCarrier]
// (PNG-shaped header prefix so first-bytes scanners don't fire
// on randomness), and [EntropyCoverHexAlphabet] (each byte
// expanded to 2 bytes drawn from a low-entropy code-like
// alphabet — 2× size, apparent ~3-4 bits/byte).
//
// None of these is a security primitive. They defeat byte-
// histogram heuristics, not adversaries with the wire format.
const OpEntropyCover PipelineOp = 4

// EntropyCover enumerates the algorithms an [OpEntropyCover] step
// can pick. Algo numbers are wire-stable.
type EntropyCover uint8

const (
	// EntropyCoverInterleave splits the input into fixed-size
	// chunks and inserts low-entropy padding between them. Drops
	// real Shannon entropy in proportion to padding ratio.
	EntropyCoverInterleave EntropyCover = 0

	// EntropyCoverCarrier prepends a PNG-shaped 32-byte header.
	// Doesn't change the bulk entropy but defeats heuristics that
	// flag "first 16 bytes look random" (common in droppers).
	EntropyCoverCarrier EntropyCover = 1

	// EntropyCoverHexAlphabet expands each byte to two bytes drawn
	// from a 16-element code-like alphabet. 2× size; apparent
	// histogram entropy drops to ~3-4 bits/byte. Real information
	// content is unchanged — useful only against histogram
	// scanners, not real cryptanalysis.
	EntropyCoverHexAlphabet EntropyCover = 2
)

// String returns the canonical lowercase cover name.
func (e EntropyCover) String() string {
	switch e {
	case EntropyCoverInterleave:
		return "interleave"
	case EntropyCoverCarrier:
		return "carrier"
	case EntropyCoverHexAlphabet:
		return "hex-alphabet"
	default:
		return fmt.Sprintf("entropy-cover(%d)", uint8(e))
	}
}

// PadPattern selects the byte pattern [EntropyCoverInterleave]
// uses to fill its low-entropy padding spans. Mixed is the
// default — a deterministic interleave of NOP / int3 / zero
// that mimics aligned code-section padding.
type PadPattern uint8

const (
	PadPatternZeros    PadPattern = 0 // 0x00 only
	PadPatternInt3     PadPattern = 1 // 0xCC repeated (debug break, common in MSVC pad)
	PadPatternNOP      PadPattern = 2 // 0x90 repeated
	PadPatternMixedASM PadPattern = 3 // Cycle through a code-like alphabet
)

// codeLikeAlphabet is the 16-byte mapping table used by
// [EntropyCoverHexAlphabet] AND [PadPatternMixedASM]. Bytes
// chosen from the top-frequency entries in real .text sections
// across MSVC and mingw builds: REX prefixes, common opcodes,
// padding bytes.
//
// Frequency-ordered: 0x00 (call/jmp displacement), 0x48 (REX.W),
// 0x89 (mov), 0x8B (mov), 0xCC (int3 pad), 0x90 (nop),
// 0xE8 (call rel32), 0xFF (call/jmp), 0x4C (REX.WR), 0x45
// (REX.RB), 0x8D (lea), 0x83 (arith imm8), 0xC3 (ret), 0x10
// (low byte common in displacements), 0x24 (sib base), 0x44
// (REX.R).
var codeLikeAlphabet = [16]byte{
	0x00, 0x48, 0x89, 0x8B, 0xCC, 0x90, 0xE8, 0xFF,
	0x4C, 0x45, 0x8D, 0x83, 0xC3, 0x10, 0x24, 0x44,
}

// invCodeLikeAlphabet inverts [codeLikeAlphabet]. Computed once
// in init; entries for non-alphabet bytes are 0xFF (sentinel).
var invCodeLikeAlphabet [256]byte

func init() {
	for i := range invCodeLikeAlphabet {
		invCodeLikeAlphabet[i] = 0xFF
	}
	for i, b := range codeLikeAlphabet {
		invCodeLikeAlphabet[b] = byte(i)
	}
}

// Default tuning for [EntropyCoverInterleave]. Chunk = 256, pad
// = 128 → padding ratio 33%; Shannon entropy on previously-
// uniform input drops from 8.0 to ~7.4 bits/byte. Stack with
// [EntropyCoverHexAlphabet] to land below 5.
const (
	defaultInterleaveChunkLog2 byte       = 8   // 1 << 8 = 256
	defaultInterleavePadSize   byte       = 128
	defaultInterleavePattern   PadPattern = PadPatternMixedASM
)

// maxInterleaveChunkLog2 caps `chunkLog2` so a malicious wire
// blob can't request a 2^32-byte chunk. 16 → 64 KiB max chunk,
// far above any realistic packed payload boundary.
const maxInterleaveChunkLog2 byte = 16

// interleaveHeaderSize is the fixed prefix the forward pass
// writes before the interleaved data. Recovers (chunk, pad,
// pattern) without an external key.
//
//	+0x00  ChunkLog2  u8  (chunk size = 1 << ChunkLog2; 1..16)
//	+0x01  PadSize    u8  (0..255 bytes between chunks)
//	+0x02  Pattern    u8  ([PadPattern])
//	+0x03  Version    u8  (0)
const interleaveHeaderSize = 4

// Sentinels for the entropy layer.
var (
	// ErrUnsupportedEntropyCover fires when a step references an
	// EntropyCover constant this build doesn't implement.
	ErrUnsupportedEntropyCover = errors.New("packer: unsupported entropy-cover algo")

	// ErrEntropyCoverCorrupt fires when the wire-side metadata
	// (header byte / alphabet sentinel / carrier magic) doesn't
	// validate during reverse.
	ErrEntropyCoverCorrupt = errors.New("packer: entropy-cover blob is corrupt")
)

// applyEntropyCover runs ONE OpEntropyCover step forward. Like
// compression it returns a nil key — all metadata needed for
// reversal is encoded in the body itself, so the pipeline's
// per-step key slot is empty.
func applyEntropyCover(e EntropyCover, key, data []byte) (out []byte, _ []byte, err error) {
	switch e {
	case EntropyCoverInterleave:
		out, err = applyInterleave(key, data)
		return out, nil, err
	case EntropyCoverCarrier:
		return applyCarrier(data), nil, nil
	case EntropyCoverHexAlphabet:
		return applyHexAlphabet(data), nil, nil
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedEntropyCover, e)
	}
}

// reverseEntropyCover runs ONE OpEntropyCover step backward.
func reverseEntropyCover(e EntropyCover, key, data []byte) ([]byte, error) {
	switch e {
	case EntropyCoverInterleave:
		return reverseInterleave(data)
	case EntropyCoverCarrier:
		return reverseCarrier(data)
	case EntropyCoverHexAlphabet:
		return reverseHexAlphabet(data)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEntropyCover, e)
	}
}

// applyInterleave splices low-entropy padding between fixed-size
// chunks of `data`. `key`, when non-nil and length 4, overrides
// the (chunkLog2, padSize, pattern, version) tuning; pass nil to
// get defaults.
func applyInterleave(key, data []byte) ([]byte, error) {
	chunkLog2 := defaultInterleaveChunkLog2
	padSize := defaultInterleavePadSize
	pattern := byte(defaultInterleavePattern)
	if len(key) == interleaveHeaderSize {
		chunkLog2 = key[0]
		padSize = key[1]
		pattern = key[2]
	} else if key != nil {
		return nil, fmt.Errorf("%w: interleave key must be %d bytes (chunkLog2/padSize/pattern/version), got %d",
			ErrUnsupportedEntropyCover, interleaveHeaderSize, len(key))
	}
	if chunkLog2 == 0 || chunkLog2 > maxInterleaveChunkLog2 {
		return nil, fmt.Errorf("%w: chunkLog2 must be in 1..%d, got %d",
			ErrUnsupportedEntropyCover, maxInterleaveChunkLog2, chunkLog2)
	}
	if pattern > byte(PadPatternMixedASM) {
		return nil, fmt.Errorf("%w: pattern out of range: %d", ErrUnsupportedEntropyCover, pattern)
	}
	chunkSize := 1 << chunkLog2

	numChunks := (len(data) + chunkSize - 1) / chunkSize
	gaps := numChunks - 1
	if gaps < 0 {
		gaps = 0
	}
	out := make([]byte, interleaveHeaderSize+len(data)+gaps*int(padSize))
	out[0] = chunkLog2
	out[1] = padSize
	out[2] = pattern
	out[3] = 0 // version

	off := interleaveHeaderSize
	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		copy(out[off:], data[start:end])
		off += end - start
		if i < numChunks-1 && padSize > 0 {
			fillPattern(out[off:off+int(padSize)], PadPattern(pattern))
			off += int(padSize)
		}
	}
	return out, nil
}

// reverseInterleave drops the padding bytes inserted by
// [applyInterleave] and recovers the original data.
func reverseInterleave(data []byte) ([]byte, error) {
	if len(data) < interleaveHeaderSize {
		return nil, fmt.Errorf("%w: interleave body shorter than 4-byte header", ErrEntropyCoverCorrupt)
	}
	chunkLog2 := data[0]
	padSize := int(data[1])
	pattern := data[2]
	if chunkLog2 == 0 || chunkLog2 > maxInterleaveChunkLog2 {
		return nil, fmt.Errorf("%w: chunkLog2 out of range: %d", ErrEntropyCoverCorrupt, chunkLog2)
	}
	if pattern > byte(PadPatternMixedASM) {
		return nil, fmt.Errorf("%w: pattern out of range: %d", ErrEntropyCoverCorrupt, pattern)
	}
	chunkSize := 1 << chunkLog2

	body := data[interleaveHeaderSize:]
	out := make([]byte, 0, len(body))
	for off := 0; off < len(body); {
		end := off + chunkSize
		if end > len(body) {
			end = len(body)
		}
		out = append(out, body[off:end]...)
		off = end
		// Skip pad if there's another chunk after; pad+chunk-edge
		// detection is by remaining-bytes count.
		if off < len(body) {
			off += padSize
		}
	}
	return out, nil
}

// fillPattern writes the configured pad pattern into dst. Caller
// has bounds-checked p; the default case is a panic-tripwire so a
// future pattern added without wiring a case here surfaces loudly
// instead of silently writing zeros that still round-trip.
func fillPattern(dst []byte, p PadPattern) {
	switch p {
	case PadPatternZeros:
		// dst comes from make() in applyInterleave — already zeroed.
	case PadPatternInt3:
		for i := range dst {
			dst[i] = 0xCC
		}
	case PadPatternNOP:
		for i := range dst {
			dst[i] = 0x90
		}
	case PadPatternMixedASM:
		// 16-byte stamp + doubling copy — compiles to memmove
		// rather than per-byte writes; ~5-10× faster on pad runs
		// ≥ 64 bytes.
		if len(dst) == 0 {
			return
		}
		n := copy(dst, codeLikeAlphabet[:])
		for n < len(dst) {
			n += copy(dst[n:], dst[:n])
		}
	default:
		panic(fmt.Sprintf("packer: unhandled PadPattern %d", p))
	}
}

// carrierPNG is the 32-byte fake PNG-shaped wrapper prepended by
// [EntropyCoverCarrier]. Magic bytes match a real PNG; the IHDR
// chunk encodes a 1×1 image dimension which is trivially valid
// against most parsers but never actually rendered. The CRC32
// is computed over a dummy literal so it parses cleanly.
//
// On the wire we additionally store the original payload size
// in 4 bytes immediately after the carrier so reverse can split.
var carrierPNG = [...]byte{
	// PNG signature (8 bytes)
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	// IHDR chunk: length (4) = 13
	0x00, 0x00, 0x00, 0x0D,
	// "IHDR"
	0x49, 0x48, 0x44, 0x52,
	// IHDR data: 1×1, 8-bit, color type 0 (greyscale), defaults
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x00, 0x00, 0x00, 0x00,
	// IHDR CRC32 (precomputed for the IHDR shape above)
	0x3B, 0x7E, 0x9B, 0x55,
}

const carrierHeaderSize = len(carrierPNG) + 4 // PNG bytes + 4-byte size prefix

// applyCarrier prepends the PNG-shaped wrapper.
func applyCarrier(data []byte) []byte {
	out := make([]byte, carrierHeaderSize+len(data))
	copy(out, carrierPNG[:])
	binary.LittleEndian.PutUint32(out[len(carrierPNG):], uint32(len(data)))
	copy(out[carrierHeaderSize:], data)
	return out
}

// reverseCarrier validates the PNG header and strips it.
func reverseCarrier(data []byte) ([]byte, error) {
	if len(data) < carrierHeaderSize {
		return nil, fmt.Errorf("%w: carrier body shorter than %d-byte header",
			ErrEntropyCoverCorrupt, carrierHeaderSize)
	}
	for i, want := range carrierPNG {
		if data[i] != want {
			return nil, fmt.Errorf("%w: carrier magic mismatch at byte %d", ErrEntropyCoverCorrupt, i)
		}
	}
	want := binary.LittleEndian.Uint32(data[len(carrierPNG):])
	body := data[carrierHeaderSize:]
	if uint32(len(body)) != want {
		return nil, fmt.Errorf("%w: carrier body is %d, prefix says %d",
			ErrEntropyCoverCorrupt, len(body), want)
	}
	return body, nil
}

// hexAlphabetMagic prefixes [EntropyCoverHexAlphabet] output so
// reverse can detect a non-hex-alphabet body and reject early.
// Two bytes (also drawn from the alphabet) + a 4-byte original-
// size LE suffix keep the wire format self-describing.
var hexAlphabetMagic = [2]byte{codeLikeAlphabet[0xC], codeLikeAlphabet[0x3]} // 0xC3 0x8B → "ret mov" pair

const hexAlphabetHeaderSize = 2 + 4 // magic + size prefix

// applyHexAlphabet expands each byte to 2 bytes via the code-like
// alphabet. The output payload is exactly 2 × len(data); a small
// fixed header carries magic + original size.
func applyHexAlphabet(data []byte) []byte {
	out := make([]byte, hexAlphabetHeaderSize+2*len(data))
	out[0] = hexAlphabetMagic[0]
	out[1] = hexAlphabetMagic[1]
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(data)))
	for i, b := range data {
		out[hexAlphabetHeaderSize+2*i] = codeLikeAlphabet[b>>4]
		out[hexAlphabetHeaderSize+2*i+1] = codeLikeAlphabet[b&0x0F]
	}
	return out
}

// reverseHexAlphabet rebuilds the original bytes from 2-byte
// alphabet pairs. Rejects bytes that aren't in [codeLikeAlphabet].
func reverseHexAlphabet(data []byte) ([]byte, error) {
	if len(data) < hexAlphabetHeaderSize {
		return nil, fmt.Errorf("%w: hex-alphabet body shorter than %d-byte header",
			ErrEntropyCoverCorrupt, hexAlphabetHeaderSize)
	}
	if data[0] != hexAlphabetMagic[0] || data[1] != hexAlphabetMagic[1] {
		return nil, fmt.Errorf("%w: hex-alphabet magic mismatch", ErrEntropyCoverCorrupt)
	}
	want := binary.LittleEndian.Uint32(data[2:6])
	body := data[hexAlphabetHeaderSize:]
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("%w: hex-alphabet body length %d not even", ErrEntropyCoverCorrupt, len(body))
	}
	if uint32(len(body)/2) != want {
		return nil, fmt.Errorf("%w: hex-alphabet decoded would be %d, prefix says %d",
			ErrEntropyCoverCorrupt, len(body)/2, want)
	}
	out := make([]byte, len(body)/2)
	for i := 0; i < len(out); i++ {
		hi := invCodeLikeAlphabet[body[2*i]]
		lo := invCodeLikeAlphabet[body[2*i+1]]
		if hi == 0xFF || lo == 0xFF {
			return nil, fmt.Errorf("%w: hex-alphabet byte at offset %d not in alphabet",
				ErrEntropyCoverCorrupt, hexAlphabetHeaderSize+2*i)
		}
		// invCodeLikeAlphabet entries are 0..15 by construction;
		// no mask on `lo` needed.
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

