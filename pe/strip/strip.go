package strip

import (
	"encoding/binary"
	"math/rand"
	"time"
)

// SetTimestamp overwrites IMAGE_FILE_HEADER.TimeDateStamp (at PE offset + 8)
// with the Unix epoch representation of t.
func SetTimestamp(peData []byte, t time.Time) []byte {
	peOffset := binary.LittleEndian.Uint32(peData[0x3C:])
	tsOffset := peOffset + 4 + 4 // PE sig(4) + Machine(2) + NumberOfSections(2) = +8, but TimeDateStamp is at COFF+4
	binary.LittleEndian.PutUint32(peData[tsOffset:], uint32(t.Unix()))
	return peData
}

// WipePclntab searches for the Go pclntab magic (0xFFFFFFF1 for Go 1.20+,
// 0xFFFFFFF0 for Go 1.16+) in section data and zeros the first 32 bytes of
// each occurrence, breaking Go-specific analysis tools (IDA go_parser,
// redress, GoReSym).
func WipePclntab(peData []byte) []byte {
	magics := [][]byte{
		{0xF1, 0xFF, 0xFF, 0xFF}, // Go 1.20+
		{0xF0, 0xFF, 0xFF, 0xFF}, // Go 1.16+
	}

	for _, magic := range magics {
		for i := 0; i <= len(peData)-4; i++ {
			if peData[i] == magic[0] &&
				peData[i+1] == magic[1] &&
				peData[i+2] == magic[2] &&
				peData[i+3] == magic[3] {
				end := i + 32
				if end > len(peData) {
					end = len(peData)
				}
				for j := i; j < end; j++ {
					peData[j] = 0
				}
			}
		}
	}

	return peData
}

// RenameSections renames PE sections according to the provided map.
// Section names in PE headers are 8-byte null-padded ASCII fields.
// Example: map[string]string{".gopclntab": ".rdata2", ".text": ".code"}
func RenameSections(peData []byte, renames map[string]string) []byte {
	if len(renames) == 0 {
		return peData
	}

	peOffset := binary.LittleEndian.Uint32(peData[0x3C:])
	coffStart := peOffset + 4
	numSections := binary.LittleEndian.Uint16(peData[coffStart+2:])
	sizeOfOptHdr := binary.LittleEndian.Uint16(peData[coffStart+16:])
	sectionTableStart := coffStart + 20 + uint32(sizeOfOptHdr)

	for i := uint16(0); i < numSections; i++ {
		offset := sectionTableStart + uint32(i)*40
		// Read current section name (8 bytes, null-padded).
		var name [8]byte
		copy(name[:], peData[offset:offset+8])
		// Trim trailing nulls for comparison.
		nameStr := string(name[:])
		for k := 0; k < 8; k++ {
			if nameStr[k] == 0 {
				nameStr = nameStr[:k]
				break
			}
		}

		if newName, ok := renames[nameStr]; ok {
			var buf [8]byte
			copy(buf[:], newName)
			copy(peData[offset:offset+8], buf[:])
		}
	}

	return peData
}

// Sanitize applies all available sanitizations with sensible defaults:
// timestamp set to a random date in 2023-2024, pclntab wiped, and
// Go-specific sections renamed.
func Sanitize(peData []byte) []byte {
	// Random timestamp between 2023-01-01 and 2024-12-31.
	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	delta := end.Unix() - start.Unix()
	randomTS := start.Add(time.Duration(rand.Int63n(delta)) * time.Second) //nolint:gosec // non-crypto rand is fine for fake timestamps
	peData = SetTimestamp(peData, randomTS)

	peData = WipePclntab(peData)

	peData = RenameSections(peData, map[string]string{
		".gopclntab": ".rdata2",
		".go.buildinfo": ".rsrc2",
		".noptrdata": ".data2",
	})

	return peData
}
