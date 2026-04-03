package strip

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalPE builds a valid-enough PE for unit tests: MZ header, PE signature,
// COFF header with 1 section, and a section header starting at the computed
// offset.
func minimalPE() []byte {
	pe := make([]byte, 512)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x80)      // e_lfanew
	copy(pe[0x80:], []byte("PE\x00\x00"))                // PE signature
	binary.LittleEndian.PutUint16(pe[0x80+4+2:], 1)      // NumberOfSections = 1
	binary.LittleEndian.PutUint16(pe[0x80+4+16:], 0xF0)  // SizeOfOptionalHeader
	secOffset := 0x80 + 4 + 20 + 0xF0                    // section header start
	copy(pe[secOffset:], ".text\x00\x00\x00")            // section name
	return pe
}

func TestSetTimestamp(t *testing.T) {
	pe := minimalPE()
	ts := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	pe = SetTimestamp(pe, ts)

	peOffset := binary.LittleEndian.Uint32(pe[0x3C:])
	got := binary.LittleEndian.Uint32(pe[peOffset+4+4:])
	assert.Equal(t, uint32(ts.Unix()), got)
}

func TestRenameSections(t *testing.T) {
	pe := minimalPE()
	pe = RenameSections(pe, map[string]string{".text": ".code"})

	peOffset := binary.LittleEndian.Uint32(pe[0x3C:])
	coffStart := peOffset + 4
	sizeOfOptHdr := binary.LittleEndian.Uint16(pe[coffStart+16:])
	secOffset := coffStart + 20 + uint32(sizeOfOptHdr)

	var name [8]byte
	copy(name[:], pe[secOffset:secOffset+8])
	assert.Equal(t, ".code\x00\x00\x00", string(name[:]))
}

func TestRenameSections_NoMatch(t *testing.T) {
	pe := minimalPE()
	original := make([]byte, len(pe))
	copy(original, pe)

	pe = RenameSections(pe, map[string]string{".bss": ".data"})
	assert.Equal(t, original, pe, "no sections should change when names don't match")
}

func TestWipePclntab(t *testing.T) {
	pe := minimalPE()
	// Embed Go 1.20+ pclntab magic at offset 0x100.
	pe[0x100] = 0xF1
	pe[0x101] = 0xFF
	pe[0x102] = 0xFF
	pe[0x103] = 0xFF
	// Fill the next 28 bytes with non-zero data.
	for i := 0x104; i < 0x120; i++ {
		pe[i] = 0xAA
	}

	pe = WipePclntab(pe)

	// Verify all 32 bytes starting at 0x100 are zeroed.
	for i := 0x100; i < 0x120; i++ {
		require.Zerof(t, pe[i], "byte at offset 0x%X should be zero", i)
	}
}

func TestWipePclntab_Go116(t *testing.T) {
	pe := minimalPE()
	// Embed Go 1.16+ pclntab magic.
	pe[0x100] = 0xF0
	pe[0x101] = 0xFF
	pe[0x102] = 0xFF
	pe[0x103] = 0xFF
	for i := 0x104; i < 0x120; i++ {
		pe[i] = 0xBB
	}

	pe = WipePclntab(pe)

	for i := 0x100; i < 0x120; i++ {
		require.Zerof(t, pe[i], "byte at offset 0x%X should be zero", i)
	}
}

func TestSanitize(t *testing.T) {
	pe := minimalPE()
	require.NotPanics(t, func() {
		pe = Sanitize(pe)
	})
	// Verify timestamp was written (non-zero).
	peOffset := binary.LittleEndian.Uint32(pe[0x3C:])
	ts := binary.LittleEndian.Uint32(pe[peOffset+4+4:])
	assert.NotZero(t, ts, "timestamp should be set")
}
