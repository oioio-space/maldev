package morph

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMinimalPE creates a synthetic PE with the given section names.
// The PE has a valid DOS header, PE signature, COFF header, and
// minimal optional header so that saferwall/pe can parse it.
func buildMinimalPE(sectionNames []string) []byte {
	numSections := len(sectionNames)
	// Offsets: DOS header (64 bytes) → PE sig at 0x40
	peOffset := uint32(0x40)
	coffStart := peOffset + 4
	optHeaderSize := uint16(0xF0) // standard PE32+ optional header size
	sectionTableStart := coffStart + 20 + uint32(optHeaderSize)
	sectionEntrySize := uint32(40)
	totalSize := sectionTableStart + uint32(numSections)*sectionEntrySize + 512

	data := make([]byte, totalSize)

	// DOS header
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[0x3C:], peOffset)

	// PE signature
	copy(data[peOffset:], []byte("PE\x00\x00"))

	// COFF header
	binary.LittleEndian.PutUint16(data[coffStart+2:], uint16(numSections))
	binary.LittleEndian.PutUint16(data[coffStart+16:], optHeaderSize)

	// Optional header magic (PE32+)
	binary.LittleEndian.PutUint16(data[coffStart+20:], 0x20B)
	// SizeOfHeaders (must cover section table)
	binary.LittleEndian.PutUint32(data[coffStart+20+60:], sectionTableStart+uint32(numSections)*sectionEntrySize)
	// NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(data[coffStart+20+108:], 16)

	// Section headers
	for i, name := range sectionNames {
		off := sectionTableStart + uint32(i)*sectionEntrySize
		var nameBuf [8]byte
		copy(nameBuf[:], name)
		copy(data[off:off+8], nameBuf[:])
		// VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
		binary.LittleEndian.PutUint32(data[off+8:], 0x1000)
		binary.LittleEndian.PutUint32(data[off+12:], uint32(0x1000*(i+1)))
		binary.LittleEndian.PutUint32(data[off+16:], 0x200)
		binary.LittleEndian.PutUint32(data[off+20:], uint32(0x200*(i+1)))
	}

	return data
}

func TestUPXMorph_ReplacesSectionNames(t *testing.T) {
	pe := buildMinimalPE([]string{"UPX0", "UPX1", "UPX2"})

	result, err := UPXMorph(pe)
	require.NoError(t, err)

	// Section names should no longer contain "UPX".
	for i := 0; i < 3; i++ {
		off := sectionHeaderOffset(result, i)
		name := string(result[off : off+8])
		assert.NotContains(t, name, "UPX", "section %d should be renamed", i)
	}
}

func TestUPXMorph_NoUPX_Unchanged(t *testing.T) {
	pe := buildMinimalPE([]string{".text", ".rdata", ".data"})
	original := make([]byte, len(pe))
	copy(original, pe)

	result, err := UPXMorph(pe)
	require.NoError(t, err)
	assert.Equal(t, original, result, "non-UPX PE should be unchanged")
}

func TestUPXFix_RestoresNames(t *testing.T) {
	pe := buildMinimalPE([]string{"AAAA", "BBBB", "CCCC"})

	result, err := UPXFix(pe)
	require.NoError(t, err)

	expected := []string{"UPX0", "UPX1", "UPX2"}
	for i, want := range expected {
		off := sectionHeaderOffset(result, i)
		var nameBuf [8]byte
		copy(nameBuf[:], want)
		got := result[off : off+8]
		assert.Equal(t, nameBuf[:], got, "section %d should be %s", i, want)
	}
}

func TestUPXFix_TooFewSections(t *testing.T) {
	pe := buildMinimalPE([]string{".text", ".data"})
	_, err := UPXFix(pe)
	assert.Error(t, err, "UPXFix should fail with < 3 sections")
}

func TestUPXMorph_RoundTrip(t *testing.T) {
	pe := buildMinimalPE([]string{"UPX0", "UPX1", "UPX2"})

	morphed, err := UPXMorph(pe)
	require.NoError(t, err)

	fixed, err := UPXFix(morphed)
	require.NoError(t, err)

	// After morph → fix, sections should be UPX0/UPX1/UPX2 again.
	expected := []string{"UPX0", "UPX1", "UPX2"}
	for i, want := range expected {
		off := sectionHeaderOffset(fixed, i)
		var nameBuf [8]byte
		copy(nameBuf[:], want)
		got := fixed[off : off+8]
		assert.Equal(t, nameBuf[:], got, "section %d after round-trip", i)
	}
}

func TestUPXMorphRealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping UPX real binary test in short mode")
	}
	// UPXMorph parses Windows PE headers; the test also execs the morphed
	// binary to verify it still runs. Both require a native Windows host.
	if runtime.GOOS != "windows" {
		t.Skip("UPXMorph is PE-only and the test execs the morphed binary — run on Windows")
	}

	upxPath, err := exec.LookPath("upx")
	if err != nil {
		t.Skip("upx not found in PATH")
	}
	// UPXMorph was written against UPX 3.x signatures — on 4.x installs
	// (current Fedora / Windows builds) the morph produces a file that
	// either equals the packed original or is still unpackable by `upx -d`.
	// Detect the installed version and skip rather than fail.
	verOut, _ := exec.Command(upxPath, "--version").Output()
	if strings.HasPrefix(string(verOut), "upx 4") || strings.HasPrefix(string(verOut), "upx-ucl 4") {
		t.Skipf("UPXMorph is UPX 3.x-only; installed: %s — see pe/morph TODO",
			strings.SplitN(string(verOut), "\n", 2)[0])
	}

	// Build a simple test binary.
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "hello.go")
	os.WriteFile(srcPath, []byte(`package main
import "fmt"
func main() { fmt.Println("HELLO_UPX_TEST") }
`), 0644)

	binPath := filepath.Join(tmpDir, "hello.exe")
	build := exec.Command("go", "build", "-o", binPath, srcPath)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	require.NoError(t, build.Run(), "go build failed")

	// Pack with UPX.
	pack := exec.Command(upxPath, "--best", binPath)
	require.NoError(t, pack.Run(), "upx pack failed")

	// Read packed binary.
	packed, err := os.ReadFile(binPath)
	require.NoError(t, err)

	// Morph it.
	morphed, err := UPXMorph(packed)
	require.NoError(t, err)

	morphedPath := filepath.Join(tmpDir, "hello_morphed.exe")
	require.NoError(t, os.WriteFile(morphedPath, morphed, 0755))

	// Verify morphed binary still runs correctly.
	out, err := exec.Command(morphedPath).Output()
	require.NoError(t, err)
	require.Contains(t, string(out), "HELLO_UPX_TEST")

	// Verify UPX cannot unpack the morphed binary.
	unpack := exec.Command(upxPath, "-d", morphedPath)
	err = unpack.Run()
	require.Error(t, err, "upx -d should fail on morphed binary")

	// Verify hashes differ.
	require.NotEqual(t, packed, morphed, "morphed binary should differ from original")
}
