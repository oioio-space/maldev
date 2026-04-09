package parse

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useSystemDLL returns the path to ntdll.dll and skips if not on Windows.
func useSystemDLL(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only: requires ntdll.dll")
	}
	path := `C:\Windows\System32\ntdll.dll`
	if _, err := os.Stat(path); err != nil {
		t.Skipf("ntdll.dll not found at %s: %v", path, err)
	}
	return path
}

func TestOpenValidPE(t *testing.T) {
	path := useSystemDLL(t)

	f, err := Open(path)
	require.NoError(t, err, "Open should succeed for a valid PE")
	require.NotNil(t, f)
	defer f.Close()

	// ntdll.dll on a 64-bit Windows system is a 64-bit DLL.
	assert.True(t, f.Is64Bit(), "ntdll.dll should be 64-bit")
	assert.True(t, f.IsDLL(), "ntdll.dll should be a DLL")
}

func TestParseSections(t *testing.T) {
	path := useSystemDLL(t)

	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	sections := f.Sections()
	require.NotEmpty(t, sections, "PE should have at least one section")

	// Every valid Windows PE has a .text section.
	var found bool
	for _, sec := range sections {
		if sec.Name == ".text" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected .text section in ntdll.dll")
}

func TestParseExports(t *testing.T) {
	path := useSystemDLL(t)

	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	exports, err := f.Exports()
	require.NoError(t, err, "Exports should not return an error for ntdll.dll")
	require.NotEmpty(t, exports, "ntdll.dll must export symbols")

	// NtClose is a fundamental syscall stub present in every ntdll build.
	var found bool
	for _, name := range exports {
		if name == "NtClose" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected NtClose in ntdll.dll exports")
}

func TestFromBytesRoundTrip(t *testing.T) {
	path := useSystemDLL(t)

	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading ntdll.dll bytes should succeed")

	f, err := FromBytes(data, path)
	require.NoError(t, err, "FromBytes should parse ntdll.dll bytes correctly")
	require.NotNil(t, f)
	defer f.Close()

	assert.True(t, f.Is64Bit(), "round-trip PE from bytes should still be 64-bit")
}

func TestParseInvalidBytes(t *testing.T) {
	// 0xDEAD is not a valid PE magic; FromBytes must return an error.
	_, err := FromBytes([]byte{0xDE, 0xAD}, "bad.exe")
	assert.Error(t, err, "FromBytes with invalid bytes must return an error")
}

func TestParseTruncatedMZ(t *testing.T) {
	// The MZ magic is present but the rest of the header is missing.
	_, err := FromBytes([]byte{'M', 'Z'}, "trunc.exe")
	assert.Error(t, err, "FromBytes with a truncated MZ stub must return an error")
}

func TestParseEmptyFile(t *testing.T) {
	_, err := FromBytes([]byte{}, "empty.exe")
	assert.Error(t, err, "FromBytes with empty bytes must return an error")
}

func TestFromBytesNilSlice(t *testing.T) {
	_, err := FromBytes(nil, "nil.exe")
	assert.Error(t, err, "FromBytes with nil bytes must return an error")
}

func TestFromBytesGarbageBytes(t *testing.T) {
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	_, err := FromBytes(garbage, "garbage.exe")
	assert.Error(t, err, "FromBytes with all-0xFF bytes must return an error")
}

func TestSectionByNameMissing(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	sec := f.SectionByName(".zzz_nonexistent")
	assert.Nil(t, sec, "SectionByName for a non-existent section must return nil")
}

func TestSectionByNameText(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	sec := f.SectionByName(".text")
	require.NotNil(t, sec, ".text section must exist in ntdll.dll")
	assert.Equal(t, ".text", sec.Name)
}

func TestSectionData(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	sec := f.SectionByName(".text")
	require.NotNil(t, sec)
	data, err := f.SectionData(sec)
	require.NoError(t, err)
	assert.NotEmpty(t, data, ".text section data must not be empty")
}

func TestImageBase(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	base := f.ImageBase()
	assert.Greater(t, base, uint64(0), "ImageBase must be positive for ntdll.dll")
	t.Logf("ImageBase: 0x%X", base)
}

func TestEntryPoint(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	// EntryPoint returns the RVA; ntdll.dll may have 0 (no DllMain).
	// Just verify the call doesn't panic and returns a valid uint32.
	ep := f.EntryPoint()
	t.Logf("EntryPoint RVA: 0x%X", ep)
}

func TestImports(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	// ntdll.dll is a low-level DLL; it may have zero imports.
	// We just verify the call doesn't error.
	_, err = f.Imports()
	assert.NoError(t, err, "Imports must not error for a valid PE")
}

func TestWriteBytes(t *testing.T) {
	path := useSystemDLL(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	f, err := FromBytes(data, path)
	require.NoError(t, err)
	defer f.Close()

	out := f.WriteBytes()
	assert.Equal(t, data, out, "WriteBytes must return the same bytes passed to FromBytes")
}
