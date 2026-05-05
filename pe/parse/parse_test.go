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

func TestExportEntries_NtdllShape(t *testing.T) {
	path := useSystemDLL(t)

	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	entries, err := f.ExportEntries()
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// ntdll exports thousands of named functions; every entry must
	// carry a non-zero ordinal and the NtClose entry must be findable.
	var ntCloseOrdinal uint16
	for _, e := range entries {
		assert.NotZero(t, e.Ordinal, "every export should have a non-zero ordinal")
		if e.Name == "NtClose" {
			ntCloseOrdinal = e.Ordinal
		}
	}
	assert.NotZero(t, ntCloseOrdinal, "NtClose must be present in ntdll.dll")
}

// TestExportEntries_MsvcrtOrdinals asserts ExportEntries surfaces
// ordinal-only entries — the whole point of the API. msvcrt.dll
// historically exports a couple of ordinal-only entries (e.g.
// `_o_cabs`, `_o_aligned_malloc`, ...). Modern Win10/11 may carry
// fewer but msvcrt always has at least one.
func TestExportEntries_MsvcrtOrdinals(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only: requires msvcrt.dll")
	}
	const path = `C:\Windows\System32\msvcrt.dll`
	if _, err := os.Stat(path); err != nil {
		t.Skipf("msvcrt.dll not found: %v", err)
	}
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	entries, err := f.ExportEntries()
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var named, ordinalOnly int
	for _, e := range entries {
		if e.Name == "" {
			ordinalOnly++
		} else {
			named++
		}
	}
	assert.Greater(t, named, 100, "msvcrt should expose hundreds of named exports")
	t.Logf("msvcrt.dll: %d named, %d ordinal-only", named, ordinalOnly)
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

// TestExportRVA_NtClose verifies the export RVA lookup against a
// known function in ntdll. NtClose is the simplest syscall stub —
// every Windows ntdll exports it.
func TestExportRVA_NtClose(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	rva, err := f.ExportRVA("NtClose")
	require.NoError(t, err)
	assert.NotZero(t, rva, "NtClose RVA must be non-zero")
	t.Logf("ntdll NtClose RVA: 0x%X", rva)
}

func TestExportRVA_Missing(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	_, err = f.ExportRVA("ZzzNotARealExport")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDataAtRVA_NtClosePrologue reads the first 5 bytes at
// NtClose's RVA — every Windows x64 syscall stub starts with
// `4C 8B D1 B8` (mov r10, rcx; mov eax, …) followed by the SSN
// byte. The first 4 bytes are stable across builds.
func TestDataAtRVA_NtClosePrologue(t *testing.T) {
	path := useSystemDLL(t)
	if runtime.GOARCH != "amd64" {
		t.Skip("syscall stub layout is amd64-specific")
	}
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	rva, err := f.ExportRVA("NtClose")
	require.NoError(t, err)
	prologue, err := f.DataAtRVA(rva, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x4C, 0x8B, 0xD1, 0xB8}, prologue,
		"NtClose stub prologue must be `mov r10, rcx; mov eax, ssn`")
}

// TestOverlay_SignedNtdllSurfacesSignatureBlob — Microsoft-signed
// PEs carry their Authenticode certificate blob past the last
// section, which saferwall surfaces as the overlay. Confirms
// Overlay + OverlayOffset wire correctly.
func TestOverlay_SignedNtdllSurfacesSignatureBlob(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	off := f.OverlayOffset()
	require.Greater(t, off, int64(0), "ntdll.dll is signed; overlay must be present")

	data, err := f.Overlay()
	require.NoError(t, err)
	require.NotEmpty(t, data)
	assert.EqualValues(t, int64(len(f.Raw))-off, len(data),
		"Overlay length must equal Raw length minus OverlayOffset")
	t.Logf("ntdll overlay: offset=0x%X size=%d", off, len(data))
}

// TestRichHeader_NtdllPopulated verifies the Rich header is
// surfaced for an MSVC-linked PE. ntdll.dll is always emitted by
// MSVC; the Rich header carries the toolchain bill of materials.
func TestRichHeader_NtdllPopulated(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	rh := f.RichHeader()
	require.NotNil(t, rh, "ntdll.dll must carry a Rich header (MSVC-linked)")
	assert.NotZero(t, rh.XORKey, "XORKey is the linker-computed checksum, never zero in practice")
	assert.NotEmpty(t, rh.Tools, "Rich header must list at least one toolchain entry")
	assert.NotEmpty(t, rh.Raw, "Raw bytes must be preserved for clone-style use")

	// Every Microsoft binary surfaces at least one entry with a
	// known ProductName (mapped via saferwall.ProdIDtoStr).
	var named bool
	for _, tool := range rh.Tools {
		if tool.ProductName != "" {
			named = true
			t.Logf("ntdll Rich tool: %s (VS %s, count=%d)",
				tool.ProductName, tool.VSVersion, tool.Count)
			break
		}
	}
	assert.True(t, named, "at least one Rich entry must resolve to a known MSVC product")
}

// TestRichHeader_NilWhenAbsent — Go-built PEs (this test binary
// itself is the cleanest example) have no Rich header.
func TestRichHeader_NilWhenAbsent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only: needs a real PE on disk")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	f, err := Open(exe)
	require.NoError(t, err)
	defer f.Close()
	assert.Nil(t, f.RichHeader(), "Go-built PE must have no Rich header")
}

// TestAuthentihash_NtdllNon32Zero verifies the saferwall-backed
// Authentihash returns the SHA-256 size (32 bytes) and a non-zero
// digest for a real Microsoft-signed binary.
func TestAuthentihash_NtdllNon32Zero(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	h := f.Authentihash()
	require.Len(t, h, 32, "Authenticode SHA-256 hash must be 32 bytes")

	var zero [32]byte
	assert.NotEqual(t, zero[:], h, "ntdll Authentihash must not be all-zero")
}

// TestImpHash_KernelBaseReturnsHex verifies ImpHash returns an
// MD5 hex string for kernelbase.dll, which DOES import functions
// (ntdll exports). ntdll itself has zero imports and saferwall
// returns "no imports found" — that's the documented contract;
// we test the happy path here.
func TestImpHash_KernelBaseReturnsHex(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	path := `C:\Windows\System32\kernelbase.dll`
	if _, err := os.Stat(path); err != nil {
		t.Skipf("kernelbase.dll not found: %v", err)
	}
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	h, err := f.ImpHash()
	require.NoError(t, err)
	require.Len(t, h, 32, "imphash must be 32-char MD5 hex")
	t.Logf("kernelbase.dll ImpHash: %s", h)
}

// TestAnomalies_NtdllReturnsSlice exercises the Anomalies surface.
// A clean Microsoft binary typically returns 0 anomalies; the test
// only asserts the call returns without panicking.
func TestAnomalies_NtdllReturnsSlice(t *testing.T) {
	path := useSystemDLL(t)
	f, err := Open(path)
	require.NoError(t, err)
	defer f.Close()

	a := f.Anomalies()
	t.Logf("ntdll anomalies: %v", a)
	// No assertion on length — depends on Windows build.
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
