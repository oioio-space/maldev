package dllproxy

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineString(t *testing.T) {
	assert.Equal(t, "AMD64", MachineAMD64.String())
	assert.Equal(t, "I386", MachineI386.String())
	assert.Equal(t, "Machine(0x1234)", Machine(0x1234).String())
}

func TestPathSchemeString(t *testing.T) {
	assert.Equal(t, "GlobalRoot", PathSchemeGlobalRoot.String())
	assert.Equal(t, "System32", PathSchemeSystem32.String())
	assert.Equal(t, "PathScheme(99)", PathScheme(99).String())
}

func TestGenerate_Errors(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		exports []string
		opts    Options
		want    error
	}{
		{"empty target", "", []string{"Foo"}, Options{}, ErrEmptyTargetName},
		{"empty exports", "version.dll", nil, Options{}, ErrEmptyExports},
		{"i386 unsupported", "version.dll", []string{"Foo"}, Options{Machine: MachineI386}, ErrI386NotSupported},
		{"payload unsupported", "version.dll", []string{"Foo"}, Options{PayloadDLL: "evil.dll"}, ErrPayloadUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(tc.target, tc.exports, tc.opts)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v, want errors.Is %v", err, tc.want)
		})
	}
}

// TestGenerate_DefaultOptions: zero-value Options must yield AMD64 +
// GlobalRoot defaults and produce a parseable PE.
func TestGenerate_DefaultOptions(t *testing.T) {
	out, err := Generate("version.dll", []string{"GetFileVersionInfoA"}, Options{})
	require.NoError(t, err)
	require.NotEmpty(t, out)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err, "stdlib debug/pe must accept the emitted DLL")
	defer f.Close()

	assert.Equal(t, uint16(MachineAMD64), f.FileHeader.Machine)
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	require.True(t, ok, "expected PE32+ optional header")
	assert.Equal(t, uint16(0x20B), oh.Magic)
	assert.Equal(t, uint64(imageBase64), oh.ImageBase)
	assert.Equal(t, uint32(0), oh.AddressOfEntryPoint, "phase 1 has no DllMain")
	assert.Equal(t, uint16(imageDLLCharacteristicsNXC), oh.DllCharacteristics)

	require.Len(t, f.Sections, 1)
	assert.Equal(t, ".rdata", strings.TrimRight(f.Sections[0].Name, "\x00"))
}

// TestGenerate_RoundTripExports walks the emitted export directory by
// hand and asserts every input export resolves to a forwarder string
// of the expected absolute-path form. Same approach the Windows
// loader uses to detect forwarders.
func TestGenerate_RoundTripExports(t *testing.T) {
	target := "version.dll"
	exports := []string{
		"GetFileVersionInfoA",
		"GetFileVersionInfoSizeA",
		"GetFileVersionInfoSizeW",
		"VerQueryValueA",
		"VerQueryValueW",
	}
	out, err := Generate(target, exports, Options{})
	require.NoError(t, err)

	got := walkForwarders(t, out)
	require.Len(t, got, len(exports))

	wantPrefix := `\\.\GLOBALROOT\SystemRoot\System32\version.dll.`
	for _, name := range exports {
		fwd, ok := got[name]
		require.True(t, ok, "export %q missing from forwarder map", name)
		assert.Equal(t, wantPrefix+name, fwd)
	}
}

// TestGenerate_PathSchemeSystem32 covers the alternate forwarder prefix.
func TestGenerate_PathSchemeSystem32(t *testing.T) {
	out, err := Generate("version.dll", []string{"VerQueryValueW"}, Options{PathScheme: PathSchemeSystem32})
	require.NoError(t, err)

	got := walkForwarders(t, out)
	assert.Equal(t, `C:\Windows\System32\version.dll.VerQueryValueW`, got["VerQueryValueW"])
}

// TestGenerate_SortsExports: input order should not affect the emitted
// export table — Windows loader does a binary search by name and
// requires alphabetic ordering of AddressOfNames.
func TestGenerate_SortsExports(t *testing.T) {
	scrambled := []string{"Zebra", "Alpha", "Mu", "Beta"}
	out, err := Generate("foo.dll", scrambled, Options{})
	require.NoError(t, err)

	names := walkExportNames(t, out)
	assert.Equal(t, []string{"Alpha", "Beta", "Mu", "Zebra"}, names)
}

// TestGenerate_LargeExportSet stress-tests the layout with a size in
// the same order as real Windows DLLs (kernel32 ~1500 exports, ole32
// ~2000). Asserts we don't break the file-alignment / section-size
// arithmetic at scale.
func TestGenerate_LargeExportSet(t *testing.T) {
	exports := make([]string, 2000)
	for i := range exports {
		exports[i] = fmt.Sprintf("Func%05d", i)
	}
	out, err := Generate("big.dll", exports, Options{})
	require.NoError(t, err)
	require.Greater(t, len(out), 0)

	got := walkForwarders(t, out)
	assert.Len(t, got, 2000)
}

// walkForwarders parses the PE bytes, finds the export directory,
// and returns a map of export name → forwarder string. Helper for the
// round-trip assertions above.
func walkForwarders(t *testing.T, image []byte) map[string]string {
	t.Helper()

	f, err := pe.NewFile(bytes.NewReader(image))
	require.NoError(t, err)
	defer f.Close()

	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	edirRVA := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	edirSize := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size

	sec := sectionContainingRVA(f, edirRVA)
	require.NotNil(t, sec, "section holding export directory not found")
	data, err := sec.Data()
	require.NoError(t, err)

	rvaToOff := func(rva uint32) uint32 { return rva - sec.VirtualAddress }

	numFuncs := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+20):])
	numNames := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+24):])
	addrFuncs := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+28):])
	addrNames := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+32):])
	addrOrds := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+36):])

	require.Equal(t, numFuncs, numNames, "all exports are named in phase 1")

	out := map[string]string{}
	for i := uint32(0); i < numNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(data[rvaToOff(addrNames+i*4):])
		ord := binary.LittleEndian.Uint16(data[rvaToOff(addrOrds+i*2):])
		fwdRVA := binary.LittleEndian.Uint32(data[rvaToOff(addrFuncs+uint32(ord)*4):])

		// Forwarder iff fwdRVA falls inside the export-data-directory range.
		require.GreaterOrEqual(t, fwdRVA, edirRVA, "function RVA must be inside export dir to be a forwarder")
		require.Less(t, fwdRVA, edirRVA+edirSize, "function RVA exceeds export dir range")

		out[readZString(data, rvaToOff(nameRVA))] = readZString(data, rvaToOff(fwdRVA))
	}
	return out
}

// walkExportNames returns the export name list in the order it appears
// in AddressOfNames (which Windows requires alphabetic).
func walkExportNames(t *testing.T, image []byte) []string {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(image))
	require.NoError(t, err)
	defer f.Close()

	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	edirRVA := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	sec := sectionContainingRVA(f, edirRVA)
	data, _ := sec.Data()
	rvaToOff := func(rva uint32) uint32 { return rva - sec.VirtualAddress }

	numNames := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+24):])
	addrNames := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+32):])

	out := make([]string, numNames)
	for i := uint32(0); i < numNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(data[rvaToOff(addrNames+i*4):])
		out[i] = readZString(data, rvaToOff(nameRVA))
	}
	return out
}

func sectionContainingRVA(f *pe.File, rva uint32) *pe.Section {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s
		}
	}
	return nil
}

func readZString(buf []byte, off uint32) string {
	end := off
	for end < uint32(len(buf)) && buf[end] != 0 {
		end++
	}
	return string(buf[off:end])
}

