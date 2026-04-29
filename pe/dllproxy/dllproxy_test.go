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

	"github.com/oioio-space/maldev/pe/cert"
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
		{"unknown machine", "version.dll", []string{"Foo"}, Options{Machine: Machine(0xDEAD)}, ErrUnsupportedMachine},
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

// TestGenerate_Phase2_PayloadDLL emits a proxy with PayloadDLL set,
// re-parses with stdlib debug/pe, and asserts the structural changes
// vs Phase 1: a .text section appears, AddressOfEntryPoint is non-zero
// inside it, IMPORT and IAT data directory entries are populated, and
// the kernel32!LoadLibraryA hint/name + payload string both live in
// .rdata where the stub expects them.
func TestGenerate_Phase2_PayloadDLL(t *testing.T) {
	out, err := Generate(
		"version.dll",
		[]string{"GetFileVersionInfoSizeA", "VerQueryValueA"},
		Options{PayloadDLL: "evil.dll"},
	)
	require.NoError(t, err)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err)
	defer f.Close()

	// Two sections: .text + .rdata.
	require.Len(t, f.Sections, 2)
	assert.Equal(t, ".text", strings.TrimRight(f.Sections[0].Name, "\x00"))
	assert.Equal(t, ".rdata", strings.TrimRight(f.Sections[1].Name, "\x00"))

	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	assert.NotZero(t, oh.AddressOfEntryPoint)
	assert.GreaterOrEqual(t, oh.AddressOfEntryPoint, f.Sections[0].VirtualAddress)
	assert.Less(t, oh.AddressOfEntryPoint, f.Sections[0].VirtualAddress+f.Sections[0].VirtualSize)

	// IMPORT directory populated.
	importDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	assert.NotZero(t, importDir.VirtualAddress, "IMPORT data directory should be non-zero in phase 2")
	assert.NotZero(t, importDir.Size)

	// IAT directory populated.
	iatDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IAT]
	assert.NotZero(t, iatDir.VirtualAddress, "IAT data directory should be non-zero in phase 2")

	// The .rdata section must contain "kernel32.dll", "LoadLibraryA",
	// and the payload string we passed in.
	rdataBytes, err := f.Sections[1].Data()
	require.NoError(t, err)
	assert.Contains(t, string(rdataBytes), "kernel32.dll")
	assert.Contains(t, string(rdataBytes), "LoadLibraryA")
	assert.Contains(t, string(rdataBytes), "evil.dll")

	// The .text section must contain the canonical Win64 prologue bytes
	// of the DllMain stub: cmp edx,1; jne; sub rsp,28h.
	textBytes, err := f.Sections[0].Data()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(textBytes), 9)
	assert.Equal(t, []byte{0x83, 0xFA, 0x01}, textBytes[:3], "stub must start with cmp edx, 1")
	assert.Equal(t, byte(0x75), textBytes[3], "byte 3 must be jne (0x75)")
	assert.Equal(t, []byte{0x48, 0x83, 0xEC, 0x28}, textBytes[5:9], "bytes 5..8 must be sub rsp, 28h")
}

// TestGenerate_Phase2_ForwardersStillWork verifies that adding a payload
// does NOT break the forwarder behaviour Phase 1 already validates —
// every input export still resolves to the GLOBALROOT path string.
func TestGenerate_Phase2_ForwardersStillWork(t *testing.T) {
	target := "version.dll"
	exports := []string{"GetFileVersionInfoSizeA", "VerQueryValueA", "VerQueryValueW"}
	out, err := Generate(target, exports, Options{PayloadDLL: "evil.dll"})
	require.NoError(t, err)

	got := walkForwarders(t, out)
	require.Len(t, got, len(exports))
	wantPrefix := `\\.\GLOBALROOT\SystemRoot\System32\version.dll.`
	for _, name := range exports {
		assert.Equal(t, wantPrefix+name, got[name])
	}
}

// TestBuildDllMainStub_Layout verifies the stub builder lays the bytes
// out exactly as documented and patches both rip-relative displacements
// against the supplied RVAs.
func TestBuildDllMainStub_Layout(t *testing.T) {
	const (
		textRVA          = 0x1000
		payloadStringRVA = 0x2400 // arbitrary downstream RVA
		iatEntryRVA      = 0x2200
	)
	stub := buildDllMainStub(payloadStringRVA, iatEntryRVA, textRVA)
	require.Len(t, stub, 32)

	// Opcode skeleton.
	assert.Equal(t, []byte{0x83, 0xFA, 0x01}, stub[0:3])      // cmp edx, 1
	assert.Equal(t, []byte{0x75, 0x15}, stub[3:5])             // jne +21
	assert.Equal(t, []byte{0x48, 0x83, 0xEC, 0x28}, stub[5:9]) // sub rsp, 28h
	assert.Equal(t, []byte{0x48, 0x8D, 0x0D}, stub[9:12])      // lea rcx, [rip+disp32]
	assert.Equal(t, []byte{0xFF, 0x15}, stub[16:18])           // call qword ptr [rip+disp32]
	assert.Equal(t, []byte{0x48, 0x83, 0xC4, 0x28}, stub[22:26]) // add rsp, 28h
	assert.Equal(t, []byte{0xB8, 0x01, 0x00, 0x00, 0x00}, stub[26:31]) // mov eax, 1
	assert.Equal(t, byte(0xC3), stub[31])                      // ret

	// Disp32 sanity: rip after lea = textRVA+16 → disp = payloadStringRVA - (textRVA+16).
	leaDisp := int32(binary.LittleEndian.Uint32(stub[12:16]))
	assert.Equal(t, int32(payloadStringRVA)-int32(textRVA+16), leaDisp)

	callDisp := int32(binary.LittleEndian.Uint32(stub[18:22]))
	assert.Equal(t, int32(iatEntryRVA)-int32(textRVA+22), callDisp)
}

// TestGenerate_I386_Forwarder builds a PE32 forwarder-only image and
// asserts the structural differences vs PE32+: OptionalHeader32
// (Magic 0x10B), 32-bit ImageBase, IMAGE_FILE_32BIT_MACHINE flag in
// the COFF Characteristics. Forwarder strings must still resolve to
// the same target paths.
func TestGenerate_I386_Forwarder(t *testing.T) {
	out, err := Generate(
		"version.dll",
		[]string{"GetFileVersionInfoSizeA", "VerQueryValueA"},
		Options{Machine: MachineI386},
	)
	require.NoError(t, err)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err)
	defer f.Close()

	assert.Equal(t, uint16(MachineI386), f.FileHeader.Machine)
	assert.Equal(t, uint16(pe.IMAGE_FILE_EXECUTABLE_IMAGE|pe.IMAGE_FILE_32BIT_MACHINE|pe.IMAGE_FILE_DLL),
		f.FileHeader.Characteristics)

	oh, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	require.True(t, ok, "expected PE32 (not PE32+) optional header")
	assert.Equal(t, uint16(0x10B), oh.Magic)
	assert.Equal(t, uint32(imageBase32), oh.ImageBase)
	assert.Equal(t, uint32(0), oh.AddressOfEntryPoint, "phase 1 path has no DllMain")

	got := walkForwarders(t, out)
	wantPrefix := `\\.\GLOBALROOT\SystemRoot\System32\version.dll.`
	assert.Equal(t, wantPrefix+"GetFileVersionInfoSizeA", got["GetFileVersionInfoSizeA"])
	assert.Equal(t, wantPrefix+"VerQueryValueA", got["VerQueryValueA"])
}

// TestGenerate_I386_PayloadStub builds a PE32 image with a payload DLL.
// Validates: two sections (.text + .rdata), entry point inside .text,
// IMPORT + IAT data dirs populated, and the i386 stub starts with the
// canonical `mov eax, [esp+8]; cmp eax, 1; jne` sequence.
func TestGenerate_I386_PayloadStub(t *testing.T) {
	out, err := Generate(
		"version.dll",
		[]string{"VerQueryValueA"},
		Options{Machine: MachineI386, PayloadDLL: "evil.dll"},
	)
	require.NoError(t, err)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err)
	defer f.Close()

	require.Len(t, f.Sections, 2)
	oh := f.OptionalHeader.(*pe.OptionalHeader32)
	assert.NotZero(t, oh.AddressOfEntryPoint)
	assert.NotZero(t, oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	assert.NotZero(t, oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)

	textBytes, err := f.Sections[0].Data()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(textBytes), 9)
	assert.Equal(t, []byte{0x8B, 0x44, 0x24, 0x08}, textBytes[0:4], "mov eax, [esp+8]")
	assert.Equal(t, []byte{0x83, 0xF8, 0x01}, textBytes[4:7], "cmp eax, 1")
	assert.Equal(t, byte(0x75), textBytes[7], "jne")
}

// TestBuildDllMainStubI386_Layout: byte-by-byte verification of the
// 28-byte i386 stub plus the absolute-address patch sites.
func TestBuildDllMainStubI386_Layout(t *testing.T) {
	const (
		payloadAbs = 0x10003000
		iatAbs     = 0x10002400
	)
	stub := buildDllMainStubI386(payloadAbs, iatAbs)
	require.Len(t, stub, 28)

	assert.Equal(t, []byte{0x8B, 0x44, 0x24, 0x08}, stub[0:4])
	assert.Equal(t, []byte{0x83, 0xF8, 0x01}, stub[4:7])
	assert.Equal(t, []byte{0x75, 0x0B}, stub[7:9])
	assert.Equal(t, byte(0x68), stub[9])
	assert.Equal(t, []byte{0xFF, 0x15}, stub[14:16])
	assert.Equal(t, []byte{0xB8, 0x01, 0x00, 0x00, 0x00}, stub[20:25])
	assert.Equal(t, []byte{0xC2, 0x0C, 0x00}, stub[25:28])

	gotPayload := binary.LittleEndian.Uint32(stub[10:14])
	gotIAT := binary.LittleEndian.Uint32(stub[16:20])
	assert.Equal(t, uint32(payloadAbs), gotPayload)
	assert.Equal(t, uint32(iatAbs), gotIAT)
}

// TestGenerateExt_OrdinalOnly verifies the ordinal-only forwarder
// path: an export with no Name and Ordinal=42 must end up as a
// `<target>.#42` forwarder, no entry in AddressOfNames, and the right
// slot in AddressOfFunctions (slot index = ordinal - Base).
func TestGenerateExt_OrdinalOnly(t *testing.T) {
	out, err := GenerateExt(
		"target.dll",
		[]Export{
			{Name: "Foo", Ordinal: 1},
			{Ordinal: 42}, // ordinal-only
			{Name: "Bar", Ordinal: 7},
		},
		Options{},
	)
	require.NoError(t, err)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err)
	defer f.Close()

	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	edirRVA := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	sec := sectionContainingRVA(f, edirRVA)
	require.NotNil(t, sec)
	data, err := sec.Data()
	require.NoError(t, err)
	rvaToOff := func(rva uint32) uint32 { return rva - sec.VirtualAddress }

	base := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+16):])
	numFuncs := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+20):])
	numNames := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+24):])

	// ordinals 1, 7, 42 → Base=1, NumFuncs=42 (1..42 dense range with
	// 39 zero slots). NumNames=2 (Foo + Bar; ordinal-only stripped).
	assert.Equal(t, uint32(1), base)
	assert.Equal(t, uint32(42), numFuncs)
	assert.Equal(t, uint32(2), numNames)

	// Walk forwarders, indexed by ordinal.
	addrFuncs := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+28):])
	getFwd := func(ordinal uint32) string {
		slot := ordinal - base
		fwdRVA := binary.LittleEndian.Uint32(data[rvaToOff(addrFuncs+slot*4):])
		if fwdRVA == 0 {
			return ""
		}
		return readZString(data, rvaToOff(fwdRVA))
	}
	assert.Equal(t, `\\.\GLOBALROOT\SystemRoot\System32\target.dll.Foo`, getFwd(1))
	assert.Equal(t, `\\.\GLOBALROOT\SystemRoot\System32\target.dll.Bar`, getFwd(7))
	assert.Equal(t, `\\.\GLOBALROOT\SystemRoot\System32\target.dll.#42`, getFwd(42))
	assert.Equal(t, "", getFwd(2), "ordinal 2 has no export — slot must be zero")
}

// TestGenerateExt_AutoOrdinals checks that Export entries left at
// Ordinal=0 get sequential ordinals starting at 1 (or after the
// highest explicit ordinal), preserving Phase 1 behaviour for
// Generate (which forwards to GenerateExt).
func TestGenerateExt_AutoOrdinals(t *testing.T) {
	out, err := GenerateExt(
		"t.dll",
		[]Export{{Name: "Alpha"}, {Name: "Beta"}, {Name: "Gamma", Ordinal: 99}},
		Options{},
	)
	require.NoError(t, err)

	f, err := pe.NewFile(bytes.NewReader(out))
	require.NoError(t, err)
	defer f.Close()

	edirRVA, _ := exportDir(f)
	sec := sectionContainingRVA(f, edirRVA)
	data, _ := sec.Data()
	rvaToOff := func(rva uint32) uint32 { return rva - sec.VirtualAddress }

	base := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+16):])
	numFuncs := binary.LittleEndian.Uint32(data[rvaToOff(edirRVA+20):])
	// Auto-assigned start at 1; explicit Gamma at 99 stretches range
	// to 1..99. Alpha=1, Beta=2, Gamma=99.
	assert.Equal(t, uint32(1), base)
	assert.Equal(t, uint32(99), numFuncs)
}

func TestGenerateExt_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   []Export
		want error
	}{
		{
			"name and ordinal both blank",
			[]Export{{Name: "Foo"}, {}},
			ErrInvalidExport,
		},
		{
			"duplicate ordinals",
			[]Export{{Name: "A", Ordinal: 5}, {Name: "B", Ordinal: 5}},
			ErrInvalidExport,
		},
		{
			"empty list",
			nil,
			ErrEmptyExports,
		},
		{
			"empty target",
			[]Export{{Name: "Foo"}},
			ErrEmptyTargetName, // injected via target=""
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "t.dll"
			if tc.want == ErrEmptyTargetName {
				target = ""
			}
			_, err := GenerateExt(target, tc.in, Options{})
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v, want errors.Is %v", err, tc.want)
		})
	}
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

	edirRVA, edirSize := exportDir(f)

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

	edirRVA, _ := exportDir(f)
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

// exportDir extracts the export directory's RVA + size from either a
// PE32 or PE32+ optional header. The two structs share the layout but
// have distinct Go types in stdlib debug/pe.
func exportDir(f *pe.File) (rva, size uint32) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		d := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return d.VirtualAddress, d.Size
	case *pe.OptionalHeader32:
		d := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return d.VirtualAddress, d.Size
	}
	return 0, 0
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

func TestGenerate_DOSStub_EmbedsCanonicalProgram(t *testing.T) {
	out, err := Generate("target.dll", []string{"foo"}, Options{DOSStub: true})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(out), 0x80)

	// e_lfanew at 0x3C must be 0x80, not 0x40.
	if got := binary.LittleEndian.Uint32(out[0x3C:]); got != 0x80 {
		t.Errorf("e_lfanew = 0x%X, want 0x80", got)
	}
	// Canonical "This program cannot be run in DOS mode." text lives
	// in the DOS program block at 0x40..0x80.
	if !bytes.Contains(out[0x40:0x80], []byte("This program cannot be run in DOS mode.")) {
		t.Error("DOS stub block missing canonical text")
	}
}

func TestGenerate_DOSStub_DefaultMinimalLayout(t *testing.T) {
	out, err := Generate("target.dll", []string{"foo"}, Options{}) // DOSStub: false
	require.NoError(t, err)

	if got := binary.LittleEndian.Uint32(out[0x3C:]); got != 0x40 {
		t.Errorf("e_lfanew = 0x%X, want 0x40 (minimal layout)", got)
	}
	if bytes.Contains(out[:0x80], []byte("This program cannot be run in DOS mode.")) {
		t.Error("minimal layout must not embed the DOS stub program")
	}
}

func TestGenerate_PatchCheckSum_NonZeroChecksum(t *testing.T) {
	out, err := Generate("target.dll", []string{"foo"}, Options{PatchCheckSum: true})
	require.NoError(t, err)

	off, err := cert.PEChecksumOffset(out)
	require.NoError(t, err)
	got := binary.LittleEndian.Uint32(out[off : off+4])
	if got == 0 {
		t.Error("PatchCheckSum left CheckSum at zero")
	}
}

func TestGenerate_NoPatchCheckSum_ZeroChecksum(t *testing.T) {
	out, err := Generate("target.dll", []string{"foo"}, Options{}) // PatchCheckSum: false
	require.NoError(t, err)

	off, err := cert.PEChecksumOffset(out)
	require.NoError(t, err)
	if got := binary.LittleEndian.Uint32(out[off : off+4]); got != 0 {
		t.Errorf("CheckSum = 0x%X without PatchCheckSum, want 0", got)
	}
}

