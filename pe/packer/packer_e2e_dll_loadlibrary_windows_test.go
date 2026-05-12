//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/testutil"
)

// patchDllMainBody overwrites the first len(body) bytes of .text in
// a BuildDLLWithReloc fixture with `body`. The default body is all
// 0xC3 (RET-only) which doesn't set RAX → loader sees BOOL=FALSE.
func patchDllMainBody(t *testing.T, pe []byte, body []byte) {
	t.Helper()
	peOff := binary.LittleEndian.Uint32(pe[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	sizeOfOptHdr := binary.LittleEndian.Uint16(pe[coffOff+transform.COFFSizeOfOptHdrOffset:])
	secTableOff := coffOff + transform.PECOFFHdrSize + uint32(sizeOfOptHdr)
	rawOff := binary.LittleEndian.Uint32(pe[secTableOff+transform.SecPointerToRawDataOffset:])
	copy(pe[rawOff:], body)
}

// TestPackBinary_FormatWindowsDLL_LoadLibrary_E2E closes slice 4.5
// of the FormatWindowsDLL plan: pack a synthetic DLL fixture
// (testutil.BuildDLLWithReloc — has IMAGE_FILE_DLL + a populated
// BASERELOC table with one DIR64 entry, satisfying InjectStubDLL's
// admission checks), write it to disk, LoadLibrary it, assert
// the loader doesn't reject the result.
//
// The fixture's "DllMain" is just `0xC3` (RET) bytes. When the
// stub tail-jumps there, RET pops the loader's return address →
// loader sees the JMP+RET as a direct return with whatever RAX
// the stub left. The BOOL semantic is "non-zero is success" so
// the synthetic body is sufficient to validate the stub
// structure end-to-end.
//
// What gets validated by this E2E that the pack-time tests can't:
//   - DllMain stub bytes are loader-acceptable (no broken section
//     layout, no invalid reloc entries, no PE structural error
//     debug/pe wouldn't catch but the kernel does)
//   - The patched DllMain slot RVA resolves correctly post-rebase
//   - The .reloc table merge in InjectStubDLL produces a
//     loader-valid block sequence (the loader silently rejects
//     PEs whose .reloc blocks overlap or step backward)
//
// What this E2E doesn't validate (slice 4.5 explicit gap):
//   - GetProcAddress on real exports — the synthetic fixture has
//     no exports. Use an MSVC-built `testlib.dll` in a future
//     extension to exercise the export path.
//   - Function-pointer rebasing through a real reloc'd absolute
//     pointer — same MSVC dependency.
func TestPackBinary_FormatWindowsDLL_LoadLibrary_E2E(t *testing.T) {
	in := testutil.BuildDLLWithReloc(t, 0x100)
	// Patch the synthetic fixture's DllMain body to a proper BOOL-
	// returning function: `mov eax, 1; ret` (B8 01 00 00 00 C3 = 6
	// bytes). The default 0xC3-only body returns whatever RAX holds
	// after the stub's restore, which can be anything — including a
	// non-pointer that the loader treats as BOOL=FALSE → DLL_INIT_FAILED.
	// We need RAX=1 explicitly for a clean LoadLibrary result.
	patchDllMainBody(t, in, []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3})
	packed, _, err := packer.PackBinary(in, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsDLL,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary FormatWindowsDLL: %v", err)
	}
	tmpDir := t.TempDir()
	dllPath := filepath.Join(tmpDir, "packed.dll")
	if err := os.WriteFile(dllPath, packed, 0o755); err != nil {
		t.Fatalf("write packed: %v", err)
	}
	h, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		t.Fatalf("LoadLibrary on packed DLL: %v", err)
	}
	defer syscall.FreeLibrary(h)
	if h == 0 {
		t.Fatal("LoadLibrary returned NULL handle without error")
	}
	t.Logf("loaded packed DLL at handle 0x%x — DllMain stub validated end-to-end", uintptr(h))
}
