package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestPackProxyDLL_HappyPath proves the fused emitter produces a
// single PE32+ DLL with: IMAGE_FILE_DLL set, an EXPORT data
// directory pointing at a populated export table, a forwarded
// reference to the legitimate target ("version.dll" embedded as
// the DLL name string), and NO LoadLibraryA IAT entry (the win
// over the chained Path A).
func TestPackProxyDLL_HappyPath(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	fused, _, err := packer.PackProxyDLL(exe, packer.ProxyDLLOptions{
		TargetName: "version",
		Exports: []dllproxy.Export{
			{Name: "GetFileVersionInfoSizeW"},
			{Name: "GetFileVersionInfoW"},
			{Name: "VerQueryValueW"},
		},
		PackOpts: packer.PackBinaryOptions{
			Format:       packer.FormatWindowsExe,
			Stage1Rounds: 3,
			Seed:         42,
		},
	})
	if err != nil {
		t.Fatalf("PackProxyDLL: %v", err)
	}
	if len(fused) == 0 {
		t.Fatal("empty fused output")
	}

	pf, err := pe.NewFile(bytes.NewReader(fused))
	if err != nil {
		t.Fatalf("debug/pe rejected fused output: %v", err)
	}
	defer pf.Close()
	if pf.Characteristics&transform.ImageFileDLL == 0 {
		t.Errorf("output Characteristics = 0x%x, missing IMAGE_FILE_DLL", pf.Characteristics)
	}

	// EXPORT directory must be populated and point inside a section.
	oh := pf.OptionalHeader.(*pe.OptionalHeader64)
	exportDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		t.Errorf("EXPORT DataDirectory empty: RVA=0x%x Size=%d",
			exportDir.VirtualAddress, exportDir.Size)
	}

	// "version" must appear somewhere in the binary (DLL name string).
	if !bytes.Contains(fused, []byte("version")) {
		t.Error("fused output doesn't embed target name 'version'")
	}

	// CRITICAL OPSEC: must NOT import LoadLibraryA — that's the
	// difference vs. PackChainedProxyDLL's two-file proxy.
	if bytes.Contains(fused, []byte("LoadLibraryA")) {
		t.Error("fused output imports LoadLibraryA — should resolve CreateThread via PEB walk instead")
	}
}

func TestPackProxyDLL_RejectsEmptyTarget(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, err := packer.PackProxyDLL(exe, packer.ProxyDLLOptions{
		Exports: []dllproxy.Export{{Name: "x"}},
	})
	if err == nil || !contains(err.Error(), "TargetName required") {
		t.Errorf("got %v, want 'TargetName required'", err)
	}
}

func TestPackProxyDLL_RejectsEmptyExports(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, err := packer.PackProxyDLL(exe, packer.ProxyDLLOptions{
		TargetName: "version",
	})
	if err == nil || !contains(err.Error(), "Exports required") {
		t.Errorf("got %v, want 'Exports required'", err)
	}
}
