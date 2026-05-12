package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildTargetDLLFixture emits a minimal forwarder DLL with the given
// named exports — used as the "embedded target" input for
// [packer.PackProxyDLLFromTarget] tests.
func buildTargetDLLFixture(t *testing.T, exports []string) []byte {
	t.Helper()
	dll, err := dllproxy.Generate("target", exports, dllproxy.Options{})
	if err != nil {
		t.Fatalf("dllproxy.Generate fixture: %v", err)
	}
	return dll
}

// TestPackProxyDLLFromTarget_MirrorsExports proves the helper
// extracts the target's named exports and feeds them through to
// [packer.PackProxyDLL]. The resulting fused proxy must carry every
// input export name in its export table (visible via debug/pe) and
// retain the IMAGE_FILE_DLL + EXPORT-directory invariants the
// underlying emitter guarantees.
func TestPackProxyDLLFromTarget_MirrorsExports(t *testing.T) {
	want := []string{"GetFileVersionInfoSizeW", "GetFileVersionInfoW", "VerQueryValueW"}
	target := buildTargetDLLFixture(t, want)

	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	fused, _, err := packer.PackProxyDLLFromTarget(exe, target, packer.ProxyDLLOptions{
		TargetName: "version",
		PackOpts: packer.PackBinaryOptions{
			Format:       packer.FormatWindowsExe,
			Stage1Rounds: 3,
			Seed:         42,
		},
	})
	if err != nil {
		t.Fatalf("PackProxyDLLFromTarget: %v", err)
	}

	pf, err := pe.NewFile(bytes.NewReader(fused))
	if err != nil {
		t.Fatalf("debug/pe rejected fused output: %v", err)
	}
	defer pf.Close()
	if pf.Characteristics&transform.ImageFileDLL == 0 {
		t.Errorf("Characteristics = 0x%x, missing IMAGE_FILE_DLL", pf.Characteristics)
	}
	oh := pf.OptionalHeader.(*pe.OptionalHeader64)
	exportDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		t.Errorf("EXPORT DataDirectory empty: RVA=0x%x Size=%d",
			exportDir.VirtualAddress, exportDir.Size)
	}
	// Each input export name must end up forwarded in the proxy.
	for _, name := range want {
		if !bytes.Contains(fused, []byte(name)) {
			t.Errorf("fused output missing exported name %q", name)
		}
	}
}

func TestPackProxyDLLFromTarget_RejectsEmptyTarget(t *testing.T) {
	target := buildTargetDLLFixture(t, []string{"x"})
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, err := packer.PackProxyDLLFromTarget(exe, target, packer.ProxyDLLOptions{})
	if err == nil || !contains(err.Error(), "TargetName required") {
		t.Errorf("got %v, want 'TargetName required'", err)
	}
}

func TestPackProxyDLLFromTarget_RejectsUnparseableTarget(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, err := packer.PackProxyDLLFromTarget(exe, []byte("not a PE at all"), packer.ProxyDLLOptions{
		TargetName: "version",
	})
	if err == nil || !contains(err.Error(), "ExportsFromBytes parse") {
		t.Errorf("got %v, want 'ExportsFromBytes parse'", err)
	}
}
