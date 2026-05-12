//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackProxyDLL_Strict_E2E is the slice 6.3 strict validation:
// proves that BOTH side effects of the fused proxy fire on a
// real Win10 loader call. Uses the existing probe_converted.exe
// fixture (writes "OK\n" to C:\maldev-probe-marker.txt then
// Sleep(INFINITE)) as the packed payload.
//
// Asserts:
//   1. LoadLibrary on the fused proxy returns a non-NULL handle
//      AND DllMain returns BOOL TRUE (the loader doesn't unload us).
//   2. The packed EXE's main() runs in a spawned thread inside
//      the host process — verified via the marker file.
//   3. GetProcAddress on a forwarded export
//      (`GetFileVersionInfoSizeW`) returns a non-NULL function
//      pointer — verified by the loader successfully resolving
//      the forwarder to the legitimate `version.dll` on the
//      system. (Calling the function would require a valid
//      filename argument and a buffer; resolving the pointer
//      alone proves the forwarder bytes were laid out
//      correctly.)
func TestPackProxyDLL_Strict_E2E(t *testing.T) {
	const markerPath = `C:\maldev-probe-marker.txt`
	_ = os.Remove(markerPath)

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe_converted.exe missing (%v); rebuild via testdata/Makefile", err)
	}

	fused, _, err := packer.PackProxyDLL(probe, packer.ProxyDLLOptions{
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

	tmpDir := t.TempDir()
	dllPath := filepath.Join(tmpDir, "version.dll")
	if err := os.WriteFile(dllPath, fused, 0o755); err != nil {
		t.Fatalf("write fused: %v", err)
	}

	h, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		t.Fatalf("LoadLibrary on fused proxy: %v", err)
	}
	defer syscall.FreeLibrary(h)
	if h == 0 {
		t.Fatal("LoadLibrary returned NULL handle without error")
	}

	// Side effect 1: forwarded export resolves to a function
	// pointer in the legitimate target.
	addr, err := syscall.GetProcAddress(h, "GetFileVersionInfoSizeW")
	if err != nil {
		t.Errorf("GetProcAddress on forwarded export failed: %v — forwarder string or export table malformed", err)
	}
	if addr == 0 {
		t.Error("GetProcAddress returned NULL — forwarder didn't resolve")
	} else {
		t.Logf("forwarded GetFileVersionInfoSizeW resolved to 0x%x (real version.dll address)", addr)
	}

	// Side effect 2: spawned payload thread writes the marker file.
	// Allow up to 2 s for the thread to spawn + write.
	deadline := time.Now().Add(2 * time.Second)
	var content []byte
	for time.Now().Before(deadline) {
		content, err = os.ReadFile(markerPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer os.Remove(markerPath)
	if err != nil {
		t.Fatalf("marker file %q never appeared — payload didn't spawn or its main() crashed: %v",
			markerPath, err)
	}
	if got, want := string(content), "OK\n"; got != want {
		t.Errorf("marker content = %q, want %q", got, want)
	}
	t.Logf("payload wrote marker — DllMain decrypted .text and CreateThread'd OEP successfully")
}
