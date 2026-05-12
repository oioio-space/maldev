//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestPackProxyDLL_LoadLibrary_E2E closes slice 6 Path B real-loader
// validation: pack a synthetic EXE as a single-file fused proxy
// that mirrors version.dll's exports, write it to disk, LoadLibrary
// it, assert the loader doesn't reject the result.
//
// This proves end-to-end:
//   - The converted-DLL stub layout (slice 5+) composes cleanly
//     with an appended export table (slice 6 Path B).
//   - The .reloc / DataDirectory[EXPORT] / SizeOfImage updates
//     done by transform.AppendExportSection don't break the
//     loader's PE validation.
//   - The combined image's Characteristics still resolve to a
//     loadable DLL (no IMAGE_FILE_DLL drift, no missing
//     directory entry).
//
// What this E2E doesn't validate (separate slice 6.3 future work):
//   - GetProcAddress on the proxied exports actually returns the
//     forwarder strings the loader resolves into the legitimate
//     target. Needs a host EXE that actually calls one of the
//     forwarded functions.
//   - The DllMain payload runs (decrypts + spawns the original
//     OEP thread). Synthetic fixture's "OEP" is a 0xC3 RET
//     which doesn't observably do anything — would need a probe
//     harness with a marker file like the converted-DLL E2E.
func TestPackProxyDLL_LoadLibrary_E2E(t *testing.T) {
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
	t.Logf("loaded fused proxy DLL at handle 0x%x — slice 6 Path B validated end-to-end", uintptr(h))
}
