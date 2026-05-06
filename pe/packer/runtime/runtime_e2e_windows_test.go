//go:build windows

package runtime_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// signedSystemEXE returns the path to a Windows-shipped EXE
// suitable for round-trip loading. xcopy.exe is preferred:
// small (~40 KB), no SxS-activation-context imports, no
// COMCTL32 v5/v6 redirection. notepad.exe imports COMCTL32 by
// ordinal which fails on this loader (documented limitation).
func signedSystemEXE(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		`C:\Windows\System32\xcopy.exe`,
		`C:\Windows\System32\where.exe`,
		`C:\Windows\System32\find.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no usable signed EXE under System32")
	return ""
}

// TestPrepare_LoadsRealEXE_ButDoesNotRun is the headline Windows
// E2E: pack notepad.exe, unpack via LoadPE, validate the
// PreparedImage looks plausible, then Free without ever calling
// Run (so the test process keeps running).
//
// Validates: parse + alloc + section copy + relocation + import
// resolution + section protections. The actual jump-to-OEP is
// gated behind MALDEV_PACKER_RUN_E2E=1 and intentionally never
// fires in CI.
func TestPrepare_LoadsRealEXE_ButDoesNotRun(t *testing.T) {
	src := signedSystemEXE(t)
	tmp := filepath.Join(t.TempDir(), filepath.Base(src))
	copyFile(t, src, tmp)

	original, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read %s: %v", tmp, err)
	}

	blob, key, err := packer.Pack(original, packer.Options{})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	img, err := runtime.LoadPE(blob, key)
	if err != nil {
		t.Fatalf("LoadPE: %v", err)
	}
	defer img.Free()

	if img.Base == 0 {
		t.Fatal("PreparedImage.Base == 0 — allocation failed")
	}
	if img.SizeOfImage == 0 {
		t.Fatal("PreparedImage.SizeOfImage == 0 — header parse failed")
	}
	if img.EntryPoint <= img.Base {
		t.Errorf("EntryPoint (%x) <= Base (%x) — bad RVA math", img.EntryPoint, img.Base)
	}
	if img.EntryPoint >= img.Base+uintptr(img.SizeOfImage) {
		t.Errorf("EntryPoint (%x) past mapped image end", img.EntryPoint)
	}
	if len(img.Imports) == 0 {
		t.Error("Imports empty — every real EXE imports SOMETHING from kernel32/ntdll")
	}

	// Spot-check: most System32 EXEs import from kernel32.
	hasKernel32 := false
	for _, imp := range img.Imports {
		if imp.DLL == "KERNEL32.dll" || imp.DLL == "kernel32.dll" {
			hasKernel32 = true
			if imp.Address == 0 {
				t.Errorf("kernel32!%s resolved to 0 — GetProcAddress lied?", imp.Function)
			}
			break
		}
	}
	if !hasKernel32 {
		t.Logf("warning: no KERNEL32.dll import seen — got: %v", uniqueImportDLLs(img.Imports))
	}

	t.Logf("loaded %d-byte EXE → base=0x%x size=%d entry=0x%x imports=%d",
		len(original), img.Base, img.SizeOfImage, img.EntryPoint, len(img.Imports))
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %s → %s: %v", src, dst, err)
	}
}

func uniqueImportDLLs(imps []runtime.ResolvedImport) []string {
	seen := map[string]bool{}
	for _, i := range imps {
		seen[i.DLL] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	return out
}
