package preset_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPresetSysoBundles asserts every preset sub-package on disk
// ships the expected three files (the blank-import Go file, its
// !windows stub, and the AMD64 resource COFF object) and that the
// .syso starts with the AMD64 COFF magic so `go build` will link
// it on a Windows target. Cross-platform — runs on Linux CI too.
//
// Closes P2.12 row 3 of the polish backlog.
func TestPresetSysoBundles(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read preset dir: %v", err)
	}

	var presets []string
	for _, e := range entries {
		if e.IsDir() {
			presets = append(presets, e.Name())
		}
	}
	if len(presets) == 0 {
		t.Fatal("no preset sub-directories found")
	}

	const sysoName = "resource_windows_amd64.syso"
	for _, id := range presets {
		t.Run(id, func(t *testing.T) {
			assertVariant(t, filepath.Join(root, id), id)
			adminPath := filepath.Join(root, id, "admin")
			if _, err := os.Stat(filepath.Join(adminPath, sysoName)); err == nil {
				assertVariant(t, adminPath, id+"/admin")
			}
		})
	}
}

// assertVariant verifies that variantDir contains the standard
// three files (`<pkg>_windows.go`, `<pkg>_stub.go`,
// `resource_windows_amd64.syso`) where pkg == basename(variantDir),
// and that the .syso carries the AMD64 COFF magic.
func assertVariant(t *testing.T, variantDir, label string) {
	t.Helper()
	const sysoName = "resource_windows_amd64.syso"
	const coffMagicAMD64 uint16 = 0x8664

	pkgName := lastSegment(variantDir)
	want := []string{
		pkgName + "_windows.go",
		pkgName + "_stub.go",
		sysoName,
	}
	for _, name := range want {
		if _, err := os.Stat(filepath.Join(variantDir, name)); err != nil {
			t.Errorf("%s: missing %s: %v", label, name, err)
		}
	}

	syso, err := os.ReadFile(filepath.Join(variantDir, sysoName))
	if err != nil {
		t.Fatalf("%s: read syso: %v", label, err)
	}
	if len(syso) < 20 {
		t.Fatalf("%s: syso too small (%d bytes)", label, len(syso))
	}
	if got := binary.LittleEndian.Uint16(syso[0:2]); got != coffMagicAMD64 {
		t.Errorf("%s: COFF Machine = 0x%04x, want 0x%04x (IMAGE_FILE_MACHINE_AMD64)",
			label, got, coffMagicAMD64)
	}
}

func lastSegment(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
