package packer_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/tc-hib/winres"
)

// loadResourceFixture reads pe/packer/testdata/winhello_w32_res.exe.
// Skips when missing — regenerate via scripts/build-fixture-winres.sh.
func loadResourceFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("testdata", "winhello_w32_res.exe")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing (%v); run scripts/build-fixture-winres.sh", err)
	}
	return b
}

// assertResourcesIntact parses the packed PE with tc-hib/winres and
// confirms RT_GROUP_ICON + RT_MANIFEST are still discoverable. Any
// "data entry out of bounds" error from winres signals a stale
// internal RVA in the resource tree (the bug the resource walker
// added in this commit fixes).
func assertResourcesIntact(t *testing.T, packed []byte) {
	t.Helper()
	rs, err := winres.LoadFromEXE(bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("winres.LoadFromEXE rejected packed output: %v", err)
	}
	var icon, manifest int
	rs.WalkType(winres.RT_GROUP_ICON, func(_ winres.Identifier, _ uint16, _ []byte) bool {
		icon++
		return true
	})
	rs.WalkType(winres.RT_MANIFEST, func(_ winres.Identifier, _ uint16, data []byte) bool {
		if !strings.Contains(string(data), "winres") {
			t.Errorf("manifest content corrupted (no 'winres' marker): %q", data)
		}
		manifest++
		return true
	})
	if icon != 1 {
		t.Errorf("RT_GROUP_ICON entries = %d, want 1", icon)
	}
	if manifest != 1 {
		t.Errorf("RT_MANIFEST entries = %d, want 1", manifest)
	}
}

// TestPackBinary_PreservesResources_Vanilla guards the baseline:
// packing a binary with embedded RT_GROUP_ICON + RT_MANIFEST without
// any randomization opts must round-trip resources cleanly.
func TestPackBinary_PreservesResources_Vanilla(t *testing.T) {
	in := loadResourceFixture(t)
	out, _, err := packer.PackBinary(in, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	assertResourcesIntact(t, out)
}

// TestPackBinary_PreservesResources_RandomizeAll guards the
// resource walker added under Phase 2-F-3-c-3: enabling every
// Phase 2 randomiser (which includes RandomizeImageVAShift) bumps
// the DataDirectory[RESOURCE] top-level RVA AND walks the resource
// tree to bump every leaf IMAGE_RESOURCE_DATA_ENTRY.OffsetToData
// RVA. Without the walker, winres.LoadFromEXE returns
// "data entry out of bounds".
func TestPackBinary_PreservesResources_RandomizeAll(t *testing.T) {
	in := loadResourceFixture(t)
	out, _, err := packer.PackBinary(in, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
		RandomizeAll: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	assertResourcesIntact(t, out)
}
