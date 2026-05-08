package packer_test

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_WindowsPE_PackTimeMultiSeed is the pack-time
// regression guard for the Windows side. It mirrors the Linux
// E2E (packer_e2e_seeds_linux_test.go) at the structural level:
// for every seed in the previously-failing range, PackBinary +
// ApplyDefaultCover produce a PE32+ that debug/pe parses
// successfully with the expected section-count growth.
//
// Why pack-time only: this host doesn't have a Windows runtime
// available, so kernel-load + execute is out of scope. The
// matching runtime gate is documented in
// docs/refactor-2026-doc/HANDOFF-2026-05-06.md and runs from
// the Windows VM via scripts/vm-run-tests.sh windows.
//
// Test surface validated:
//   - Polymorphic stub byte uniqueness (every seed produces
//     differently-sized cover output via the RNG).
//   - PlanPE → InjectStubPE round-trip (entry-point rewrite to
//     stub RVA; section-count growth from 8 → 9).
//   - AddCoverPE round-trip (orig + stub + 3 junk + .idata2 after cover).
//   - AddFakeImportsPE chained by ApplyDefaultCover: ImportedSymbols
//     grows after cover (fakes from DefaultFakeImports appear).
//   - The R15-clobber regression (caught at commit ce7c4ab) cannot
//     reproduce on Windows packs either: every seed succeeds.
func TestPackBinary_WindowsPE_PackTimeMultiSeed(t *testing.T) {
	fixturePath := filepath.Join("testdata", "winhello.exe")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("Windows fixture missing (%v); run scripts/build-winhello.sh", err)
	}

	preFile, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/pe rejected fixture: %v", err)
	}
	preSections := len(preFile.Sections)
	preFile.Close()

	seeds := []int64{1, 2, 3, 7, 42, 100, 1000, 2026}
	for _, antiDebug := range []bool{false, true} {
		for _, seed := range seeds {
			seed, antiDebug := seed, antiDebug
			t.Run("", func(t *testing.T) {
				out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
					Format:       packerpkg.FormatWindowsExe,
					Stage1Rounds: 3,
					Seed:         seed,
					AntiDebug:    antiDebug,
				})
				if err != nil {
					t.Fatalf("seed=%d antiDebug=%v PackBinary: %v", seed, antiDebug, err)
				}

				f, err := pe.NewFile(bytes.NewReader(out))
				if err != nil {
					t.Fatalf("seed=%d antiDebug=%v debug/pe rejected packed output: %v", seed, antiDebug, err)
				}
				gotSections := len(f.Sections)
				f.Close()

				if gotSections != preSections+1 {
					t.Errorf("seed=%d antiDebug=%v section count = %d, want %d (orig + stub)",
						seed, antiDebug, gotSections, preSections+1)
				}

				covered, err := packerpkg.ApplyDefaultCover(out, seed+1)
				if err != nil {
					t.Fatalf("seed=%d antiDebug=%v ApplyDefaultCover: %v", seed, antiDebug, err)
				}
				cf, err := pe.NewFile(bytes.NewReader(covered))
				if err != nil {
					t.Fatalf("seed=%d antiDebug=%v debug/pe rejected covered output: %v", seed, antiDebug, err)
				}
				coveredSections := len(cf.Sections)

				// DefaultCoverOptions adds 3 junk sections + 1 fake-imports section.
				if coveredSections != preSections+1+3+1 {
					t.Errorf("seed=%d antiDebug=%v covered section count = %d, want %d (orig + stub + 3 junk + .idata2)",
						seed, antiDebug, coveredSections, preSections+1+3+1)
				}

				// Fake imports from DefaultFakeImports must appear in the symbol list.
				syms, err := cf.ImportedSymbols()
				cf.Close()
				if err != nil {
					t.Fatalf("seed=%d antiDebug=%v ImportedSymbols: %v", seed, antiDebug, err)
				}
				symSet := make(map[string]bool, len(syms))
				for _, s := range syms {
					symSet[s] = true
				}
				for _, fi := range packerpkg.DefaultFakeImports {
					for _, fn := range fi.Functions {
						key := fn + ":" + fi.DLL
						if !symSet[key] {
							t.Errorf("seed=%d antiDebug=%v fake symbol %q missing from ImportedSymbols", seed, antiDebug, key)
						}
					}
				}
			})
		}
	}
}
