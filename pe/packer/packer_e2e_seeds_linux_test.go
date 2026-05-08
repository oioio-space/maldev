//go:build linux && maldev_packer_run_e2e

package packer_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_LinuxELF_MultiSeed locks the regression that
// caught the R15-clobber bug (see commit history): seeds 3+ used
// to pick R15 (the prologue's TextRVA holder) as a per-round
// register, destroying the address and segfaulting on the first
// decoder dereference. The fix threads stage1.BaseReg through
// poly.Engine.EncodePayloadExcluding so the per-round pool
// excludes R15.
//
// Each seed produces a fully independent stub via the polymorphic
// engine; running every one to clean exit is the strongest
// guarantee that no future register-pool change reintroduces the
// clobber.
func TestPackBinary_LinuxELF_MultiSeed(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "pe", "packer", "runtime",
		"testdata", "hello_static_pie")
	fixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Seeds spanning the previously-failing range. seed=1 + seed=2
	// happened to avoid R15; everything else picked it. Test all.
	seeds := []int64{1, 2, 3, 7, 42, 100, 1000, 2026}

	for _, seed := range seeds {
		t.Run("", func(t *testing.T) {
			packed, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
				Format:       packer.FormatLinuxELF,
				Stage1Rounds: 3,
				Seed:         seed,
			})
			if err != nil {
				t.Fatalf("seed=%d PackBinary: %v", seed, err)
			}

			runAndCheck(t, seed, "packed", packed)
		})
	}
}

// TestPackBinary_LinuxELF_MultiSeed_WithCover extends the multi-seed
// test by chaining ApplyDefaultCover after PackBinary. v0.62.0 lifted
// the ErrCoverSectionTableFull limitation for Go static-PIE binaries
// via PHT relocation, so the cover layer must now succeed AND the
// resulting binary must still run to clean exit.
func TestPackBinary_LinuxELF_MultiSeed_WithCover(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "pe", "packer", "runtime",
		"testdata", "hello_static_pie")
	fixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	seeds := []int64{1, 2, 3, 7, 42, 100, 1000, 2026}

	for _, seed := range seeds {
		t.Run("", func(t *testing.T) {
			packed, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
				Format:       packer.FormatLinuxELF,
				Stage1Rounds: 3,
				Seed:         seed,
			})
			if err != nil {
				t.Fatalf("seed=%d PackBinary: %v", seed, err)
			}

			covered, err := packer.ApplyDefaultCover(packed, seed)
			if err != nil {
				t.Fatalf("seed=%d ApplyDefaultCover: %v (PHT relocation should succeed for Go static-PIE)", seed, err)
			}

			runAndCheck(t, seed, "covered", covered)
		})
	}
}

// runAndCheck writes blob to a temp file, executes it, and asserts
// "hello from packer" appears in combined stdout+stderr.
func runAndCheck(t *testing.T, seed int64, label string, blob []byte) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), label+".elf")
	if err := os.WriteFile(tmp, blob, 0o755); err != nil {
		t.Fatalf("seed=%d write %s: %v", seed, label, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tmp)
	cmd.Env = append(os.Environ(), "MALDEV_PACKER_RUN_E2E=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("seed=%d %s subprocess: %v\n  stderr: %q", seed, label, err, stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "hello from packer") {
		t.Errorf("seed=%d %s output does not contain 'hello from packer'\n  stdout: %q\n  stderr: %q",
			seed, label, stdout.String(), stderr.String())
	}
}
