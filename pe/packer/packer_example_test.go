package packer_test

import (
	"fmt"
	"os"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// ExamplePackBinary shows the v0.61.0 UPX-style transform on a
// Linux ELF input. Output is single-binary; the kernel handles
// loading. Stage1Rounds=3 is the ship-tested baseline.
func ExamplePackBinary() {
	input, err := os.ReadFile("input.elf")
	if err != nil {
		return
	}
	out, key, err := packer.PackBinary(input, packer.PackBinaryOptions{
		Format:       packer.FormatLinuxELF,
		Stage1Rounds: 3,
		Seed:         time.Now().UnixNano(),
	})
	if err != nil {
		return
	}
	fmt.Printf("packed %d bytes (key %x...)\n", len(out), key[:8])
	_ = os.WriteFile("output.elf", out, 0o755)
}

// ExampleAddCoverPE chains the cover layer after a PackBinary
// call to inflate the PE static surface with three junk
// sections of mixed entropy.
func ExampleAddCoverPE() {
	packed, err := os.ReadFile("packed.exe")
	if err != nil {
		return
	}
	covered, err := packer.AddCoverPE(packed, packer.CoverOptions{
		JunkSections: []packer.JunkSection{
			{Name: ".rsrc", Size: 0x4000, Fill: packer.JunkFillRandom},
			{Name: ".pdata", Size: 0x2000, Fill: packer.JunkFillPattern},
			{Name: ".tls", Size: 0x1000, Fill: packer.JunkFillZero},
		},
	})
	if err != nil {
		return
	}
	_ = os.WriteFile("covered.exe", covered, 0o755)
}

// ExampleApplyDefaultCover is the one-liner cover layer.
// Auto-detects PE vs ELF and applies a 3-section default with
// randomized legit-looking names. Operators chain it after
// PackBinary; ELF static-PIE inputs return
// ErrCoverSectionTableFull and the operator falls back to the
// bare PackBinary output.
func ExampleApplyDefaultCover() {
	packed, err := os.ReadFile("packed.bin")
	if err != nil {
		return
	}
	out := packed
	if covered, err := packer.ApplyDefaultCover(packed, time.Now().UnixNano()); err == nil {
		out = covered
	}
	_ = os.WriteFile("output.bin", out, 0o755)
}
