// packer-suite — runnable companion to docs/examples/upx-style-packer.md.
//
// Reads an input PE32+ or ELF64, applies the v0.61.0 UPX-style
// transform via packer.PackBinary, then chains the cover layer
// via packer.ApplyDefaultCover when the input has PHT slack
// (PE always; ELF when the first PT_LOAD doesn't cover offset 0).
//
// Usage:
//
//	go build -o /tmp/packer-suite ./cmd/examples/packer-suite
//	/tmp/packer-suite <input> <output>
//
// Cross-platform — runs on linux/windows/darwin. The output binary
// runs on the platform matching its detected format.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <input> <output>\n", os.Args[0])
		os.Exit(2)
	}

	payload, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}

	format := packer.FormatLinuxELF
	if isPE(payload) {
		format = packer.FormatWindowsExe
	}

	// One captured seed feeds both PackBinary and the cover layer
	// (offset by 1 so the two RNG streams diverge). Capturing once
	// avoids same-nanosecond-tick collision on fast machines.
	seed := time.Now().UnixNano()
	packed, key, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:       format,
		Stage1Rounds: 3,
		Seed:         seed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "PackBinary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("packed %d → %d bytes (key %x...)\n", len(payload), len(packed), key[:8])

	out := packed
	covered, coverErr := packer.ApplyDefaultCover(packed, seed+1)
	switch {
	case coverErr == nil:
		out = covered
		fmt.Printf("cover applied: %d → %d bytes\n", len(packed), len(covered))
	case errors.Is(coverErr, packer.ErrCoverInvalidOptions):
		fmt.Fprintf(os.Stderr, "cover skipped (invalid options): %v\n", coverErr)
	default:
		fmt.Printf("cover skipped: %v (using bare PackBinary output)\n", coverErr)
	}

	if err := os.WriteFile(os.Args[2], out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d bytes to %s\n", len(out), os.Args[2])
}

func isPE(b []byte) bool {
	return len(b) >= 2 && b[0] == 'M' && b[1] == 'Z'
}
