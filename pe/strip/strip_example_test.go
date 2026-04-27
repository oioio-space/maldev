package strip_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/strip"
)

// Sanitize wipes Go-toolchain artefacts (pclntab magic, Go-named
// section labels, TimeDateStamp) from the supplied PE bytes and
// returns the cleaned blob.
func ExampleSanitize() {
	raw, err := os.ReadFile("implant.exe")
	if err != nil {
		return
	}
	clean := strip.Sanitize(raw)
	fmt.Printf("clean %d bytes (in: %d)\n", len(clean), len(raw))
	_ = os.WriteFile("implant_clean.exe", clean, 0o644)
}
