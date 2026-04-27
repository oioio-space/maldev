//go:build windows

package hwbp_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/hwbp"
)

// Detect returns hardware breakpoints set inside ntdll across
// every thread in the current process — typical EDR surface.
func ExampleDetect() {
	bps, err := hwbp.Detect()
	if err != nil {
		return
	}
	for _, bp := range bps {
		fmt.Printf("DR%d → %x (TID %d)\n", bp.Register, bp.Address, bp.TID)
	}
}

// ClearAll zeros every set HWBP across every thread. Pair
// with evasion/unhook for full integrity restore (HWBPs +
// inline hooks).
func ExampleClearAll() {
	cleared, err := hwbp.ClearAll()
	if err != nil {
		return
	}
	fmt.Printf("cleared %d HWBP(s)\n", cleared)
}
