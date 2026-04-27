//go:build windows

package cet_test

import (
	"bytes"
	"fmt"

	"github.com/oioio-space/maldev/evasion/cet"
)

// Enforced reports whether CET shadow stack is active for the current
// process. Cheap to call; use it before deciding between Disable and
// Wrap.
func ExampleEnforced() {
	if cet.Enforced() {
		fmt.Println("CET active — APC paths require ENDBR64 marker")
	}
}

// Disable best-effort relaxes the shadow-stack policy. Returns an error
// if the image is /CETCOMPAT-compiled or the host kernel rejects.
func ExampleDisable() {
	if err := cet.Disable(); err != nil {
		fmt.Println("disable refused:", err)
	}
}

// Wrap prepends ENDBR64 to a shellcode buffer if not already present.
// Side-effect-free, idempotent — safe to call unconditionally.
func ExampleWrap() {
	sc := []byte{0x90, 0x90, 0xc3} // nop nop ret
	wrapped := cet.Wrap(sc)
	fmt.Println(bytes.HasPrefix(wrapped, cet.Marker))
	// Output: true
}

// Composition: detect, try Disable, fall back to Wrap if refused.
func Example_chain() {
	sc := []byte{0xc3}
	if cet.Enforced() {
		if err := cet.Disable(); err != nil {
			sc = cet.Wrap(sc)
		}
	}
	_ = sc // hand to inject.ExecuteCallback or similar
}
