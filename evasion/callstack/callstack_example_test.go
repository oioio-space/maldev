//go:build windows && amd64

package callstack_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/callstack"
)

// FindReturnGadget locates a usable RET gadget in ntdll.dll. Used as
// the building block for synthesised unwind chains.
func ExampleFindReturnGadget() {
	gadget, err := callstack.FindReturnGadget()
	if err != nil {
		fmt.Println("gadget:", err)
		return
	}
	fmt.Printf("RET gadget at 0x%x\n", gadget)
}

// Validate vets a hand-built Frame chain — checks that every entry
// has a resolvable RUNTIME_FUNCTION so RtlVirtualUnwind can walk it.
func ExampleValidate() {
	chain := []callstack.Frame{
		// caller-supplied frames go here
	}
	if err := callstack.Validate(chain); err != nil {
		fmt.Println("invalid:", err)
	}
}
