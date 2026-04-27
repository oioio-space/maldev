//go:build windows

package acg_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/acg"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Enable applies ProcessDynamicCodePolicy. After this returns, no
// further VirtualAlloc(PAGE_EXECUTE) succeeds.
func ExampleEnable() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := acg.Enable(caller); err != nil {
		fmt.Println("acg:", err)
	}
}

// Compose with evasion.ApplyAll alongside other defence-in-depth
// hardening. Apply ACG LAST — it blocks future RWX allocation.
func Example_chain() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = evasion.ApplyAll([]evasion.Technique{
		acg.Guard(),
	}, caller)
}
