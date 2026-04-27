//go:build windows && bsod_demo

// Build-tag-gated to prevent accidental crashes. To run the example test:
//
//	go test -tags 'bsod_demo' ./cleanup/bsod/...
//
// Without the tag the file is excluded from the build.
package bsod_test

import (
	"fmt"

	"github.com/oioio-space/maldev/cleanup/bsod"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Trigger a Blue Screen of Death via NtRaiseHardError. CRASHES THE HOST.
// Only the failure path is reachable from Go; success means the host is
// already gone before the next instruction executes.
func ExampleTrigger() {
	caller := wsyscall.New(wsyscall.MethodIndirect, nil)
	if err := bsod.Trigger(caller); err != nil {
		// On success this line is never reached.
		fmt.Println("trigger failed:", err)
	}
}
