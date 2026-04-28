//go:build windows

package ntapi_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/ntapi"
	"golang.org/x/sys/windows"
)

// NtAllocateVirtualMemory carves an RWX region inside the current
// process — the simplest reflective-loader scaffolding.
// CurrentProcess() is windows.Handle(^uintptr(0)).
func ExampleNtAllocateVirtualMemory() {
	const size = 0x1000
	addr, err := ntapi.NtAllocateVirtualMemory(
		windows.CurrentProcess(),
		0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		fmt.Println("alloc:", err)
		return
	}
	_ = addr
}

// NtCreateThreadEx spawns a thread on the supplied entry point.
// HideFromDebugger flag is set internally — the thread does not
// surface in EnumProcessThreads.
func ExampleNtCreateThreadEx() {
	var startAddr, parameter uintptr
	hThread, err := ntapi.NtCreateThreadEx(windows.CurrentProcess(), startAddr, parameter)
	if err != nil {
		fmt.Println("thread:", err)
		return
	}
	defer windows.CloseHandle(hThread)
}
