//go:build windows

package memory_test

import (
	"fmt"

	"github.com/oioio-space/maldev/cleanup/memory"
	"golang.org/x/sys/windows"
)

// WipeAndFree zeroes a VirtualAlloc'd region (re-protecting it RW
// first), then releases the pages via VirtualFree.
func ExampleWipeAndFree() {
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Println("alloc:", err)
		return
	}
	// …copy shellcode + execute…
	if err := memory.WipeAndFree(addr, 4096); err != nil {
		fmt.Println("wipe:", err)
	}
}
