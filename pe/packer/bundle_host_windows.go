//go:build amd64 && windows

package packer

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mmapRX allocates a VirtualAlloc'd PAGE_EXECUTE_READWRITE region of
// at least size bytes. Windows backend mirroring the Linux mmap
// helper used by the bundle host-introspection asm trampoline.
func mmapRX(size int) []byte {
	addr, err := windows.VirtualAlloc(0, uintptr(size),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		panic("packer: VirtualAlloc PAGE_EXECUTE_READWRITE: " + err.Error())
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
}

// hostWinBuild returns the Windows build number via RtlGetVersion. The
// API is documented to never fail (always STATUS_SUCCESS) and the Go
// wrapper in golang.org/x/sys/windows reflects that with a no-arg
// signature returning a populated [windows.OsVersionInfoEx]. nil should
// never come back; defensive return 0 covers the contract.
//
// The bundle stub-side asm (see [stage1.EmitPEBBuildRead]) reads the
// same DWORD straight from the PEB without an API call, so the host-
// side preview produced here matches the runtime evaluator byte-for-
// byte on a given Windows host.
func hostWinBuild() uint32 {
	info := windows.RtlGetVersion()
	if info == nil {
		return 0
	}
	return info.BuildNumber
}

// _ keeps unsafe imported in case future versions of the helper need
// alignof/offsetof checks against [windows.OsVersionInfoEx]. Avoids a
// churning import diff each time the OS-info API surface shifts.
var _ = unsafe.Sizeof(windows.OsVersionInfoEx{})
