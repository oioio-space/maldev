//go:build windows

package enum

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

const th32csSnapProcess = 0x00000002

// List returns all running processes on the system.
func List() ([]Process, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var procs []Process

	ret, _, e1 := api.ProcCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	handle := windows.Handle(ret)
	if handle == windows.InvalidHandle {
		return nil, e1
	}
	defer windows.CloseHandle(handle)

	var entry api.PROCESSENTRY32W
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	ret, _, e1 = api.ProcProcess32FirstW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, e1
	}

	procs = append(procs, Process{
		PID:  entry.Th32ProcessID,
		PPID: entry.Th32ParentProcessID,
		Name: syscall.UTF16ToString(entry.SzExeFile[:]),
	})

	for {
		ret, _, e1 = api.ProcProcess32NextW.Call(uintptr(handle), uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			if errno, ok := e1.(syscall.Errno); ok && errno == 18 { // ERROR_NO_MORE_FILES
				break
			}
			return procs, e1
		}
		procs = append(procs, Process{
			PID:  entry.Th32ProcessID,
			PPID: entry.Th32ParentProcessID,
			Name: syscall.UTF16ToString(entry.SzExeFile[:]),
		})
	}

	return procs, nil
}
