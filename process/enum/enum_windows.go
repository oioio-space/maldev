//go:build windows

package enum

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// List returns all running processes on the system.
func List() ([]Process, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var procs []Process

	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(handle, &entry); err != nil {
		return nil, err
	}

	procs = append(procs, Process{
		PID:  entry.ProcessID,
		PPID: entry.ParentProcessID,
		Name: syscall.UTF16ToString(entry.ExeFile[:]),
	})

	for {
		err := windows.Process32Next(handle, &entry)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 18 { // ERROR_NO_MORE_FILES
				break
			}
			return procs, err
		}
		procs = append(procs, Process{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Name: syscall.UTF16ToString(entry.ExeFile[:]),
		})
	}

	return procs, nil
}
