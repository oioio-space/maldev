//go:build windows

package enum

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const errNoMoreFiles = syscall.Errno(18) // ERROR_NO_MORE_FILES

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

	procs = append(procs, processFromEntry(&entry))

	for {
		err := windows.Process32Next(handle, &entry)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == errNoMoreFiles {
				break
			}
			return procs, err
		}
		procs = append(procs, processFromEntry(&entry))
	}

	return procs, nil
}

// Threads returns the thread IDs belonging to the given process.
// Uses CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD.
func Threads(pid uint32) ([]uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(snap, &te); err != nil {
		return nil, err
	}

	var tids []uint32
	for {
		if te.OwnerProcessID == pid {
			tids = append(tids, te.ThreadID)
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			break
		}
	}
	return tids, nil
}

// processFromEntry converts a ProcessEntry32 to a Process, populating
// SessionID via ProcessIdToSessionId (silently 0 on failure).
func processFromEntry(e *windows.ProcessEntry32) Process {
	p := Process{
		PID:  e.ProcessID,
		PPID: e.ParentProcessID,
		Name: syscall.UTF16ToString(e.ExeFile[:]),
	}
	windows.ProcessIdToSessionId(e.ProcessID, &p.SessionID)
	return p
}
