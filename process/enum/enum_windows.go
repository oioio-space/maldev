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

// ImagePath returns the full image path for a given process via
// QueryFullProcessImageNameW. Requires PROCESS_QUERY_LIMITED_INFORMATION
// (granted to the current user for processes it owns, and to admins
// for everything except Protected Process Light).
func ImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// Module is a single loaded module (DLL or main exe) for a process.
type Module struct {
	Name string // base file name, e.g. "kernel32.dll"
	Path string // full path, e.g. "C:\\Windows\\System32\\kernel32.dll"
	Base uintptr
	Size uint32
}

// Modules returns every module loaded into the given process via
// CreateToolhelp32Snapshot(TH32CS_SNAPMODULE). Requires the same
// rights as OpenProcess for that pid; protected processes return an
// error. The first returned module is the process's main exe.
func Modules(pid uint32) ([]Module, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	if err := windows.Module32First(snap, &me); err != nil {
		return nil, err
	}
	var mods []Module
	for {
		mods = append(mods, Module{
			Name: syscall.UTF16ToString(me.Module[:]),
			Path: syscall.UTF16ToString(me.ExePath[:]),
			Base: uintptr(unsafe.Pointer(me.ModBaseAddr)),
			Size: me.ModBaseSize,
		})
		if err := windows.Module32Next(snap, &me); err != nil {
			break
		}
	}
	return mods, nil
}
