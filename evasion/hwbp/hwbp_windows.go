//go:build windows

package hwbp

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

const contextDebugRegisters = 0x00100010 // CONTEXT_DEBUG_REGISTERS (x64)

// Breakpoint describes a hardware breakpoint found in a thread's debug registers.
type Breakpoint struct {
	Register int     // DR index (0-3)
	Address  uintptr // Address being monitored
	ThreadID uint32  // Thread that has the breakpoint set
}

// Detect reads the debug registers of the current thread and returns any
// active hardware breakpoints (DR0-DR3 with corresponding DR7 enable bits).
func Detect() ([]Breakpoint, error) {
	tid := windows.GetCurrentThreadId()
	return detectOnThread(tid)
}

// DetectAll enumerates all threads in the current process and returns
// hardware breakpoints found on any thread.
func DetectAll() ([]Breakpoint, error) {
	tids, err := currentProcessThreads()
	if err != nil {
		return nil, err
	}
	var all []Breakpoint
	for _, tid := range tids {
		bps, err := detectOnThread(tid)
		if err != nil {
			continue
		}
		all = append(all, bps...)
	}
	return all, nil
}

// ClearAll clears all hardware breakpoints on all threads in the current process.
// Returns the number of threads modified.
func ClearAll() (int, error) {
	tids, err := currentProcessThreads()
	if err != nil {
		return 0, err
	}
	cleared := 0
	for _, tid := range tids {
		if err := clearOnThread(tid); err == nil {
			cleared++
		}
	}
	return cleared, nil
}

func detectOnThread(tid uint32) ([]Breakpoint, error) {
	hThread, err := windows.OpenThread(
		windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
		false, tid,
	)
	if err != nil {
		return nil, fmt.Errorf("open thread: %w", err)
	}
	defer windows.CloseHandle(hThread)

	var ctx api.Context64
	ctx.ContextFlags = contextDebugRegisters
	ret, _, e := api.ProcGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
	if ret == 0 {
		return nil, fmt.Errorf("get context: %w", e)
	}

	dr := [4]uint64{ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3}
	var bps []Breakpoint
	for i, addr := range dr {
		if addr != 0 && ctx.Dr7&(1<<(2*uint(i))) != 0 {
			bps = append(bps, Breakpoint{
				Register: i,
				Address:  uintptr(addr),
				ThreadID: tid,
			})
		}
	}
	return bps, nil
}

func clearOnThread(tid uint32) error {
	hThread, err := windows.OpenThread(
		windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT,
		false, tid,
	)
	if err != nil {
		return fmt.Errorf("open thread: %w", err)
	}
	defer windows.CloseHandle(hThread)

	var ctx api.Context64
	ctx.ContextFlags = contextDebugRegisters
	ret, _, e := api.ProcGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
	if ret == 0 {
		return fmt.Errorf("get context: %w", e)
	}

	ctx.Dr0 = 0
	ctx.Dr1 = 0
	ctx.Dr2 = 0
	ctx.Dr3 = 0
	ctx.Dr6 = 0
	ctx.Dr7 = 0
	ctx.ContextFlags = contextDebugRegisters

	ret, _, e = api.ProcSetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
	if ret == 0 {
		return fmt.Errorf("set context: %w", e)
	}
	return nil
}

func currentProcessThreads() ([]uint32, error) {
	pid := windows.GetCurrentProcessId()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
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
