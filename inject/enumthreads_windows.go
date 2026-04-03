//go:build windows && amd64

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// systemProcessInformation is the information class for NtQuerySystemInformation
// that returns process and thread data.
const systemProcessInformation = 5

// x64 struct offsets within SYSTEM_PROCESS_INFORMATION.
const (
	spiNextEntryOffset    = 0   // uint32
	spiNumberOfThreads    = 4   // uint32
	spiUniqueProcessID    = 80  // uintptr
	spiThreadsArrayOffset = 184 // start of SYSTEM_THREAD_INFORMATION[]
)

// x64 SYSTEM_THREAD_INFORMATION size and ClientId offset.
const (
	stiSize             = 80 // sizeof(SYSTEM_THREAD_INFORMATION) on x64
	stiClientIDOffset   = 56 // offset of CLIENT_ID within SYSTEM_THREAD_INFORMATION
	stiUniqueThreadSize = 8  // sizeof(uintptr) for UniqueThread in CLIENT_ID
)

// FindAllThreadsNt returns thread IDs for a process using NtQuerySystemInformation
// instead of CreateToolhelp32Snapshot. NtQuerySystemInformation is less commonly
// monitored by EDR products than the Toolhelp32 snapshot API.
//
// If caller is non-nil, the NT syscall is routed through it for EDR bypass;
// otherwise the standard ntdll export is used.
func FindAllThreadsNt(pid int, caller *wsyscall.Caller) ([]uint32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid process identifier")
	}

	// Start with a reasonable buffer and grow as needed.
	bufSize := uint32(1 << 20) // 1 MiB
	var buf []byte
	var retLen uint32

	for {
		buf = make([]byte, bufSize)

		var status uintptr
		if caller != nil {
			r, _ := caller.Call("NtQuerySystemInformation",
				systemProcessInformation,
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(bufSize),
				uintptr(unsafe.Pointer(&retLen)),
			)
			status = r
		} else {
			status, _, _ = api.ProcNtQuerySystemInformation.Call(
				systemProcessInformation,
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(bufSize),
				uintptr(unsafe.Pointer(&retLen)),
			)
		}
		// STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
		if status == 0xC0000004 {
			bufSize = retLen + 4096
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("system information query failed: NTSTATUS 0x%X", status)
		}
		break
	}

	targetPID := uintptr(pid)
	offset := uint32(0)

	for {
		if int(offset)+spiThreadsArrayOffset > len(buf) {
			break
		}

		entry := buf[offset:]
		nextEntryOffset := *(*uint32)(unsafe.Pointer(&entry[spiNextEntryOffset]))
		numThreads := *(*uint32)(unsafe.Pointer(&entry[spiNumberOfThreads]))
		uniquePID := *(*uintptr)(unsafe.Pointer(&entry[spiUniqueProcessID]))

		if uniquePID == targetPID {
			threads := make([]uint32, 0, numThreads)
			threadsBase := offset + spiThreadsArrayOffset

			for i := uint32(0); i < numThreads; i++ {
				threadOffset := threadsBase + i*stiSize
				if int(threadOffset)+stiClientIDOffset+stiUniqueThreadSize*2 > len(buf) {
					break
				}
				// CLIENT_ID: { UniqueProcess uintptr; UniqueThread uintptr }
				// UniqueThread is the second field.
				clientIDBase := threadOffset + stiClientIDOffset
				uniqueThread := *(*uintptr)(unsafe.Pointer(&buf[clientIDBase+stiUniqueThreadSize]))
				threads = append(threads, uint32(uniqueThread))
			}
			return threads, nil
		}

		if nextEntryOffset == 0 {
			break
		}
		offset += nextEntryOffset
	}

	return nil, fmt.Errorf("process not found in system information")
}
