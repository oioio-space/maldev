//go:build windows

package api

// MEMORYSTATUSEX for GlobalMemoryStatusEx.
type MEMORYSTATUSEX struct {
	DwLength                uint32
	DwMemoryLoad            uint32
	UllTotalPhys            uint64
	UllAvailPhys            uint64
	UllTotalPageFile        uint64
	UllAvailPageFile        uint64
	UllTotalVirtual         uint64
	UllAvailVirtual         uint64
	UllAvailExtendedVirtual uint64
}

// PROCESSENTRY32W is removed. Use windows.ProcessEntry32 from golang.org/x/sys/windows.
