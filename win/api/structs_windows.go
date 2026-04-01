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

// ListEntry matches the Windows LIST_ENTRY structure (two pointers).
type ListEntry struct {
	Flink uintptr
	Blink uintptr
}

// SystemHandle is a single entry in the SYSTEM_HANDLE_INFORMATION_EX array.
type SystemHandle struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// SystemHandleInformationEx is the header for NtQuerySystemInformation(64).
type SystemHandleInformationEx struct {
	HandleCount uintptr
	Reserved    uintptr
	Handles     [1]SystemHandle
}

// Context64 represents an x64 thread context (CONTEXT structure, simplified).
type Context64 struct {
	_                    [6]uint64 // P1Home-P6Home
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}
