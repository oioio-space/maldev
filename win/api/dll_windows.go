//go:build windows

// Package api is the single source of truth for all Windows DLL handles and
// shared structures. All other maldev modules MUST import from here instead
// of declaring their own LazyDLL. This prevents duplicate handles and ensures
// consistent DLL search path restriction (NewLazySystemDLL limits to System32).
package api

import "golang.org/x/sys/windows"

var (
	Kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	Ntdll    = windows.NewLazySystemDLL("ntdll.dll")
	Advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	User32   = windows.NewLazySystemDLL("user32.dll")
	Shell32  = windows.NewLazySystemDLL("shell32.dll")
	Userenv  = windows.NewLazySystemDLL("userenv.dll")
	Netapi32 = windows.NewLazySystemDLL("netapi32.dll")
)

// kernel32.dll procs
//
// Procs with typed wrappers in golang.org/x/sys/windows are NOT listed here.
// Use the typed wrappers instead:
//   windows.CreateToolhelp32Snapshot, windows.Process32First, windows.Process32Next,
//   windows.VirtualAlloc, windows.VirtualProtect, windows.VirtualProtectEx,
//   windows.WriteProcessMemory, windows.ReadProcessMemory, windows.OpenProcess,
//   windows.CreateProcess, windows.VirtualFree, windows.ResumeThread.
var (
	ProcVirtualAllocEx             = Kernel32.NewProc("VirtualAllocEx")
	ProcCreateRemoteThread         = Kernel32.NewProc("CreateRemoteThread")
	ProcCreateThread               = Kernel32.NewProc("CreateThread")
	ProcGetDiskFreeSpaceExW        = Kernel32.NewProc("GetDiskFreeSpaceExW")
	ProcGlobalMemoryStatusEx       = Kernel32.NewProc("GlobalMemoryStatusEx")
	ProcGetLogicalDrives           = Kernel32.NewProc("GetLogicalDrives")
	ProcGetDriveTypeW              = Kernel32.NewProc("GetDriveTypeW")
	ProcGetVolumeInformationW      = Kernel32.NewProc("GetVolumeInformationW")
	ProcMoveFileExW                = Kernel32.NewProc("MoveFileExW")
	ProcIsDebuggerPresent          = Kernel32.NewProc("IsDebuggerPresent")
	ProcSetProcessMitigationPolicy = Kernel32.NewProc("SetProcessMitigationPolicy")
	ProcSetFileInformationByHandle = Kernel32.NewProc("SetFileInformationByHandle")
	ProcWaitForSingleObject        = Kernel32.NewProc("WaitForSingleObject")
	ProcConvertThreadToFiber       = Kernel32.NewProc("ConvertThreadToFiber")
	ProcCreateFiber                = Kernel32.NewProc("CreateFiber")
	ProcSwitchToFiber              = Kernel32.NewProc("SwitchToFiber")
	ProcQueueUserAPC               = Kernel32.NewProc("QueueUserAPC")
	ProcSuspendThread              = Kernel32.NewProc("SuspendThread")
	ProcGetThreadContext           = Kernel32.NewProc("GetThreadContext")
	ProcSetThreadContext           = Kernel32.NewProc("SetThreadContext")
	ProcRtlCopyMemory              = Kernel32.NewProc("RtlCopyMemory")
)

// ntdll.dll procs
var (
	ProcNtQuerySystemInformation = Ntdll.NewProc("NtQuerySystemInformation")
	ProcNtQueryInformationToken  = Ntdll.NewProc("NtQueryInformationToken")
	ProcNtWriteVirtualMemory     = Ntdll.NewProc("NtWriteVirtualMemory")
	ProcNtProtectVirtualMemory   = Ntdll.NewProc("NtProtectVirtualMemory")
	ProcNtCreateThreadEx         = Ntdll.NewProc("NtCreateThreadEx")
	ProcNtQueryInformationThread = Ntdll.NewProc("NtQueryInformationThread")
	ProcEtwEventWrite            = Ntdll.NewProc("EtwEventWrite")
	ProcEtwEventWriteEx          = Ntdll.NewProc("EtwEventWriteEx")
	ProcEtwEventWriteFull        = Ntdll.NewProc("EtwEventWriteFull")
	ProcEtwEventWriteString      = Ntdll.NewProc("EtwEventWriteString")
	ProcEtwEventWriteTransfer    = Ntdll.NewProc("EtwEventWriteTransfer")
	ProcRtlCreateUserThread      = Ntdll.NewProc("RtlCreateUserThread")
	ProcNtAllocateVirtualMemory  = Ntdll.NewProc("NtAllocateVirtualMemory")
	ProcRtlMoveMemory            = Ntdll.NewProc("RtlMoveMemory")
)

// advapi32.dll procs
var (
	ProcLogonUserW                          = Advapi32.NewProc("LogonUserW")
	ProcImpersonateLoggedOnUser             = Advapi32.NewProc("ImpersonateLoggedOnUser")
	ProcSetNamedSecurityInfoW               = Advapi32.NewProc("SetNamedSecurityInfoW")
	ProcConvertStringSecurityDescriptorToSD = Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	ProcSetServiceObjectSecurity            = Advapi32.NewProc("SetServiceObjectSecurity")
	ProcCreateProcessWithLogonW             = Advapi32.NewProc("CreateProcessWithLogonW")
)

// user32.dll procs
var (
	ProcMessageBoxW = User32.NewProc("MessageBoxW")
	ProcMessageBeep = User32.NewProc("MessageBeep")
)

// shell32.dll procs
var (
	ProcSHGetSpecialFolderPathW = Shell32.NewProc("SHGetSpecialFolderPathW")
	ProcShellExecuteW           = Shell32.NewProc("ShellExecuteW")
)
