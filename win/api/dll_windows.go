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
	Amsi     = windows.NewLazySystemDLL("amsi.dll")
	Crypt32  = windows.NewLazySystemDLL("crypt32.dll")
	Gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	Mscoree  = windows.NewLazySystemDLL("mscoree.dll")
	Oleaut32 = windows.NewLazySystemDLL("oleaut32.dll")
	Wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
)

// Thread access rights.
const ThreadAllAccess = 0x1FFFFF

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
	ProcSetThreadPriority          = Kernel32.NewProc("SetThreadPriority")
	ProcTerminateThread            = Kernel32.NewProc("TerminateThread")
	ProcCreateTimerQueueTimer      = Kernel32.NewProc("CreateTimerQueueTimer")
	ProcDeleteTimerQueue           = Kernel32.NewProc("DeleteTimerQueue")
	ProcReadDirectoryChangesW      = Kernel32.NewProc("ReadDirectoryChangesW")
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
	ProcRtlCreateUserThread              = Ntdll.NewProc("RtlCreateUserThread")
	ProcNtAllocateVirtualMemory          = Ntdll.NewProc("NtAllocateVirtualMemory")
	ProcRtlMoveMemory                    = Ntdll.NewProc("RtlMoveMemory")
	ProcNtCreateSection                  = Ntdll.NewProc("NtCreateSection")
	ProcNtCreateProcessEx                = Ntdll.NewProc("NtCreateProcessEx")
	ProcNtQueryInformationProcess        = Ntdll.NewProc("NtQueryInformationProcess")
	ProcRtlCreateProcessParametersEx    = Ntdll.NewProc("RtlCreateProcessParametersEx")
	ProcRtlInitUnicodeString             = Ntdll.NewProc("RtlInitUnicodeString")
	ProcEtwpCreateEtwThread              = Ntdll.NewProc("EtwpCreateEtwThread")
	ProcNtQueueApcThreadEx               = Ntdll.NewProc("NtQueueApcThreadEx")
	ProcNtMapViewOfSection               = Ntdll.NewProc("NtMapViewOfSection")
	ProcNtUnmapViewOfSection             = Ntdll.NewProc("NtUnmapViewOfSection")
	ProcTpAllocWork                      = Ntdll.NewProc("TpAllocWork")
	ProcTpPostWork                       = Ntdll.NewProc("TpPostWork")
	ProcTpWaitForWork                    = Ntdll.NewProc("TpWaitForWork")
	ProcTpReleaseWork                    = Ntdll.NewProc("TpReleaseWork")
	ProcNtNotifyChangeDirectoryFile      = Ntdll.NewProc("NtNotifyChangeDirectoryFile")
	ProcRtlRegisterWait                  = Ntdll.NewProc("RtlRegisterWait")
	ProcRtlDeregisterWaitEx              = Ntdll.NewProc("RtlDeregisterWaitEx")
)

// advapi32.dll procs
var (
	ProcLogonUserW                          = Advapi32.NewProc("LogonUserW")
	ProcImpersonateLoggedOnUser             = Advapi32.NewProc("ImpersonateLoggedOnUser")
	ProcSetNamedSecurityInfoW               = Advapi32.NewProc("SetNamedSecurityInfoW")
	ProcConvertStringSecurityDescriptorToSD = Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	ProcSetServiceObjectSecurity            = Advapi32.NewProc("SetServiceObjectSecurity")
	ProcCreateProcessWithLogonW             = Advapi32.NewProc("CreateProcessWithLogonW")
	ProcI_QueryTagInformation               = Advapi32.NewProc("I_QueryTagInformation")
)

// user32.dll procs
var (
	ProcMessageBoxW  = User32.NewProc("MessageBoxW")
	ProcMessageBeep  = User32.NewProc("MessageBeep")
	ProcEnumWindows  = User32.NewProc("EnumWindows")
	ProcSendMessageW = User32.NewProc("SendMessageW")
	ProcFindWindowW  = User32.NewProc("FindWindowW")
)

// crypt32.dll procs
var (
	ProcCertEnumSystemStore = Crypt32.NewProc("CertEnumSystemStore")
)

// shell32.dll procs
var (
	ProcSHGetSpecialFolderPathW = Shell32.NewProc("SHGetSpecialFolderPathW")
	ProcShellExecuteW           = Shell32.NewProc("ShellExecuteW")
)

// userenv.dll procs
var (
	ProcCreateEnvironmentBlock  = Userenv.NewProc("CreateEnvironmentBlock")
	ProcDestroyEnvironmentBlock = Userenv.NewProc("DestroyEnvironmentBlock")
)

// amsi.dll procs
var (
	ProcAmsiScanBuffer  = Amsi.NewProc("AmsiScanBuffer")
	ProcAmsiOpenSession = Amsi.NewProc("AmsiOpenSession")
)

// mscoree.dll procs
var (
	ProcCLRCreateInstance  = Mscoree.NewProc("CLRCreateInstance")
	ProcCorBindToRuntimeEx = Mscoree.NewProc("CorBindToRuntimeEx")
)

// wtsapi32.dll procs
var (
	ProcWTSQuerySessionInformationW = Wtsapi32.NewProc("WTSQuerySessionInformationW")
)

// oleaut32.dll procs
var (
	ProcSafeArrayCreateVector  = Oleaut32.NewProc("SafeArrayCreateVector")
	ProcSafeArrayAccessData    = Oleaut32.NewProc("SafeArrayAccessData")
	ProcSafeArrayUnaccessData  = Oleaut32.NewProc("SafeArrayUnaccessData")
	ProcSafeArrayDestroy       = Oleaut32.NewProc("SafeArrayDestroy")
	ProcSafeArrayPutElement    = Oleaut32.NewProc("SafeArrayPutElement")
	ProcSysAllocString         = Oleaut32.NewProc("SysAllocString")
	ProcSysFreeString          = Oleaut32.NewProc("SysFreeString")
)
