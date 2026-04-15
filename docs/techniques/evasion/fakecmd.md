# FakeCmdLine — PEB CommandLine Overwrite

[<- Back to Evasion](README.md)

## What It Does

Overwrites the `CommandLine` field in the current process PEB so that usermode
process-listing tools (Task Manager, Process Explorer, `Get-Process`, WMIC)
display a fake command line rather than the real one.

## How It Works

Every Windows process has a PEB accessible via
`NtQueryInformationProcess(ProcessBasicInformation)`. The PEB holds a pointer
to `RTL_USER_PROCESS_PARAMETERS`, whose `CommandLine` is a `UNICODE_STRING`.
Overwriting its `Length`, `MaximumLength` and `Buffer` fields makes any tool
that reads this structure see the fake value.

The kernel's `EPROCESS.SeAuditProcessCreationInfo` is **not** affected —
kernel EDR callbacks (`PsSetCreateProcessNotifyRoutine`) still see the
original command line recorded at process creation.

## API

```go
// Spoof overwrites the current process PEB CommandLine.
func Spoof(fakeCmd string, caller *wsyscall.Caller) error

// Restore reverts to the value saved before the first Spoof call.
func Restore() error

// Current reads the active PEB CommandLine.
func Current() string

// SpoofPID overwrites a REMOTE process PEB CommandLine via ReadProcessMemory /
// WriteProcessMemory / NtAllocateVirtualMemory on a handle opened with
// PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION.
// No Restore counterpart — track the original string yourself if you need it.
func SpoofPID(pid uint32, fakeCmd string, caller *wsyscall.Caller) error
```

## Remote Spoofing

`SpoofPID` applies the same PEB overwrite to another process. The target handle
must be opened with VM read/write/operate rights, which typically requires the
caller to hold SeDebugPrivilege or run elevated. The sequence is:

1. `OpenProcess` with `PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION`
2. `NtQueryInformationProcess` → PEB address
3. `ReadProcessMemory` → `ProcessParameters` pointer at PEB+0x20 → `CommandLine` UNICODE_STRING at PP+0x70
4. `NtAllocateVirtualMemory` in the target for the new UTF-16 buffer
5. `WriteProcessMemory` the new string, then patch Length / MaximumLength / Buffer of the UNICODE_STRING

Like `Spoof`, only user-mode readers (debuggers, Process Hacker, sysmon ProcessAccess filters) observe the fake value. Kernel `ProcessCreate` audit records are not affected because they were stamped at CreateProcess time.

## Usage

```go
import "github.com/oioio-space/maldev/evasion/fakecmd"

if err := fakecmd.Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil); err != nil {
    log.Fatal(err)
}
defer fakecmd.Restore()
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |

## Detection

**Low** — In-memory only. Kernel audit fields unchanged. A defender that
reads the PEB `CommandLine` in the target process sees the spoof; a defender
that reads the kernel audit record sees the real command line.
