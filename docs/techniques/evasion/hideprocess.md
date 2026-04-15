# HideProcess — NtQuerySystemInformation Patch in Target

[<- Back to Evasion](README.md)

## What It Does

Patches the first bytes of `NtQuerySystemInformation` inside a **target**
process with a stub that returns `STATUS_NOT_IMPLEMENTED (0xC0000002)`.
Blinds that process's ability to enumerate running processes — Task Manager,
Process Explorer, Process Hacker etc. will show an empty list when run inside
the patched process.

## How It Works

Process-enumeration tools rely on
`NtQuerySystemInformation(SystemProcessInformation, …)`. On Windows 8+, ntdll
is loaded at the same virtual address in every process (shared KUSER_SHARED +
ASLR randomised once per boot), so we resolve the target VA locally, open the
target with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, and patch the prologue:

```
mov eax, 0xC0000002  ; B8 02 00 00 C0
ret                   ; C3
```

## API

```go
// PatchProcessMonitor patches NtQSI in the target process.
// Requires PROCESS_VM_WRITE|PROCESS_VM_OPERATION on the target.
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Hide Artifacts: Hidden Window / Indicator Removal on Host | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) |

## Detection

**Medium** — Any integrity-check of ntdll bytes in a running process detects
the overwrite. Kernel-side enumeration is not affected (any EDR agent reading
process lists from the kernel still sees everything).
