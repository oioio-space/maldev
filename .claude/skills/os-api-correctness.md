---
name: os-api-correctness
description: Use AUTOMATICALLY when writing, modifying, or reviewing code that calls Windows APIs (MSDN), Linux syscalls, or manipulates OS structures — verifies function signatures, return value semantics (NTSTATUS vs BOOL vs HANDLE), struct layouts, syscall numbers, constants, and flag combinations against official sources. Understands intentional maldev tricks (memory patching, undocumented APIs, PE header walking) and does not flag them as errors.
---

# OS API Correctness Verification

Verify every OS-level API interaction against official documentation (MSDN, Linux man pages). **Run automatically** after writing code that touches Windows APIs, Linux syscalls, or OS structures.

## When to Trigger

- After writing any `api.Proc*.Call()`, `windows.*()`, or `syscall.*()` call
- After defining or modifying a struct that mirrors an OS structure
- After using raw syscall numbers or OS constants
- After writing unsafe.Pointer arithmetic on OS memory

## Check 1: Return Value Semantics

**This is the #1 source of bugs.** Windows has THREE different return conventions:

| Convention | Success | Failure | Functions |
|-----------|---------|---------|-----------|
| **NTSTATUS** | `== 0` | `!= 0` | All `Nt*`, `Rtl*` functions in ntdll |
| **BOOL** | `!= 0` | `== 0` | Most kernel32/advapi32 functions |
| **HANDLE** | `!= 0` (and != INVALID_HANDLE_VALUE) | `== 0` or `== INVALID_HANDLE_VALUE` | CreateThread, CreateFile, OpenProcess |

### Verification Matrix

```
api.ProcNtCreateThreadEx.Call(...)    → NTSTATUS: check r != 0 for error
api.ProcCreateRemoteThread.Call(...)  → HANDLE:   check r == 0 for error
api.ProcQueueUserAPC.Call(...)        → BOOL:     check r == 0 for error
api.ProcSuspendThread.Call(...)       → DWORD:    0xFFFFFFFF = error, else previous suspend count
api.ProcWaitForSingleObject.Call(...) → DWORD:    0=WAIT_OBJECT_0, 0x102=TIMEOUT, 0xFFFFFFFF=FAILED
api.ProcSetProcessMitigationPolicy.Call(...) → BOOL: check r == 0 for error
api.ProcIsDebuggerPresent.Call(...)   → BOOL:     non-zero = debugger present (not an error)

windows.VirtualProtect(...)           → wrapped by Go: check err != nil
windows.OpenProcess(...)              → wrapped by Go: check err != nil
windows.CreateProcess(...)            → wrapped by Go: check err != nil
```

**Red flag**: `if r != 0` on a BOOL-returning function, or `if r == 0` on an NTSTATUS function.

## Check 2: Function Signatures (Parameter Count & Types)

Verify parameter count matches MSDN. Common errors:

| Function | Correct Param Count | Common Error |
|----------|-------------------|--------------|
| NtCreateThreadEx | 11 | Missing trailing zero parameters |
| NtAllocateVirtualMemory | 6 | Forgetting ZeroBits parameter |
| NtProtectVirtualMemory | 5 | Confusing with VirtualProtectEx (4 params) |
| NtWriteVirtualMemory | 5 | Missing NumberOfBytesWritten |
| CreateRemoteThread | 7 | Missing lpThreadId |
| QueueUserAPC | 3 | pfnAPC is param 1 (not 2) |
| RtlCreateUserThread | 10 | Complex signature with many zero params |
| NtQueueApcThreadEx | 6 | UserApcOption is param 2 |

### NT functions with in/out pointer parameters

These modify their pointer arguments — the Go caller must pass `uintptr(unsafe.Pointer(&var))`:

```
NtAllocateVirtualMemory: BaseAddress* (in/out), RegionSize* (in/out)
NtProtectVirtualMemory:  BaseAddress* (in/out), RegionSize* (in/out), OldProtect* (out)
NtWriteVirtualMemory:    NumberOfBytesWritten* (out)
NtCreateThreadEx:        ThreadHandle* (out)
```

## Check 3: Windows Constants

Verify constants match MSDN values:

```
Memory Protection:
  PAGE_NOACCESS          = 0x01
  PAGE_READONLY          = 0x02
  PAGE_READWRITE         = 0x04
  PAGE_EXECUTE           = 0x10
  PAGE_EXECUTE_READ      = 0x20
  PAGE_EXECUTE_READWRITE = 0x40

Memory Allocation:
  MEM_COMMIT  = 0x1000
  MEM_RESERVE = 0x2000
  MEM_RELEASE = 0x8000

Process Access:
  PROCESS_CREATE_THREAD     = 0x0002
  PROCESS_VM_OPERATION      = 0x0008
  PROCESS_VM_READ           = 0x0010
  PROCESS_VM_WRITE          = 0x0020
  PROCESS_QUERY_INFORMATION = 0x0400
  PROCESS_ALL_ACCESS        = 0x1F0FFF (Win Vista+)

Thread Access:
  THREAD_TERMINATE          = 0x0001
  THREAD_SET_CONTEXT        = 0x0010
  THREAD_SUSPEND_RESUME     = 0x0002
  THREAD_QUERY_INFORMATION  = 0x0040
  THREAD_ALL_ACCESS         = 0x1FFFFF

Context Flags (x64):
  CONTEXT_FULL = 0x10001F

Creation Flags:
  CREATE_SUSPENDED         = 0x00000004
  CREATE_NO_WINDOW         = 0x08000000
  CREATE_UNICODE_ENVIRONMENT = 0x00000400

Section:
  SEC_IMAGE        = 0x01000000
  SECTION_ALL_ACCESS = 0x000F001F

Mitigation Policies:
  ProcessDynamicCodePolicy          = 2
  ProcessBinarySignaturePolicy      = 8
```

## Check 4: Linux Syscall Numbers

Verify per-architecture:

| Syscall | amd64 | x86 (386) | arm64 |
|---------|-------|-----------|-------|
| memfd_create | 319 | 356 | 279 |
| write | 1 | 4 | 64 |
| mmap | 9 | 90 | 222 |

**Red flag**: Using amd64 syscall number in a `386` or `arm64` build-tagged file.

## Check 5: Struct Layout Correctness

For manually-defined structs, verify field sizes and alignment match the OS:

```
MEMORYSTATUSEX: total 64 bytes (with dwLength at offset 0)
  - dwLength must be initialized to sizeof(MEMORYSTATUSEX)

CONTEXT64 (x64): 1232 bytes
  - Rip at offset +0xF8
  - Rsp at offset +0x98
  - ContextFlags at offset +0x30

PE Section Header: 40 bytes each
  - Name[8] at +0, VirtualSize at +8, VirtualAddress at +12

PROCESS_BASIC_INFORMATION (x64): 48 bytes
  - PebBaseAddress at offset +0x08

UNICODE_STRING (x64): 16 bytes
  - Length at +0, MaximumLength at +2, Buffer at +8 (pointer aligned)
```

## Check 6: Handle Lifecycle

Every opened handle must be closed. Verify:

```
windows.OpenProcess(...)   → defer windows.CloseHandle(hProcess)
windows.OpenThread(...)    → defer windows.CloseHandle(hThread) OR close in loop
windows.CreateProcess(...) → defer CloseHandle(pi.Process); defer CloseHandle(pi.Thread)
CreateToolhelp32Snapshot   → defer windows.CloseHandle(snapshot)
NtCreateSection(...)       → track and close hSection
```

**Red flag**: Handle opened inside a loop without close before next iteration.

## INTENTIONAL MALDEV TRICKS — Do NOT Flag These

These patterns look wrong but are correct for offensive security:

### Memory Patching (ETW, AMSI, Unhook)
```go
// Overwriting function prologues is INTENTIONAL
*(*byte)(unsafe.Pointer(addr + uintptr(i))) = patchByte
// XOR EAX,EAX; RET (0x31 0xC0 0xC3) to neutralize AMSI
// XOR RAX,RAX; RET (0x48 0x33 0xC0 0xC3) to neutralize ETW
```
**Do not flag**: Writing to executable memory after VirtualProtect(RWX).

### Undocumented NT Functions
```go
// These are real functions exported by ntdll, just not in public MSDN docs:
EtwpCreateEtwThread  // Internal ETW thread creation
NtQueueApcThreadEx   // Extended APC with special user APC flag
I_QueryTagInformation // Service tag query (advapi32)
```
**Do not flag**: Using undocumented exports. DO verify the parameter count is consistent with known signatures.

### Manual PE Header Walking (In-Memory)
```go
// Reading loaded PE headers via unsafe.Pointer is CORRECT for in-memory images
// debug/pe cannot be used because loaded images use RVA layout, not file layout
lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
```
**Do not flag**: PE header navigation via unsafe.Pointer on loaded DLL base addresses.

### Syscall Stubs (Direct/Indirect)
```go
// Writing machine code to executable memory is INTENTIONAL
// 4C 8B D1 B8 XX XX 00 00 0F 05 C3 = mov r10,rcx; mov eax,SSN; syscall; ret
stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1 // mov r10, rcx
```
**Do not flag**: Assembling syscall stubs in allocated RWX pages.

### SSN Resolution from Ntdll Prologues
```go
// Reading bytes from ntdll function prologues to extract SSN is CORRECT
// Pattern: 4C 8B D1 B8 [SSN:2bytes] 00 00
if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
    ssn = uint16(bytes[4]) | uint16(bytes[5])<<8
}
```
**Do not flag**: Reading ntdll function bytes for SSN extraction.

### Process Herpaderping
```go
// Creating a section from a file, then overwriting the file, then creating
// a process from the section — the kernel uses the cached image, not the disk file
NtCreateSection(..., SEC_IMAGE, ..., hFile) // Cache payload
// Overwrite file with decoy
NtCreateProcessEx(..., hSection, ...) // Kernel uses cached payload
```
**Do not flag**: Writing to a file after creating a section from it.

### TOCTOU Race (CVE-2024-30088)
```go
// Deliberately racing kernel buffer access is the EXPLOIT MECHANISM
// Corrupting ListEntry pointers to cause kernel confusion
ptr.Flink = corruptValue
```
**Do not flag**: Intentional data race patterns in exploit code.

## Verification Process

When using the microsoft-docs MCP tools, verify:
1. `microsoft_docs_search` for function signature confirmation
2. `microsoft_code_sample_search` for usage patterns
3. Cross-reference parameter counts and return types

For Linux, verify against:
- `man 2 <syscall>` for syscall semantics
- `/usr/include/asm/unistd_64.h` (or arch-specific) for syscall numbers
- `man 5 proc` for /proc filesystem format

## Output Format

Only report actual errors. Silence = all correct.

```
API error: [file:line] [function] — [what's wrong] (MSDN: [correct info])
```

Example:
```
API error: inject/foo.go:42 NtCreateThreadEx — checking r == 0 for error, but NTSTATUS uses r != 0
API error: inject/bar.go:15 memfd_create — syscall 319 in arm64 file, should be 279
```
