[← Back to README](../README.md)

# Evasion Module Reference

The `evasion/` module provides composable defense evasion techniques for Windows (and some cross-platform) environments. Every technique implements the `evasion.Technique` interface, allowing you to mix and match them into ordered pipelines.

## Overview

| Package | Technique | MITRE ATT&CK | Detection | Platform |
|---------|-----------|---------------|-----------|----------|
| `evasion/amsi` | AMSI memory patching | T1562.001 -- Impair Defenses | Medium | Windows |
| `evasion/etw` | ETW event write patching | T1562.001 -- Impair Defenses | Medium | Windows |
| `evasion/unhook` | ntdll.dll restoration | T1562.001 -- Impair Defenses | High | Windows |
| `evasion/acg` | Arbitrary Code Guard policy | T1562.001 -- Impair Defenses | Low | Windows 10+ |
| `evasion/blockdlls` | Block non-Microsoft DLLs | T1562.001 -- Impair Defenses | Low | Windows 10+ |
| `evasion/phant0m` | Event Log thread termination | T1562.002 -- Disable Event Logging | High | Windows |
| `evasion/herpaderping` | Process image tampering via kernel section cache | T1055 -- Process Injection | Medium | Windows 10+ |
| `evasion/hwbp` | Hardware breakpoint detection and clearing | T1622 -- Debugger Evasion | Low | Windows |
| `evasion/sleepmask` | Encrypt memory regions during sleep | T1027 -- Obfuscated Files | Medium | Windows |
| `evasion/antidebug` | Debugger detection | T1622 -- Debugger Evasion | Low | Cross-platform |
| `evasion/antivm` | VM/hypervisor detection | T1497.001 -- System Checks | Low | Cross-platform |
| `evasion/timing` | CPU-burning delays | T1497.003 -- Time Based Evasion | Low | Cross-platform |
| `evasion/sandbox` | Multi-factor sandbox detection | T1497 -- Sandbox Evasion | Low | Cross-platform |
| `evasion/fakecmd` | PEB CommandLine overwrite | T1036.005 -- Masquerading | Low | Windows |
| `evasion/hideprocess` | Patch `NtQuerySystemInformation` in a target process | T1564.001 -- Hidden Process | Medium | Windows |
| `evasion/stealthopen` | Open files by NTFS Object ID (bypass path-based EDR hooks) | T1036 -- Masquerading | Low | Windows |
| `evasion/cet` | Detect / relax Intel CET shadow-stack + emit ENDBR64 marker | T1562.001 -- Impair Defenses | High | Windows 11 |
| `evasion/hook` | x64 inline hooking with trampoline (Go callbacks) | T1574.012 -- Hijack Execution Flow: Inline Hooking | High | Windows (x64) |
| `evasion/hook/bridge` | IPC control channel for remote hook handlers | T1574.012 -- Hijack Execution Flow | Medium | Windows |
| `evasion/hook/shellcode` | Pre-fabricated x64 handler shellcode templates | T1574.012 -- Hijack Execution Flow | High | Windows (x64) |
| `evasion/preset` | Composable technique presets | -- | -- | Windows |

Full technique walk-throughs:
[fakecmd](techniques/evasion/fakecmd.md) · [hideprocess](techniques/evasion/hideprocess.md) · [stealthopen](techniques/evasion/stealthopen.md) · [inline-hook](techniques/evasion/inline-hook.md) · [ntdll-unhooking](techniques/evasion/ntdll-unhooking.md) · [amsi-bypass](techniques/evasion/amsi-bypass.md) · [etw-patching](techniques/evasion/etw-patching.md)

## Core Interface (`evasion`)

All technique packages are unified by a single interface defined in `evasion/evasion.go`:

```go
// Technique is a single evasion action that can be applied.
type Technique interface {
    Name() string
    Apply(caller Caller) error
}

// Caller is an opaque type (interface{}) for syscall method configuration.
// On Windows, pass a *wsyscall.Caller. On other platforms, pass nil.
type Caller = interface{}
```

#### `ApplyAll(techniques []Technique, caller Caller) map[string]error`
**Purpose:** Executes every technique in order, collecting failures.
**Parameters:**
- `techniques` -- ordered slice of Technique values to apply
- `caller` -- a `*wsyscall.Caller` for direct/indirect syscalls, or `nil` for standard WinAPI

**Returns:** `nil` if all succeeded; otherwise a map of technique name to error.

**Example:**
```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
)

errs := evasion.ApplyAll([]evasion.Technique{
    amsi.ScanBufferPatch(),
    etw.All(),
}, nil)
if errs != nil {
    for name, err := range errs {
        log.Printf("evasion %s failed: %v", name, err)
    }
}
```

---

## amsi -- AMSI Memory Patching

**MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools
**Platform:** Windows
**Detection:** Medium

### Why use this?

The Antimalware Scan Interface (AMSI) lets security products intercept and scan in-memory content before execution -- PowerShell scripts, .NET assemblies, VBScript, JScript, and Win32 API calls. If your implant runs any of these inside its process, AMSI will scan the content and potentially flag it. Patching AMSI removes that inspection point entirely.

### How it works

Two independent patches are provided. They target different functions in `amsi.dll` and complement each other:

**PatchScanBuffer:**
1. Resolves `AmsiScanBuffer` in the loaded `amsi.dll` via `LazyProc.Find()`.
2. If `amsi.dll` is not loaded (e.g., no AMSI consumer in the process), returns `nil` immediately -- nothing to patch.
3. Calls `VirtualProtect` (or `NtProtectVirtualMemory` via Caller) to make the function entry writable.
4. Overwrites the first 3 bytes with `31 C0 C3` (`xor eax, eax; ret`). This makes the function return `S_OK` (0) with `AMSI_RESULT_CLEAN` for every scan.
5. Restores original page protection.

**PatchOpenSession:**
1. Resolves `AmsiOpenSession` in `amsi.dll`.
2. Scans the first 1024 bytes of the function body for opcode `0x74` (JZ -- jump if zero).
3. Flips it to `0x75` (JNZ -- jump if not zero), inverting the branch condition.
4. This causes `AmsiOpenSession` to always take the failure path, preventing AMSI session initialization. Without a valid session, no scans can occur.

### Functions

#### `PatchScanBuffer(caller *wsyscall.Caller) error`
**Purpose:** Patches `AmsiScanBuffer` to always return `S_OK` (clean).
**Parameters:**
- `caller` -- syscall method for memory protection changes. `nil` uses standard `VirtualProtect`.

**Returns:** `nil` on success or if `amsi.dll` is not loaded. Error if `VirtualProtect` or memory write fails.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/amsi"

if err := amsi.PatchScanBuffer(nil); err != nil {
    log.Fatalf("AMSI patch failed: %v", err)
}
```

#### `PatchOpenSession(caller *wsyscall.Caller) error`
**Purpose:** Flips a conditional jump in `AmsiOpenSession` to prevent session initialization.
**Parameters:**
- `caller` -- syscall method for memory protection changes. `nil` uses standard `VirtualProtect`.

**Returns:** `nil` on success or if `amsi.dll` is not loaded. Error if the `JZ` opcode is not found in the first 1024 bytes (unusual, may indicate a new Windows version).

#### `PatchAll(caller *wsyscall.Caller) error`
**Purpose:** Applies both `PatchScanBuffer` and `PatchOpenSession` in sequence.
**Returns:** The first error encountered, or `nil` if both succeed.

#### Technique Adapters

| Constructor | Name | Wraps |
|-------------|------|-------|
| `amsi.ScanBufferPatch()` | `amsi:ScanBuffer` | `PatchScanBuffer` |
| `amsi.OpenSessionPatch()` | `amsi:OpenSession` | `PatchOpenSession` |
| `amsi.All()` | `amsi:All` | `PatchAll` |

### Advantages
- Fast (3-byte or 1-byte patch) and reliable across Windows versions
- Gracefully returns `nil` when AMSI is not loaded -- safe to call unconditionally
- Supports syscall method routing to bypass hooks on `VirtualProtect`

### Limitations
- EDR products may monitor `VirtualProtect` calls on `amsi.dll` memory pages
- Only affects the current process; child processes will have their own AMSI
- The `PatchOpenSession` JZ scan may fail on future Windows versions if the function layout changes

### Detection
- Sysmon: no direct event, but ETW providers can log `VirtualProtect` on amsi.dll pages
- EDR: memory integrity checks on amsi.dll, page protection change callbacks
- Microsoft Defender: Tamper Protection can detect and block AMSI patches in some configurations

---

## etw -- ETW Event Write Patching

**MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools
**Platform:** Windows
**Detection:** Medium

### Why use this?

Event Tracing for Windows (ETW) is the primary telemetry framework on Windows. EDR products, Windows Defender, and the kernel itself use ETW to collect events about process creation, network activity, .NET assembly loads, and more. Patching ETW event writing functions in `ntdll.dll` silences all ETW telemetry from the current process, blinding security tools that consume these events.

### How it works

1. For each of the 5 `EtwEventWrite*` functions in `ntdll.dll`, the function entry point is resolved via `LazyProc`.
2. `VirtualProtect` (or `NtProtectVirtualMemory` via Caller) marks the page as `PAGE_EXECUTE_READWRITE`.
3. The first 4 bytes are overwritten with `48 33 C0 C3` (`xor rax, rax; ret`). This makes each function return `STATUS_SUCCESS` (0) without writing any event.
4. Original page protection is restored.
5. Functions not present on the current OS version (older Windows builds) are silently skipped.

The `NtTraceEvent` patch works identically but targets the lower-level NT syscall that some ETW providers use directly.

### Functions

#### `Patch(caller *wsyscall.Caller) error`
**Purpose:** Patches all 5 high-level ETW event writing functions in `ntdll.dll`:
- `EtwEventWrite`
- `EtwEventWriteEx`
- `EtwEventWriteFull`
- `EtwEventWriteString`
- `EtwEventWriteTransfer`

**Parameters:**
- `caller` -- syscall method. `nil` uses standard WinAPI.

**Returns:** `nil` on success. Functions not present on the current OS are silently skipped. Error if `VirtualProtect` fails on a present function.

#### `PatchNtTraceEvent(caller *wsyscall.Caller) error`
**Purpose:** Patches `NtTraceEvent` in `ntdll.dll` -- a lower-level function used by some ETW providers.
**Parameters:**
- `caller` -- syscall method. `nil` uses standard WinAPI.

**Returns:** `nil` on success or if `NtTraceEvent` is not present.

#### `PatchAll(caller *wsyscall.Caller) error`
**Purpose:** Applies both `Patch` and `PatchNtTraceEvent`.
**Returns:** The first error encountered, or `nil` if both succeed.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/etw"

// Silence all ETW telemetry from this process
if err := etw.PatchAll(nil); err != nil {
    log.Fatalf("ETW patch failed: %v", err)
}
```

#### Technique Adapters

| Constructor | Name | Wraps |
|-------------|------|-------|
| `etw.PatchTechnique()` | `etw:Patch` | `Patch` |
| `etw.NtTraceTechnique()` | `etw:NtTraceEvent` | `PatchNtTraceEvent` |
| `etw.All()` | `etw:All` | `PatchAll` |

### Advantages
- Silences all ETW telemetry from the current process in a single call
- Missing functions are silently skipped -- safe across Windows versions
- 4-byte patch per function, minimal memory footprint

### Limitations
- In-memory `ntdll.dll` patches are detectable by memory integrity checks
- Does not affect kernel-mode ETW providers (e.g., kernel audit events still fire)
- Some EDR products have moved to kernel-mode callbacks that do not rely on user-mode ETW

### Detection
- Periodic `ntdll.dll` .text section integrity scans (comparing in-memory vs on-disk)
- Sysmon Event ID 7 (Image loaded) can correlate with missing subsequent ETW events
- Kernel-mode ETW consumers remain unaffected

---

## unhook -- ntdll.dll Hook Removal

**MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools
**Platform:** Windows
**Detection:** High

### Why use this?

EDR products install inline hooks (JMP trampolines) on critical NT functions in `ntdll.dll` -- the lowest user-mode layer before the kernel. These hooks intercept calls to `NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtWriteVirtualMemory`, etc., letting the EDR inspect arguments and block malicious operations. Unhooking restores the original function prologues, allowing syscalls to pass directly to the kernel without EDR inspection.

### How it works

Three methods are provided, ordered by increasing sophistication:

**ClassicUnhook (single function):**
1. Reads the clean `ntdll.dll` from `C:\Windows\System32\ntdll.dll` on disk.
2. Parses the PE export directory to find the target function's file offset.
3. Reads the first 5 bytes (the clean syscall stub prologue) from the on-disk copy.
4. Resolves the same function in the loaded (hooked) ntdll via `LazyProc`.
5. Overwrites the hooked bytes with the clean ones using `VirtualProtect` + `WriteProcessMemory` (or NT equivalents via Caller).

**FullUnhook (entire .text section):**
1. Reads the full `ntdll.dll` from disk and parses it as a PE.
2. Extracts the entire `.text` section data.
3. Loads `ntdll.dll` to get its base address, computes the in-memory `.text` address.
4. Sets the region to `PAGE_EXECUTE_READWRITE`, copies the clean `.text` over the hooked one, restores protection.

**PerunUnhook (from child process memory):**
1. Spawns `notepad.exe` in `CREATE_SUSPENDED | CREATE_NO_WINDOW` state.
2. Because EDR hooks are applied during process initialization (usually via `LdrLoadDll` callbacks), a suspended process may have a clean ntdll -- especially if the EDR only hooks after the initial thread runs.
3. `ntdll.dll` is loaded at the same base address in all processes on the same boot (ASLR is per-boot, not per-process).
4. Reads the `.text` section from the child process via `ReadProcessMemory`.
5. Overwrites the local hooked `.text` with the clean copy.
6. Terminates the child process.

### Functions

#### `ClassicUnhook(funcName string, caller *wsyscall.Caller) error`
**Purpose:** Restores the first 5 bytes of a single hooked ntdll function from the on-disk copy.
**Parameters:**
- `funcName` -- the ntdll export name, e.g., `"NtAllocateVirtualMemory"`
- `caller` -- syscall method. `nil` uses standard WinAPI.

**Returns:** Error if the function cannot be found on disk or in memory.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/unhook"

err := unhook.ClassicUnhook("NtAllocateVirtualMemory", nil)
if err != nil {
    log.Fatalf("unhook failed: %v", err)
}
```

#### `FullUnhook(caller *wsyscall.Caller) error`
**Purpose:** Replaces the entire `.text` section of the loaded `ntdll.dll` with the clean version from disk. Removes ALL hooks at once.
**Parameters:**
- `caller` -- syscall method. When non-nil, uses `NtProtectVirtualMemory` and `NtWriteVirtualMemory` to bypass potential hooks on `VirtualProtect`/`WriteProcessMemory`.

**Returns:** Error if ntdll cannot be read from disk or the `.text` section is missing.

**Example:**
```go
if err := unhook.FullUnhook(nil); err != nil {
    log.Fatalf("full unhook failed: %v", err)
}
```

#### `PerunUnhook(caller *wsyscall.Caller) error`
**Purpose:** Reads a pristine ntdll `.text` section from a freshly spawned suspended child process (`notepad.exe`) and overwrites the hooked copy in the current process.
**Parameters:**
- `caller` -- syscall method. `nil` uses standard WinAPI.

**Returns:** Error if the child process cannot be spawned or the memory read fails.

**Example:**
```go
if err := unhook.PerunUnhook(nil); err != nil {
    log.Fatalf("perun unhook failed: %v", err)
}
```

### Hook Detection Functions

#### `DetectHooked(funcNames []string) ([]string, error)`
**Purpose:** Checks each function's first 4 bytes against the canonical x64 syscall stub prologue (`4C 8B D1 B8` -- `mov r10, rcx; mov eax, <syscall_number>`). Returns names of functions that do not match, indicating an active inline hook.
**Parameters:**
- `funcNames` -- list of ntdll export names to check. Use `CommonHookedFunctions` for the standard set.

**Returns:** Slice of hooked function names. Empty slice means no hooks detected.

**Example:**
```go
hooked, err := unhook.DetectHooked(unhook.CommonHookedFunctions)
if err != nil {
    log.Fatal(err)
}
if len(hooked) > 0 {
    log.Printf("hooked functions: %v", hooked)
}
```

#### `IsHooked(funcName string) (bool, error)`
**Purpose:** Convenience wrapper to check a single function.

**Example:**
```go
if hooked, err := unhook.IsHooked("NtAllocateVirtualMemory"); err == nil && hooked {
    unhook.ClassicUnhook("NtAllocateVirtualMemory", nil)
}
```

#### `Inspect(funcNames []string) ([]HookInfo, error)`
**Purpose:** Returns detailed hook status for every function, including the raw 8-byte prologue. Unlike `DetectHooked`, it returns an entry for every function (hooked or not).
**Returns:** Slice of `HookInfo` structs:

```go
type HookInfo struct {
    Name     string   // ntdll export name
    Hooked   bool     // true if prologue does not match clean stub
    Prologue [8]byte  // first 8 bytes as observed in memory
}
```

**Example:**
```go
infos, _ := unhook.Inspect(unhook.CommonHookedFunctions)
for _, info := range infos {
    status := "clean"
    if info.Hooked {
        status = "HOOKED"
    }
    fmt.Printf("%-30s %s  % X\n", info.Name, status, info.Prologue)
}
```

#### `CommonHookedFunctions` (variable)
The 10 ntdll functions most frequently targeted by EDR inline hooks:
`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtMapViewOfSection`, `NtQueueApcThread`, `NtSetContextThread`, `NtResumeThread`, `NtCreateSection`, `NtOpenProcess`.

### Technique Adapters

| Constructor | Name | Wraps |
|-------------|------|-------|
| `unhook.Classic(funcName)` | `unhook:Classic(<funcName>)` | `ClassicUnhook` |
| `unhook.ClassicAll(funcNames)` | one per function | `ClassicUnhook` for each |
| `unhook.CommonClassic()` | one per `CommonHookedFunctions` entry | `ClassicUnhook` for each |
| `unhook.Full()` | `unhook:Full` | `FullUnhook` |
| `unhook.Perun(target)` | `unhook:Perun(<target>)` | `PerunUnhook` |

### Advantages
- `ClassicUnhook` is targeted and low-noise -- only a few bytes change
- `FullUnhook` guarantees removal of every inline hook in a single operation
- `PerunUnhook` avoids reading ntdll from disk, which some EDRs monitor
- Detection functions let you check first, unhook selectively

### Limitations
- `ClassicUnhook` and `FullUnhook` read ntdll.dll from disk -- monitored by some EDRs (Sysmon Event ID 11 / file read on system DLLs)
- `PerunUnhook` spawns a child process -- `CreateProcess` in suspended mode is itself a suspicious pattern
- Some EDRs re-hook after unhooking if they run periodic integrity checks
- Kernel-mode hooks (e.g., SSDT hooks, minifilter callbacks) are not affected

### Detection
- Sysmon Event ID 7 (Image loaded) combined with subsequent missing telemetry
- EDR memory integrity scans comparing ntdll .text section hash
- `CreateProcess` with `CREATE_SUSPENDED` flag (for PerunUnhook)
- `ReadProcessMemory` from a child process targeting ntdll addresses

---

## acg -- Arbitrary Code Guard

**MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools
**Platform:** Windows 10 1709+
**Detection:** Low

### Why use this?

Arbitrary Code Guard (ACG) is a Windows mitigation policy that prevents a process from allocating or modifying executable memory pages. Once enabled, calls like `VirtualAlloc(PAGE_EXECUTE_READWRITE)` will fail. This blocks EDR from injecting dynamic hooks or executable code into your process -- but it also means you cannot allocate new executable memory yourself. Use this **after** all shellcode injection is complete.

### How it works

1. Calls `SetProcessMitigationPolicy` (kernel32.dll) with policy ID `ProcessDynamicCodePolicy` (2).
2. Sets the `ProhibitDynamicCode` flag to 1 in a `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` struct.
3. The kernel enforces this policy for the lifetime of the process -- it cannot be reversed.
4. Any subsequent attempt to allocate `PAGE_EXECUTE_*` memory or change protection to executable will fail with `STATUS_ACCESS_DENIED`.

### Functions

#### `Enable(caller *wsyscall.Caller) error`
**Purpose:** Activates Arbitrary Code Guard for the current process.
**Parameters:**
- `caller` -- accepted for API consistency but has no effect. `SetProcessMitigationPolicy` is a kernel32 export with no NT equivalent routable through the Caller.

**Returns:** Error if `SetProcessMitigationPolicy` fails (e.g., older Windows version).

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/acg"

// Apply AFTER all shellcode has been injected and is running
if err := acg.Enable(nil); err != nil {
    log.Printf("ACG not available: %v", err)
}
```

#### Technique Adapter

| Constructor | Name | Wraps |
|-------------|------|-------|
| `acg.Guard()` | `acg:Guard` | `Enable` |

### Advantages
- Kernel-enforced -- cannot be bypassed from user mode once enabled
- Very low detection profile -- this is a legitimate Windows mitigation policy
- Blocks EDR code injection into the process

### Limitations
- **Irreversible** -- once enabled, no executable memory can be allocated for the process lifetime
- Must be applied **after** all shellcode injection is complete
- The Caller parameter has no effect (kernel32 call, not routable through NT syscalls)
- Requires Windows 10 1709 or later

### Detection
- Process mitigation policy queries (`GetProcessMitigationPolicy`) can see ACG is enabled
- Unusual for most applications -- an analyst inspecting the process may flag it

---

## blockdlls -- Block Non-Microsoft DLLs

**MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools
**Platform:** Windows 10 1709+
**Detection:** Low

### Why use this?

EDR agents inject their monitoring DLLs into every process. These DLLs are signed by the EDR vendor (CrowdStrike, SentinelOne, etc.), not by Microsoft. By enabling the `MicrosoftSignedOnly` binary signature policy, only Microsoft-signed DLLs can be loaded into the process, effectively blocking EDR DLL injection.

### How it works

1. Calls `SetProcessMitigationPolicy` (kernel32.dll) with policy ID `ProcessSignaturePolicy` (8).
2. Sets the `MicrosoftSignedOnly` flag to 1 in a `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` struct.
3. The kernel enforces this policy: any subsequent `LoadLibrary` call for a DLL not signed by Microsoft will fail.

### Functions

#### `Enable(caller *wsyscall.Caller) error`
**Purpose:** Blocks loading of non-Microsoft-signed DLLs into the current process.
**Parameters:**
- `caller` -- accepted for API consistency but has no effect (same kernel32 limitation as ACG).

**Returns:** Error if `SetProcessMitigationPolicy` fails.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/blockdlls"

if err := blockdlls.Enable(nil); err != nil {
    log.Printf("BlockDLLs not available: %v", err)
}
```

#### Technique Adapter

| Constructor | Name | Wraps |
|-------------|------|-------|
| `blockdlls.MicrosoftOnly()` | `blockdlls:MicrosoftOnly` | `Enable` |

### Advantages
- Kernel-enforced, cannot be bypassed from user mode
- Very low detection profile -- legitimate Windows feature
- Prevents EDR DLL injection entirely

### Limitations
- **Irreversible** for the process lifetime
- May break legitimate third-party DLLs (e.g., GPU drivers, accessibility tools, IME)
- Requires Windows 10 1709 or later
- The Caller parameter has no effect

### Detection
- Process mitigation policy inspection
- A process that loads no third-party DLLs may be unusual in some environments

---

## phant0m -- Event Log Thread Termination

**MITRE ATT&CK:** T1562.002 -- Impair Defenses: Disable Windows Event Logging
**Platform:** Windows
**Detection:** High

### Why use this?

The Windows Event Log service writes security-critical events (logons, process creation, privilege escalation). Stopping the service outright is noisy and triggers immediate alerts. Phant0m takes a subtler approach: it kills the worker threads inside the Event Log service process while leaving the svchost.exe host process running. The service appears healthy to service control queries, but no events are actually written.

### How it works

1. Opens the Service Control Manager and queries the `EventLog` service to get its hosting PID (the specific svchost.exe instance).
2. Takes a thread snapshot of the entire system via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`.
3. Iterates all threads; for each thread owned by the EventLog PID:
   - **Service tag validation (Vista+):** Reads the thread's `SubProcessTag` via `NtQueryInformationThread` and resolves it to a service name via `I_QueryTagInformation` (from `advapi32.dll`). Only threads confirmed to belong to the `EventLog` service are terminated. This prevents collateral damage to other services sharing the same svchost.exe instance.
   - If `I_QueryTagInformation` is unavailable (pre-Vista), falls back to killing all threads of the PID (original behavior).
   - Opens the thread with `THREAD_TERMINATE` access
   - Terminates it via `TerminateThread` (or `NtTerminateThread` via Caller)
4. The svchost.exe process continues running (other services in the same host are unaffected), but the Event Log service has no worker threads to process events.

**Note on Caller routing:** The `NtQueryInformationThread` and `I_QueryTagInformation` calls used for service tag validation are read-only queries that do not modify thread or process state. They are not routed through the Caller because they are not security-sensitive operations that EDRs typically hook for injection detection. Only `NtTerminateThread` (the destructive operation) is routed through the Caller when provided.

### Functions

#### `Kill(caller *wsyscall.Caller) error`
**Purpose:** Terminates all threads belonging to the Windows Event Log service.
**Parameters:**
- `caller` -- when non-nil, uses `NtTerminateThread` via the specified syscall method. When nil, uses `TerminateThread` from kernel32.

**Returns:** Error if the EventLog PID cannot be found, or if no threads were successfully terminated.

**Requires:** `SeDebugPrivilege` (typically available to SYSTEM or elevated administrator).

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/phant0m"

if err := phant0m.Kill(nil); err != nil {
    log.Printf("phant0m failed: %v", err)
}
// Event Log is now silenced -- security events will not be recorded
```

### Advantages
- Event Log service appears running to service queries
- No service stop/start events are generated
- Other services in the same svchost.exe are unaffected

### Limitations
- Requires elevated privileges (SeDebugPrivilege)
- The Event Log service may be automatically restarted by the Service Control Manager if it detects thread loss
- Very high detection risk in mature environments
- Does not affect ETW kernel-mode events that bypass the Event Log service

### Detection
- Thread termination in svchost.exe hosting EventLog is highly anomalous
- Sysmon Event ID 1 (Process creation) for the tool itself
- Gap in Event Log continuity (missing events for a time window)
- EDR behavioral rules for thread termination in system processes

---

## herpaderping -- Process Herpaderping

**MITRE ATT&CK:** T1055 -- Process Injection
**Platform:** Windows 10+
**Detection:** Medium

### Why use this?

Process Herpaderping exploits a fundamental timing gap in the Windows process creation model. When a process is created from an image section, the kernel caches the PE image in memory at `NtCreateSection` time. The on-disk file can be modified *after* the section is created but *before* the initial thread triggers EDR security callbacks. The result: the running process executes your payload, but the file on disk (which EDR inspects) shows benign content.

### How it works

1. **Write payload to disk:** The payload PE is written to a target file path.
2. **Create image section:** `NtCreateSection` with `SEC_IMAGE` creates a kernel-backed section object from the file. At this point, the PE image is cached in kernel memory.
3. **Create process from section:** `NtCreateProcessEx` creates a process object backed by the section. The process exists but has no threads yet.
4. **Overwrite file on disk:** The target file is overwritten with decoy content -- either a benign PE (e.g., svchost.exe) or random bytes. The kernel's cached image is unaffected.
5. **Set up PEB:** Process parameters (ImagePathName, CommandLine) are written to the new process's PEB via `NtQueryInformationProcess` + `WriteProcessMemory`.
6. **Create initial thread:** `NtCreateThreadEx` starts execution. This triggers the EDR's process creation callback -- but when it inspects the file on disk, it sees the decoy, not the payload.

### Functions

#### `Run(cfg Config) error`
**Purpose:** Executes a PE using the Process Herpaderping technique.
**Parameters:**
- `cfg` -- a `Config` struct (see below).

**Returns:** Error if any step fails (file I/O, NT API calls, PEB setup).

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/herpaderping"

err := herpaderping.Run(herpaderping.Config{
    PayloadPath: "implant.exe",
    TargetPath:  `C:\Temp\legit.exe`,
    DecoyPath:   `C:\Windows\System32\svchost.exe`,
})
if err != nil {
    log.Fatalf("herpaderping failed: %v", err)
}
```

#### Technique Adapter

| Constructor | Name | Wraps |
|-------------|------|-------|
| `herpaderping.Technique(cfg)` | `herpaderping` | `Run` |

### Configuration

```go
type Config struct {
    // PayloadPath is the path to the PE to execute stealthily.
    PayloadPath string

    // TargetPath is the path where the PE will be written temporarily.
    // This file is overwritten with decoy content before thread creation.
    // If empty, a temp file is used.
    TargetPath string

    // DecoyPath is the path to a legitimate PE used to overwrite the target.
    // If empty, the target is overwritten with random bytes.
    DecoyPath string

    // Caller routes NT syscalls through direct/indirect methods.
    // nil = standard WinAPI (LazyProc.Call).
    Caller *wsyscall.Caller
}
```

- `PayloadPath` -- **required.** The PE you want to execute.
- `TargetPath` -- where the payload is temporarily written. If empty, `os.CreateTemp` provides a path. Choose a path that looks legitimate (e.g., `C:\ProgramData\update.exe`).
- `DecoyPath` -- a benign PE to replace the payload on disk. If empty, the file is overwritten with random bytes of the same size. Using a real PE (like `svchost.exe`) is more convincing to automated analysis.
- `Caller` -- set to a `*wsyscall.Caller` to route `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx`, and `NtAllocateVirtualMemory` through direct/indirect syscalls.

### Advantages
- The file on disk always shows benign content when EDR inspects it
- Kernel-cached image is immutable after section creation
- Works with any PE payload

### Limitations
- Requires write access to the target path
- The file is briefly on disk with payload content (between write and overwrite)
- Sysmon Event ID 25 (ProcessTampering) specifically detects this technique
- The created process has unusual characteristics (no parent-child lineage visible in some tools)
- Temp file cleanup is best-effort

### Detection
- **Sysmon Event ID 25** (ProcessTampering) -- specifically designed to detect file modification between section creation and thread creation
- File system monitoring for write-then-overwrite patterns on executables
- Process creation with section-backed images where the file hash changes

---

## antidebug -- Debugger Detection

**MITRE ATT&CK:** T1622 -- Debugger Evasion
**Platform:** Cross-platform (Windows + Linux)
**Detection:** Low

### Why use this?

If your code is being analyzed under a debugger, you may want to alter behavior -- exit, produce benign output, or sleep indefinitely. This package provides a simple cross-platform check for attached debuggers.

### How it works

**Windows:** Calls `kernel32!IsDebuggerPresent`, which reads the `BeingDebugged` flag from the Process Environment Block (PEB). This flag is set by the kernel when a debugger attaches via `DebugActiveProcess` or when the process is created under a debugger.

**Linux:** Reads `/proc/self/status` and parses the `TracerPid` field. A non-zero value indicates a debugger (ptrace-based) is attached.

### Functions

#### `IsDebuggerPresent() bool`
**Purpose:** Returns `true` if a debugger is attached to the current process.
**Parameters:** None.
**Returns:** `true` if debugging is detected, `false` otherwise. Never returns an error.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/antidebug"

if antidebug.IsDebuggerPresent() {
    os.Exit(0) // bail out
}
```

### Advantages
- Cross-platform (Windows + Linux)
- Zero dependencies beyond OS primitives
- Extremely fast -- single API call or file read

### Limitations
- Trivially bypassed: an analyst can patch the PEB `BeingDebugged` flag or use `ScyllaHide`
- On Windows, does not detect kernel debuggers (WinDbg in kernel mode)
- On Windows, does not detect anti-anti-debug tools that clear the PEB flag
- On Linux, does not detect `LD_PRELOAD`-based debugging tools that do not use ptrace

### Detection
- Calling `IsDebuggerPresent` is common and not suspicious by itself
- Static analysis: the import/call is trivial to spot in disassembly

---

## antivm -- Virtual Machine Detection

**MITRE ATT&CK:** T1497.001 -- Virtualization/Sandbox Evasion: System Checks
**Platform:** Cross-platform (Windows + Linux)
**Detection:** Low

### Why use this?

Malware analysts typically run samples inside virtual machines. Detecting VM artifacts lets you avoid execution in analysis environments. This package checks multiple indicators across 5 dimensions: registry keys, filesystem artifacts, NIC MAC address prefixes, running processes, and CPUID/BIOS product names.

### How it works

The package maintains a `DefaultVendors` list covering 11 hypervisors: Hyper-V, Parallels, VirtualBox, VirtualPC, VMware, Xen, QEMU, Proxmox, KVM, Docker, and WSL. Each vendor has characteristic indicators:

- **Registry keys** (Windows): VM guest tools install known registry keys and services
- **Files** (Windows): guest agent drivers and executables in `system32\drivers\`
- **NIC MAC prefixes**: each hypervisor vendor has allocated OUI prefixes (e.g., VMware = `00:0C:29`)
- **Processes**: guest agent processes like `vmtoolsd`, `vboxtray`, `qemu-ga`
- **CPUID/BIOS**: on Windows, reads `HARDWARE\DESCRIPTION\System\BIOS\SystemProductName` for hypervisor keywords; on Linux, checks `/proc/cpuinfo` for the `hypervisor` flag

Detection dimensions are selected via a bitmask (`CheckType`), and the vendor list is configurable.

### Functions

#### `Detect(cfg Config) (string, error)`
**Purpose:** Checks vendors from the given Config and returns the first detected vendor name. Short-circuits on first match.
**Parameters:**
- `cfg` -- configuration struct (see below).

**Returns:** Vendor name (e.g., `"VMware"`) or empty string if none detected.

#### `DetectAll(cfg Config) ([]string, error)`
**Purpose:** Checks all vendors and returns every detected vendor name. Does not short-circuit.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/antivm"

vendors, err := antivm.DetectAll(antivm.DefaultConfig())
if err != nil {
    log.Fatal(err)
}
for _, v := range vendors {
    fmt.Printf("detected: %s\n", v)
}
```

#### `DetectVM() string`
**Purpose:** Convenience function using `DefaultConfig()`. Returns first detected vendor or empty string.

#### `IsRunningInVM() bool`
**Purpose:** Returns `true` if any VM indicator from `DefaultVendors` is detected.

**Example:**
```go
if antivm.IsRunningInVM() {
    os.Exit(0)
}
```

#### `DetectNic(macPrefixes []string) (bool, string, error)`
**Purpose:** Returns `true` if any network interface has a MAC address matching one of the given prefixes.
**Returns:** `(found, matchedMAC, error)`.

#### `DetectFiles(files []string) (bool, string)`
**Purpose:** Returns `true` if any of the given file paths exists on disk.
**Returns:** `(found, firstMatchedPath)`.

#### `DetectRegKey(keys []RegKey) (bool, RegKey, error)`
**Purpose:** Returns `true` if any of the given registry keys is present. Supports three modes:
- Keys with `ExpectedValue` -- checks the value content for a substring match
- Keys ending in `*` -- checks sub-key name prefixes
- All others -- checks key existence only

#### `DetectProcess(procNames []string) (bool, string, error)`
**Purpose:** Returns `true` if any running process name contains one of the given substrings (case-insensitive).

#### `DetectCPUID() (bool, string)`
**Purpose:** Platform-specific hypervisor detection.
- **Windows:** Reads `HKLM\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName` and checks against known hypervisor keywords (vmware, virtualbox, kvm, qemu, xen, hyper-v, parallels).
- **Linux:** Reads `/proc/cpuinfo` and checks for the `hypervisor` flag (CPUID leaf 1, ECX bit 31).

### Configuration

```go
type CheckType uint

const (
    CheckRegistry CheckType = 1 << iota  // Registry-key detection (Windows only)
    CheckFiles                            // Filesystem artifact detection
    CheckNIC                              // MAC address prefix detection
    CheckProcess                          // Running-process detection
    CheckCPUID                            // Hypervisor CPUID / product-name detection
    CheckAll = CheckRegistry | CheckFiles | CheckNIC | CheckProcess | CheckCPUID
)

type Config struct {
    Vendors []Vendor    // nil = use DefaultVendors
    Checks  CheckType   // 0 = CheckAll
}
```

- `Vendors` -- set to nil for the built-in list, or provide your own `[]Vendor` for custom indicators.
- `Checks` -- bitmask selecting which detection dimensions to evaluate. Use `|` to combine.

**Example -- fast check with no disk access:**
```go
cfg := antivm.Config{
    Checks: antivm.CheckProcess | antivm.CheckCPUID,
}
vendor, _ := antivm.Detect(cfg)
```

### Advantages
- 11 hypervisors covered out of the box
- 5 independent detection dimensions reduce false negatives
- Fully configurable -- restrict checks for speed or stealth
- Cross-platform (registry checks are skipped on Linux)

### Limitations
- Determined analysts can strip VM artifacts (remove guest tools, spoof MAC, rename processes)
- Registry and file checks require disk access, which may be monitored
- CPUID-based detection can be fooled by hypervisor configuration (e.g., `hypervisor.cpuid.v0 = FALSE` in VMware)

### Detection
- Registry key enumeration (`HKLM\HARDWARE`, `HKLM\SYSTEM\CurrentControlSet\Services`) is common and not suspicious
- Process enumeration via `CreateToolhelp32Snapshot` is also common
- Behavioral analysis may flag the combination of all these checks

---

## timing -- CPU-Burning Delays

**MITRE ATT&CK:** T1497.003 -- Virtualization/Sandbox Evasion: Time Based Evasion
**Platform:** Cross-platform
**Detection:** Low

### Why use this?

Sandboxes typically hook `Sleep`/`NtDelayExecution` and fast-forward time to speed up analysis. A CPU-burning delay cannot be fast-forwarded because it consumes real CPU cycles. If the sandbox skips the delay, the code resumes too early and the time check fails. If it lets the delay run, the analysis timeout may expire before the payload executes.

### How it works

**BusyWait:** Enters a tight loop checking `time.Now()` against a deadline. No sleep syscalls are issued -- the goroutine burns CPU until the wall-clock duration elapses.

**BusyWaitPrimality:** Computes primality of ~500,000 numbers using trial division. This produces a CPU-intensive workload that looks like legitimate computation rather than a busy-wait loop -- harder for automated analysis to classify as evasion.

### Functions

#### `BusyWait(d time.Duration)`
**Purpose:** Burns CPU for the specified duration without calling Sleep.
**Parameters:**
- `d` -- how long to wait. Typical values: 5-30 seconds.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/timing"

timing.BusyWait(10 * time.Second)
// 10 seconds of real wall-clock time have now passed
```

#### `BusyWaitPrimality()`
**Purpose:** Burns CPU using primality testing (~200ms on modern hardware). Harder to detect than a simple time-check loop because the workload resembles legitimate computation.

**Example:**
```go
timing.BusyWaitPrimality()
```

### Advantages
- Cannot be fast-forwarded by sandbox Sleep hooks
- `BusyWaitPrimality` is harder to classify as evasion via static or behavioral analysis
- Cross-platform, no OS-specific calls

### Limitations
- Burns CPU -- visible in resource monitoring
- `BusyWait` with long durations is detectable as a tight loop with no I/O
- `BusyWaitPrimality` has a fixed ~200ms duration (not configurable)

### Detection
- High CPU usage with no I/O or syscalls for extended periods
- Behavioral heuristics for busy-wait patterns

---

## sandbox -- Multi-Factor Sandbox Detection

**MITRE ATT&CK:** T1497 -- Virtualization/Sandbox Evasion
**Platform:** Cross-platform (full feature set on Windows)
**Detection:** Low

### Why use this?

No single check reliably distinguishes a sandbox from a real machine. This package combines 9 independent detection dimensions into a single configurable checker: debugger detection, VM indicators, CPU core count, RAM size, disk size, suspicious usernames, suspicious hostnames, fake domain DNS resolution, and analysis tool processes.

### How it works

The `Checker` orchestrates all detection checks against a configurable `Config`. It delegates to `antidebug.IsDebuggerPresent()`, `antivm.IsRunningInVM()`, and then performs hardware/environment checks using Win32 APIs (`GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, etc.) and process enumeration.

The fake domain check sends an HTTP GET to a non-existent domain. In a real environment this fails (the domain does not resolve). Sandboxes often intercept all DNS queries and return valid responses -- if the request succeeds, the environment is likely a sandbox.

### Functions

#### `New(cfg Config) *Checker`
**Purpose:** Creates a new Checker with the given configuration.

#### `(*Checker) IsSandboxed(ctx context.Context) (bool, string, error)`
**Purpose:** Runs all configured checks and returns `true` if any indicator fires.
**Parameters:**
- `ctx` -- context for cancellation/timeout (used by HTTP and process enumeration checks).

**Returns:** `(detected, reason, error)`. When `StopOnFirst` is true (default), returns immediately on first detection. When false, runs all checks and returns a combined reason string.

**Example:**
```go
import "github.com/oioio-space/maldev/evasion/sandbox"

checker := sandbox.New(sandbox.DefaultConfig())
if sandboxed, reason, _ := checker.IsSandboxed(ctx); sandboxed {
    log.Printf("sandbox detected: %s", reason)
    os.Exit(0)
}
```

#### `(*Checker) CheckAll(ctx context.Context) []Result`
**Purpose:** Runs every detection check and returns a `Result` for each.
**Returns:** Slice of `Result` structs:

```go
type Result struct {
    Name     string // "debugger", "vm", "cpu", "ram", "disk", "username", "hostname", "domain", "process"
    Detected bool
    Detail   string // human-readable explanation
    Err      error  // non-nil only if the check itself failed
}
```

**Example:**
```go
results := checker.CheckAll(ctx)
for _, r := range results {
    if r.Detected {
        fmt.Printf("[!] %s: %s\n", r.Name, r.Detail)
    }
}
```

#### `(*Checker) IsDebuggerPresent() bool`
Delegates to `antidebug.IsDebuggerPresent()`.

#### `(*Checker) IsRunningInVM() bool`
Delegates to `antivm.IsRunningInVM()`.

#### `(*Checker) HasEnoughRAM() (bool, error)`
Returns true if total physical RAM meets `cfg.MinRAMGB`.

#### `(*Checker) HasEnoughDisk() (bool, error)`
Returns true if total disk size at `cfg.DiskPath` meets `cfg.MinDiskGB`.

#### `(*Checker) HasEnoughCPU() bool`
Returns true if `runtime.NumCPU() >= cfg.MinCPUCores`.

#### `(*Checker) BadUsername() (bool, string, error)`
Returns true if the current username matches any entry in `cfg.BadUsernames`.

#### `(*Checker) BadHostname() (bool, string, error)`
Returns true if the hostname matches any entry in `cfg.BadHostnames`.

#### `(*Checker) CheckProcesses(ctx context.Context) (bool, string, error)`
Returns true if any running process name matches `cfg.BadProcesses` (case-insensitive substring).

#### `(*Checker) FakeDomainReachable(ctx context.Context) (bool, int, error)`
Returns true if `cfg.FakeDomain` responds to HTTP GET. Uses a random User-Agent from an embedded list.

#### `(*Checker) BusyWait()`
Delegates to `timing.BusyWait(cfg.EvasionTimeout)`.

#### `DiskTotalBytes(p string) (uint64, error)`
**Purpose:** Returns the total capacity in bytes of the volume at the given path. Standalone utility function.

### Configuration

```go
type Config struct {
    MinDiskGB      float64       // minimum disk size (default: 64)
    MinRAMGB       float64       // minimum RAM (default: 4)
    MinCPUCores    int           // minimum CPU cores (default: 2)
    BadUsernames   []string      // analyst usernames (default: sandbox, malware, virus, test, ...)
    BadHostnames   []string      // sandbox hostnames (default: sandbox, cuckoo, joe, any.run, ...)
    BadProcesses   []string      // analysis tools (default: wireshark, procmon, x64dbg, ida, ghidra, ...)
    FakeDomain     string        // domain that should NOT respond (empty = skip check)
    DiskPath       string        // disk to check (default: "C:\" on Windows, "/" on Linux)
    RequestTimeout time.Duration // HTTP timeout (default: 5s)
    EvasionTimeout time.Duration // max time for evasion busy-wait
    StopOnFirst    bool          // stop at first detection (default: true)
}
```

`DefaultConfig()` returns sensible defaults. Customize by modifying the returned struct:

```go
cfg := sandbox.DefaultConfig()
cfg.MinRAMGB = 8
cfg.StopOnFirst = false
cfg.FakeDomain = "http://this-domain-does-not-exist-7f3a2b.com"
cfg.BadProcesses = append(cfg.BadProcesses, "custom-analyzer")
checker := sandbox.New(cfg)
```

### Advantages
- 9 independent detection dimensions reduce false negatives
- Configurable thresholds for different target environments
- `StopOnFirst` mode for fast bail-out vs. `CheckAll` for detailed reporting
- Fake domain check catches sandbox DNS interception

### Limitations
- Combined pattern of all these checks may itself be flagged by advanced sandboxes
- Hardware checks (RAM, disk, CPU) can be spoofed by the hypervisor
- Username/hostname lists need updating for new sandbox products
- Fake domain check requires network access

### Detection
- Behavioral heuristics for multiple environment enumeration calls in sequence
- The specific combination of `GlobalMemoryStatusEx` + `GetDiskFreeSpaceExW` + process enumeration + DNS probe is a known fingerprint

---

## preset -- Composable Technique Presets

**Platform:** Windows
**Detection:** Varies by preset

### Why use this?

Rather than manually composing technique slices, presets give you battle-tested combinations for common scenarios. They return `[]evasion.Technique` slices ready for `evasion.ApplyAll`.

### Presets

#### `Minimal() []evasion.Technique`
**Contains:** AMSI ScanBuffer patch + ETW All patch.
**Use when:** You want the least detectable baseline -- silence AMSI and ETW without touching ntdll hooks.

#### `Stealth() []evasion.Technique`
**Contains:** Minimal + Classic unhook for all 10 `CommonHookedFunctions`.
**Use when:** You need to bypass EDR user-mode hooks but want to minimize disk reads (5 bytes per function, not the whole .text section).

#### `Aggressive() []evasion.Technique`
**Contains:** AMSI All + ETW All + Full ntdll unhook + ACG Guard + BlockDLLs MicrosoftOnly.
**Use when:** Maximum evasion is needed and you have already completed all shellcode injection. ACG and BlockDLLs are irreversible.

| Preset | Techniques | Detection Risk |
|--------|-----------|----------------|
| `Minimal()` | AMSI + ETW | Low |
| `Stealth()` | + unhook 10 common NT functions | Medium |
| `Aggressive()` | + full ntdll unhook + ACG + BlockDLLs | High |

**Example:**
```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/preset"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Use a preset with direct syscalls
caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
errs := evasion.ApplyAll(preset.Stealth(), caller)
if errs != nil {
    for name, err := range errs {
        log.Printf("%s: %v", name, err)
    }
}
```

### Advantages
- Ready-to-use combinations tested for compatibility
- One import, one function call
- Works with `evasion.ApplyAll` and the Caller system

### Limitations
- `Aggressive` preset applies ACG and BlockDLLs, which are irreversible
- Presets are fixed combinations -- for fine-grained control, compose your own `[]evasion.Technique`

---

## hwbp -- Hardware Breakpoint Detection and Clearing

**MITRE ATT&CK:** T1622 -- Debugger Evasion
**Platform:** Windows
**Detection:** Low

### Why use this?

EDR products and security researchers use hardware breakpoints (debug registers DR0-DR3) to monitor specific API calls without modifying code. Unlike software breakpoints (INT 3 / `0xCC`), hardware breakpoints leave no visible byte changes in memory, making them harder to detect via integrity checks. However, they are visible through `GetThreadContext`. This package detects and clears hardware breakpoints across all threads in the current process.

### How it works

Each x64 thread has 4 debug address registers (DR0-DR3) and a control register (DR7). DR7 contains enable bits for each breakpoint. The package reads the thread context with `CONTEXT_DEBUG_REGISTERS`, checks which DR registers are non-zero with corresponding DR7 enable bits, and optionally zeros all debug registers.

### Types

#### `Breakpoint`

```go
type Breakpoint struct {
    Register int     // DR index (0-3)
    Address  uintptr // Address being monitored
    ThreadID uint32  // Thread that has the breakpoint set
}
```

### Functions

#### `Detect`

```go
func Detect() ([]Breakpoint, error)
```

**Purpose:** Reads the debug registers of the current thread and returns any active hardware breakpoints (DR0-DR3 with corresponding DR7 enable bits).

---

#### `DetectAll`

```go
func DetectAll() ([]Breakpoint, error)
```

**Purpose:** Enumerates all threads in the current process and returns hardware breakpoints found on any thread. Uses `process/enum.Threads` for thread enumeration.

---

#### `ClearAll`

```go
func ClearAll() (int, error)
```

**Purpose:** Clears all hardware breakpoints on all threads in the current process by zeroing DR0-DR3, DR6, and DR7. Returns the number of threads modified.

**How it works:** Opens each thread with `THREAD_GET_CONTEXT | THREAD_SET_CONTEXT`, reads the context, zeros all debug registers, and writes the context back.

---

#### `Technique`

```go
func Technique() evasion.Technique
```

**Purpose:** Returns an `evasion.Technique` adapter that detects and clears all hardware breakpoints. Name: `"hwbp:DetectAll"`. Calls `DetectAll()` followed by `ClearAll()`.

**Example:**

```go
import "github.com/oioio-space/maldev/evasion/hwbp"

// Check for EDR hardware breakpoints
bps, err := hwbp.DetectAll()
if err != nil {
    log.Fatal(err)
}
if len(bps) > 0 {
    log.Printf("found %d hardware breakpoints, clearing...", len(bps))
    cleared, _ := hwbp.ClearAll()
    log.Printf("cleared breakpoints on %d threads", cleared)
}
```

### Advantages
- Detects a common EDR instrumentation technique that is invisible to memory integrity scans
- Clearing is non-destructive to the process -- no code is modified
- Works with the `evasion.Technique` interface for composable pipelines

### Limitations
- Only detects user-mode hardware breakpoints; kernel debuggers set breakpoints via different mechanisms
- Some EDRs may re-set breakpoints after they are cleared
- Requires `THREAD_GET_CONTEXT` and `THREAD_SET_CONTEXT` access, which may be restricted

---

## sleepmask -- Encrypted Sleep

**MITRE ATT&CK:** T1027 -- Obfuscated Files or Information
**Platform:** Windows
**Detection:** Medium

### Why use this?

Memory scanners (both EDR real-time scanners and manual forensic tools) look for known shellcode and implant signatures in process memory. During sleep periods -- when the implant is idle between C2 check-ins -- the payload sits in memory unprotected. Sleep masking encrypts the implant's memory regions with a random XOR key before sleeping, then decrypts after waking. This defeats static memory signature scans during the sleep window.

### How it works

1. Generates a 32-byte cryptographically random XOR key.
2. XOR-encrypts each registered memory region in-place.
3. Downgrades page protection from `PAGE_EXECUTE_READ` (or whatever the original was) to `PAGE_READWRITE` -- removing the execute permission prevents code execution from the encrypted pages and is less suspicious to scanners looking for RWX regions.
4. Sleeps for the specified duration (either `NtDelayExecution` via `time.Sleep` or CPU-burn busy wait).
5. Restores `PAGE_READWRITE` temporarily, XOR-decrypts each region, then restores the **original** page permissions.
6. Zeros the XOR key from memory.

### Types

#### `Region`

```go
type Region struct {
    Addr uintptr // Base address of the memory region
    Size uintptr // Size in bytes
}
```

#### `SleepMethod`

```go
type SleepMethod int

const (
    MethodNtDelay SleepMethod = iota // Uses NtDelayExecution (standard, hookable)
    MethodBusyTrig                    // CPU-burn trigonometric busy wait (defeats Sleep hooks)
)
```

#### `Mask`

```go
type Mask struct {
    // unexported fields
}
```

### Functions

#### `New`

```go
func New(regions ...Region) *Mask
```

**Purpose:** Creates a `Mask` for the given memory regions. Default sleep method is `MethodNtDelay`.

---

#### `WithMethod`

```go
func (m *Mask) WithMethod(method SleepMethod) *Mask
```

**Purpose:** Sets the sleep method. Returns the `Mask` for chaining.

---

#### `Sleep`

```go
func (m *Mask) Sleep(d time.Duration)
```

**Purpose:** Encrypts all registered regions, sleeps for the given duration, then decrypts and restores original page permissions.

**Parameters:**
- `d` -- Sleep duration. If zero or negative, returns immediately.

**Example:**

```go
import (
    "time"
    "github.com/oioio-space/maldev/evasion/sleepmask"
)

// Register the shellcode region for encryption during sleep
mask := sleepmask.New(sleepmask.Region{
    Addr: shellcodeAddr,
    Size: shellcodeSize,
}).WithMethod(sleepmask.MethodBusyTrig)

// Encrypted sleep loop
for {
    doC2Checkin()
    mask.Sleep(30 * time.Second)
}
```

### Advantages
- Defeats static memory signature scans during the sleep window
- Random key per sleep cycle prevents key reuse attacks
- Preserves original page permissions (does not hardcode `PAGE_EXECUTE_READ`)
- `MethodBusyTrig` defeats hooks on `Sleep`/`NtDelayExecution`

### Limitations
- XOR encryption is trivially reversible if the key is recovered from a memory dump taken at the right moment
- The encrypt/decrypt transitions create brief windows where the memory is visible in plaintext
- `VirtualProtect` calls during encrypt/decrypt are observable by EDR
- Does not protect against kernel-mode memory scanning

## fakecmd -- PEB CommandLine Spoof

**Package:** `evasion/fakecmd`
**MITRE:** T1036.005 -- Masquerading: Match Legitimate Name or Location
**Detection:** Low — in-memory only; kernel `EPROCESS` retains the original command line.

### How it works

Every Windows process has a Process Environment Block (PEB) that contains a pointer to `RTL_USER_PROCESS_PARAMETERS`. That structure holds a `UNICODE_STRING CommandLine` field at offset `+0x70` (x64). Process-listing tools such as Process Explorer, `wmic process get commandline`, and PowerShell `Get-Process` read this field from the target process's memory. By walking the PEB via `NtQueryInformationProcess` and overwriting the `UNICODE_STRING` in-place, the displayed command line changes without modifying the kernel `EPROCESS.ImageFileName` or the original process creation arguments.

The original UNICODE_STRING fields are saved on the first `Spoof` call and restored verbatim by `Restore`.

### Usage

```go
import "github.com/oioio-space/maldev/evasion/fakecmd"

// Overwrite PEB CommandLine — callers see svchost from now on.
if err := fakecmd.Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil); err != nil {
    log.Fatal(err)
}
defer fakecmd.Restore()

// Read back what is currently in the PEB.
fmt.Println(fakecmd.Current())
```

### API

| Function | Description |
|----------|-------------|
| `Spoof(fakeCmd string, caller *wsyscall.Caller) error` | Overwrite PEB CommandLine with `fakeCmd`. First call saves originals. |
| `Restore() error` | Restore original PEB CommandLine. No-op if Spoof was never called. |
| `Current() string` | Return the CommandLine string currently in the PEB. |

### Advantages
- Zero external artifacts — no file, registry, or network indicators
- Works without elevated privileges (own process only)
- Compatible with all four `wsyscall.Caller` methods for EDR bypass

### Limitations
- Only affects the current process's PEB; cannot spoof remote processes without injection
- Kernel `EPROCESS.SeAuditProcessCreationInfo` retains the real image path
- ETW process-creation events (logged at creation time) are unaffected
- GC pressure: fake UTF-16 buffers are pinned in memory until `Restore` is called
