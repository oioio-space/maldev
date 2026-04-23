# Injection Techniques Overview

> **MITRE ATT&CK:** T1055 -- Process Injection | **Detection:** High -- all injection methods are monitored by EDR products

## What Is Process Injection?

Process injection is a family of techniques that place executable code (shellcode) into another process's memory and trigger its execution. This allows malware to run inside a trusted process, inheriting its identity, permissions, and trust level. Security tools watching for suspicious new processes see nothing unusual -- the code runs inside an already-running, legitimate application.

maldev provides a unified `inject` package with 15 injection methods across Windows and Linux, a fluent builder API, middleware decorators for evasion, and automatic fallback support.

## Target Categories

The **Target** column below tells you *where* the shellcode ends up running
— this drives the OpSec trade-offs and the API surface you need.

| Target              | Meaning                                                                                  | Who pays the cost        | Typical API calls                                    |
|---------------------|------------------------------------------------------------------------------------------|--------------------------|------------------------------------------------------|
| **Self**            | Shellcode runs inside the current `maldev`-built process.                                | Our own process          | None cross-process — direct `VirtualAlloc` + exec    |
| **Local**           | Same as Self, but the technique deliberately avoids spawning a new thread (callback abuse, pool work, module stomping). Useful when any visible `CreateThread` would be flagged. | Our own process          | `VirtualAlloc` / `EnumWindows` / `TpPostWork` / stomp |
| **Remote**          | Shellcode runs inside an already-running OS process (PID supplied by the caller). Requires `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` (+ possibly `PROCESS_CREATE_THREAD`). | Target PID's process     | `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + thread trigger |
| **Child (suspended)** | We *spawn* a new process in `CREATE_SUSPENDED` state, write shellcode into it, then resume. The child never executes its original entry point. | Newly-created child process | `CreateProcess(CREATE_SUSPENDED)` + write + resume/APC/hijack |

**Stealth ranking by target** (generally): Local > Child (suspended) >
Remote. Local avoids cross-process memory primitives entirely; Child is
acceptable because the process tree is predictable (our malware spawned
it); Remote is the loudest — `WriteProcessMemory` into an unrelated
running process is a classic EDR trigger.

## Technique Comparison

| Technique | Method Constant | Target | Creates Thread? | Uses WriteProcessMemory? | Stealth | Complexity |
|-----------|----------------|--------|-----------------|--------------------------|---------|------------|
| [CreateRemoteThread](create-remote-thread.md) | `MethodCreateRemoteThread` | Remote | Yes | Yes | Low | Low |
| [Early Bird APC](early-bird-apc.md) | `MethodEarlyBirdAPC` | Child (suspended) | No (APC) | Yes | Medium | Medium |
| [Module Stomping](module-stomping.md) | `ModuleStomp()` | Local | Caller decides | No | High | Medium |
| [Section Mapping](section-mapping.md) | `SectionMapInject()` | Remote | Yes | No | High | High |
| [Callback Execution](callback-execution.md) | `ExecuteCallback()` | Local | No | No | High | Low |
| [Thread Pool](thread-pool.md) | `ThreadPoolExec()` | Local | No (pool) | No | High | Medium |
| [KernelCallbackTable](kernel-callback-table.md) | `KernelCallbackExec()` | Remote | No | Yes | High | High |
| [Phantom DLL](phantom-dll.md) | `PhantomDLLInject()` | Remote | No (caller) | Yes | Very High | High |
| [Thread Hijack](thread-hijack.md) | `MethodThreadHijack` | Child (suspended) | No | Yes | Medium | Medium |
| [Argument Spoofing](process-arg-spoofing.md) | `SpawnWithSpoofedArgs()` | Child (suspended) | No | Yes | Medium | Medium |
| [EtwpCreateEtwThread](etwp-create-etw-thread.md) | `MethodEtwpCreateEtwThread` | Self | Yes (internal) | No | High | Low |
| [NtQueueApcThreadEx](nt-queue-apc-thread-ex.md) | `MethodNtQueueApcThreadEx` | Remote | No (special APC) | Yes | Medium | Medium |

## Decision Flow

```mermaid
flowchart TD
    Start([Need to run shellcode]) --> Q1{Self or remote?}
    Q1 -->|Self-inject| Q2{Need memory stealth?}
    Q1 -->|Remote process| Q3{Can create new process?}

    Q2 -->|Yes| MS[Module Stomping]
    Q2 -->|No| Q4{Avoid thread creation?}

    Q4 -->|Yes| CB[Callback Execution]
    Q4 -->|Pool is fine| TP[Thread Pool]
    Q4 -->|Thread is fine| CT[CreateThread]

    Q3 -->|Yes| Q5{Need APC stealth?}
    Q3 -->|No, existing PID| Q6{Avoid WriteProcessMemory?}

    Q5 -->|Yes| EB[Early Bird APC]
    Q5 -->|Thread hijack| TH[Thread Hijack]

    Q6 -->|Yes| SM[Section Mapping]
    Q6 -->|WPM is OK| Q7{Target has windows?}

    Q7 -->|Yes| KC[KernelCallbackTable]
    Q7 -->|No| CRT[CreateRemoteThread]

    style MS fill:#2d5016,color:#fff
    style SM fill:#2d5016,color:#fff
    style CB fill:#2d5016,color:#fff
    style TP fill:#2d5016,color:#fff
    style KC fill:#2d5016,color:#fff
```

## Architecture

All injection methods implement the `Injector` interface:

```go
type Injector interface {
    Inject(shellcode []byte) error
}
```

The builder API provides fluent construction with syscall method selection:

```go
injector, err := inject.Build().
    Method(inject.MethodEarlyBirdAPC).
    ProcessPath(`C:\Windows\System32\svchost.exe`).
    IndirectSyscalls().
    Use(inject.WithCPUDelayConfig(inject.CPUDelayConfig{MaxIterations: 10_000_000})).
    Create()
```

The Pipeline pattern separates memory setup from execution, allowing mix-and-match:

```go
p := inject.NewPipeline(
    inject.RemoteMemory(hProcess, caller),
    inject.CreateRemoteThreadExecutor(hProcess, caller),
)
err := p.Inject(shellcode)
```

## SelfInjector — Getting the Region Back

Self-process injectors (`MethodCreateThread`, `MethodCreateFiber`,
`MethodEtwpCreateEtwThread` on Windows; `MethodProcMem` on Linux) place the
shellcode inside the current process. The base `Injector` interface throws
that address away, forcing callers who want to sleep-mask or wipe the
region to compute it themselves. The optional `SelfInjector` interface
exposes it:

```go
type Region struct {
    Addr uintptr
    Size uintptr
}

type SelfInjector interface {
    Injector
    InjectedRegion() (Region, bool)
}
```

Type-assert the `Injector` you got back and you can feed the region
directly into `evasion/sleepmask` for the beacon-loop pattern:

```go
inj, _ := inject.NewWindowsInjector(&inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodIndirect,
})
if err := inj.Inject(shellcode); err != nil { return err }

if self, ok := inj.(inject.SelfInjector); ok {
    if r, ok := self.InjectedRegion(); ok {
        mask := sleepmask.New(sleepmask.Region{Addr: r.Addr, Size: r.Size})
        for {
            // ... beacon work ...
            mask.Sleep(30 * time.Second)
        }
    }
}
```

Contract details:

- Returns `(Region{}, false)` before the first successful `Inject`.
- Returns `(Region{}, false)` on cross-process methods (CRT, APC, EarlyBird,
  ThreadHijack, Rtl, NtQueueApcThreadEx) — the region lives in the target
  process, not ours.
- Failed `Inject` calls do **not** clobber a previously-published region.
- All three decorators (`WithValidation`, `WithCPUDelay`, `WithXOR`) and
  the `Pipeline` transparently forward `InjectedRegion` to the wrapped
  injector, so the pattern works at the end of any `Chain`.

See `evasion/sleepmask/doc.go` and `docs/techniques/evasion/sleep-mask.md`
for the encrypted-sleep side of this pattern.

## Syscall Methods

Every injection method supports four syscall routing modes via `WindowsConfig.SyscallMethod`:

| Mode | Constant | Hooks Bypassed | Use When |
|------|----------|---------------|----------|
| WinAPI | `wsyscall.MethodWinAPI` | None | Testing, no EDR |
| Native API | `wsyscall.MethodNativeAPI` | kernel32 | Light EDR |
| Direct Syscall | `wsyscall.MethodDirect` | All userland | Medium EDR |
| Indirect Syscall | `wsyscall.MethodIndirect` | All userland + CFG | Heavy EDR |
