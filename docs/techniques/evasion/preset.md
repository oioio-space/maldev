# Preset — Ready-to-Use Evasion Combinations

[<- Back to Evasion](README.md)

**Package:** `github.com/oioio-space/maldev/evasion/preset`
**Platform:** Windows only

Preset bundles the most common evasion techniques into three opinionated
configurations keyed on risk tolerance. Each preset returns
`[]evasion.Technique` for use with `evasion.ApplyAll()`.

---

## Minimal

**Risk:** Low  
**Use case:** Droppers, stagers, initial-access payloads where staying off
radar matters more than bypassing advanced EDR hooks.

### Included techniques

| Technique | Package | What it does |
|-----------|---------|--------------|
| `amsi.ScanBufferPatch()` | `evasion/amsi` | Overwrites `AmsiScanBuffer` entry with `xor eax,eax; ret` — all AMSI scans return clean |
| `etw.All()` | `evasion/etw` | Patches all `EtwEventWrite*` functions and `NtTraceEvent` with `xor rax,rax; ret` — ETW events are silently dropped |

### Rationale

AMSI and ETW are the two highest-signal telemetry paths for script/reflective
loaders. Patching only these two functions has the smallest footprint: no disk
reads of ntdll, no process spawning, no mitigation policy changes. The patch
surface is three small memory writes. Suitable whenever the primary concern is
bypassing in-memory script scanning rather than defeating userland hooks on
injection primitives.

---

## Stealth

**Risk:** Medium  
**Use case:** Post-exploitation tooling, injectors, and loaders that need to
perform process injection without inline hook interference from EDR agents.

### Included techniques

Stealth is a superset of Minimal — all Minimal techniques apply, plus:

| Technique | Package | What it does |
|-----------|---------|--------------|
| `amsi.ScanBufferPatch()` | `evasion/amsi` | (from Minimal) AMSI bypass |
| `etw.All()` | `evasion/etw` | (from Minimal) ETW silence |
| `unhook.Classic("NtAllocateVirtualMemory")` | `evasion/unhook` | Restores first 5 bytes of syscall stub from on-disk ntdll |
| `unhook.Classic("NtWriteVirtualMemory")` | `evasion/unhook` | Same for write primitive |
| `unhook.Classic("NtProtectVirtualMemory")` | `evasion/unhook` | Same for protect primitive |
| `unhook.Classic("NtCreateThreadEx")` | `evasion/unhook` | Same for thread creation |
| `unhook.Classic("NtMapViewOfSection")` | `evasion/unhook` | Same for section mapping |
| `unhook.Classic("NtQueueApcThread")` | `evasion/unhook` | Same for APC-based injection |
| `unhook.Classic("NtSetContextThread")` | `evasion/unhook` | Same for thread hijacking |
| `unhook.Classic("NtResumeThread")` | `evasion/unhook` | Same for thread resume |
| `unhook.Classic("NtCreateSection")` | `evasion/unhook` | Same for section creation |
| `unhook.Classic("NtOpenProcess")` | `evasion/unhook` | Same for process opening |

All 10 functions come from `unhook.CommonHookedFunctions` via `unhook.CommonClassic()`.

### Rationale

EDR/AV products hook the 10 functions in `CommonHookedFunctions` because they
are the core primitives for process injection and shellcode execution. Classic
unhooking reads the original prologue bytes from the clean on-disk ntdll.dll
and writes them back — no process spawning, just targeted 5-byte patches.
This is surgical: only restore what is likely hooked, minimise the number of
memory writes, and avoid the large-region writes of FullUnhook that are
easier to detect via integrity checks. The combination of AMSI+ETW silence
plus unhooking gives adequate coverage for most injection scenarios without
the irreversible side effects of Aggressive.

---

## Aggressive

**Risk:** High  
**Use case:** Red team finals, assumed-breach scenarios, long-dwell implants
where maximum evasion is worth trading away compatibility and reversibility.

> **CRITICAL: ACG is irreversible.**
> `acg.Guard()` calls `SetProcessMitigationPolicy(ProhibitDynamicCode=1)`.
> After this call, `VirtualAlloc(PAGE_EXECUTE_*)` and related calls fail for
> the remainder of the process lifetime. You MUST complete all shellcode
> injection and RWX memory allocation BEFORE calling `preset.Aggressive()`.
> Applying it beforehand will break your own injection code.

### Included techniques

| Technique | Package | What it does |
|-----------|---------|--------------|
| `amsi.All()` | `evasion/amsi` | Patches both `AmsiScanBuffer` and `AmsiOpenSession` — full AMSI neutralisation |
| `etw.All()` | `evasion/etw` | Patches all `EtwEventWrite*` and `NtTraceEvent` |
| `unhook.Full()` | `evasion/unhook` | Replaces the entire ntdll `.text` section from the on-disk copy — removes every inline hook in one operation |
| `acg.Guard()` | `evasion/acg` | Enables Arbitrary Code Guard — blocks EDR from injecting executable code into this process (irreversible) |
| `blockdlls.MicrosoftOnly()` | `evasion/blockdlls` | Blocks loading of non-Microsoft-signed DLLs — prevents EDR agent DLLs from being injected (irreversible) |

### Rationale

Aggressive trades reversibility for depth. `amsi.All()` patches both AMSI
entry points rather than just `ScanBuffer`, closing the bypass gap around
session-level checks. `unhook.Full()` replaces the entire `.text` section
rather than patching individual functions — guaranteed to remove every hook,
at the cost of a larger and more conspicuous memory write. ACG and BlockDLLs
are process mitigation policies that harden the process against EDR
counter-injection; because they are kernel-enforced and irreversible, they
provide the strongest possible protection but must be the last step. This
combination is appropriate when the mission is high-value and the dwell time
is long enough that EDR will attempt active response.

---

## Usage Examples

### Basic usage

```go
import (
    "log"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/preset"
)

func main() {
    // Apply Stealth preset (returns nil map on full success)
    errs := evasion.ApplyAll(preset.Stealth(), nil)
    for name, err := range errs {
        log.Printf("evasion technique %s failed: %v", name, err)
    }
}
```

### With indirect syscalls (Caller)

```go
import (
    "log"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/preset"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    caller, err := wsyscall.New(wsyscall.MethodIndirect, wsyscall.WithHellsGate())
    if err != nil {
        log.Fatal(err)
    }
    errs := evasion.ApplyAll(preset.Stealth(), caller)
    for name, err := range errs {
        log.Printf("%s: %v", name, err)
    }
}
```

### Aggressive preset — inject first, harden after

```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/preset"
    "github.com/oioio-space/maldev/inject"
)

func run(shellcode []byte) error {
    // Step 1: apply Stealth first so injection primitives are unhooked
    evasion.ApplyAll(preset.Stealth(), nil)

    // Step 2: do all injection / RWX allocation here
    if err := inject.RunShellcode(shellcode); err != nil {
        return err
    }

    // Step 3: NOW apply Aggressive — ACG and BlockDLLs lock down the process
    // No further RWX allocation is possible after this point
    evasion.ApplyAll(preset.Aggressive(), nil)
    return nil
}
```

### Custom combination

```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/evasion/unhook"
)

// Custom: AMSI + ETW + only the functions we actually call
techniques := []evasion.Technique{
    amsi.ScanBufferPatch(),
    etw.All(),
    unhook.Classic("NtAllocateVirtualMemory"),
    unhook.Classic("NtCreateThreadEx"),
}
evasion.ApplyAll(techniques, nil)
```

---

## Decision Matrix

| Scenario | Preset | Rationale |
|----------|--------|-----------|
| Script dropper, no injection | Minimal | AMSI+ETW is all that matters for script scanning |
| Reflective loader executing shellcode | Stealth | Needs unhooked NtAllocateVirtualMemory + NtCreateThreadEx |
| Process injection via APC | Stealth | Needs NtQueueApcThread unhooked |
| Thread hijacking | Stealth | Needs NtSetContextThread + NtResumeThread unhooked |
| Long-dwell implant, post-injection | Aggressive | ACG+BlockDLLs harden against EDR counter-injection |
| Red team final objective, assumed-breach | Aggressive | Maximum evasion depth warranted |
| EDR with heavy hook coverage suspected | Aggressive (Full unhook) | Full .text replacement vs. targeted 5-byte patches |
| Constrained environment, compatibility required | Minimal | No disk reads, no irreversible changes |
| Custom: known hook set | Manual composition | Build from individual techniques for minimal footprint |
