---
last_reviewed: 2026-04-27
reflects_commit: 3fd7622
---

# Evasion techniques

[← maldev README](../../../README.md) · [docs/index](../../index.md)

In-process and on-host primitives that **disable, blind, restore, or
hide** the defensive surface so subsequent injection / collection /
post-ex code runs unobserved. Every package in this area accepts a
`*wsyscall.Caller` and composes via `evasion.ApplyAll` or
`evasion/preset` recipes.

## TL;DR

```mermaid
flowchart LR
    A[unhook ntdll] --> B[patch AMSI]
    B --> C[patch ETW]
    C --> D[harden process<br>ACG / BlockDLLs / CET]
    D --> E[sleepmask between callbacks]
```

The "operator's first 100 ms" — restore clean syscall stubs, blind the
two main monitoring channels, harden the process against future hooks,
mask payload memory during sleep.

## Packages

| Package | Tech page | Detection | One-liner |
|---|---|---|---|
| [`evasion/acg`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/acg) | [acg-blockdlls.md](acg-blockdlls.md) | quiet | Arbitrary Code Guard — block dynamic-code allocation in own process |
| [`evasion/amsi`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi) | [amsi-bypass.md](amsi-bypass.md) | noisy | Patch `AmsiScanBuffer` / `AmsiOpenSession` for "always clean" verdicts |
| [`evasion/blockdlls`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/blockdlls) | [acg-blockdlls.md](acg-blockdlls.md) | quiet | Microsoft-only DLL signature requirement |
| [`evasion/callstack`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack) | [callstack-spoof.md](callstack-spoof.md) | quiet | Call-stack spoof primitives — fake return addresses for syscalls |
| [`evasion/cet`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/cet) | [cet.md](cet.md) | noisy | Intel CET shadow-stack opt-out + ENDBR64 marker for APC paths |
| [`evasion/etw`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw) | [etw-patching.md](etw-patching.md) | moderate | Patch ntdll ETW write helpers with `xor rax,rax; ret` |
| [`evasion/hook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook) | [inline-hook.md](inline-hook.md) | quiet | Install your own inline hooks (probe, group, remote, bridge) |
| [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) | [inline-hook.md](inline-hook.md) | quiet | IPC bridge — out-of-process hook controller |
| [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) | [inline-hook.md](inline-hook.md) | quiet | x64 trampoline / prologue-steal generator |
| [`evasion/kcallback`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback) | [kernel-callback-removal.md](kernel-callback-removal.md) | very-noisy | Enumerate / remove kernel callback registrations (BYOVD-pluggable) |
| [`evasion/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset) | [preset.md](preset.md) | varies | Curated `Minimal` / `Stealth` / `Aggressive` Technique bundles |
| [`evasion/sleepmask`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask) | [sleep-mask.md](sleep-mask.md) | quiet | Encrypt payload memory during sleep with EKKO / Foliage / Inline strategies |
| [`evasion/stealthopen`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen) | [stealthopen.md](stealthopen.md) | quiet | NTFS Object-ID file access — bypass path-based EDR file hooks |
| [`evasion/unhook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook) | [ntdll-unhooking.md](ntdll-unhooking.md) | noisy | Restore `ntdll.dll` syscall stubs from disk or fresh child process |

Cross-categorised pages currently living here (packages live elsewhere):

| Page | Actual package | Note |
|---|---|---|
| [../recon/anti-analysis.md](../recon/anti-analysis.md) | `recon/antidebug`, `recon/antivm` | moved to recon/ — debugger + VM detection |
| [../kernel/byovd-rtcore64.md](../kernel/byovd-rtcore64.md) | `kernel/driver/rtcore64` | moved to kernel/ — BYOVD primitive used by kcallback + lsassdump |
| [../recon/dll-hijack.md](../recon/dll-hijack.md) | `recon/dllhijack` | moved to recon/ — discovery is recon, exploitation is evasion |
| [../process/fakecmd.md](../process/fakecmd.md) | `process/tamper/fakecmd` | PEB CommandLine spoof — moved to process/ |
| [../process/hideprocess.md](../process/hideprocess.md) | `process/tamper/hideprocess` | NtQSI patch to hide PIDs — moved to process/ |
| [../recon/hw-breakpoints.md](../recon/hw-breakpoints.md) | `recon/hwbp` | moved to recon/ — DR0–DR7 inspection |
| [../process/phant0m.md](../process/phant0m.md) | `process/tamper/phant0m` | EventLog svchost thread kill — moved to process/ |
| [ppid-spoofing.md](ppid-spoofing.md) | `c2/shell` (PPIDSpoofer) | spawn-time parent PID spoof |
| [../recon/sandbox.md](../recon/sandbox.md) | `recon/sandbox` | moved to recon/ — multi-factor orchestrator |
| [../recon/timing.md](../recon/timing.md) | `recon/timing` | moved to recon/ — time-based evasion |

## Quick decision tree

| You want to… | Use |
|---|---|
| …blind PowerShell / .NET AMSI scanning | [`amsi.PatchAll`](amsi-bypass.md) |
| …blind ETW for the current process | [`etw.PatchAll`](etw-patching.md) |
| …restore EDR-hooked syscall stubs before patching | [`unhook.FullUnhook`](ntdll-unhooking.md) or [`unhook.CommonClassic`](ntdll-unhooking.md) |
| …make memory scanners blind during sleep | [`sleepmask`](sleep-mask.md) |
| …ship a single "do everything sane" recipe | [`preset.Stealth()`](preset.md) |
| …read a sensitive file path without leaving a path-based event | [`stealthopen`](stealthopen.md) |
| …survive Win11+CET-enforced hosts on APC paths | [`cet.Wrap`](cet.md) or [`cet.Disable`](cet.md) |
| …spoof call-stack return addresses for stealth syscalls | [`callstack.SpoofCall`](callstack-spoof.md) |
| …remove a kernel callback (PsSetLoadImageNotifyRoutine etc.) | [`kcallback`](kernel-callback-removal.md) (requires BYOVD reader) |

## MITRE ATT&CK

| T-ID | Name | Packages | D3FEND counter |
|---|---|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | `evasion/sleepmask` | D3-PMA |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | `evasion/callstack`, `evasion/stealthopen` | D3-PSA |
| [T1497](https://attack.mitre.org/techniques/T1497/) | Virtualization/Sandbox Evasion | `recon/sandbox`, `recon/antivm`, `recon/timing` | D3-PSA, D3-PMA |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | `evasion/{amsi,etw,unhook,acg,blockdlls,cet,kcallback,preset}` | D3-PMC, D3-PSA |
| [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | Impair Defenses: Disable Windows Event Logging | `process/tamper/phant0m` | D3-RAPA |
| [T1574.012](https://attack.mitre.org/techniques/T1574/012/) | Hijack Execution Flow: COR_PROFILER | `evasion/hook` (inline hook scaffold) | D3-PMC |
| [T1622](https://attack.mitre.org/techniques/T1622/) | Debugger Evasion | `recon/antidebug`, `recon/hwbp` | D3-PSA |

## See also

- [Operator path: 30-minute implant](../../by-role/operator.md#30-minute-path-a-working-implant)
- [Researcher path: Caller pattern](../../by-role/researcher.md#the-caller-pattern)
- [Detection eng path: AMSI / ETW / unhook artifacts](../../by-role/detection-eng.md)
- [`docs/evasion.md`](../../evasion.md) — flat API reference (legacy; will be regenerated by `cmd/docgen`)
