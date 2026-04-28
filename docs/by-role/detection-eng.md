---
last_reviewed: 2026-04-27
reflects_commit: 2df4ee4
---

# For detection engineers (blue team)

[← maldev README](../../README.md) · [docs/index](../index.md)

Every technique here has been **measured against EDR / Defender / event
logs**. This page lists the artifacts each leaves behind, where to look,
and which D3FEND counter-technique applies. Use it to write detections,
plan red-team exercises, or harden endpoints.

## TL;DR

> [!TIP]
> If your goal is "what should I monitor first", focus on the **noisy** /
> **very-noisy** rows in the Detection Difficulty table below. Those are
> the techniques where the trade-off is worst for the attacker — easiest
> wins for the defender.

## Detection difficulty matrix

Every package is annotated with a [`Detection level`](../conventions/documentation.md#per-package-docs-docgo)
field in its `doc.go`. Buckets:

| Bucket | Operator can hide it? | Defender notes |
|---|---|---|
| `very-quiet` | Yes — zero artifacts above noise | In-process, common syscalls only. Detection requires per-process behavioural ML. |
| `quiet` | Mostly | Minimal trace, no event log. Maybe one transient registry/file artifact. |
| `moderate` | Sometimes | Distinguishable syscall pattern; volume-based detection works. |
| `noisy` | No without effort | ETW provider, event log entry, cross-process activity. |
| `very-noisy` | No | Signature-detected by Defender or EDR; specific API hooks watched. |

`cmd/docgen` (Phase 3 of the doc refactor) produces a flat table of all
public packages by detection level. Until then, see each package's
`doc.go`.

## Per-area detection guidance

### Syscalls — `win/syscall`

| Stance | Telemetry left | Detection vector |
|---|---|---|
| `MethodWinAPI` | Standard CRT call | None — looks like any benign program |
| `MethodNativeAPI` | `ntdll!Nt*` direct call | Frequency-based: a process making 200+ NT calls/sec is unusual |
| `MethodDirect` | `syscall` instruction inside loaded module | EDR call-stack walking detects RIP not in ntdll. **D3-PCM (Process Code Modification)** |
| `MethodIndirect` | `syscall` instruction inside ntdll (jumped to from caller via heap stub) | Hard to detect from user-mode. Heap stub page is RW↔RX-cycled per call — `VirtualProtect` rate may be a heuristic. Kernel-mode ETW (TI events) sees the issuing thread. **D3-PSM (Process Spawn Monitoring)** |
| `MethodIndirectAsm` | Same end-effect as `MethodIndirect` but stub lives in implant `.text` (Go-asm, fixed RVA) | No `VirtualProtect` heuristic. YARA on the asm stub bytes still possible — morph or strip. **D3-PSM** |

> [!NOTE]
> ETW Threat Intelligence provider (Microsoft-Windows-Threat-Intelligence)
> emits `EVENT_TI_NTPROTECT` and `EVENT_TI_NTALLOCATEVIRTUAL` regardless of
> whether the call came from ntdll or a direct syscall instruction.
> Subscribing to TI events is the single best detection investment for
> this area.

### AMSI / ETW patching — `evasion/amsi`, `evasion/etw`

| Artifact | Where |
|---|---|
| 3-byte patch in `amsi.dll!AmsiScanBuffer` (`31 C0 C3`) | Memory scan of `amsi.dll` RX section after process load |
| 4-byte patch in `ntdll.dll!EtwEventWrite{,Ex,Full,String,Transfer}` (`48 33 C0 C3`) | Memory scan of `ntdll.dll` RX |
| `NtProtectVirtualMemory` call switching `RX → RWX → RX` on `amsi`/`ntdll` | ETW TI / EDR call-stack inspection |
| Reduced AMSI scan rate from PowerShell host | PowerShell `Microsoft.PowerShell.AMSI` provider drops to zero |

**Hunt query (KQL pseudo-code):**

```text
DeviceImageLoadEvents
| where FileName == "amsi.dll"
| join DeviceProcessEvents on InitiatingProcessId
| project ProcessName, AmsiBytes = read 3 bytes at AmsiScanBuffer offset
| where AmsiBytes != original_bytes
```

**D3FEND counters:** D3-PSM (Process Spawn Monitoring), D3-PMC (Process
Module Code Manipulation Detection). Hardening: **AMSI Provider DLL pinned
+ signed**.

### ntdll unhooking — `evasion/unhook`

| Artifact | Where |
|---|---|
| `NtCreateSection`/`NtMapViewOfSection` call sequence opening a fresh `ntdll.dll` from disk | Process memory access pattern |
| Original syscall stubs `4C 8B D1 B8 …` re-written over EDR-hooked ones | RX-page scan; compares running ntdll bytes against on-disk |

**Hunt:** memory-scan ntdll RX section for stubs that diverge from on-disk
bytes after the EDR's hook installer ran.

### Sleep masking — `evasion/sleepmask`

| Artifact | Where |
|---|---|
| Process thread stack XOR-encrypted during sleep | Kernel thread-stack walking detects high-entropy stack regions |
| ROP chain (`StrategyEkko`) | EDR call-stack heuristics — return addresses on stack don't match valid call sites |
| Timer queue API spike (`StrategyTimerQueue`) | `RtlCreateTimer`, `WaitForSingleObject` patterns |

**D3FEND:** D3-PSEP (Process Self-Modification). Hardening: kernel
thread-stack walking on a 5–30 second cadence.

### Injection — `inject`

Per-method telemetry (excerpt; full table per technique page):

| Method | ETW TI events | Detection difficulty |
|---|---|---|
| `MethodCreateThread` | `EVENT_TI_NTCREATETHREAD` | very-noisy |
| `MethodCreateRemoteThread` | `EVENT_TI_NTCREATETHREADEX` cross-process | very-noisy |
| `MethodEarlyBirdAPC` | `EVENT_TI_NTQUEUEAPCTHREAD` + suspended process | noisy |
| `MethodSectionMap` | `NtCreateSection` + `NtMapViewOfSection(EXECUTE)` | quiet |
| `MethodPhantomDLL` | `NtCreateSection(SEC_IMAGE)` from a non-existent on-disk path | very-quiet |
| `MethodKernelCallbackTable` | `KernelCallbackTable` write to PEB | very-quiet (rare in legit) |
| `MethodModuleStomp` | RX-page write to a loaded module | quiet |
| `MethodThreadHijack` | `NtSuspendThread` + `NtSetContextThread` cross-process | noisy |

See [docs/techniques/injection/](../techniques/injection/README.md) for the
per-method artifact list.

### Credential access — `credentials/*`

| Package | Telemetry |
|---|---|
| `credentials/lsassdump` | `OpenProcess(PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION, …, lsass.exe PID)` from non-system context |
| `credentials/sekurlsa` | None standalone — operates on a dump file |
| `credentials/samdump` | Live mode: `reg.exe save HKLM\SAM …`. Offline: file read of registry hive |
| `credentials/goldenticket` | `LsaCallAuthenticationPackage(KerbSubmitTicketMessage, …)` — visible in TI provider |

**Hardening:** Credential Guard (LSASS in VTL1) defeats `lsassdump`
write/read; **Protected Process Light** (PPL) requires the BYOVD
unprotect path which is itself detectable via signed-driver provenance
events (Sysmon Event 6).

### Persistence — `persistence/*`

| Mechanism | Event log | Sysmon equivalent |
|---|---|---|
| Registry Run/RunOnce | none built-in | Event 12 / 13 (registry write) |
| Startup folder LNK | none | Event 11 (file create) |
| Scheduled Task (COM) | TaskScheduler-Operational 4698 | Event 4698 |
| Windows Service install | System log 7045 | Event 4697 |
| Local account creation | Security 4720 | — |

**D3FEND:** D3-RAPA (Resource Access Pattern Analysis), D3-PFV
(Persistent File Volume Inspection).

### Cleanup — `cleanup/*`

The most-overlooked area for blue. Cleanup deliberately **removes**
artifacts the rest of the chain would have left.

| Technique | What it erases | What it leaves |
|---|---|---|
| `cleanup/selfdelete` | Implant binary on disk | NTFS `$Bitmap` change, `$LogFile` entry, ADS rename log |
| `cleanup/timestomp` | File timestamp recency | `$STANDARD_INFORMATION` updated; `$FILE_NAME` MFT timestamps unchanged (forensic disparity) |
| `cleanup/wipe` (`memory.WipeAndFree`) | Sensitive bytes in process memory | `NtFreeVirtualMemory` call |
| `cleanup/ads` | Stream existence | NTFS `$Data:streamname` MFT entry remains visible to MFT-aware tooling |
| `cleanup/bsod` | All in-memory state | Crash dump (if configured) |

**Forensic detection:** MFT inconsistency between `$STANDARD_INFORMATION`
and `$FILE_NAME` timestamps is the canonical timestomp tell.

## Hardening recommendations

1. **Enable ETW Threat Intelligence provider** and ship its events to your
   SIEM. Single highest-leverage signal for this entire library.
2. **Credential Guard** + LSASS in PPL (kernel `RunAsPPL=1`).
3. **WDAC / AppLocker** with publisher allow-list — defeats Donut-loaded
   PE shellcode if PE policy applies (depends on AMSI integration).
4. **Sysmon** with [SwiftOnSecurity baseline](https://github.com/SwiftOnSecurity/sysmon-config)
   covers most artifact categories above.
5. **Driver block-list policy** — Microsoft's
   [vulnerable driver block list](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
   includes RTCore64; enable it.

## Hunt repository (placeholder)

> [!NOTE]
> A `docs/hunts/` directory with Sigma rules and KQL queries per
> technique is on the Phase 5 roadmap. Until then, the per-technique
> "OPSEC & Detection" sections (mandatory by
> [doc-conventions](../conventions/documentation.md)) carry the
> hunt-relevant artefacts.

## Where to next

- [Researcher path](researcher.md) — same techniques explained from the
  attacker design angle.
- [Operator path](operator.md) — see how the chain composes; useful for
  red-team / purple-team coordination.
- [MITRE map](../mitre.md) — full ATT&CK / D3FEND reconciliation.
- [docs/techniques/](../techniques/) — drill into any specific
  technique.
