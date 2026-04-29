---
package: github.com/oioio-space/maldev/recon/dllhijack
last_reviewed: 2026-04-27
reflects_commit: f31fca1
---

# DLL search-order hijack discovery

[← recon index](README.md) · [docs/index](../../index.md)

## TL;DR

Discover DLL-search-order hijack opportunities across services,
running processes, scheduled tasks, and `autoElevate=true`
binaries. [`ScanAll`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack) returns
`Opportunity` records carrying the writable hijack path + the
legitimate resolved DLL location. [`Validate`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack)
proves the hijack works by dropping a canary; [`Rank`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack)
prioritises by integrity gain.

## Primer

A DLL hijack works when an application loads `xyz.dll` and
Windows resolves the load via the search-order rules — first
the application directory, then `System32`, then `PATH`. If the
operator can drop a `xyz.dll` in a writable directory the
application checks *before* `System32`, the operator's code
runs at the next load.

This package finds those opportunities programmatically:

- **Services** — services running as SYSTEM whose binary path
  is in a writable directory + missing IAT-imported DLL = root
  on next service start.
- **Processes** — live process IATs walked via Toolhelp32; same
  filter.
- **Scheduled tasks** — registered tasks parsed via COM
  ITaskService.
- **AutoElevate** — System32 `.exe` whose manifest carries
  `autoElevate=true` (fodhelper, sdclt, eventvwr, …) — these
  silently elevate without UAC prompt; a hijack here is a
  textbook UAC bypass.

`KnownDLLs` (HKLM\…\Session Manager\KnownDLLs) are excluded —
those are early-load-mapped from `\KnownDlls\` and bypass the
search order entirely.

## How It Works

```mermaid
flowchart LR
    subgraph scan [Scanners]
        SVC[ScanServices<br/>SCM enum + IAT walk]
        PROC[ScanProcesses<br/>Toolhelp32 + loaded modules]
        TASK[ScanScheduledTasks<br/>COM ITaskService]
        AE[ScanAutoElevate<br/>System32 manifest filter]
    end
    SVC --> ALL[ScanAll → []Opportunity]
    PROC --> ALL
    TASK --> ALL
    AE --> ALL
    ALL --> RANK[Rank<br/>integrity-gain score]
    RANK --> VAL[Validate<br/>drop canary + trigger]
    VAL --> CONF[ValidationResult<br/>confirmed hijack]
```

## API Reference

| Symbol | Description |
|---|---|
| [`ScanAll(opts...) ([]Opportunity, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanAll) | Aggregate all four scanners |
| `ScanServices`, `ScanProcesses`, `ScanScheduledTasks`, `ScanAutoElevate` | Individual scanners |
| [`Rank(opps) []Opportunity`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Rank) | Score by integrity gain + autoElevate |
| [`Validate(opp, canary, opts) (*ValidationResult, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Validate) | Drop canary, trigger, observe |
| [`SearchOrder(exeDir) []string`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#SearchOrder) | DLL search-order resolution |
| [`HijackPath(exeDir, dllName) (hijackDir, resolvedDir string)`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#HijackPath) | First writable dir < first legitimate dir |
| [`IsAutoElevate(peBytes) bool`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#IsAutoElevate) | Manifest probe |

`Opportunity` carries: `Kind`, `ID`, `DisplayName`, `Binary`,
`MissingDLL`, `HijackedPath`, `ResolvedDLL`, `IntegrityGain`,
`AutoElevate`.

## Examples

### Simple — list ranked opportunities

```go
import "github.com/oioio-space/maldev/recon/dllhijack"

opps, _ := dllhijack.ScanAll()
for _, o := range dllhijack.Rank(opps)[:5] {
    fmt.Printf("%s %s → %s\n", o.Kind, o.DisplayName, o.HijackedPath)
}
```

### Composed — UAC-bypass scan only

```go
ae, _ := dllhijack.ScanAutoElevate()
for _, o := range ae {
    fmt.Printf("UAC bypass: drop %s in %s\n", o.MissingDLL, o.HijackedPath)
}
```

### Advanced — validate before deploying

```go
canary, _ := os.ReadFile("canary.dll") // emits a marker file on load

res, err := dllhijack.Validate(opp, canary, dllhijack.ValidateOpts{
    TriggerFunc: func() error { /* invoke the victim */ return nil },
    Timeout:     30 * time.Second,
})
if err == nil && res.Triggered {
    // confirmed; safe to drop the real payload
}
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Write to service directory by non-installer process | EDR file-write telemetry — high-fidelity |
| New DLL in `%PROGRAMFILES%\…` written by user-context process | Defender ASR rule |
| DLL load from non-System32 path with System32 binary name | EDR module-load rule |
| AutoElevate exe spawning child from unusual path | Defender for Endpoint MsSense flags |
| Sysmon Event 7 (image loaded) for unsigned DLL in System32-adjacent path | Universal high-fidelity |

**D3FEND counters:**

- [D3-EAL](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/)
  — strict allowlisting catches unsigned DLLs.
- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/)
  — DLL signature verification.

**Hardening for the operator:**

- Drop the hijack DLL with a Microsoft Authenticode signature
  via [`pe/cert.Copy`](../pe/certificate-theft.md).
- Match `VERSIONINFO` to the legitimate DLL via
  [`pe/masquerade`](../pe/masquerade.md).
- Validate before deploying — `Validate` runs the canary in
  isolation, no implant exposure.
- Prefer `ScanAutoElevate` results: UAC bypass is the highest
  integrity-gain category.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Hijack Execution Flow: DLL Search Order Hijacking | full | D3-EAL, D3-FCA |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism: Bypass UAC | partial — autoElevate hijacks | D3-EAL |

## Limitations

- **Static IAT only by default.** Runtime `LoadLibrary` calls
  not in the IAT are missed unless `ScanProcesses` happens to
  catch them via Toolhelp32.
- **Validate may detonate.** `Validate` actually runs the
  canary in the target's context — operators must understand
  the side-effects of triggering the victim.
- **Admin scans.** `ScanServices` enumerates SCM-registered
  services; some entries return ACCESS_DENIED without admin.
- **AutoElevate fragility.** Microsoft has been silently
  hardening autoElevate binaries — the canonical fodhelper
  bypass is patched on Win11; verify per build.

## See also

- [`pe/dllproxy`](../pe/dll-proxy.md) — pure-Go forwarder DLL emitter; the natural payload generator for the Opportunities discovered here.
- [`pe/imports`](../pe/imports.md) — sibling import-table walker.
- [`pe/cert`](../pe/certificate-theft.md) — sign the hijack DLL.
- [`pe/masquerade`](../pe/masquerade.md) — clone target DLL identity.
- [`persistence/service`](../persistence/service.md) —
  alternative SYSTEM persistence.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
