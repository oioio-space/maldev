---
package: github.com/oioio-space/maldev/recon/dllhijack
last_reviewed: 2026-05-04
reflects_commit: 7a8c466
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
        SVC["ScanServices<br>SCM enum + IAT walk"]
        PROC["ScanProcesses<br>Toolhelp32 + loaded modules"]
        TASK["ScanScheduledTasks<br>COM ITaskService"]
        AE["ScanAutoElevate<br>System32 manifest filter"]
    end
    SVC --> ALL["ScanAll returns Opportunity slice"]
    PROC --> ALL
    TASK --> ALL
    AE --> ALL
    ALL --> RANK["Rank<br>integrity-gain score"]
    RANK --> VAL["Validate<br>drop canary + trigger"]
    VAL --> CONF["ValidationResult<br>confirmed hijack"]
```

## API Reference

### `type ScanOpts struct { Opener stealthopen.Opener }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanOpts)

Optional knob accepted by every scanner. Setting `Opener` routes
PE file reads through a [`stealthopen.Opener`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen)
(e.g. NTFS Object-ID open) so path-keyed EDR file hooks see no
scan. Zero value is plain `os.Open`.

**Platform:** cross-platform.

### `type Kind int`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Kind)

Victim surface enum: `KindService`, `KindProcess`,
`KindScheduledTask`, `KindAutoElevate`. `String()` returns the
lowercase label.

**Platform:** cross-platform.

### `type Opportunity struct { ... }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Opportunity)

One discovered hijack candidate. Fields: `Kind`, `ID`,
`DisplayName`, `BinaryPath`, `HijackedDLL`, `HijackedPath`
(writable target), `ResolvedDLL` (current legitimate path),
`SearchDir`, `Writable`, `Reason`, `AutoElevate`,
`IntegrityGain`, `Score` (filled by `Rank`).

**Platform:** cross-platform.

### `func ScanAll(opts ...ScanOpts) ([]Opportunity, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanAll)

Aggregates `ScanServices` + `ScanProcesses` +
`ScanScheduledTasks` + `ScanAutoElevate`. Pass at most one
`ScanOpts`.

**Returns:** flat `[]Opportunity` (un-ranked); first non-nil
scanner error.

**OPSEC:** SCM enumeration, Toolhelp32 process walk, ITaskService
COM enumeration — all routine reconnaissance APIs, but each
emits ETW + Sysmon events at high volume. Stealth-Opener swap
shifts file-read indicators from path-based to ObjectID-based.

**Required privileges:** unprivileged for `ScanProcesses`/
`ScanAutoElevate`; some service entries return `ACCESS_DENIED`
without admin.

**Platform:** Windows-only (stub on other OSes returns nil).

### `func ScanServices(opts ...ScanOpts) ([]Opportunity, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanServices)

Walks SCM-registered services + their PE imports.

**Returns:** opportunities pointing at SYSTEM-context binaries.

**Required privileges:** non-admin sees only services with
`SERVICE_QUERY_CONFIG` granted; admin sees the full list.

**Platform:** Windows-only.

### `func ScanProcesses(opts ...ScanOpts) ([]Opportunity, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanProcesses)

Toolhelp32 process snapshot + per-process IAT walk via the PE
on disk.

**Platform:** Windows-only.

### `func ScanScheduledTasks(opts ...ScanOpts) ([]Opportunity, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanScheduledTasks)

ITaskService COM enumeration of registered tasks + IAT walk.

**Platform:** Windows-only.

### `func ScanAutoElevate(opts ...ScanOpts) ([]Opportunity, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ScanAutoElevate)

Walks `%WinDir%\System32` for `.exe` whose manifest carries
`autoElevate=true` (fodhelper, sdclt, eventvwr, …); each hit
becomes a UAC-bypass candidate.

**Side effects:** reads every PE under System32 — Defender file-IO
heuristics may flag the bulk read pattern.

**Platform:** Windows-only.

### `func Rank(opps []Opportunity) []Opportunity`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Rank)

In-place scores every Opportunity (+200 AutoElevate, +100
IntegrityGain, +50 Service, +20 ScheduledTask, +10
AutoElevate-base, +5 Process) and returns a new slice sorted by
descending `Score`. Ties broken by `BinaryPath` then
`HijackedDLL`.

**Returns:** copy of `opps`, sorted; original slice
score-mutated.

**Platform:** cross-platform.

### `func Validate(opp Opportunity, canaryDLL []byte, opts ValidateOpts) (*ValidationResult, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#Validate)

Drops `canaryDLL` at `opp.HijackedPath`, triggers the victim
(restart service / run task), and polls `opts.MarkerDir` for a
file matching `opts.MarkerGlob`. Cleanup is unconditional.

**Parameters:** `opp` — target Opportunity (`KindProcess` is
unsupported and returns an error); `canaryDLL` — bytes of a DLL
whose `DllMain` writes the marker file; `opts` — see
`ValidateOpts`.

**Returns:** `*ValidationResult` describing each phase
(`Dropped`, `Triggered`, `Confirmed`, `MarkerPath`,
`MarkerContents`, `TriggerAt`, `ConfirmedAt`, `CleanedUp`,
`Errors`); error only on validation-fatal failures (missing
`HijackedPath`, empty canary, drop / trigger failure).

**Side effects:** writes a DLL to disk, restarts the target
service or invokes the scheduled task, removes both the canary
and any new markers on exit.

**OPSEC:** loud — file write + service restart is high-fidelity
EDR telemetry. Run only on dedicated test boxes; never on a
production target before first-run validation.

**Required privileges:** write to the hijack path (admin for
`%WinDir%\System32` siblings; SCM `SERVICE_STOP`/`SERVICE_START`
to restart services).

**Platform:** Windows-only.

### `type ValidateOpts struct { MarkerGlob, MarkerDir string; Timeout, PollInterval time.Duration; KeepCanary bool }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ValidateOpts)

Knobs for `Validate`. Zero value polls
`%ProgramData%\maldev-canary-*.marker` for 15 s every 200 ms
and removes the canary DLL on exit.

**Platform:** Windows-only.

### `type ValidationResult struct { ... }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ValidationResult)

Phase-by-phase outcome of `Validate`: `Dropped`, `Triggered`,
`Confirmed`, `MarkerPath`, `MarkerContents`, `TriggerAt`,
`ConfirmedAt`, `CleanedUp`, `Errors`.

**Platform:** Windows-only.

### `func SearchOrder(exeDir string) []string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#SearchOrder)

Returns the directories the loader walks for a DLL load from
`exeDir`: app dir → System32 → SysWOW64 → Windows. Assumes
SafeDllSearchMode is enabled (default since XP SP1).

**Platform:** Windows-only (stub returns nil elsewhere).

### `func HijackPath(exeDir, dllName string) (hijackDir, resolvedDir string)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#HijackPath)

Computes the hijack candidate for one (exe, DLL) pair. Skips
KnownDLLs (registry-listed, loader bypasses search). Returns
the first writable directory earlier than the resolved
location.

**Returns:** `(hijackDir, resolvedDir)` — both empty when no
hijack is possible.

**Platform:** Windows-only (stub returns empty pair elsewhere).

### `func IsAutoElevate(peBytes []byte) bool`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#IsAutoElevate)

Byte-level scan of the PE for an embedded manifest with
`<autoElevate>true</autoElevate>` or `autoElevate="true"`. No
XML parser.

**Returns:** `true` when the marker is present.

**Platform:** cross-platform — operates on bytes.

### `func ParseBinaryPath(cmdline string) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack#ParseBinaryPath)

Extracts the executable path from an SCM-style
`BinaryPathName` (handles quoted / unquoted forms with
trailing args).

**Returns:** the path or empty string on parse failure.

**Platform:** cross-platform.

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
    fmt.Printf("UAC bypass: drop %s in %s\n", o.ResolvedDLL, o.HijackedPath)
}
```

### Advanced — validate before deploying

```go
canary, _ := os.ReadFile("canary.dll") // emits %ProgramData%\maldev-canary-*.marker on load

res, err := dllhijack.Validate(opp, canary, dllhijack.ValidateOpts{
    Timeout: 30 * time.Second,
})
if err == nil && res.Triggered {
    // confirmed; safe to drop the real payload
}
```

The caller must invoke the victim binary out-of-band (e.g.
restart the service that owns the hijack target) so the
canary DLL is actually loaded and emits its marker.

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
