---
package: github.com/oioio-space/maldev/persistence/registry
last_reviewed: 2026-04-27
reflects_commit: f8b1a51
---

# Registry Run / RunOnce persistence

[← persistence index](README.md) · [docs/index](../../index.md)

## TL;DR

Write the implant's path to one of the four canonical Run /
RunOnce registry keys (HKCU + HKLM, persistent + one-shot).
Windows launches every value at user logon. HKCU does not need
admin; HKLM does. Implements [`persistence.Mechanism`](../../../persistence)
for redundant composition.

## Primer

Windows reads four registry keys at logon and launches every
value as a process command-line. This is one of the oldest and
most documented persistence techniques — and one of the most
monitored. Its appeal is the trivial install (single
`RegSetValueEx`) and the no-admin HKCU path: even a
limited-token implant can self-restart after every reboot.

`Run` keys persist across reboots; `RunOnce` keys self-delete
after firing once — useful for first-boot bootstrappers that
hand off to a more durable mechanism and then vanish.

## How It Works

```mermaid
sequenceDiagram
    participant Impl as Implant
    participant Reg as HKCU\…\Run
    participant Logon as User logon
    participant Bin as Implant binary

    Impl->>Reg: RegSetValueEx("IntelGraphicsUpdate",<br/>"C:\…\winupdate.exe")
    Note over Logon: Reboot / log off + log on
    Logon->>Reg: RegEnumValue
    Reg-->>Logon: each Run value
    Logon->>Bin: CreateProcess(value as cmdline)
```

Registry paths:

| Hive | Key | Behaviour | Admin? |
|---|---|---|---|
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Run` | persistent, per-user | no |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\RunOnce` | one-shot, per-user | no |
| HKLM | `Software\Microsoft\Windows\CurrentVersion\Run` | persistent, machine-wide | yes |
| HKLM | `Software\Microsoft\Windows\CurrentVersion\RunOnce` | one-shot, machine-wide | yes |

`RunOnce` self-cleanup happens after launch *succeeds* — values
where the binary is missing or fails to launch stay in the
registry, which is itself a forensic tell.

## API Reference

### `type Hive int` / `type KeyType int`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#Hive)

| Constant | Maps to |
|---|---|
| `HiveCurrentUser` | `HKEY_CURRENT_USER` |
| `HiveLocalMachine` | `HKEY_LOCAL_MACHINE` |
| `KeyRun` | `…\CurrentVersion\Run` |
| `KeyRunOnce` | `…\CurrentVersion\RunOnce` |

### Functions

| Symbol | Description |
|---|---|
| [`Set(hive, keyType, name, value)`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#Set) | Write the value; create the key if missing |
| [`Get(hive, keyType, name)`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#Get) | Read a single value |
| [`Delete(hive, keyType, name)`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#Delete) | Remove the value (idempotent) |
| [`Exists(hive, keyType, name)`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#Exists) | Cheap presence probe |
| [`RunKey(hive, keyType, name, value) *RunKeyMechanism`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry#RunKey) | `Mechanism` adapter for `persistence.InstallAll` |

### Sentinel errors

| Error | Trigger |
|---|---|
| `ErrNotFound` | `Get` / `Exists` on a value that doesn't exist |

## Examples

### Simple — HKCU install + remove

```go
import "github.com/oioio-space/maldev/persistence/registry"

_ = registry.Set(registry.HiveCurrentUser, registry.KeyRun,
    "IntelGraphicsUpdate", `C:\Users\Public\winupdate.exe`)
defer registry.Delete(registry.HiveCurrentUser, registry.KeyRun,
    "IntelGraphicsUpdate")
```

### Composed — Mechanism + idempotent install

```go
m := registry.RunKey(registry.HiveCurrentUser, registry.KeyRun,
    "IntelGraphicsUpdate", `C:\Users\Public\winupdate.exe`)

if exists, _ := registry.Exists(registry.HiveCurrentUser,
    registry.KeyRun, "IntelGraphicsUpdate"); !exists {
    _ = m.Install()
}
```

### Advanced — hive selection + RunOnce bootstrap

Pick HKLM when the implant has admin, otherwise fall back to
HKCU; pair with a `RunOnce` bootstrap that hands off to a
service.

```go
import (
    "github.com/oioio-space/maldev/persistence/registry"
    "github.com/oioio-space/maldev/win/privilege"
)

const (
    name    = "IntelGraphicsCompat"
    payload = `C:\Users\Public\Intel\stage1.exe`
)

hive := registry.HiveCurrentUser
if admin, elevated, _ := privilege.IsAdmin(); admin && elevated {
    hive = registry.HiveLocalMachine
}

if exists, _ := registry.Exists(hive, registry.KeyRun, name); exists {
    return
}
_ = registry.Set(hive, registry.KeyRun, name, payload)
_ = registry.Set(hive, registry.KeyRunOnce, name+"_bootstrap",
    payload+" --bootstrap")
```

See [`ExampleSet`](../../../persistence/registry/registry_example_test.go)
+ [`ExampleRunKeyMechanism`](../../../persistence/registry/registry_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Sysmon Event 13 (registry value set) under `…\Run` | High-fidelity rule on every mature EDR; HKCU\…\Run draws less default coverage than HKLM\…\Run |
| `autoruns.exe` Run-key listing | Sysinternals Autoruns is universal IR triage |
| Defender ASR rule "Block credential stealing" doesn't apply, but ASR "Block persistence through WMI event subscription" detects siblings | EDR rule library |
| Value name keyed against known IOC list (`payload`, `update`, `svchost`) | Naive YARA-style rules on registry value contents |
| Binary path under user-writable directories (`%TEMP%`, `%APPDATA%\Local\Temp`) | Defender heuristic — legitimate Run values target installed-software paths |
| `RegEnumValue` / `RegOpenKeyEx` from non-explorer.exe | EDR API telemetry; rare unless tooling explicitly polls Run keys |

**D3FEND counters:**

- [D3-SICA](https://d3fend.mitre.org/technique/d3f:SystemConfigurationDatabaseAnalysis/)
  — registry change auditing.
- [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/)
  — Run-key value content inspection.

**Hardening for the operator:**

- Prefer HKCU when current-user scope is sufficient — lower
  default coverage and no admin prompt.
- Pick value names that mimic real Run-key values (Adobe
  Updater, Intel Graphics, Microsoft OneDrive) — pair the
  binary path with a name + path that match.
- Drop the binary in `%PROGRAMDATA%\Microsoft\…\` rather than
  `%TEMP%`.
- Pair with another mechanism via `persistence.InstallAll` so
  loss of the Run key (`autoruns.exe -e -accepteula -c` cleanup)
  does not lose persistence.
- For one-shot bootstrappers, use `RunOnce` so the registry
  evidence vanishes on first boot.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | full — Run / RunOnce both supported | D3-SICA, D3-SEA |

## Limitations

- **Logon trigger only.** Run keys fire at *user logon*, not at
  boot. For pre-logon execution use
  [`persistence/service`](service.md) or
  [`persistence/scheduler`](task-scheduler.md) with a `Boot` /
  `Startup` trigger.
- **HKLM admin requirement.** Without admin the operator is
  HKCU-only.
- **No CWD control.** Windows launches Run-key values via
  `CreateProcess` with the user's profile as CWD; binaries
  that depend on a specific CWD must encode it via `cd /d`
  in the value or read it from a config.
- **Value-name collision.** Two implants writing to the same
  value name cause silent overwrite — pick distinctive names.
- **Visible to standard tooling.** `regedit`, `reg query`,
  PowerShell `Get-ItemProperty`, and `autoruns.exe` all
  surface Run-key values. No way to hide a Run-key entry from
  a thorough triage.

## See also

- [`persistence/startup`](startup-folder.md) — sibling logon
  trigger via StartUp folder.
- [`persistence/scheduler`](task-scheduler.md) — sibling
  with broader trigger options (boot, daily, time).
- [`persistence/service`](service.md) — sibling SYSTEM-scope
  persistence with pre-logon boot trigger.
- [`win/privilege`](../syscalls/) — `IsAdmin` for hive
  selection.
- [`crypto`](../crypto/README.md) — encrypt the on-disk
  payload.
- [`cleanup/timestomp`](../cleanup/) — match the binary's
  file timestamps to a trusted neighbour.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
