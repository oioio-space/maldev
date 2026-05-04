---
package: github.com/oioio-space/maldev/persistence/startup
last_reviewed: 2026-05-04
reflects_commit: f774f7e
---

# StartUp folder persistence

[← persistence index](README.md) · [docs/index](../../index.md)

## TL;DR

Drop a `.lnk` shortcut into the user or machine StartUp folder.
Windows Shell launches every shortcut it finds at user logon. No
admin needed for user-scope; admin for machine-wide. Implements
[`persistence.Mechanism`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence). Sibling to
[`persistence/registry`](registry.md) — pair them for
redundancy.

## Primer

The StartUp folder is the GUI-era equivalent of Run keys.
Windows Shell scans two well-known directories at logon and
launches every shortcut it finds:

- **User**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- **Machine**: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

Once-popular as an "easy" persistence path, it's now well-known
to defensive tooling — but the user folder still sees less
default scrutiny than HKLM\…\Run on most stacks. The package
wraps [`persistence/lnk`](lnk.md) (LNK creation primitive) with
the right paths and a `Mechanism` adapter.

## How It Works

```mermaid
sequenceDiagram
    participant Impl as "Implant"
    participant Lnk as "persistence/lnk"
    participant FS as "%APPDATA%\…\Startup"
    participant Logon as "User logon"
    participant Shell as "Windows Shell"

    Impl->>Lnk: New().SetTargetPath(payload).Save(<dir>\Update.lnk)
    Lnk->>FS: write .lnk
    Note over Logon: Reboot / log off + log on
    Shell->>FS: enumerate Startup folder
    FS-->>Shell: Update.lnk (target = payload)
    Shell->>Impl: CreateProcess(payload)
```

Per-user paths can be discovered via `SHGetKnownFolderPath` /
`%APPDATA%`; the package's `UserDir` / `MachineDir` helpers
encapsulate that.

## API Reference

`name` arguments throughout this package are the LNK's basename
*without* the `.lnk` suffix — every function appends it before
hitting disk.

### `UserDir() (string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#UserDir)

`SHGetKnownFolderPath(FOLDERID_Startup)` — typically
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp`.

**Returns:** absolute path; wrapped error from
`folder.GetKnown`.

**Side effects:** none.

**OPSEC:** silent (read-only known-folder query).

**Required privileges:** none.

**Platform:** Windows-only.

### `MachineDir() (string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#MachineDir)

`SHGetKnownFolderPath(FOLDERID_CommonStartup)` — typically
`%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`.

**Returns:** absolute path; wrapped error.

**Side effects:** none.

**OPSEC:** silent.

**Required privileges:** none for resolution; admin to write into
the resolved path.

**Platform:** Windows-only.

### `Install(name, targetPath, args string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#Install)

Resolve [`UserDir`](#userdir-string-error) and drop
`<dir>/<name>.lnk` via
[`lnk.New().SetTargetPath(targetPath).SetArguments(args).Save(...)`](lnk.md#shortcutsavepath-string-error).
Window style is left at the system default (no
`SetWindowStyle`).

**Returns:** error from `UserDir` or `Save`.

**Side effects:** writes one `.lnk`; opens + closes a COM
apartment.

**OPSEC:** path is path-scoped on every mature EDR; the LNK
itself inherits the OPSEC profile of `lnk.Save` (WSH
activation telemetry).

**Required privileges:** none (user-scope folder).

**Platform:** Windows-only.

### `InstallMachine(name, targetPath, args string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#InstallMachine)

Same as `Install` but writes into
[`MachineDir`](#machinedir-string-error). Fires the LNK at every
user logon.

**Returns:** error from `MachineDir` or `Save`.

**Side effects:** writes one `.lnk` under `%ProgramData%`.

**OPSEC:** machine-folder writes draw stricter rules than
user-folder writes — admin involvement adds to the signal.

**Required privileges:** local admin (write on
`%ProgramData%\…\StartUp`).

**Platform:** Windows-only.

### `Remove(name string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#Remove)

`os.Remove` on `<UserDir>/<name>.lnk`.

**Returns:** wrapped `os.Remove` error (includes ENOENT).

**Side effects:** one file unlink.

**OPSEC:** file-deletion event under `%APPDATA%` — pair with
`cleanup`.

**Required privileges:** none (user-scope).

**Platform:** Windows-only.

### `RemoveMachine(name string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#RemoveMachine)

`os.Remove` on `<MachineDir>/<name>.lnk`.

**Side effects:** one file unlink under `%ProgramData%`.

**Required privileges:** local admin.

**Platform:** Windows-only.

### `Exists(name string) bool`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#Exists)

`os.Stat` against the user-scope path. No `ExistsMachine`
counterpart — caller can compose `MachineDir` + `os.Stat`
inline.

**Returns:** true iff `<UserDir>/<name>.lnk` exists and is
stat-able.

**Side effects:** none.

**OPSEC:** silent.

**Required privileges:** none.

**Platform:** Windows-only.

### `Shortcut(name, targetPath, args string) *ShortcutMechanism`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#Shortcut)

Constructor for the `persistence.Mechanism` adapter (duck-typed,
user-scope only).

**Returns:** `*ShortcutMechanism` for use with
`persistence.InstallAll`.

**Side effects:** none until `Install`.

**Platform:** Windows-only.

### `type ShortcutMechanism struct`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup#ShortcutMechanism)

Implements `persistence.Mechanism`:
`Name()` returns `"startup:user"`,
`Install()` delegates to [`Install`](#installname-targetpath-args-string-error),
`Uninstall()` to [`Remove`](#removename-string-error),
`Installed()` to [`Exists`](#existsname-string-bool).

**Platform:** Windows-only.

## Examples

### Simple — user-scope drop

```go
import "github.com/oioio-space/maldev/persistence/startup"

_ = startup.Install("WindowsUpdate",
    `C:\Users\Public\winupdate.exe`,
    "--silent")
defer startup.Remove("WindowsUpdate")
```

### Composed — Mechanism + idempotency

```go
m := startup.Shortcut("WindowsUpdate",
    `C:\Users\Public\winupdate.exe`, "")
if !startup.Exists("WindowsUpdate") {
    _ = m.Install()
}
```

### Advanced — machine-wide install + timestomp

Drop the launcher in the machine folder so the implant runs at
*every* user's logon, then timestomp the resulting LNK so it
blends with surrounding Microsoft files.

```go
import (
    "os"
    "path/filepath"

    "github.com/oioio-space/maldev/cleanup/timestomp"
    "github.com/oioio-space/maldev/persistence/startup"
)

const target = `C:\ProgramData\Microsoft\winupdate.exe`

if err := startup.InstallMachine("WindowsUpdate", target, ""); err != nil {
    panic(err)
}

machineDir, _ := startup.MachineDir()
lnkPath := filepath.Join(machineDir, "WindowsUpdate.lnk")

ref, _ := os.Stat(`C:\Windows\System32\svchost.exe`)
t := ref.ModTime()
_ = timestomp.SetFull(lnkPath, t, t, t)
```

### Pipeline — startup + registry redundancy

Pair a Run-key with the StartUp shortcut so removing one does
not lose persistence.

```go
import (
    "github.com/oioio-space/maldev/persistence"
    "github.com/oioio-space/maldev/persistence/registry"
    "github.com/oioio-space/maldev/persistence/startup"
)

const target = `C:\Users\Public\winupdate.exe`

mechs := []persistence.Mechanism{
    startup.Shortcut("WindowsUpdate", target, ""),
    registry.RunKey(registry.HiveCurrentUser, registry.KeyRun,
        "WindowsUpdateBackup", target),
}
_ = persistence.InstallAll(mechs)
```

See [`ExampleShortcut`](../../../persistence/startup/startup_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| File creation under `%APPDATA%\…\Startup` | Path-scoped EDR rules — high-fidelity even for benign-looking LNKs |
| File creation under `%PROGRAMDATA%\…\StartUp` | Same, with admin involvement adding to the signal |
| `autoruns.exe -lcuser` / `-l` listing | Sysinternals Autoruns surfaces both folders |
| LNK pointing at user-writable / temp paths | Defender heuristic |
| LNK with mismatched icon vs target binary | EDR rule cross-checks `IconLocation` vs `TargetPath` |
| Implant binary lacking signature + Microsoft VERSIONINFO | Pair with [`pe/masquerade`](../pe/masquerade.md) + [`pe/cert`](../pe/certificate-theft.md) |

**D3FEND counters:**

- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/)
  — LNK header inspection.
- [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/)
  — target-binary review.

**Hardening for the operator:**

- Prefer the user folder unless machine-wide is required —
  lower default coverage.
- Match icon + display name to a plausible identity (Notes,
  Update, OneDrive).
- Pair with [`cleanup/timestomp`](../cleanup/) so the LNK's
  MFT timestamps blend with surrounding Microsoft artefacts.
- Pair with [`persistence/registry`](registry.md) for
  redundancy via `persistence.InstallAll`.
- Avoid this technique when the target stack runs strict ASR
  rules ("Block executable content from email client and
  webmail" applies to LNKs delivered via that channel).

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Startup Folder | full — user + machine | D3-FCA |
| [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Shortcut Modification | partial — LNK creation primitive (delegated to `persistence/lnk`) | D3-FCA |

## Limitations

- **Logon-only trigger.** Like Run keys, fires at user logon
  — not at boot.
- **One LNK per name.** Re-installing under the same name
  overwrites the existing shortcut without warning.
- **Windows-only.** No cross-platform stub.
- **Visible to standard triage.** Both folders are universal
  IR triage targets.
- **No service-account context.** LNKs run in the logging-in
  user's session — for SYSTEM-scope persistence use
  [`persistence/service`](service.md).

## See also

- [`persistence/lnk`](lnk.md) — underlying LNK creation
  primitive.
- [`persistence/registry`](registry.md) — sibling logon
  trigger; pair for redundancy.
- [`persistence/scheduler`](task-scheduler.md) — sibling with
  pre-logon (boot / startup) triggers.
- [`pe/masquerade`](../pe/masquerade.md) — clone identity for
  the launched binary.
- [`cleanup/timestomp`](../cleanup/) — align LNK timestamps.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
