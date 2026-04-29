---
package: github.com/oioio-space/maldev/recon/folder
last_reviewed: 2026-04-27
reflects_commit: f31fca1
---

# Windows special-folder paths

[← recon index](README.md) · [docs/index](../../index.md)

## TL;DR

Resolve Windows special folder paths (Desktop, AppData,
Startup, Program Files, …) via `SHGetSpecialFolderPathW`. Used
by `persistence/startup` for StartUp-folder paths, by
`credentials/lsassdump` for `%SystemRoot%\System32\ntoskrnl.exe`,
and by any payload that needs a per-user / per-machine
well-known path.

## Primer

Windows uses **CSIDL** (Constant Special ID List) values to
identify well-known folders abstractly. `SHGetSpecialFolderPathW`
takes a CSIDL constant and returns the resolved filesystem path,
handling per-user / per-machine differences and folder
redirection in domain environments transparently.

The function is technically deprecated in favor of
`SHGetKnownFolderPath` (Vista+, KNOWNFOLDERID enum), but the
older API remains widely supported and avoids COM
initialization overhead.

## API Reference

Two paths: the **modern** [GetKnown] (KNOWNFOLDERID, recommended
by Microsoft for new code) and the **legacy** [Get] (CSIDL, kept
for backwards compatibility).

### `GetKnown(rfid *windows.KNOWNFOLDERID, flags uint32) (string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#GetKnown)

Thin wrapper around `golang.org/x/sys/windows.KnownFolderPath` —
that helper already handles the `SHGetKnownFolderPath` HRESULT
contract + `CoTaskMemFree` of the API-allocated `PWSTR`. The
package-local wrapper exists only to wrap the underlying error
in [`ErrKnownFolderNotFound`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#ErrKnownFolderNotFound)
for `errors.Is` discrimination on the caller side.

**Parameters:**
- `rfid` — pointer to one of the `windows.FOLDERID_*` constants
  (e.g. `windows.FOLDERID_RoamingAppData`) or a `windows.KNOWNFOLDERID`
  parsed from a custom GUID (3rd-party Shell extensions).
- `flags` — bitwise OR of any `windows.KF_FLAG_*` bits — typically
  `0` (default), `windows.KF_FLAG_CREATE` (force directory
  creation), `windows.KF_FLAG_DONT_VERIFY` (skip existence check).

**Returns:**
- `string` — resolved path. Not `MAX_PATH`-capped.
- `error` — wraps [`ErrKnownFolderNotFound`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#ErrKnownFolderNotFound)
  via `%w` when Shell32 returns a non-success HRESULT.

**Side effects:** none. `windows.KnownFolderPath` releases the
API-allocated `PWSTR` internally.

**OPSEC:** very-quiet. `SHGetKnownFolderPath` is in every
modern installer / Office app / browser path.

**Required privileges:** `unprivileged`.

**Platform:** `windows` ≥ Vista (KNOWNFOLDERID introduced in Vista).

### `Get(csidl CSIDL, createIfNotExist bool) string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#Get)

Legacy path. Resolves a `CSIDL` constant via
`SHGetSpecialFolderPathW`. Microsoft recommends `GetKnown` for
new code; keep this for callers that already key on CSIDL.

**Parameters:**
- `csidl` — one of the `CSIDL_*` constants.
- `createIfNotExist` — pass `true` to create the folder when
  missing.

**Returns:**
- `string` — resolved path or empty on failure.

**Side effects:** caps at `MAX_PATH` (260 chars).

**OPSEC:** very-quiet. Universal Win32 API.

**Required privileges:** `unprivileged`.

**Platform:** `windows` (all versions).

### Common KNOWNFOLDERID constants

Use any `windows.FOLDERID_*` GUID directly — the catalogue lives
in [`golang.org/x/sys/windows`](https://pkg.go.dev/golang.org/x/sys/windows)
and covers everything from `FOLDERID_Profile` /
`FOLDERID_Desktop` / `FOLDERID_Documents` / `FOLDERID_Downloads`
to per-extension entries that 3rd-party Shell extensions
register. No package-local re-export — saves the maintenance
burden of mirroring upstream.

### Common CSIDL constants (legacy)

`CSIDL_DESKTOP`, `CSIDL_APPDATA`, `CSIDL_LOCAL_APPDATA`,
`CSIDL_COMMON_APPDATA`, `CSIDL_STARTUP`, `CSIDL_COMMON_STARTUP`,
`CSIDL_PROGRAM_FILES`, `CSIDL_PROGRAM_FILESX86`, `CSIDL_SYSTEM`,
`CSIDL_WINDOWS`, `CSIDL_TEMPLATES`.

## Examples

### Simple — modern KNOWNFOLDERID

```go
import (
    "github.com/oioio-space/maldev/recon/folder"
    "golang.org/x/sys/windows"
)

appdata, _   := folder.GetKnown(windows.FOLDERID_RoamingAppData, 0)
downloads, _ := folder.GetKnown(windows.FOLDERID_Downloads, 0)
system, _    := folder.GetKnown(windows.FOLDERID_System, 0)

// Force creation (KFF_CREATE) when staging a per-user drop directory:
stage, _ := folder.GetKnown(windows.FOLDERID_LocalAppData, windows.KF_FLAG_CREATE)
```

### Simple — legacy CSIDL

```go
appdata := folder.Get(folder.CSIDL_APPDATA, false)
startup := folder.Get(folder.CSIDL_STARTUP, false)
system  := folder.Get(folder.CSIDL_SYSTEM, false)
```

### Composed — feed persistence

```go
import (
    "path/filepath"

    "github.com/oioio-space/maldev/recon/folder"
)

implant := filepath.Join(
    folder.Get(folder.CSIDL_LOCAL_APPDATA, false),
    "Microsoft", "OneDrive", "Update", "winupdate.exe",
)
```

### Advanced — resolve ntoskrnl path for kernel-driver work

```go
ntos := filepath.Join(
    folder.Get(folder.CSIDL_SYSTEM, false),
    "ntoskrnl.exe",
)
// feeds credentials/lsassdump.DiscoverProtectionOffset(ntos, opener)
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `SHGetSpecialFolderPathW` calls | Universal Win32 API — invisible |
| Subsequent file writes to resolved paths | EDR file-write telemetry; flag depends on the path |

**D3FEND counters:** none specific — primitive itself is
universally legitimate.

**Hardening:** none — the call is invisible. Hardening is at
the consumer (the writes the path drives).

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | full | — |

## Limitations

- **CSIDL is the legacy path.** Microsoft recommends
  KNOWNFOLDERID for new code. The package now ships both:
  use [`GetKnown`](#getknownrfid-windowsguid-flags-knownfolderflag-string-error)
  for new callers; `Get` stays for backwards compatibility.
  KNOWNFOLDERID also exposes folders the legacy CSIDL set
  cannot resolve (`FOLDERID_Downloads`, third-party Shell
  extensions).
- **`GetKnown` returns API-allocated PWSTR.** The wrapper
  frees it via `CoTaskMemFree` on every call — never returns
  a borrowed buffer the caller must clean up.
- **MAX_PATH cap on `Get` only.** The legacy path truncates
  paths longer than 260 chars (`Get`); `GetKnown` is uncapped.
- **Some virtual folders return empty.** `CSIDL_NETWORK`,
  `CSIDL_PRINTERS`, and similar non-filesystem virtual folders
  return empty strings.
- **Folder redirection is opaque.** Domain-joined hosts with
  redirected user folders return the redirected (network) path,
  not the local cached one — operators relying on local-only
  paths must validate.

## See also

- [`persistence/startup`](../persistence/startup-folder.md) —
  primary consumer (StartUp folder).
- [`credentials/lsassdump`](../credentials/lsassdump.md) —
  consumer (System32 path resolution).
- [`recon/drive`](drive.md) — sibling drive enumeration.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
