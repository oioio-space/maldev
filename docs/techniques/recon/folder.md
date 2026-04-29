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

### `GetKnown(rfid windows.GUID, flags KnownFolderFlag) (string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#GetKnown)

Resolves a `KNOWNFOLDERID` GUID to its filesystem path via
`SHGetKnownFolderPath`. Handles the `PWSTR` ownership contract
(API-allocated buffer freed via `CoTaskMemFree`) internally.

**Parameters:**
- `rfid` — any of the exported `FOLDERID_*` GUIDs or a custom
  `windows.GUID` (3rd-party Shell extensions register their own).
- `flags` — bit-set of `KnownFolderFlag`. `0` for default,
  `KFF_CREATE` to force directory creation, `KFF_DONT_VERIFY`
  to skip the existence check.

**Returns:**
- `string` — resolved path. Not `MAX_PATH`-capped.
- `error` — `ErrKnownFolderNotFound` (wrapped) when Shell32
  returns a non-success HRESULT.

**Side effects:** none beyond the Shell32 call. The internal
`CoTaskMemFree` releases the API-allocated `PWSTR`.

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

`FOLDERID_Profile`, `FOLDERID_Desktop`, `FOLDERID_Documents`,
`FOLDERID_Downloads`, `FOLDERID_LocalAppData`,
`FOLDERID_RoamingAppData`, `FOLDERID_Programs`,
`FOLDERID_Startup`, `FOLDERID_System`, `FOLDERID_Windows`,
`FOLDERID_ProgramFiles`, `FOLDERID_ProgramFilesX86`,
`FOLDERID_PublicDesktop`, `FOLDERID_CommonStartup`.

### Common CSIDL constants (legacy)

`CSIDL_DESKTOP`, `CSIDL_APPDATA`, `CSIDL_LOCAL_APPDATA`,
`CSIDL_COMMON_APPDATA`, `CSIDL_STARTUP`, `CSIDL_COMMON_STARTUP`,
`CSIDL_PROGRAM_FILES`, `CSIDL_PROGRAM_FILESX86`, `CSIDL_SYSTEM`,
`CSIDL_WINDOWS`, `CSIDL_TEMPLATES`.

## Examples

### Simple — modern KNOWNFOLDERID

```go
import "github.com/oioio-space/maldev/recon/folder"

appdata, _   := folder.GetKnown(folder.FOLDERID_RoamingAppData, 0)
downloads, _ := folder.GetKnown(folder.FOLDERID_Downloads, 0)
system, _    := folder.GetKnown(folder.FOLDERID_System, 0)

// Force creation (KFF_CREATE) when staging a per-user drop directory:
stage, _ := folder.GetKnown(folder.FOLDERID_LocalAppData, folder.KFF_CREATE)
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

- **Deprecated API.** Microsoft recommends `SHGetKnownFolderPath`
  (KNOWNFOLDERID); kept here for COM-free compatibility.
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
