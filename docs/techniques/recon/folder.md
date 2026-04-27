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

| Symbol | Description |
|---|---|
| [`Get(csidl, createIfNotExist) string`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#Get) | Resolve CSIDL to filesystem path |
| [`type CSIDL`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder#CSIDL) | Per-folder constant |

Common CSIDLs: `CSIDL_DESKTOP`, `CSIDL_APPDATA`,
`CSIDL_LOCAL_APPDATA`, `CSIDL_COMMON_APPDATA`,
`CSIDL_STARTUP`, `CSIDL_COMMON_STARTUP`, `CSIDL_PROGRAM_FILES`,
`CSIDL_PROGRAM_FILESX86`, `CSIDL_SYSTEM`, `CSIDL_WINDOWS`,
`CSIDL_TEMPLATES`.

## Examples

### Simple — common folders

```go
import "github.com/oioio-space/maldev/recon/folder"

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
