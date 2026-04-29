---
package: github.com/oioio-space/maldev/cleanup/ads
last_reviewed: 2026-04-29
reflects_commit: 4d55e88
---

# NTFS Alternate Data Streams

[← cleanup index](README.md) · [docs/index](../../index.md)

## TL;DR

Read, write, list, delete named data streams attached to NTFS files
(`file:streamname:$DATA`). Streams don't appear in `dir`, Explorer, or
most file APIs — useful for hiding payloads, storing implant state, and
the `cleanup/selfdelete` rename trick.

## Primer

Every file on an NTFS volume has a default unnamed data stream
(`:$DATA`) — that's what `cat` / `Get-Content` reads. NTFS additionally
allows arbitrary named streams attached to the same file. The streams
share the file's MFT entry, ACL, and timestamps; they're addressable as
`file.txt:hidden:$DATA`. Most user-facing tooling ignores everything but
the default stream, which makes ADS a quiet stash spot.

ADS support is filesystem-bound. NTFS supports it; FAT32, exFAT, ext4,
and any non-Windows filesystem do not. Crossing a non-NTFS boundary
(e.g., copying to a USB stick) silently drops the streams.

## How it works

```mermaid
sequenceDiagram
    participant Caller
    participant ads
    participant Kernel as "NTFS driver"
    participant File as "some.txt"
    Caller->>ads: Write("some.txt", "hidden", payload)
    ads->>Kernel: CreateFileW("some.txt:hidden", GENERIC_WRITE)
    Kernel->>File: allocate/locate stream "hidden"
    Kernel-->>ads: HANDLE
    ads->>Kernel: WriteFile(HANDLE, payload)
    ads->>Kernel: CloseHandle(HANDLE)
    ads-->>Caller: nil
```

The package wraps `CreateFileW` with the colon-suffix syntax. The kernel
handles stream allocation transparently. List uses
`NtQueryInformationFile(FileStreamInformation)` to walk the MFT entry's
stream attribute list.

## API Reference

### `Write(path, stream string, data []byte) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#Write)

Append-or-replace `data` into the named stream of `path`.

**Parameters:** `path` — NTFS file (must exist). `stream` — stream name (any
non-empty string, no colons). `data` — bytes to write.

**Returns:** `error` — wraps `CreateFileW` / `WriteFile` failures, or "not
NTFS" when the volume doesn't support ADS.

**Side effects:** stream is created if absent, replaced if present.

### `WriteVia(creator stealthopen.Creator, path, stream string, data []byte) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#WriteVia)

Same semantics as `Write`, but routes through the operator-supplied
[`stealthopen.Creator`](../evasion/stealthopen.md). nil falls back to
`os.Create` (identical to plain `Write`); non-nil layers transactional
NTFS, encryption, or any other write primitive on top of the ADS
landing. Internally calls `stealthopen.WriteAll` with the
`<path>:<stream>` composite path.

### `Read(path, stream string) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#Read)

Read the entire named stream into memory.

### `ReadVia(opener stealthopen.Opener, path, stream string) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#ReadVia)

Same semantics as `Read`, but routes through the operator-supplied
[`stealthopen.Opener`](../evasion/stealthopen.md). nil falls back to
plain `os.Open` on the composite `<path>:<stream>` (identical to
`Read`); non-nil layers an operator-controlled read primitive on top.

> [!CAUTION]
> [`*stealthopen.Stealth`](../evasion/stealthopen.md) opens by NTFS
> Object ID and addresses the **MFT entry** (the main stream). Named
> ADS streams share the entry but are addressed by stream name; the
> Object-ID path cannot reach them. An Opener that needs to defeat
> path-based EDR hooks AND read a specific named stream must route
> through `NtCreateFile` with the composite path (FILE_OBJECT
> resolution) rather than Object-ID resolution.

### `List(path string) ([]string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#List)

Enumerate all stream names attached to `path` (excluding the default
unnamed stream).

### `Delete(path, stream string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads#Delete)

Remove the named stream. The base file remains.

## Examples

### Simple

```go
import "github.com/oioio-space/maldev/cleanup/ads"

_ = ads.Write(`C:\Users\Public\desktop.ini`, "config", []byte("c2=1.2.3.4"))

cfg, _ := ads.Read(`C:\Users\Public\desktop.ini`, "config")

streams, _ := ads.List(`C:\Users\Public\desktop.ini`)
// streams: []string{"config"}

_ = ads.Delete(`C:\Users\Public\desktop.ini`, "config")
```

### Composed (with `crypto`)

```go
key := crypto.RandomKey(32)
ct, _ := crypto.AESGCMEncrypt(key, []byte(state))
_ = ads.Write(`C:\Windows\Temp\index.dat`, "s", ct)

// Later:
ct, _ = ads.Read(`C:\Windows\Temp\index.dat`, "s")
state, _ := crypto.AESGCMDecrypt(key, ct)
```

### Advanced (chain with selfdelete)

`cleanup/selfdelete` uses ADS rename internally:

```go
// selfdelete renames the default stream to ":x" via the same primitive
// surface the ads package exposes, then sets DELETE disposition.
// See cleanup/selfdelete/selfdelete.go for the full sequence.
selfdelete.Run()
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| MFT entry size grows when stream is added | NTFS forensic tools (Sleuth Kit, Plaso) |
| `CreateFileW` with colon-suffix path | EDR file-IO event aggregation; rare in benign software |
| `dir /R` lists all streams | Manual triage |
| `Get-Item -Stream *` (PowerShell) | Manual hunt |
| Sysinternals Streams tool | Forensic walkthrough |

**D3FEND counter:** [D3-FCR](https://d3fend.mitre.org/technique/d3f:FileContentRules/)
(File Content Rules) — antivirus engines can scan named streams when
configured.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage |
|---|---|---|
| [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | Hide Artifacts: NTFS File Attributes | Named-stream payload storage |

## Limitations

- **NTFS-only.** Cross-filesystem copy drops streams.
- **Many AVs scan ADS.** Defender enumerates and scans named streams by
  default since Win10 1607.
- **Mark-of-the-Web** stream (`Zone.Identifier`) is added automatically
  to internet-downloaded files; collisions are unlikely but worth
  avoiding (don't use `Zone.Identifier` as your stream name).
- **Backup tools** (Robocopy with `/B`, Windows Backup) preserve streams;
  unaware tools (`copy`, `xcopy` without `/B`) silently drop them.
- **Stealth read of named ADS streams is non-trivial.** [`ReadVia`](#readviaopener-stealthopenopener-path-stream-string-byte-error)
  + nil-fallback uses path-based `os.Open` on `<path>:<stream>` —
  visible to path-hooking EDRs. The repo's bundled
  [`*stealthopen.Stealth`](../evasion/stealthopen.md) routes through
  NTFS Object IDs which addresses the MFT entry only (main stream),
  *not* a specific named stream. A stealth-on-ADS read primitive
  needs a custom Opener built on `NtCreateFile` with the composite
  path; not provided by this package.

## See also

- [`cleanup/selfdelete`](self-delete.md) — primary internal consumer.
- [Sysinternals Streams](https://learn.microsoft.com/sysinternals/downloads/streams)
  — operator-side enumeration.
- [microsoft/go-winio backup.go](https://github.com/microsoft/go-winio/blob/main/backup.go)
  — original ADS code structure inspiration.
- [CQURE Academy — Alternate Data Streams](https://cqureacademy.com/blog/alternate-data-streams/).
