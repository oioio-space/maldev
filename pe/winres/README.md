# pe/winres — Compile-time PE Resource Embedding

Blank-importable sub-packages that embed a Windows application manifest,
icon bundle and VERSIONINFO into the final binary via `.syso` objects.
The `go` toolchain links these automatically.

**MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location.

## Usage — single blank import

```go
package main

import (
    _ "github.com/oioio-space/maldev/pe/winres/masquerade/cmd"
)

func main() { /* … */ }
```

After `go build`, Task Manager / Process Explorer / `Get-Item` show the
binary as `cmd.exe` (Microsoft Corp, Windows Command Processor, cmd icon).

## Available identities (5) × UAC variants (2) = 10 packages

| Identity | Invoker (default)              | requireAdministrator        |
|----------|--------------------------------|-----------------------------|
| cmd.exe  | `masquerade/cmd`               | `masquerade/cmd/admin`      |
| svchost  | `masquerade/svchost`           | `masquerade/svchost/admin`  |
| taskmgr  | `masquerade/taskmgr`           | `masquerade/taskmgr/admin`  |
| explorer | `masquerade/explorer`          | `masquerade/explorer/admin` |
| notepad  | `masquerade/notepad`           | `masquerade/notepad/admin`  |

Import **at most one** package from this tree. Windows binaries carry a
single `RT_MANIFEST` (ID=1); two blank-imports would produce a
duplicate-symbol linker error.

## Regenerating the `.syso` objects

The committed `resource_windows_amd64.syso` files are produced from the
reference executables under `%SystemRoot%\System32`. To regenerate (e.g.
after Microsoft ships new icons in a Windows update):

```bash
# On a Windows host, read-only access to System32 suffices:
go run ./pe/winres/internal/gen
```

The generator is pure Go (uses `github.com/tc-hib/winres`), requires no
external CLI, and does not modify the host filesystem outside this repo.

## CLR legacy activation (orthogonal)

Embedding `useLegacyV2RuntimeActivationPolicy` via a PE manifest is **not**
possible — that directive is read from an external `<exe>.config` file by
mscoree.dll. If your binary imports `pe/clr` and calls `clr.Load()`, call
`clr.InstallRuntimeActivationPolicy()` earlier in `main` — it drops the
required `<exe>.config` next to the running binary.

## What gets embedded

Per variant:

- `RT_MANIFEST` (ID=1) — reconstructed from the source exe's manifest with
  `requestedExecutionLevel` set to `asInvoker` (base) or
  `requireAdministrator` (admin variant). `<trustInfo>`/compatibility
  blocks preserved.
- `RT_GROUP_ICON` + `RT_ICON` — all icons from the source exe (unchanged).
- `RT_VERSION` — VERSIONINFO from the source exe (CompanyName,
  FileDescription, OriginalFilename, ProductName etc. — unchanged).

## OPSEC notes

- Static inspection (PE parsing, `sigcheck /m`) will see the embedded
  manifest & VERSIONINFO. This is shallow masquerading, not digital
  signature spoofing.
- Authenticode signatures are **not** forged. For signed appearance, pair
  with a stolen or self-signed cert (`pe/cert`).
- Defender ML models have been observed flagging Go binaries whose
  VERSIONINFO claims Microsoft origin. Test with your target AV before
  relying on it operationally.
