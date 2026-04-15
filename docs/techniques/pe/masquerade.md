# PE Resource Masquerade — Compile-Time Identity Embedding

[<- Back to PE Operations](README.md)

## What It Does

Embeds the manifest, icons and VERSIONINFO of a legitimate Windows executable
into a Go binary at **compile time**, via blank-importable sub-packages
containing pre-generated `.syso` objects. The Go linker picks them up
automatically — no runtime work, no external tool invocation.

Result: Task Manager, Process Explorer, `Get-Item`, `sigcheck` display the
binary as `cmd.exe` / `svchost.exe` / `taskmgr.exe` / `explorer.exe` /
`notepad.exe` (Microsoft Corporation, original filename, real icon).

## How It Works

```mermaid
flowchart LR
    A[reference .exe in System32] --> B[go-winres/tc-hib parser]
    B --> C[AppManifest + RT_ICON + RT_VERSION]
    C --> D[manifest patched per UAC variant]
    D --> E[WriteObject -> resource_windows_amd64.syso]
    E --> F[committed in pe/winres/masquerade/id/variant/]
    F --> G[blank import in user's main]
    G --> H[go build links .syso automatically]
    H --> I[output .exe carries embedded resources]
```

At build time, `go build` finds every `*_windows_amd64.syso` in an imported
package directory and merges its COFF `.rsrc` section into the final binary.
No external tool is invoked during build.

The `.syso` generator lives at `pe/winres/internal/gen/main.go` — a pure-Go
program that reads the reference executable read-only from
`%SystemRoot%\System32`, extracts its resource set, patches the manifest
`requestedExecutionLevel`, and re-emits the `.syso` per variant.

## Available Identities

| Identity | Source EXE | Base variant (invoker) | Admin variant (requireAdministrator) |
|----------|-----------|---|---|
| `cmd`      | `System32\cmd.exe`      | `pe/winres/masquerade/cmd`      | `pe/winres/masquerade/cmd/admin`      |
| `svchost`  | `System32\svchost.exe`  | `pe/winres/masquerade/svchost`  | `pe/winres/masquerade/svchost/admin`  |
| `taskmgr`  | `System32\taskmgr.exe`  | `pe/winres/masquerade/taskmgr`  | `pe/winres/masquerade/taskmgr/admin`  |
| `explorer` | `Windows\explorer.exe`  | `pe/winres/masquerade/explorer` | `pe/winres/masquerade/explorer/admin` |
| `notepad`  | `System32\notepad.exe`  | `pe/winres/masquerade/notepad`  | `pe/winres/masquerade/notepad/admin`  |

**5 identities × 2 UAC variants = 10 packages.** Each is ~34 KB
(`resource_windows_amd64.syso`) plus a 3-line package stub.

## Usage

```go
package main

import (
    _ "github.com/oioio-space/maldev/pe/winres/masquerade/svchost"
)

func main() {
    // Your payload. Process Explorer now shows this binary as svchost.exe.
}
```

After `go build`:

```powershell
PS> (Get-Item .\mybin.exe).VersionInfo | Format-List
CompanyName      : Microsoft Corporation
FileDescription  : Host Process for Windows Services
OriginalFilename : svchost.exe
ProductName      : Microsoft® Windows® Operating System
```

## Rules

1. **At most one** blank-import from `pe/winres/masquerade/*` per final
   binary. Windows PEs carry exactly one `RT_MANIFEST` (ID=1); two
   imports would produce a duplicate-symbol linker error.
2. Choose the UAC variant that matches operational need:
   - **base** (`asInvoker`): no UAC prompt — stealthy, runs with the
     invoking shell's token.
   - **admin** (`requireAdministrator`): forces UAC consent UI on launch.
     Only pick this if the target identity naturally requires elevation
     (e.g. `taskmgr/admin`) — a cmd.exe requesting admin is suspicious.

## What Is Embedded

| Resource              | Content                                                       |
|-----------------------|---------------------------------------------------------------|
| `RT_MANIFEST` (ID 1)  | Rebuilt from source exe + patched `requestedExecutionLevel`.  |
| `RT_GROUP_ICON`/`RT_ICON` | All icon sizes from the source exe, unchanged.            |
| `RT_VERSION`          | Source exe's VERSIONINFO unchanged (CompanyName, FileDescription, OriginalFilename, ProductName, FileVersion). |

`.rdata` strings, imports and `.text` instructions are **not** modified
— this is shallow masquerading (metadata only), not code spoofing.

## Regeneration

```bash
# On a Windows host (read-only access to System32 is enough):
go run ./pe/winres/internal/gen
```

The generator is pure Go (uses `github.com/tc-hib/winres` as a library)
and does not modify the host filesystem outside this repository.

Regenerate when:
- A Windows update refreshes icons/metadata of a reference exe.
- You want to add a new identity (extend the `identities` slice in
  `pe/winres/internal/gen/main.go`).
- You want to add a new variant (e.g. `highestAvailable` UAC level).

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |

## Detection

**Low** — static inspection (PE parsing, `sigcheck /m`, Process Explorer's
"Verified Signer" column) will see that the embedded manifest and
VERSIONINFO claim Microsoft authorship, but:

- The binary is **not Authenticode-signed** — `sigcheck` shows
  `Verified: Unsigned` and Microsoft binaries are always signed, so any
  defender who checks the signature catches the spoof.
- Defender ML heuristics sometimes flag Go binaries whose VERSIONINFO
  claims Microsoft origin (unusual combination). Test with your target
  AV before relying operationally.
- The Go compiler leaves `.rdata` strings that give away Go authorship
  (`runtime.`, `main.`, etc.). Pair with `pe/strip` and/or `pe/morph`
  for deeper cover.

## Pairings

- **`pe/cert`** — sign the spoofed binary with a stolen or self-signed
  certificate to defeat signature-based detection.
- **`pe/strip`** — remove Go pclntab and timestamps that betray
  Go-compiled origin.
- **`pe/clr`** — CLR-host detection blends with `masquerade/svchost`
  (svchost legitimately hosts managed services).

## Credits

- [tc-hib/winres](https://github.com/tc-hib/winres) — pure-Go COFF `.rsrc`
  emitter used by the generator.
