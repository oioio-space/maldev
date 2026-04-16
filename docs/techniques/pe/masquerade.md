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
    E --> F[committed in pe/masquerade/preset/id/variant/]
    F --> G[blank import in user's main]
    G --> H[go build links .syso automatically]
    H --> I[output .exe carries embedded resources]
```

At build time, `go build` finds every `*_windows_amd64.syso` in an imported
package directory and merges its COFF `.rsrc` section into the final binary.
No external tool is invoked during build.

The `.syso` generator lives at `pe/masquerade/internal/gen/main.go` — a pure-Go
program that reads the reference executable read-only from
`%SystemRoot%\System32`, extracts its resource set, patches the manifest
`requestedExecutionLevel`, and re-emits the `.syso` per variant.

## Available Identities

| Identity | Source EXE | Base variant (invoker) | Admin variant (requireAdministrator) |
|----------|-----------|---|---|
| `cmd`      | `System32\cmd.exe`      | `pe/masquerade/preset/cmd`      | `pe/masquerade/preset/cmd/admin`      |
| `svchost`  | `System32\svchost.exe`  | `pe/masquerade/preset/svchost`  | `pe/masquerade/preset/svchost/admin`  |
| `taskmgr`  | `System32\taskmgr.exe`  | `pe/masquerade/preset/taskmgr`  | `pe/masquerade/preset/taskmgr/admin`  |
| `explorer` | `Windows\explorer.exe`  | `pe/masquerade/preset/explorer` | `pe/masquerade/preset/explorer/admin` |
| `notepad`  | `System32\notepad.exe`  | `pe/masquerade/preset/notepad`  | `pe/masquerade/preset/notepad/admin`  |

**5 identities × 2 UAC variants = 10 packages.** Each is ~34 KB
(`resource_windows_amd64.syso`) plus a 3-line package stub.

## Usage

```go
package main

import (
    _ "github.com/oioio-space/maldev/pe/masquerade/preset/svchost"
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

1. **At most one** blank-import from `pe/masquerade/preset/*` per final
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
go run ./pe/masquerade/internal/gen
```

The generator is pure Go (uses `github.com/tc-hib/winres` as a library)
and does not modify the host filesystem outside this repository.

Regenerate when:
- A Windows update refreshes icons/metadata of a reference exe.
- You want to add a new identity (extend the `identities` slice in
  `pe/masquerade/internal/gen/main.go`).
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

## Programmatic API — `pe/masquerade`

The `pe/masquerade` package provides a runtime/build-time-scriptable alternative
to the pre-generated `.syso` packages. Instead of committing a `.syso` to the
repo, a generator script (or `go generate` step) extracts resources from any
source PE and emits a fresh `.syso` each build.

Import path: `github.com/oioio-space/maldev/pe/masquerade`

### Quick Clone (one-liner)

```go
package main

import "github.com/oioio-space/maldev/pe/masquerade"

func main() {
    err := masquerade.Clone(
        `C:\Windows\System32\svchost.exe`,
        "resource_windows_amd64.syso",
        masquerade.AMD64,
        masquerade.AsInvoker,
    )
    if err != nil {
        panic(err)
    }
    // Run: go build ./... — the emitted .syso is picked up automatically.
}
```

### Extract, Modify, Generate (composable)

```go
res, err := masquerade.Extract(`C:\Windows\System32\notepad.exe`)
if err != nil {
    panic(err)
}

// Patch individual fields before generating — everything else is kept verbatim.
res.VersionInfo.OriginalFilename = "updater.exe"
res.VersionInfo.FileDescription  = "Windows Update Service"

if err := res.GenerateSyso("resource_windows_amd64.syso", masquerade.AMD64, masquerade.AsInvoker); err != nil {
    panic(err)
}
```

### Inspecting Extracted Icons

Icons are stored internally to avoid leaking the `winres` dependency. Use
`IconCount()` to check how many icon groups were extracted:

```go
res, _ := masquerade.Extract(`C:\Windows\System32\notepad.exe`)
fmt.Printf("Extracted %d icon group(s)\n", res.IconCount())

// Icons are automatically included in GenerateSyso — no manual handling needed.
res.GenerateSyso("resource.syso", masquerade.AMD64, masquerade.AsInvoker)
```

### Swapping Icons Between PEs

To use icons from one PE with version info from another, extract both and
use `Build` with `WithSourcePE` for the icon donor:

```go
// Use svchost icons but custom version info
err := masquerade.Build("resource.syso", masquerade.AMD64,
    masquerade.WithSourcePE(`C:\Windows\System32\svchost.exe`),
    masquerade.WithVersionInfo(&masquerade.VersionInfo{
        FileDescription:  "My Custom Service",
        CompanyName:      "Microsoft Corporation",
        OriginalFilename: "myservice.exe",
        FileVersion:      "10.0.19041.1",
        ProductVersion:   "10.0.19041.1",
    }),
)
```

### Build from Scratch (no source PE)

```go
import (
    "image"
    _ "image/png"
    "os"

    "github.com/oioio-space/maldev/pe/masquerade"
    "github.com/tc-hib/winres"
)

// Load a custom icon from a .png or .ico file.
f, _ := os.Open("app_icon.png")
img, _, _ := image.Decode(f)
f.Close()
icon, _ := winres.NewIconFromResizedImage(img, nil)

err := masquerade.Build("resource_windows_amd64.syso", masquerade.AMD64,
    masquerade.WithExecLevel(masquerade.RequireAdministrator),
    masquerade.WithVersionInfo(&masquerade.VersionInfo{
        FileDescription:  "Host Process for Windows Services",
        CompanyName:      "Microsoft Corporation",
        ProductName:      "Microsoft® Windows® Operating System",
        OriginalFilename: "svchost.exe",
        FileVersion:      "10.0.19041.1",
        ProductVersion:   "10.0.19041.1",
    }),
    masquerade.WithIcons([]*winres.Icon{icon}),
)
```

Without `WithSourcePE`, a minimal manifest (Win10 compatibility) and no
icons are used. `WithIcons` accepts `[]*winres.Icon` — use
`winres.NewIconFromResizedImage` to create one from any Go `image.Image`,
or `winres.LoadICO` to load a `.ico` file directly.

### Build from Any PE + Certificate

```go
import (
    "github.com/oioio-space/maldev/pe/cert"
    "github.com/oioio-space/maldev/pe/masquerade"
)

// Steal the Authenticode cert from the reference PE.
c, err := cert.Read(`C:\Windows\System32\svchost.exe`)
if err != nil {
    panic(err)
}

err = masquerade.Build("resource_windows_amd64.syso", masquerade.AMD64,
    masquerade.WithSourcePE(`C:\Windows\System32\svchost.exe`),
    masquerade.WithExecLevel(masquerade.HighestAvailable),
    masquerade.WithCertificate(c),
)

// After go build, apply the stolen cert to the final binary:
// cert.Write("mybinary.exe", c)
```

**Note:** The certificate is stored in `Resources.Certificate` for reference
but is **not** embedded in the `.syso` — Authenticode certificates must be
appended to the final PE after linking, using `cert.Write`.

### Execution Levels

| Constant | Manifest value | Use case |
|---|---|---|
| `AsInvoker` | `asInvoker` | Runs with the invoking shell's token — no UAC prompt. Default, most stealthy. |
| `HighestAvailable` | `highestAvailable` | Requests the highest privilege the current user can obtain. UAC prompt only if the user is an admin. |
| `RequireAdministrator` | `requireAdministrator` | Always forces the UAC consent UI. Pick only for identities where elevation is expected (e.g. `taskmgr`). |

### API Reference

| Symbol | Kind | Description |
|--------|------|-------------|
| `Extract(pePath string) (*Resources, error)` | func | Open a PE and extract manifest, icons, version info, and Authenticode certificate. |
| `(*Resources).GenerateSyso(output string, arch Arch, level ExecLevel) error` | method | Write a `.syso` COFF object from the current `Resources` state. Reuses original resources when no fields are overridden. |
| `(*Resources).IconCount() int` | method | Returns the number of icon groups extracted from the PE. |
| `Clone(srcPE, outputSyso string, arch Arch, level ExecLevel) error` | func | One-step Extract + GenerateSyso. |
| `Build(output string, arch Arch, opts ...Option) error` | func | Generate `.syso` from options; optionally starts from a source PE. Returns `ErrEmptySourcePE` if `WithSourcePE("")` is used. |
| `WithSourcePE(pePath string) Option` | option | Seed `Build` with resources extracted from an existing PE (icons, manifest, version info). |
| `WithExecLevel(level ExecLevel) Option` | option | Override the manifest's `requestedExecutionLevel`. |
| `WithManifest(xml []byte) Option` | option | Replace the entire manifest with raw XML. |
| `WithVersionInfo(vi *VersionInfo) Option` | option | Override all version resource strings. |
| `WithIcons(icons []*winres.Icon) Option` | option | Override icon resources (requires importing `github.com/tc-hib/winres` directly). |
| `WithCertificate(c *cert.Certificate) Option` | option | Store a certificate for post-build application (not embedded in `.syso`). |
| `ErrEmptySourcePE` | error | Returned when `WithSourcePE` is called with an empty path. |
| `AMD64`, `I386` | `Arch` | Target CPU architecture for the emitted `.syso`. |
| `AsInvoker`, `HighestAvailable`, `RequireAdministrator` | `ExecLevel` | Requested execution level values. |

## Credits

- [tc-hib/winres](https://github.com/tc-hib/winres) — pure-Go COFF `.rsrc`
  emitter used by the generator.
