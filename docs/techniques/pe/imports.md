---
package: github.com/oioio-space/maldev/pe/imports
last_reviewed: 2026-05-04
reflects_commit: 3de532d
---

# PE Import Table Analysis

[← pe index](README.md) · [docs/index](../../index.md)

## TL;DR

Walk a PE's `IMAGE_DIRECTORY_ENTRY_IMPORT` and return every
`(DLL, Function)` pair the binary depends on. Pure Go via
`debug/pe` — no `DbgHelp`, no `LoadLibrary`, runs on any host
parsing any PE. Used to scope unhooking passes, build dynamic
API-resolution payloads, and triage unknown binaries.

## Primer

Every Windows EXE or DLL carries a list of the functions it calls
from other DLLs — the import table. Reading it tells you exactly
which kernel or user-mode APIs the binary relies on without
running it. Defenders use this for triage; offensive tooling uses
it to scope unhook passes (only restore the Nt* you actually
call) and to feed downstream syscall-discovery (extract SSNs from
ntdll exports the binary imports).

The package is fully cross-platform — it operates on PE bytes via
the standard library's `debug/pe` parser, so a Linux build host
can introspect a Windows implant without round-tripping through
Wine or signtool.

## How It Works

```mermaid
flowchart LR
    A["PE bytes"] --> B["debug/pe.NewFile"]
    B --> C["ImportedSymbols<br>walks IMAGE_IMPORT_DESCRIPTOR"]
    C --> D{"parse Func then DLL"}
    D --> E["List Import<br>DLL + Function"]
    E --> F["evasion/unhook<br>or wsyscall SSN extract"]
```

- Read the PE optional header and locate
  `IMAGE_DIRECTORY_ENTRY_IMPORT`.
- Walk each `IMAGE_IMPORT_DESCRIPTOR`, following
  `OriginalFirstThunk` (or `FirstThunk` if the original is zero)
  to resolve each imported function.
- Handle both by-name and by-ordinal entries.
- Return a flat `[]Import` slice — callers reshape as needed.

## API Reference

### `type Import struct { DLL, Function, Ordinal, ByOrdinal, Hint, Delay }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#Import)

One row of the import surface. Fields beyond DLL/Function are
new since the saferwall migration (v0.40.1+) — the previous
`debug/pe`-backed implementation silently dropped them:

```go
type Import struct {
    DLL       string  // import descriptor name
    Function  string  // empty when ByOrdinal is true
    Ordinal   uint32  // valid when ByOrdinal is true
    ByOrdinal bool    // true for ordinal-only entries (msvcrt etc.)
    Hint     uint16   // export-name-pointer-table index hint
    Delay    bool     // true when sourced from delay-import descriptor
}
```

`Delay` distinguishes the two import flavours present in modern
PEs:

  - `false`: classic import (IMAGE_IMPORT_DESCRIPTOR — loader
    resolves before user code runs).
  - `true`: delay-load import (IMAGE_DELAY_IMPORT_DESCRIPTOR —
    loader installs a stub, defers resolution until the first
    call). Modern Windows binaries (Edge, Office, OneDrive,
    Teams) route the bulk of their dependencies through
    delay-load.

**Side effects:** pure data.

**Required privileges:** unprivileged (pure data type).

**Platform:** cross-platform.

### `List(pePath string) ([]Import, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#List)

Parse the PE on disk and return every import.

**Parameters:** `pePath` — PE file (EXE or DLL).

**Returns:** flat slice ordered by descriptor then thunk; error
from file open or PE parse.

**Side effects:** reads `pePath`.

**OPSEC:** read-only file access — exceedingly common, not a
useful signal on its own.

**Required privileges:** unprivileged (read access on `pePath`).

**Platform:** cross-platform.

### `ListByDLL(pePath, dllName string) ([]Import, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#ListByDLL)

Filter `List`'s output to imports from the named DLL.
Case-insensitive match against
`IMAGE_IMPORT_DESCRIPTOR.Name`.

**Parameters:** `pePath` — PE file; `dllName` — descriptor name
to match (e.g. `"ntdll.dll"`).

**Returns:** filtered slice; error as `List`.

**Side effects:** reads `pePath`.

**Required privileges:** unprivileged (read access on `pePath`).

**Platform:** cross-platform.

### `FromReader(r io.ReaderAt) ([]Import, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#FromReader)

Parse a PE buffer already in memory — useful when the bytes are
decrypted in-process and never touch disk. Requires an
`io.ReadSeeker` under the hood (saferwall expects the full
buffer); plain `io.ReaderAt` callers drain into bytes via
[FromBytes] instead.

**Parameters:** `r` — `io.ReadSeeker` (`bytes.Reader` is the
typical choice).

**Returns:** import slice; error from saferwall parse or
non-Seeker readers.

**Side effects:** none.

**OPSEC:** silent — no file system access.

**Required privileges:** unprivileged (in-memory parse).

**Platform:** cross-platform.

### `FromBytes(data []byte) ([]Import, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#FromBytes)

Parse a PE byte slice. Sets every saferwall `Omit*` flag except
the import + delay-import directories — the parse stays sub-ms
even on large PEs.

**Parameters:** `data` — full PE image.

**Returns:** flat slice covering both classic + delay imports.

**Required privileges:** unprivileged.

**Platform:** cross-platform.

### `ListDelay(pePath string) ([]Import, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports#ListDelay)

Convenience filter — returns only entries with `Delay == true`.
Operator question this answers: *"what dependencies does this
binary defer until first use?"* On Edge that's 153 entries; on
notepad ~25; on a Go-built binary 0.

**Parameters:** `pePath` — PE file.

**Returns:** filtered slice; error as `List`.

**Side effects:** reads `pePath`.

**Required privileges:** unprivileged (read access on `pePath`).

**Platform:** cross-platform.

## Examples

### Simple — list every import

```go
import (
    "fmt"

    "github.com/oioio-space/maldev/pe/imports"
)

imps, _ := imports.List(`C:\Windows\System32\notepad.exe`)
for _, imp := range imps {
    fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
}
```

### Composed — filter to ntdll, parse from memory

```go
import (
    "bytes"

    "github.com/oioio-space/maldev/pe/imports"
)

ntImps, _ := imports.ListByDLL(`C:\loader.exe`, "ntdll.dll")
inMem, _ := imports.FromReader(bytes.NewReader(decryptedPE))
```

### Advanced — unhook only what we actually call

Layered with `evasion/unhook` so only the Nt* the loader actually
imports get restored — minimal `.text` write footprint, no
unused-function crumbs for an EDR's integrity checker.

```go
import (
    "os"

    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/unhook"
    "github.com/oioio-space/maldev/pe/imports"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

self, _ := os.Executable()
ntImps, _ := imports.ListByDLL(self, "ntdll.dll")

caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewTartarus())
defer caller.Close()

techs := make([]evasion.Technique, 0, len(ntImps))
for _, i := range ntImps {
    techs = append(techs, unhook.Classic(i.Function))
}
_ = evasion.ApplyAll(techs, caller)
```

See [`ExampleList`](../../../pe/imports/imports_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| File-read of a PE | EDR file-access telemetry — but read-only access is exceedingly common; not a useful signal |
| Subsequent unhooking write to ntdll `.text` | Sysmon Event 8 (CreateRemoteThread / ImageWrite); ETW Microsoft-Windows-Threat-Intelligence — the *consumer* of import data, not import parsing itself |
| YARA on the implant binary's IAT | Static rules against unusual ntdll-import sets — large `Nt*` lists imply a syscall-driven loader |

**D3FEND counters:**

- [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/)
  — IAT inspection on submitted samples.

**Hardening for the operator:**

- Strip unused imports at link time (`-trimpath`, garble) so the
  IAT only carries what the loader genuinely needs.
- Do the import walk against the on-disk PE before any unhooking;
  parsing is invisible.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | discovery primitive — drives runtime resolution and unhook scoping | [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/) |

## Limitations

- **By-ordinal imports** surface as `#<ordinal>` strings; resolving
  ordinals to names requires the target DLL's export table
  (separate operation).
- **Bound imports** are read straight from the descriptor — the
  cached resolved address is the value at *bind time*; current
  IAT may differ.
- **Delay-loaded imports** (DELAYIMPORT directory) are not
  enumerated by this package; use `debug/pe` directly or wait
  for first-use resolution.
- **Manifest-redirected DLLs** show their declared name, not the
  redirect target — useful for IOC matching, not for runtime
  resolution.

## See also

- [`pe/parse`](README.md) — sibling read-only PE walker.
- [`win/syscall`](../syscalls/) — consumes the import list to
  derive SSNs from ntdll.
- [`evasion/unhook`](../evasion/ntdll-unhooking.md) — primary
  consumer for scoped unhooks.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
