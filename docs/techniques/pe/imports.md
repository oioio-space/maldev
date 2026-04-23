# PE Import Table Analysis

[<- Back to PE index](README.md)

**MITRE ATT&CK:** [T1106 - Native API](https://attack.mitre.org/techniques/T1106/) (discovery of imported APIs)
**Package:** `pe/imports`
**Platform:** Cross-platform (operates on PE bytes — no loader required)
**Detection:** N/A — static analysis only

---

## For Beginners

Every Windows EXE or DLL carries a list of the functions it calls from other DLLs — the import table. Reading it tells you exactly which kernel or user-mode APIs the binary relies on, without running it. Defenders use this for triage; offensive tooling uses it to scope unhooking and reduce noise.

---

## How It Works

```mermaid
flowchart LR
    A[PE bytes] --> B[debug/pe.Open]
    B --> C[ImportedSymbols]
    C --> D{parse<br/>"Func:DLL"}
    D --> E["[]Import{DLL,Function}"]
    E --> F[feed evasion/unhook<br/>or wsyscall]
```

- Reads the PE optional header and locates `IMAGE_DIRECTORY_ENTRY_IMPORT`.
- Walks each `IMAGE_IMPORT_DESCRIPTOR`, following `OriginalFirstThunk` (or `FirstThunk` if the original is zero) to resolve each imported function.
- Handles both by-name and by-ordinal entries.
- Pure Go via `debug/pe` — no `DbgHelp`, no `LoadLibrary`, works on any host parsing any PE.

---

## Usage

```go
import "github.com/oioio-space/maldev/pe/imports"

// List every DLL!Func pair.
imps, err := imports.List(`C:\Windows\System32\notepad.exe`)
if err != nil {
    panic(err)
}
for _, imp := range imps {
    fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
}

// Filter to one DLL — typical use: list only ntdll imports.
ntImps, _ := imports.ListByDLL(selfPEPath, "ntdll.dll")

// Parse from an in-memory PE (no filesystem hit).
imps, _ = imports.FromReader(bytes.NewReader(peBytes))
```

Typical output (truncated):

```text
KERNEL32.dll!GetProcAddress
KERNEL32.dll!LoadLibraryW
USER32.dll!GetMessageW
```

---

## Combined Example

Enumerate the loader's own ntdll imports, morph its section table, then
hand the import list to `evasion/unhook` so only the Nt* functions the
binary actually calls get restored — smallest possible memory-write
footprint, zero unused-function crumbs for the EDR's integrity checker.

```go
package main

import (
    "os"

    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/unhook"
    "github.com/oioio-space/maldev/pe/imports"
    "github.com/oioio-space/maldev/pe/morph"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    selfPath, _ := os.Executable()

    // 1. Morph section names (defeats UPX/Go section-table signatures).
    raw, _ := os.ReadFile(selfPath)
    morphed, _ := morph.UPXMorph(raw)
    _ = os.WriteFile(selfPath+".mut", morphed, 0o644)

    // 2. Read our own ntdll imports — the exact set of syscalls we need.
    ntImps, _ := imports.ListByDLL(selfPath, "ntdll.dll")
    targets := make([]string, 0, len(ntImps))
    for _, i := range ntImps {
        targets = append(targets, i.Function)
    }

    // 3. Unhook only those functions. No wasted writes on Nt*Debug*,
    //    Nt*LPC*, etc. that this binary never calls.
    caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewTartarus())
    defer caller.Close()
    techs := make([]evasion.Technique, 0, len(targets))
    for _, fn := range targets {
        techs = append(techs, unhook.Classic(fn))
    }
    _ = evasion.ApplyAll(techs, caller)
}
```

Layered benefit: `pe/morph` changes the on-disk fingerprint so static
signatures miss, `pe/imports` scopes the runtime unhook pass to
precisely what the loader calls (the minimal write footprint an EDR
can flag via `.text` integrity monitoring), and `wsyscall`'s Tartarus
resolver handles the unhook's own syscalls without going through
potentially-hooked stubs — three passive passes that compose into a
loader with no static signature, no EDR hooks on its critical path,
and no extra memory writes to explain.

---

## API Reference

See [pe.md](../../pe.md#peimports----pe-import-table-analysis)
