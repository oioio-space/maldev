---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

[← Back to README](../README.md)

# In-process Runtimes

This page documents the two in-process code-loader packages in maldev:

- **`runtime/bof`** — Beacon Object File (BOF) loader for in-memory COFF execution
- **`runtime/clr`** — In-process .NET CLR hosting (reflective assembly execution, T1620)

Both packages **execute** code in the current process, distinguishing
them from `pe/*` (which parse / transform / convert PE binaries
without executing them) and from `inject/` (which runs raw shellcode).
The carve-out from `pe/` to `runtime/` shipped in v0.21.0.

For in-depth technique walkthroughs:

- BOF Loader: [docs/techniques/runtime/bof-loader.md](techniques/runtime/bof-loader.md)
- CLR Hosting: [docs/techniques/runtime/clr.md](techniques/runtime/clr.md)

---

## runtime/bof -- Beacon Object File Loader

Package `bof` provides a minimal Beacon Object File (BOF) loader for in-memory COFF execution. BOFs are compiled COFF (.o) object files that can be loaded and executed without writing a full PE to disk.

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)
**Platform:** Windows (amd64)
**Detection:** Medium -- executable memory allocation (RWX) is visible to EDR, but the payload never touches disk.

### Types

#### `BOF`

```go
type BOF struct {
    Data  []byte
    Entry string // entry point function name (default: "go")
}
```

Represents a parsed COFF object file. Set `Entry` before calling `Execute` to specify a custom entry point function name.

### Functions

#### `Load`

```go
func Load(data []byte) (*BOF, error)
```

**Purpose:** Parses a COFF object file from raw bytes. Validates the COFF header and machine type (x64 only).

**Parameters:**
- `data` -- Raw COFF object file bytes (.o file).

**Returns:** A `*BOF` ready for execution, or an error if the file is invalid or not x64.

---

#### `Execute`

```go
func (b *BOF) Execute(args []byte) ([]byte, error)
```

**Purpose:** Runs the BOF's entry point with the given arguments. The BOF is loaded into executable memory, relocations are applied, and the entry function is called using the BOF calling convention: `go(char *data, int len)`.

**Parameters:**
- `args` -- Raw argument bytes passed to the BOF entry function. Pass `nil` for no arguments.

**Returns:** Output bytes (currently `nil`) and any execution error.

**How it works:**
1. Parses section headers from the COFF data.
2. Locates the `.text` section containing machine code.
3. Allocates RWX memory via `VirtualAlloc` and copies the `.text` data.
4. Applies COFF relocations (`IMAGE_REL_AMD64_ADDR64`, `IMAGE_REL_AMD64_ADDR32NB`, `IMAGE_REL_AMD64_REL32`).
5. Resolves the entry point symbol from the COFF symbol table.
6. Calls the entry function via `syscall.Syscall`.
7. Frees the executable memory on return.

**Limitations:**
- Beacon API functions (`BeaconOutput`, `BeaconFormatAlloc`, etc.) are NOT resolved. BOFs that call Beacon APIs will crash.
- Only x64 COFF files are supported.
- Only basic relocation types are handled.

**Example:**

```go
import (
    "log"
    "os"

    "github.com/oioio-space/maldev/runtime/bof"
)

func main() {
    data, err := os.ReadFile("mybof.o")
    if err != nil {
        log.Fatal(err)
    }

    b, err := bof.Load(data)
    if err != nil {
        log.Fatal(err)
    }

    _, err = b.Execute(nil)
    if err != nil {
        log.Fatal(err)
    }
}
```

---

## runtime/clr -- In-Process .NET CLR Hosting

Package `clr` hosts the .NET Common Language Runtime in the current process via the `ICLRMetaHost` / `ICorRuntimeHost` COM interfaces and executes managed assemblies entirely in memory.

**MITRE ATT&CK:** T1620 (Reflective Code Loading)
**Platform:** Windows (requires a .NET Framework 4.x runtime)
**Detection:** Medium -- loading `clr.dll` inside a non-.NET host process is a strong heuristic. AMSI v2 scans every assembly passed to `AppDomain.Load_3`, so call `evasion/amsi.PatchAll()` first for flagged payloads.

See [docs/techniques/runtime/clr.md](techniques/runtime/clr.md) for the full walkthrough (COM interface chain, AppDomain lifecycle, AMSI interaction).

### Minimal usage

```go
package main

import (
    "log"
    "os"

    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/runtime/clr"
)

func main() {
    _ = amsi.PatchAll(nil) // required for AMSI-flagged assemblies

    rt, err := clr.Load(nil)
    if err != nil {
        log.Fatal(err)
    }
    defer rt.Close()

    assembly, err := os.ReadFile("Seatbelt.exe")
    if err != nil {
        log.Fatal(err)
    }
    if err := rt.ExecuteAssembly(assembly, []string{"-group=all"}); err != nil {
        log.Fatal(err)
    }
}
```

---
