---
package: github.com/oioio-space/maldev/runtime/bof
last_reviewed: 2026-05-04
reflects_commit: 4d87569
---

# BOF (Beacon Object File) loader

[← runtime index](README.md) · [docs/index](../../index.md)

## TL;DR

You have a `.o` file (compiled C object) — typically a public
BOF from TrustedSec / Outflank / FortyNorth (whoami, situational
awareness, file ops). You want to run it inside your implant
without spawning a child process. This package loads + executes
the COFF in memory.

| You want to… | Use | Notes |
|---|---|---|
| Run a BOF from disk | [`Run`](#run) | Loads `.o`, parses COFF, resolves Beacon API, executes |
| Run a BOF from memory | [`RunBytes`](#runbytes) | When the BOF was decrypted in-process and never landed on disk |
| Pass arguments to the BOF (parsed via `BeaconData*`) | `Config.Args` | Variadic — the BOF's `BeaconDataInt` / `BeaconDataPtr` etc. consume them |

What this DOES achieve:

- Public BOFs (TrustedSec/CS-Situational-Awareness-BOF,
  TrustedSec/CS-Remote-OPs-BOF, Outflank/C2-Tool-Collection)
  run unmodified.
- Beacon API stubs implemented in Go — no Cobalt Strike needed
  on the operator side.
- Dynamic imports (`KERNEL32`, `ADVAPI32`, …) resolve through
  PEB + ROR13 hash, so the BOF's import table doesn't appear
  as plaintext strings.

What this does NOT achieve:

- **x64 only** — no x86, no ARM64.
- **Doesn't sandbox** — BOF runs in your process address space.
  Crash in the BOF = crash in your implant.
- **AMSI / ETW telemetry from the BOF still fires** — pair
  with [`evasion/preset.Stealth`](../evasion/preset.md) before
  `Run`.

## Primer

A BOF is a relocatable COFF (`.o`) object compiled by MSVC /
MinGW. The format is the same as Linux's `.o` but for Windows
PE-style relocations. BOFs were popularised by Cobalt Strike's
`inline-execute` command — a tactical execution primitive that
runs a small piece of native code inside the implant's process
without spawning a fresh process or writing a PE to disk.

Use cases:

- Run small Windows-API-heavy snippets (token enum, share
  enum, share scan) that don't need a full PE infrastructure.
- Distribute compiled techniques as a `.o` artefact rather
  than a full implant.
- Compose with the implant's runtime — the BOF runs in the
  caller's address space, so it can interact with implant
  state directly.

## How It Works

```mermaid
flowchart LR
    INPUT[BOF .o bytes] --> PARSE[parse COFF<br>header + sections]
    PARSE --> ALLOC[VirtualAlloc RWX<br>copy .text + .data]
    ALLOC --> RELOC[apply relocations<br>ADDR64 / ADDR32NB / REL32]
    RELOC --> SYM[resolve entry symbol<br>from COFF symtab]
    SYM --> EXEC[jump to entry<br>via function ptr]
    EXEC --> OUT[capture output<br>via stdout redirect]
```

## API Reference

Package: `runtime/bof` ([pkg.go.dev](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof))

### `type BOF`

- godoc: loaded BOF instance — holds the parsed COFF, the RWX page, the resolved entry-point pointer, the per-call output and errors buffers, and the optional spawn-to path.
- Description: produced by `Load`. Concurrency-safe through a package-wide mutex that serialises Beacon API callbacks; concurrent `Execute` calls block on each other.
- Side effects: holds an RWX VirtualAlloc'd region for the lifetime of the value.
- OPSEC: behavioural EDR sees the RWX allocation + execute-from-allocation pattern. Pair with sleep-mask + RW→RX flip for steady-state cover.
- Required privileges: medium-IL is enough — RWX from VirtualAlloc works under any token.
- Platform: Windows amd64.

### `Load(data []byte) (*BOF, error)`

- godoc: parse a COFF object file from bytes and ready it for execution.
- Description: validates the COFF header (machine = `0x8664`), allocates a single contiguous RWX page covering every section with raw data plus a tail import-table region, applies relocations (ABSOLUTE / ADDR64 / ADDR32 / ADDR32NB / REL32 / REL32_1..5), resolves the entry-point symbol, and returns a ready `*BOF`.
- Parameters: `data` — the raw `.o` bytes.
- Returns: `*BOF` ready for `Execute`; `error` for invalid header, unsupported relocation, unresolved external symbol, or out-of-range REL32 target.
- Side effects: one VirtualAlloc(RWX) per Load call; the allocation persists for the BOF's lifetime.
- OPSEC: parse + load are silent (pure userland arithmetic). The RWX allocation itself is the visible IOC.
- Required privileges: none.
- Platform: Windows amd64. Returns an error on non-amd64 BOFs.

### `(*BOF).Execute(args []byte) ([]byte, error)`

- godoc: run the BOF's entry point with the packed argument buffer; return the captured `BeaconPrintf` / `BeaconOutput` stream.
- Description: serialised package-wide via the `bofMu` mutex — concurrent Execute calls on any BOF block on each other so the `currentBOF` cursor the Beacon API stubs read remains coherent. Resets the output / errors buffers before invocation, calls into the entry-point pointer with `(args_ptr, len)` per the CS `go(char*, int)` signature, then returns whatever the BOF wrote.
- Parameters: `args` — produced by `(*Args).Pack()` or hand-rolled in CS-compatible LE wire format. Pass `nil` for arg-less BOFs.
- Returns: captured output bytes; `error` if the entry point itself faults or any Beacon API stub fails fatally.
- Side effects: invokes native code in the calling process. Anything the BOF does (file I/O, registry, IOCTLs) happens under the calling process's token.
- OPSEC: the BOF runs in-process, so its API trail looks like the host's. Behavioural EDR may correlate the unusual API mix with the prior RWX allocation.
- Required privileges: whatever the BOF itself requires.
- Platform: Windows amd64.

### `(*BOF).SetSpawnTo(path string)`

- godoc: configure the path the loader returns when the BOF calls `BeaconGetSpawnTo`.
- Description: pinned for the BOF instance's lifetime — the address handed to the `BeaconGetSpawnTo` callback stays stable across re-Executes. Empty string (the default) means "no spawn target"; the BOF receives a NULL pointer and typically falls back to its own logic.
- Parameters: `path` — fork-and-run target (e.g. `"C:\\Windows\\System32\\notepad.exe"`).
- Returns: nothing.
- Side effects: allocates a NUL-terminated copy in `BOF.spawnToCStr`.
- OPSEC: value-only setter; no telemetry.
- Required privileges: none.
- Platform: Windows.

### `(*BOF).Errors() []byte`

- godoc: snapshot of whatever the BOF emitted via `BeaconErrorD` / `BeaconErrorDD` / `BeaconErrorNA` during the last `Execute`.
- Description: the errors channel is separate from the output buffer — operators inspect them independently. Returns nil before the first Execute. The slice is a fresh copy: safe to retain across subsequent Execute calls (which clear the underlying buffer).
- Parameters: receiver only.
- Returns: a copy of the errors buffer.
- Side effects: one allocation for the returned copy.
- OPSEC: pure read.
- Required privileges: none.
- Platform: Windows.

### `type Args`

- godoc: CS-compatible argument packer — produces the little-endian wire format `BeaconDataParse` / `BeaconDataInt` / `BeaconDataExtract` consume.
- Description: zero-value usable; build via `NewArgs` for clarity. The wire format matches TrustedSec COFFLoader / Outflank — public BOFs decode it natively.
- Required privileges: none.
- Platform: Windows (the type is defined under the `windows` build tag; Linux callers can still cross-compile BOFs but cannot run them).

### `NewArgs() *Args`

- godoc: allocate an empty argument packer.
- Description: returns an `*Args` with an empty internal `bytes.Buffer`. Equivalent to `&Args{}`.
- Parameters: none.
- Returns: `*Args` ready for `Add*` calls.
- Side effects: one struct allocation.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

### `(*Args).AddInt(v int32)`

- godoc: append a 32-bit signed integer in little-endian byte order.
- Description: 4 bytes, no length prefix (size is implicit in the type). LE matches the CS canonical native-int read on x64.
- Parameters: `v` — value to append.
- Returns: nothing.
- Side effects: 4 bytes appended to the internal buffer.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

### `(*Args).AddShort(v int16)`

- godoc: append a 16-bit signed integer in little-endian byte order.
- Description: 2 bytes, no length prefix. Read via `BeaconDataShort` on the BOF side.
- Parameters: `v` — value to append.
- Returns: nothing.
- Side effects: 2 bytes appended.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

### `(*Args).AddString(s string)`

- godoc: append a NUL-terminated string with a 4-byte little-endian length prefix.
- Description: layout: `[uint32 LE length] [bytes of s] [0x00]`. Length includes the NUL terminator. Read via `BeaconDataExtract` on the BOF side.
- Parameters: `s` — UTF-8 string. Embedded NULs are accepted but truncate the BOF-side read at the first NUL.
- Returns: nothing.
- Side effects: 4 + len(s) + 1 bytes appended.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

### `(*Args).AddBytes(data []byte)`

- godoc: append a byte slice with a 4-byte little-endian length prefix.
- Description: layout: `[uint32 LE length] [data bytes]`. No NUL terminator. The BOF reads the pointer + length via `BeaconDataExtract`; the returned pointer points into the args buffer (no copy on read).
- Parameters: `data` — raw bytes. Empty slice produces a 4-byte length-only prefix.
- Returns: nothing.
- Side effects: 4 + len(data) bytes appended.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

### `(*Args).Pack() []byte`

- godoc: return a defensive copy of the packed buffer ready for `(*BOF).Execute`.
- Description: copy semantics mean callers can mutate the returned slice without affecting subsequent `Pack()` calls or the internal buffer (validated by `TestArgsPackIsolated`).
- Parameters: receiver only.
- Returns: copy of the packed bytes.
- Side effects: one allocation for the returned copy.
- OPSEC: silent.
- Required privileges: none.
- Platform: Windows.

## Examples

### Simple — load + execute

```go
import (
    "os"

    "github.com/oioio-space/maldev/runtime/bof"
)

data, _ := os.ReadFile("whoami.o")
b, err := bof.Load(data)
if err != nil {
    return
}
output, _ := b.Execute(nil)
fmt.Println(string(output))
```

### Composed — chain multiple BOFs

```go
for _, path := range []string{"whoami.o", "netstat.o", "tasklist.o"} {
    data, _ := os.ReadFile(path)
    b, err := bof.Load(data)
    if err != nil {
        continue
    }
    out, _ := b.Execute(nil)
    fmt.Printf("=== %s ===\n%s\n", path, out)
}
```

### Advanced — pack arguments via `Args`

```go
data, _ := os.ReadFile("parse_args.o")
b, _ := bof.Load(data)

a := bof.NewArgs()
a.AddInt(42)
a.AddString("hello-args")

out, _ := b.Execute(a.Pack())
fmt.Println(string(out))
```

The wire format is little-endian to match the Cobalt Strike
canonical: TrustedSec COFFLoader, Outflank etc. read length
prefixes via `memcpy` into a native `int`, which on x64 is a
little-endian load. Use `AddInt` / `AddShort` for fixed-width
ints, `AddString` for length-prefixed NUL-terminated strings,
`AddBytes` for raw blobs.

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `VirtualAlloc(RWX)` followed by EXECUTE from the alloc | Behavioural EDR — high-fidelity reflective-loader signal |
| Module-load events for non-stack `.text` regions | ETW Microsoft-Windows-Threat-Intelligence |
| BOF entry-point execution from non-image memory | Defender for Endpoint MsSense |

**D3FEND counters:**

- [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/) — RWX execute-from-allocation telemetry.
- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/) — YARA on the loaded bytes.

**Hardening for the operator:**

- Allocate `RW` then `RX` via `VirtualProtect` instead of
  `RWX` — defeats the simplest RWX-watcher rules.
- Encrypt the BOF at rest via [`crypto`](../crypto/README.md);
  decrypt + load + immediately re-encrypt the source buffer.
- Pair with [`evasion/sleepmask`](../evasion/sleep-mask.md)
  for cleartext-at-rest mitigation.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | partial — in-memory native code execution | D3-PA |
| [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | full — COFF reflective load | D3-FCA, D3-PA |

## Limitations

- **Beacon-API surface — full set with one varargs caveat.**
  Implemented: `BeaconPrintf` + `BeaconFormatPrintf` (format
  string forwarded verbatim — see vararg note below),
  `BeaconOutput`, `BeaconDataParse` / `DataInt` / `DataShort` /
  `DataLength` / `DataExtract`, `BeaconFormatAlloc` / `Reset` /
  `Free` / `Append` / `Int` / `ToString`, `BeaconErrorD` /
  `ErrorDD` / `ErrorNA` (routed to a per-BOF errors buffer
  exposed via `(*BOF).Errors()`), `BeaconGetSpawnTo`
  (path settable via `(*BOF).SetSpawnTo`). Any other
  `__imp_Beacon*` import fails at relocation time with
  `unresolved external symbol __imp_BeaconXxx` — the failure
  is loud and traceable rather than silent NULL-patching.
- **`BeaconPrintf` / `BeaconFormatPrintf` varargs are not
  expanded.** `syscall.NewCallback` binds a fixed-arity Go
  function as a stdcall callback; Go cannot introspect cdecl
  varargs from inside the callback. We chose option **(a)**
  in the design discussion: forward the format string verbatim.
  BOFs that pass a literal format with no `%` directives
  behave correctly; BOFs relying on `printf`-style expansion
  see the format string raw.

  Two alternatives were considered and rejected for the default
  build:

  - **(b) Leave `__imp_BeaconPrintf` / `BeaconFormatPrintf`
    unresolved** so BOFs that depend on varargs fail at load
    time with a loud error. Honest but breaks compatibility
    with the large TrustedSec / Outflank corpus where
    `BeaconPrintf(CALLBACK_OUTPUT, "...")` is used as a
    no-args writer in 80% of cases.

  - **(c) Implement varargs via cgo.** A C wrapper around
    `vsnprintf` would expand the format and call back into Go
    with the rendered string. Requires:
      1. A C cross-compile toolchain in the build environment
         (mingw-w64 on Linux dev hosts, MSVC on Windows CI).
      2. CGO_ENABLED=1 — flips the entire library out of pure-Go
         mode, which the README sells as a hard guarantee.
      3. A different binary surface in `runtime/bof` for cgo vs.
         pure-Go builds, plus a build-tag matrix.

    The cost is steep relative to the gain (a minority of BOFs).
    Operators who need full vararg expansion can fork the
    package, drop a `bof_cgo_windows.go` file behind
    `//go:build windows && cgo && bof_cgo`, and supply a C-side
    `vsnprintf` wrapper they register via a hook hung off
    `resolveBeaconImport`. That extension point is intentionally
    left open; the default build prioritises pure-Go and
    accepts the verbatim-format trade-off.
- **External Win32 imports — two forms supported.**
  CS-canonical dollar-form (`__imp_KERNEL32$LoadLibraryA`)
  resolves via `parseDollarImport` → `api.ResolveByHash` (PEB
  walk + ROR13 module/function hash, no `GetProcAddress` /
  `LoadLibrary` call appears in the API trail). Mingw-w64 bare
  form (`__imp_LoadLibraryA` with no DLL prefix) resolves by
  walking a curated module list — kernel32, advapi32, user32,
  ws2_32, ole32, shell32 — first hit wins. Symbols not in the
  curated set still fail loudly. Add a module to
  `bareImportSearchOrder` in `beacon_api_windows.go` if a
  particular BOF needs more coverage.
- **Concurrency: BOF execution is serialised package-wide.** The
  Beacon API stubs read a single `currentBOF` pointer guarded
  by `bofMu`. Concurrent `Execute` calls block on each other.
  This matches the CS-compatible loader convention (BOF
  execution is fundamentally single-threaded) but is worth
  knowing if a host program runs many BOFs in parallel.
- **x64 only.** `Machine == 0x8664` required.
- **Relocation coverage.** `IMAGE_REL_AMD64_ABSOLUTE` (no-op),
  `_ADDR64`, `_ADDR32` (errors out cleanly when target exceeds
  32-bit range), `_ADDR32NB`, `_REL32`, and the `_REL32_1`
  through `_REL32_5` bias variants. Exotic relocations (TLS, GOT,
  `_SECTION`, `_SECREL`) are not supported — the loader fails
  with `unsupported relocation type: 0xNN` so the failure mode
  is obvious instead of a silent corruption.
- **RWX allocation is loud.** Hardened EDRs flag RWX from any
  source; pair with sleep-mask + RW→RX flip.

## See also

- [`runtime/clr`](clr.md) — sibling reflective runtime (.NET).
- [`crypto`](../crypto/README.md) — encrypt BOF at rest.
- [`evasion/sleepmask`](../evasion/sleep-mask.md) — hide BOF
  bytes at rest.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
