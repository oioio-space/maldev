---
package: github.com/oioio-space/maldev/runtime/bof
last_reviewed: 2026-04-27
reflects_commit: 3797037
---

# BOF (Beacon Object File) loader

[← runtime index](README.md) · [docs/index](../../index.md)

## TL;DR

Load + execute a Cobalt Strike-style Beacon Object File (BOF) —
a compiled COFF object — entirely in process memory. Parses
COFF, applies relocations, resolves entry-point, jumps into
RWX memory. x64-only; no Beacon-API helpers (BOFs that call
`BeaconOutput` etc. crash).

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

| Symbol | Description |
|---|---|
| [`type BOF`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof#BOF) | Loaded BOF instance |
| [`Load(data []byte) (*BOF, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof#Load) | Parse + relocate + ready to execute |
| `(*BOF).Execute(args []byte) ([]byte, error)` | Run the entry point; return captured stdout |

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

- **No Beacon-API resolution.** BOFs that call `BeaconOutput`,
  `BeaconFormatAlloc`, `BeaconErrorD` etc. crash. Use BOFs
  built without the Beacon-API contract or implement a stub
  resolver (out of scope here).
- **x64 only.** `Machine == 0x8664` required.
- **Limited relocation types.** ADDR64 / ADDR32NB / REL32 only;
  exotic relocations (TLS, GOT) not supported.
- **No symbol resolution beyond the entry point.** External
  imports are not resolved — pure in-process code only.
- **RWX allocation is loud.** Hardened EDRs flag RWX from any
  source; pair with sleep-mask + RW→RX flip.

## See also

- [`runtime/clr`](clr.md) — sibling reflective runtime (.NET).
- [`crypto`](../crypto/README.md) — encrypt BOF at rest.
- [`evasion/sleepmask`](../evasion/sleep-mask.md) — hide BOF
  bytes at rest.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
