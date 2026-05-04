---
package: github.com/oioio-space/maldev/pe/srdi
last_reviewed: 2026-05-04
reflects_commit: 3de532d
---

# PE-to-Shellcode (Donut)

[← pe index](README.md) · [docs/index](../../index.md)

## TL;DR

Convert a native EXE / DLL, .NET assembly, or scripting payload
(VBS / JS / XSL) into position-independent shellcode via the
Donut framework — flat byte buffer ready to feed any injection
primitive in `inject/`. Built-in AMSI / WLDP bypass + optional
dual-mode (x86 + x64) output. Pure Go, cross-compiles from Linux.

## Primer

Windows insists executables live on disk as `.exe` / `.dll`
files; you can't normally hand the loader a flat byte buffer and
say "run this PE". Donut wraps an arbitrary PE (or .NET assembly,
or script) with a small position-independent loader stub that
bootstraps PE headers in memory, applies relocations, resolves
imports, and calls the entry point — all from a flat byte buffer
the operator can pass to any injection primitive.

The technique works for native PEs, .NET assemblies (no managed
runtime needed on disk — Donut hosts the CLR in process), and
scripts (VBScript / JScript / XSL through a built-in
mshta-equivalent runner). Output is one buffer regardless of
input format, sized roughly +5–10 % over the original.

## How It Works

```mermaid
sequenceDiagram
    participant Caller
    participant Donut as "srdi (go-donut)"
    participant Stub as "Loader stub<br>(in-memory)"
    participant Payload as "PE / .NET / Script"

    Caller->>Donut: ConvertFile(path, cfg)
    Donut->>Donut: Parse + classify input
    Donut->>Donut: Compress payload bytes
    Donut->>Donut: Embed AMSI / WLDP bypass
    Donut->>Donut: Attach PIC loader stub
    Donut-->>Caller: shellcode []byte

    Note over Caller,Stub: After injection into target process
    Stub->>Stub: PIC bootstrap (locate self)
    Stub->>Stub: AMSI / WLDP patch (configurable)
    Stub->>Stub: Decompress payload
    Stub->>Payload: Map sections + relocate + resolve imports
    Payload->>Payload: Call entry point
```

Generated shellcode layout:

```text
[ PIC Donut loader stub ]   ← position-independent x64 / x86 / x84
[ embedded config block ]   ← Arch, Bypass, Method, Class, Params
[ compressed payload ]      ← original PE / .NET / script bytes
```

### Input format matrix

| Format | `Type` constant | `Class` required | `Method` required |
|---|---|---|---|
| Native EXE | `ModuleEXE` | — | — |
| Native DLL | `ModuleDLL` | — | export name |
| .NET EXE | `ModuleNetEXE` | — | — |
| .NET DLL | `ModuleNetDLL` | yes | yes |
| VBScript | `ModuleVBS` | — | — |
| JScript | `ModuleJS` | — | — |
| XSL | `ModuleXSL` | — | — |

## API Reference

### `type Arch int` — `ArchX32`, `ArchX64`, `ArchX84`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#Arch)

Target architecture for the emitted shellcode. `ArchX64` is the
zero-value used by `DefaultConfig`; `ArchX84` produces a
dual-mode blob that runs on both x86 and x64 hosts.

**OPSEC:** `ArchX84` doubles signature surface — pick a single
arch when the target environment is known.

**Required privileges:** unprivileged (pure data constant).

**Platform:** cross-platform (emitter); shellcode targets Windows.

### `type ModuleType int`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#ModuleType)

Input format selector. Values: `ModuleNetDLL`, `ModuleNetEXE`,
`ModuleDLL`, `ModuleEXE`, `ModuleVBS`, `ModuleJS`, `ModuleXSL`.
See the format matrix above for which fields are required.

**Required privileges:** unprivileged (pure data constant).

**Platform:** cross-platform.

### `type Config struct`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#Config)

Knob set passed to every `Convert*`. Fields: `Arch` (default
`ArchX64`); `Type` (0 → auto-detected by `ConvertFile` only);
`Class` — .NET class name (required for `ModuleNetDLL`);
`Method` — .NET method or native DLL export to call;
`Parameters` — command-line passed to the payload; `Bypass` —
AMSI/WLDP behaviour (1 skip, 2 abort on fail, 3 continue on
fail); `Thread` — run the entry point in a new thread.

**Required privileges:** unprivileged (pure data type).

**Platform:** cross-platform.

### `DefaultConfig() *Config`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#DefaultConfig)

Returns `&Config{Arch: ArchX64, Type: ModuleEXE, Bypass: 3}` —
the most common stage-as-EXE path with continue-on-AMSI-fail.

**Side effects:** none.

**Required privileges:** unprivileged (pure data constructor).

**Platform:** cross-platform.

### `ConvertFile(path string, cfg *Config) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#ConvertFile)

Read a file from disk and produce position-independent shellcode.
Auto-detects `cfg.Type` from the file extension when zero.

**Parameters:** `path` — input PE / .NET assembly / script;
`cfg` — nil → `DefaultConfig`.

**Returns:** flat byte slice ready for any injection primitive;
error from file read or Donut conversion.

**Side effects:** reads `path`.

**OPSEC:** silent at conversion; the resulting buffer carries
Donut's signature byte pattern.

**Required privileges:** unprivileged (read access on `path`).

**Platform:** cross-platform (emitter).

### `ConvertBytes(data []byte, cfg *Config) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#ConvertBytes)

Convert an in-memory PE buffer. Useful when the payload is
decrypted in-process and never lands on disk. `cfg.Type` must be
set explicitly — there's no extension to auto-detect.

**Parameters:** `data` — raw PE bytes (validates the `MZ`
header); `cfg` — must set `Type`.

**Returns:** shellcode bytes; error on short input, missing
`MZ`, or Donut failure.

**Side effects:** none.

**Required privileges:** unprivileged (in-memory conversion).

**Platform:** cross-platform.

### `ConvertDLL(dllPath string, cfg *Config) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#ConvertDLL)

Shorthand for `ConvertFile` with `cfg.Type` pinned to
`ModuleDLL`. `cfg.Method` should name the export to call.

**Side effects:** reads `dllPath`.

**Required privileges:** unprivileged (read access on `dllPath`).

**Platform:** cross-platform.

### `ConvertDLLBytes(dllBytes []byte, cfg *Config) ([]byte, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi#ConvertDLLBytes)

In-memory variant of `ConvertDLL`.

**Side effects:** none.

**Required privileges:** unprivileged (in-memory conversion).

**Platform:** cross-platform.

## Examples

### Simple — convert a native EXE

```go
import "github.com/oioio-space/maldev/pe/srdi"

cfg := srdi.DefaultConfig()
shellcode, _ := srdi.ConvertFile("payload.exe", cfg)
```

### Composed — DLL with named export

```go
cfg := srdi.DefaultConfig()
cfg.Type = srdi.ModuleDLL
cfg.Method = "ReflectiveLoader"
shellcode, _ := srdi.ConvertDLL("payload.dll", cfg)
```

### Advanced — .NET DLL + dual-mode + remote injection

End-to-end: convert a .NET DLL to dual-mode shellcode, then hand
it to `inject.NewWindowsInjector` with indirect syscalls.

```go
import (
    "github.com/oioio-space/maldev/inject"
    "github.com/oioio-space/maldev/pe/srdi"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

cfg := &srdi.Config{
    Arch:   srdi.ArchX84, // dual x86 + x64
    Type:   srdi.ModuleNetDLL,
    Class:  "Loader.Stub",
    Method: "Run",
    Bypass: 3,
}
sc, _ := srdi.ConvertFile("loader.dll", cfg)

icfg := inject.DefaultWindowsConfig(inject.MethodCreateRemoteThread, targetPID)
icfg.SyscallMethod = wsyscall.MethodIndirect

inj, _ := inject.NewWindowsInjector(icfg)
_ = inj.Inject(sc)
```

See [`ExampleConvertFile`](../../../pe/srdi/srdi_example_test.go)
+ [`ExampleConvertBytes`](../../../pe/srdi/srdi_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Donut loader stub byte signature | YARA / memory scanners — Defender, MDE, CrowdStrike all carry Donut signatures by default |
| RWX page allocation in target | Behavioural EDR — Donut's mini-loader writes then executes; RWX is the canonical "shellcode" tell |
| AMSI / WLDP patch ranges in lsass / current process | Microsoft-Windows-Threat-Intelligence ETW provider |
| .NET assembly load events without a corresponding `.exe` on disk | ETW Microsoft-Windows-DotNETRuntime; Defender flags managed runtime hosting from non-managed processes |
| Sustained `LoadLibraryW` / `GetProcAddress` from a freshly-allocated region | EDR API correlation |

**D3FEND counters:**

- [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/)
  — RWX + execute-from-allocation telemetry.
- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/)
  — YARA on the loader stub byte pattern.

**Hardening for the operator:**

- Encrypt the shellcode with [`crypto`](../crypto/README.md)
  before the injector writes it to RWX — the stub stays
  detectable but only after the implant has staged.
- Use `inject`'s sleep-mask + indirect syscall combination so
  the stub bytes are absent from memory between callbacks.
- Avoid `ArchX84` unless dual-mode is genuinely required — the
  larger blob carries both x86 + x64 signatures.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Process Injection: Dynamic-link Library Injection | partial — produces shellcode for downstream injection (consumer side) | D3-PA |
| [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | full — Donut loader stub is a textbook reflective loader | D3-FCA, D3-PA |

## Limitations

- **Detectable stub.** Donut's loader carries a known byte
  pattern; signature-based YARA + memory scans flag it.
- **RWX allocation.** The mini PE loader writes and then
  executes — RWX is the canonical shellcode tell.
- **No built-in obfuscation.** Stub bytes are not encrypted by
  default; pair with `crypto` + sleep masking.
- **Windows payloads only.** Shellcode generation runs
  cross-platform; the produced shellcode targets Windows.
- **+5–10% size overhead.** Donut compresses the input but adds
  the loader stub; expect modest growth.

## Credits

- [Binject/go-donut](https://github.com/Binject/go-donut) — pure-Go Donut port (vendored).
- [TheWover/donut](https://github.com/TheWover/donut) — original C reference.
- [monoxgas/sRDI](https://github.com/monoxgas/sRDI) — sRDI technique that inspired Donut.

## See also

- [`inject`](../injection/README.md) — execution surface for the
  produced shellcode.
- [`crypto`](../crypto/README.md) — payload encryption pre-conversion.
- [`evasion/sleepmask`](../evasion/sleep-mask.md) — hide the
  stub between callbacks.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
