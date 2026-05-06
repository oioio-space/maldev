---
last_reviewed: 2026-04-27
reflects_commit: e171423
---

# In-process runtimes

[← maldev README](../../../README.md) · [docs/index](../../index.md)

In-process loaders that execute foreign code (BOFs, .NET assemblies)
without spawning child processes. The implant becomes its own
post-exploitation runtime — useful when child-process creation is
heavily monitored.

> **Where to start (novice path):**
> 1. [`bof`](bof-loader.md) — load a Cobalt-Strike-style BOF
>    (small custom C-compiled gadget) in-process. Cheapest
>    in-process post-ex runtime.
> 2. [`clr`](clr.md) — host the .NET CLR in-process to run
>    Mimikatz / Seatbelt / SharpHound assemblies without
>    spawning `powershell.exe` or dropping `.exe` to disk.
>
> Both avoid child-process creation. Pair with
> [`evasion/preset`](../evasion/preset.md) so the BOF / CLR
> calls don't tip AMSI / ETW.

## Packages

| Package | Tech page | Detection | One-liner |
|---|---|---|---|
| [`runtime/bof`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof) | [bof-loader.md](bof-loader.md) | quiet | Beacon Object File / COFF loader for in-memory x64 object-file execution |
| [`runtime/clr`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr) | [clr.md](clr.md) | moderate | In-process .NET CLR hosting via `ICLRMetaHost` / `ICorRuntimeHost` |

## Quick decision tree

| You want to… | Use |
|---|---|
| …run a small custom C-compiled gadget without dropping an EXE | [`runtime/bof`](bof-loader.md) |
| …run a .NET assembly (Mimikatz, Seatbelt, SharpHound) in-process | [`runtime/clr`](clr.md) |
| …drop a managed assembly to disk and run it | not this area — see Donut via [`pe/srdi`](../pe/pe-to-shellcode.md) |

## MITRE ATT&CK

| T-ID | Name | Packages | D3FEND counter |
|---|---|---|---|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | `runtime/bof` (in-process gadget runtime) | D3-PSA |
| [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | `runtime/clr` | D3-PMA, D3-PSA |

## See also

- [Operator path: end-to-end chain](../../by-role/operator.md)
- [Researcher path: how the CLR v2 activation chain works](../../by-role/researcher.md#in-process-runtime)
