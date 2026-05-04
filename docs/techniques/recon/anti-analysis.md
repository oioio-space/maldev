---
package: github.com/oioio-space/maldev/recon/antidebug + github.com/oioio-space/maldev/recon/antivm
last_reviewed: 2026-05-04
reflects_commit: 7a8c466
---

# Anti-analysis (debugger + VM detection)

[← recon index](README.md) · [docs/index](../../index.md)

## TL;DR

Cross-platform debugger detection ([`antidebug`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug))
+ multi-vendor VM/hypervisor detection ([`antivm`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm)).
Single-shot primitives the implant runs at startup; bail if a
debugger is attached or the host fingerprints as VirtualBox /
VMware / Hyper-V / Parallels / Xen / QEMU / Docker / WSL.

## Primer

Sandboxes are virtual machines. Analysts attach debuggers. If
the implant exits before either can capture a behavioural trace,
the analysis pipeline goes home with empty hands. `antidebug` +
`antivm` are the two cheapest "is this an analysis environment?"
primitives — both bail in microseconds.

`antidebug` reads the PEB BeingDebugged flag (Windows) or
`/proc/self/status TracerPid` (Linux). `antivm` runs configurable
checks across 7 dimensions (registry, files, NIC MAC prefixes,
processes, CPUID/BIOS, DMI info) keyed against vendor-specific
fingerprints. Pair both with [`recon/sandbox`](sandbox.md) for
the multi-factor orchestrator.

## How It Works

```mermaid
flowchart LR
    subgraph debug [antidebug]
        WIN[Windows: IsDebuggerPresent<br>PEB BeingDebugged]
        LIN[Linux: /proc/self/status<br>TracerPid != 0]
    end
    subgraph vm [antivm]
        REG[Registry keys<br>HKLM\HARDWARE\…]
        FILES[VM driver files<br>vmtoolsd, vbox*]
        NIC[MAC prefixes<br>00:0C:29 VMware]
        PROC[Process names<br>vmtoolsd, vboxservice]
        DMI[DMI info<br>BIOS / chassis]
        CPU[CPUID flags<br>hypervisor bit]
    end
    debug --> OUT[bool / vendor name]
    vm --> OUT
    OUT --> SANDBOX[recon/sandbox<br>orchestrator]
```

## API Reference

Two packages: `recon/antidebug` (single-shot debugger probe) +
`recon/antivm` (configurable multi-dimension hypervisor probe).

### Package `recon/antidebug`

#### `func IsDebuggerPresent() bool`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug#IsDebuggerPresent)

Returns `true` when a debugger is attached to the calling process.
Windows path calls `kernel32!IsDebuggerPresent` (PEB
`BeingDebugged` read); Linux path scans
`/proc/self/status` for a non-zero `TracerPid`.

**Returns:** `true` if a debugger is present; `false` on any read
or parse failure (fail-open).

**OPSEC:** the Win32 call is universal and unhooked on every
EDR — no signature; the Linux read of `/proc/self/status` is
similarly invisible.

**Required privileges:** none — self-process only.

**Platform:** cross-platform (Windows / Linux).

### Package `recon/antivm`

#### `type Vendor`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#Vendor)

Per-platform record of indicators. Windows: `Name`, `Keys`
(`[]RegKey`), `Files`, `Nic`, `Proc`. Linux: `Name`, `Files`,
`Nic`, `Proc`, `DMI`. Constructed inline by callers or pulled
from `DefaultVendors`.

**Platform:** cross-platform (struct shape varies by build tag).

#### `type RegKey struct { Hive registry.Key; Path string; ExpectedValue string }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#RegKey)

Registry-key indicator. Empty `ExpectedValue` matches existence
only.

**Platform:** Windows-only.

#### `var DefaultVendors []Vendor`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DefaultVendors)

Built-in indicator list — Hyper-V, Parallels, VirtualBox,
VirtualPC, VMware, Xen, QEMU, Proxmox, KVM, Docker, WSL. Used
when `Config.Vendors` is nil.

**Platform:** cross-platform (entries differ by build tag).

#### `type CheckType uint`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#CheckType)

Bitmask selecting detection dimensions. Constants:
`CheckRegistry` (Windows-only, skipped on Linux), `CheckFiles`,
`CheckNIC`, `CheckProcess`, `CheckCPUID`, and the union
`CheckAll`.

**Platform:** cross-platform.

#### `type Config struct { Vendors []Vendor; Checks CheckType }`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#Config)

Detection configuration. Nil `Vendors` falls back to
`DefaultVendors`; zero `Checks` falls back to `CheckAll`.

**Platform:** cross-platform.

#### `func DefaultConfig() Config`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DefaultConfig)

Returns a zero-value `Config` (nil `Vendors`, zero `Checks`) —
which expands to `DefaultVendors` + `CheckAll` at runtime.

**Returns:** zero `Config`.

**Platform:** cross-platform.

#### `func Detect(cfg Config) (string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#Detect)

Runs the configured checks against each vendor in order and
returns the first matching vendor name.

**Parameters:** `cfg` — vendor list + check bitmask.

**Returns:** vendor name on first match (e.g. `"VMware"`); empty
string if no vendor matched; error from any check that failed
to execute.

**OPSEC:** registry probes / NIC enumeration / file `Stat` are
all universal user-mode operations — no individual signature.
Behavioural correlation of "many vendor probes then early
exit" is post-fact.

**Required privileges:** none — most checks open `HKLM\SOFTWARE`
keys readable by every authenticated user.

**Platform:** cross-platform.

#### `func DetectAll(cfg Config) ([]string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectAll)

Like `Detect`, but iterates every vendor and returns the full
list of matches.

**Returns:** sorted-by-config-order slice of matching vendor
names; error from any failing check.

**Platform:** cross-platform.

#### `func DetectVM() string`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectVM)

Convenience wrapper around `Detect(DefaultConfig())`. Returns
the vendor name or empty string; swallows errors.

**Platform:** cross-platform.

#### `func IsRunningInVM() bool`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#IsRunningInVM)

Boolean shorthand for `DetectVM() != ""`.

**Platform:** cross-platform.

#### `func DetectNic(macPrefixes []string) (bool, string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectNic)

Walks `net.Interfaces` and returns the first NIC whose MAC
starts with any prefix in `macPrefixes`.

**Parameters:** `macPrefixes` — uppercase, colon-separated OUI
prefixes (e.g. `"00:0C:29"` for VMware).

**Returns:** `(true, "<MAC>:<ifname>", nil)` on match; empty
string with `false` otherwise; error from interface
enumeration.

**Platform:** cross-platform.

#### `func DetectFiles(files []string) (bool, string)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectFiles)

`os.Stat` each path; return on first hit.

**Returns:** `(true, path)` on first existing file; `(false, "")`
otherwise.

**Platform:** cross-platform.

#### `func DetectProcess(procNames []string) (bool, string, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectProcess)

Iterates running processes (Toolhelp32 on Windows, `/proc` on
Linux) and matches against `procNames`.

**Returns:** `(true, processName, nil)` on first match; error
from the process snapshot.

**Required privileges:** none beyond default process-list visibility.

**Platform:** cross-platform.

#### `func DetectRegKey(keys []RegKey) (bool, RegKey, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectRegKey)

Probes each `RegKey` for existence (and optional value match).

**Returns:** `(true, matchedKey, nil)` on first hit.

**Platform:** Windows-only.

#### `func DetectDMI() (bool, string)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectDMI)

Reads `/sys/class/dmi/id/*` files (sys_vendor, product_name,
board_vendor, …) and matches against well-known hypervisor
strings.

**Returns:** `(true, "<dmiPath>:<keyword>")` on first match.

**Platform:** Linux-only.

#### `func DetectCPUID() (bool, string)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm#DetectCPUID)

Reads CPUID leaf 0x40000000 (hypervisor vendor signature) on
Windows; reads `/proc/cpuinfo` and matches against hypervisor
keywords on Linux.

**Returns:** `(true, vendorString)` on match.

**OPSEC:** invisible to user-mode telemetry — CPUID is an
unprivileged instruction.

**Platform:** cross-platform.

## Examples

### Simple — bail on detection

```go
import (
    "os"

    "github.com/oioio-space/maldev/recon/antidebug"
    "github.com/oioio-space/maldev/recon/antivm"
)

if antidebug.IsDebuggerPresent() {
    os.Exit(0)
}
if name, _ := antivm.Detect(antivm.DefaultConfig()); name != "" {
    os.Exit(0)
}
```

### Composed — narrow vendor + dimension

```go
cfg := antivm.Config{
    Vendors: []antivm.Vendor{
        {Name: "VMware", Nic: []string{"00:0C:29"}, Files: []string{`C:\windows\system32\drivers\vmtoolsd.sys`}},
    },
    Checks: antivm.CheckNIC | antivm.CheckFiles,
}
if name, _ := antivm.Detect(cfg); name != "" {
    return
}
```

### Advanced — orchestrator integration

See [`recon/sandbox`](sandbox.md) for the multi-factor
[`Checker.IsSandboxed`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox) — debugger +
VM detection are two of the seven dimensions it composes.

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `IsDebuggerPresent` Win32 call | Universal — invisible |
| `/proc/self/status` read | Linux: invisible |
| Registry probes against VM driver keys | EDR usually invisible; some sandbox-aware AV may flag patterns |
| MAC-prefix interface enumeration | Universally invisible |
| CPUID `0x40000000` (hypervisor leaf) | Invisible to user-mode telemetry |
| Behavioural correlation: many checks then early exit | Sandboxes time-out themselves; correlation is post-fact |

**D3FEND counters:**

- [D3-EI](https://d3fend.mitre.org/technique/d3f:ExecutionIsolation/)
  — sandbox executor design.

**Hardening for the operator:**

- Pair `antidebug` + `antivm` with timing-based evasion
  ([`recon/timing`](timing.md)) — sandboxes time out before a
  multi-second BusyWait completes.
- Use [`recon/sandbox`](sandbox.md) for the multi-factor
  pipeline rather than calling primitives independently.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1622](https://attack.mitre.org/techniques/T1622/) | Debugger Evasion | full — `antidebug.IsDebuggerPresent` | D3-EI |
| [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | Virtualization/Sandbox Evasion: System Checks | full — `antivm` 7 dimensions | D3-EI |

## Limitations

- **PEB-only on Windows.** Sophisticated debuggers can clear
  the `BeingDebugged` flag — ScyllaHide and similar harden it.
- **No anti-VMI.** Bare-metal VMI (Volatility-on-host) defeats
  every userland check.
- **Static fingerprints.** Vendors who customise OEM strings
  in DMI / registry can defeat default fingerprints; supply
  custom `Vendor` lists for hostile environments.
- **WSL detection is loose.** WSL2 looks very VM-like; expect
  false positives if WSL is a legitimate target.

## See also

- [Sandbox orchestrator](sandbox.md) — multi-factor pipeline.
- [Time-based evasion](timing.md) — pair to defeat sandbox
  fast-forward.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
