# maldev -- Modular Malware Development Library in Go

A modular, multi-module Go library providing building blocks for offensive security tooling, red team operations, and penetration testing. Each module is independently importable and designed to compile on its target platform without pulling in unrelated dependencies.

## Module Table

| Module | Import Path | Description |
|--------|-------------|-------------|
| **core** | `github.com/oioio-space/maldev/core` | Pure Go utilities: crypto, encoding, hashing, compatibility shims (no syscall deps) |
| **win** | `github.com/oioio-space/maldev/win` | Windows API primitives: DLL handles, token manipulation, privilege helpers, impersonation, domain queries, version detection |
| **evasion** | `github.com/oioio-space/maldev/evasion` | Anti-analysis and evasion: AMSI/ETW bypass, ntdll unhooking, ACG, DLL blocking, Phant0m, anti-debug, anti-VM, sandbox detection, timing evasion |
| **injection** | `github.com/oioio-space/maldev/injection` | Unified shellcode injection: 8 Windows methods (CRT, APC, EarlyBird, Hollowing, Syscall, Fiber, etc.) + 3 Linux methods (ptrace, memfd, procmem) with fallback chains |
| **privilege** | `github.com/oioio-space/maldev/privilege` | Privilege escalation: UAC bypass techniques (FODHelper, SLUI, SilentCleanup, EventVwr) |
| **process** | `github.com/oioio-space/maldev/process` | Process utilities: cross-platform enumeration, session management, cross-session process creation |
| **system** | `github.com/oioio-space/maldev/system` | System information: drive detection/monitoring, network interface enumeration, special folder paths, UI (message boxes) |
| **pe** | `github.com/oioio-space/maldev/pe` | PE file manipulation: UPX header mutation to defeat unpackers and change file hashes |
| **cleanup** | `github.com/oioio-space/maldev/cleanup` | Artifact cleanup: self-deletion (NTFS ADS), service hiding (DACL), secure file wiping, timestomping |
| **c2** | `github.com/oioio-space/maldev/c2` | Command and control: reverse shell with reconnection, Meterpreter staging, TLS transport with cert pinning, certificate generation |
| **cve** | `github.com/oioio-space/maldev/cve/CVE-2024-30088` | Exploit implementations: CVE-2024-30088 Windows kernel TOCTOU race for local privilege escalation to SYSTEM |
| **tools** | `tools/rshell` | Standalone tool binaries built on the library modules |

## Quick Start

### Installation

```bash
# Import the modules you need in your go.mod
go get github.com/oioio-space/maldev/injection@latest
go get github.com/oioio-space/maldev/evasion@latest
go get github.com/oioio-space/maldev/c2@latest
```

### Example: Shellcode Injection with Evasion

```go
package main

import (
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/injection"
)

func main() {
    // Disable AMSI and ETW
    amsi.PatchScanBuffer()
    etw.PatchETW()

    // Inject shellcode into current process
    cfg := &injection.Config{
        Method:   injection.MethodCreateThread,
        Fallback: true,
    }
    shellcode, _ := injection.ReadShellcode("payload.bin")
    injection.InjectWithFallback(cfg, shellcode)
}
```

## Build Instructions

### Requirements

- **Go 1.20+** (uses auto-seeded math/rand, generics in compat layer)
- **Windows SDK** headers are NOT required -- all syscalls use `golang.org/x/sys/windows`
- **CGO is optional** -- the injection module supports pure Go execution on Linux via `purego`

### Building

```bash
# Build all modules (workspace mode)
go build ./...

# Build a specific module
cd injection && go build ./...

# Cross-compile for Windows from Linux/macOS
GOOS=windows GOARCH=amd64 go build ./...

# Cross-compile for Linux from Windows
set GOOS=linux
set GOARCH=amd64
go build ./...

# Build with size optimization
go build -ldflags="-s -w" ./...
```

### Workspace Mode

The project uses Go workspaces (`go.work`) to link all modules for local development:

```bash
# All modules are automatically resolved via go.work
go build ./...
go test ./...
```

## Architecture

```
maldev/
|
|-- core/                  Pure Go utilities (no syscall dependencies)
|   |-- crypto/            Encryption primitives (AES, RC4, XOR)
|   |-- encode/            Encoding (Base64, hex, UUID)
|   |-- hash/              Hashing (MD5, SHA-256, DJB2, CRC32)
|   |-- utils/             General helpers
|   +-- compat/            Go version compatibility shims (slices, slog, cmp)
|
|-- win/                   Windows API layer
|   |-- api/               DLL handles + procedure references (single source of truth)
|   |-- token/             Token manipulation (privileges, integrity, duplication)
|   |-- privilege/         Admin detection, RunAs, CreateProcessWithLogon
|   |-- impersonate/       Thread impersonation
|   |-- domain/            Domain membership queries
|   +-- version/           OS version detection + CVE vulnerability checks
|
|-- evasion/               Anti-analysis and defense evasion
|   |-- amsi/              AMSI bypass (memory patching)
|   |-- etw/               ETW bypass (event write patching)
|   |-- unhook/            EDR unhooking (ntdll restoration)
|   |-- acg/               Arbitrary Code Guard policy
|   |-- blockdlls/         Non-Microsoft DLL blocking
|   |-- phant0m/           Event Log thread termination
|   |-- antidebug/         Debugger detection (cross-platform)
|   |-- antivm/            VM/hypervisor detection (cross-platform)
|   |-- timing/            Time-based evasion (CPU burn)
|   +-- sandbox/           Sandbox detection orchestrator
|
|-- injection/             Shellcode injection (8 Windows + 3 Linux methods)
|
|-- privilege/             Privilege escalation
|   +-- uacbypass/         UAC bypass (FODHelper, SLUI, SilentCleanup, EventVwr)
|
|-- process/               Process management
|   |-- enum/              Process enumeration (cross-platform)
|   +-- session/           Cross-session execution and impersonation
|
|-- system/                System information
|   |-- drive/             Drive detection and monitoring
|   |-- network/           IP address and local detection
|   |-- folder/            Windows special folder paths
|   +-- ui/                Message boxes and system sounds
|
|-- pe/                    PE file manipulation
|   +-- morph/             UPX header mutation
|
|-- cleanup/               Artifact cleanup
|   |-- selfdelete/        Self-deletion (NTFS ADS, script, reboot)
|   |-- service/           Service hiding (DACL manipulation)
|   |-- wipe/              Secure file wiping
|   +-- timestomp/         File timestamp manipulation
|
|-- c2/                    Command and control
|   |-- cert/              TLS certificate generation
|   |-- transport/         TCP/TLS transport with cert pinning
|   |-- shell/             Reverse shell with reconnection + evasion
|   +-- meterpreter/       Metasploit Meterpreter staging
|
|-- cve/                   Exploit implementations
|   +-- CVE-2024-30088/    Windows kernel LPE (TOCTOU race)
|
+-- tools/                 Standalone tool binaries
    +-- rshell/            Reverse shell tool
```

## License

This project is for authorized security research, red team operations, and penetration testing purposes only. Unauthorized use of these tools against systems you do not own or have explicit permission to test is prohibited.
