# maldev

Modular malware development library in Go for offensive security research.

## Architecture

```
Layer 0 (pure)     crypto/  encode/  hash/  random/
                        |
Layer 1 (OS)       win/api  win/syscall  win/ntapi  win/token  win/privilege  win/version
                        |
Layer 2 (tech)     evasion/*  inject/  process/  pe/  cleanup/  system/  uacbypass/
                        |
Layer 3 (orch)     c2/transport  c2/shell  c2/meterpreter  c2/cert
                        |
Exploits           exploit/cve202430088
Executables        cmd/rshell
Internal           internal/compat (slog/cmp/slices polyfills for Go 1.21)
```

Dependencies flow strictly bottom-up. Layer 0 packages are pure Go with no OS interaction. Layer 1 wraps Windows APIs behind a single `win/api` package that serves as the source of truth for all DLL handles. Layer 2 implements offensive techniques. Layer 3 orchestrates transport, shells, and staging. The `win/syscall` package provides a pluggable `Caller` that any technique can accept to route NT calls through WinAPI, NativeAPI, direct syscalls, or indirect syscalls.

## Quick Start

```go
import "github.com/oioio-space/maldev/evasion/amsi"

err := amsi.PatchAll(nil) // patch AMSI + bypass session init
```

## Documentation

| Guide | Content |
|-------|---------|
| [Evasion Techniques](docs/evasion.md) | AMSI, ETW, unhook, herpaderping, ACG, sandbox detection, presets |
| [Process Injection](docs/injection.md) | 13 injection methods, fallback chains, syscall bypass |
| [Syscall Methods](docs/syscalls.md) | WinAPI, NativeAPI, Direct, Indirect syscall strategies |
| [Command & Control](docs/c2.md) | TCP/TLS transport, reverse shell, meterpreter staging |
| [MITRE ATT&CK Map](docs/mitre.md) | Complete technique coverage table |

## Packages

| Layer | Package | Description | Platform |
|-------|---------|-------------|----------|
| Crypto | `crypto` | AES-256-GCM, ChaCha20-Poly1305, RC4, XOR | Cross-platform |
| Crypto | `encode` | Base64, Base64URL, UTF-16LE, ROT13, PowerShell encoding | Cross-platform |
| Crypto | `hash` | MD5, SHA-1, SHA-256, SHA-512, ROR13 (API hashing) | Cross-platform |
| Crypto | `random` | Cryptographic random strings, bytes, integers, durations | Cross-platform |
| Win | `win/api` | DLL handles, procedure refs, memory patching | Windows |
| Win | `win/syscall` | Pluggable syscall strategies (WinAPI/Direct/Indirect) | Windows |
| Win | `win/ntapi` | Type-safe NT function wrappers | Windows |
| Win | `win/token` | Token manipulation, privilege management | Windows |
| Win | `win/privilege` | Admin detection, RunAs, elevation helpers | Windows |
| Win | `win/impersonate` | Thread impersonation with automatic revert | Windows |
| Win | `win/domain` | Domain membership queries | Windows |
| Win | `win/version` | OS version detection, CVE vulnerability checks | Windows |
| Evasion | `evasion/*` | 12 techniques -- see [evasion docs](docs/evasion.md) | Mixed |
| Injection | `inject` | 8 Windows + 5 Linux methods -- see [injection docs](docs/injection.md) | Mixed |
| Process | `process/enum` | Cross-platform process enumeration | Cross-platform |
| Process | `process/session` | Cross-session execution and impersonation | Windows |
| PE | `pe/parse` | PE file parsing (sections, exports, imports) | Cross-platform |
| PE | `pe/morph` | UPX header mutation to break unpackers | Cross-platform |
| PE | `pe/srdi` | DLL-to-shellcode conversion (sRDI) | Cross-platform |
| Cleanup | `cleanup/selfdelete` | Self-deletion (NTFS ADS, script, reboot) | Windows |
| Cleanup | `cleanup/service` | Service hiding via DACL manipulation | Windows |
| Cleanup | `cleanup/wipe` | Multi-pass random overwrite before deletion | Cross-platform |
| Cleanup | `cleanup/timestomp` | File timestamp manipulation | Cross-platform |
| C2 | `c2/transport` | TCP/TLS transport with cert pinning | Cross-platform |
| C2 | `c2/shell` | Reverse shell with reconnection, PTY, evasion | Cross-platform |
| C2 | `c2/meterpreter` | Meterpreter stager (TCP/HTTP/HTTPS) | Cross-platform |
| C2 | `c2/cert` | Self-signed X.509 certificate generation | Cross-platform |
| Privilege | `uacbypass` | FODHelper, SLUI, SilentCleanup, EventVwr | Windows |
| Exploit | `exploit/cve202430088` | Kernel TOCTOU race for LPE to SYSTEM | Windows |
| System | `system/drive` | Drive enumeration, monitoring, volume info | Windows |
| System | `system/network` | IP address retrieval, local address detection | Cross-platform |
| System | `system/folder` | Windows special folder paths (CSIDL) | Windows |
| System | `system/ui` | Message boxes and system sounds | Windows |

## Build

```bash
# Build all packages (excludes ignore/)
go build $(go list ./...)

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build $(go list ./...)

# Build with size optimization
go build -ldflags="-s -w" $(go list ./...)

# Run all tests
go test $(go list ./...)
```

**Requirements:**
- Go 1.21+
- Windows SDK headers are NOT required -- all syscalls use `golang.org/x/sys/windows`
- CGO is optional -- the `inject` package supports pure Go execution on Linux via `purego`

## Testing

```bash
# Run safe (non-intrusive) tests
./testutil/run-tests.sh

# Run intrusive tests (requires admin, modifies system state)
./testutil/run-tests.sh --intrusive

# Run Linux tests via Podman
./testutil/run-tests.sh --linux
```

## Project Structure

```
maldev/
+-- crypto/                AES-GCM, ChaCha20, RC4, XOR
+-- encode/                Base64, UTF-16LE, ROT13, PowerShell encoding
+-- hash/                  MD5, SHA-256, SHA-512, ROR13 (API hashing)
+-- random/                Cryptographic random generation
+-- win/
|   +-- api/               DLL handles, procedure refs, memory patching
|   +-- syscall/           Pluggable syscall strategies (WinAPI/Direct/Indirect)
|   +-- ntapi/             Type-safe NT function wrappers
|   +-- token/             Token manipulation and privilege management
|   +-- privilege/         Admin detection, RunAs, elevation helpers
|   +-- impersonate/       Thread impersonation
|   +-- domain/            Domain membership queries
|   +-- version/           OS version detection, CVE checks
+-- evasion/
|   +-- amsi/              AMSI memory patching
|   +-- etw/               ETW event write patching
|   +-- unhook/            ntdll restoration (Classic, Full, Perun)
|   +-- acg/               Arbitrary Code Guard policy
|   +-- blockdlls/         Non-Microsoft DLL blocking
|   +-- phant0m/           Event Log thread termination
|   +-- herpaderping/      Process image tampering (kernel section cache)
|   +-- antidebug/         Debugger detection
|   +-- antivm/            VM/hypervisor detection
|   +-- timing/            CPU-burning time delays
|   +-- sandbox/           Multi-factor sandbox detection
|   +-- preset/            Composable technique presets
+-- inject/                Shellcode injection (8 Win + 5 Linux methods)
+-- process/
|   +-- enum/              Cross-platform process enumeration
|   +-- session/           Cross-session execution
+-- pe/
|   +-- parse/             PE file parsing (sections, exports, imports)
|   +-- morph/             UPX header mutation
|   +-- srdi/              DLL-to-shellcode conversion (sRDI)
+-- cleanup/
|   +-- selfdelete/        Self-deletion (NTFS ADS, script, reboot)
|   +-- service/           Service hiding (DACL)
|   +-- wipe/              Secure file wiping
|   +-- timestomp/         Timestamp manipulation
+-- c2/
|   +-- cert/              X.509 certificate generation
|   +-- transport/         TCP/TLS transport with cert pinning
|   +-- shell/             Reverse shell with reconnection
|   +-- meterpreter/       Meterpreter staging (TCP/HTTP/HTTPS)
+-- uacbypass/             UAC bypass (FODHelper, SLUI, SilentCleanup, EventVwr)
+-- exploit/
|   +-- cve202430088/      CVE-2024-30088 kernel LPE
+-- system/
|   +-- drive/             Drive detection and monitoring
|   +-- network/           IP and local address detection
|   +-- folder/            Windows special folder paths
|   +-- ui/                Message boxes, system sounds
+-- cmd/
|   +-- rshell/            Standalone reverse shell binary
+-- internal/
|   +-- compat/            Go version compatibility shims
+-- testutil/              Test harness and helpers
```

## License

This project is for authorized security research, red team operations, and penetration testing only. Unauthorized use against systems you do not own or have explicit permission to test is prohibited.
