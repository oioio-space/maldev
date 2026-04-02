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
| **[Evasion Techniques](docs/evasion.md)** | [AMSI](docs/evasion.md#amsi-bypass-evasionamsi) &#183; [ETW](docs/evasion.md#etw-bypass-evasionetw) &#183; [Unhook](docs/evasion.md#ntdll-unhooking-evasionunhook) &#183; [Herpaderping](docs/evasion.md#process-herpaderping-evasionherpaderping----t1055) &#183; [Phant0m](docs/evasion.md#phant0m-evasionphant0m) &#183; [Sandbox](docs/evasion.md#sandbox-detection-evasionsandbox) &#183; [AntiVM](docs/evasion.md#antivm----parameterizable-config-evasionantivm) &#183; [Presets](docs/evasion.md#composable-evasion-evasionpreset) &#183; [Hook Detection](docs/evasion.md#hook-detection-evasionunhook) |
| **[Process Injection](docs/injection.md)** | [13 methods](docs/injection.md#injection-methods) &#183; [Remote inject](docs/injection.md#remote-injection-into-an-existing-process) &#183; [Fallback](docs/injection.md#injection-with-automatic-fallback) &#183; [Syscall bypass](docs/injection.md#injection-with-syscall-bypass-edr-evasion) |
| **[Syscall Methods](docs/syscalls.md)** | WinAPI &#183; NativeAPI &#183; Direct &#183; Indirect syscall strategies + SSN resolvers |
| **[Command & Control](docs/c2.md)** | TCP/TLS transport &#183; Reverse shell &#183; Meterpreter staging |
| **[MITRE ATT&CK Map](docs/mitre.md)** | 17 techniques across all packages |

## Packages

| Layer | Package | Description | MITRE | Platform |
|-------|---------|-------------|-------|----------|
| Crypto | `crypto` | AES-256-GCM, ChaCha20-Poly1305, RC4, XOR | -- | Cross-platform |
| Crypto | `encode` | Base64, Base64URL, UTF-16LE, ROT13, PowerShell | -- | Cross-platform |
| Crypto | `hash` | MD5, SHA-256, SHA-512, ROR13 (API hashing) | -- | Cross-platform |
| Crypto | `random` | Cryptographic random strings, bytes, integers | -- | Cross-platform |
| Win | `win/api` | DLL handles, procedure refs, memory patching | -- | Windows |
| Win | `win/syscall` | Pluggable syscall (WinAPI/Direct/Indirect) | -- | Windows |
| Win | `win/ntapi` | Type-safe NT function wrappers | -- | Windows |
| Win | `win/token` | Token manipulation, privilege management | -- | Windows |
| Win | `win/privilege` | Admin detection, RunAs, elevation helpers | -- | Windows |
| Win | `win/impersonate` | Thread impersonation with automatic revert | -- | Windows |
| Win | `win/domain` | Domain membership queries | -- | Windows |
| Win | `win/version` | OS version detection, CVE checks | -- | Windows |
| Evasion | [`evasion/amsi`](docs/evasion.md#amsi-bypass-evasionamsi) | AMSI memory patching | T1562.001 | Windows |
| Evasion | [`evasion/etw`](docs/evasion.md#etw-bypass-evasionetw) | ETW event write patching | T1562.001 | Windows |
| Evasion | [`evasion/unhook`](docs/evasion.md#ntdll-unhooking-evasionunhook) | ntdll.dll restoration | T1562.001 | Windows |
| Evasion | [`evasion/acg`](docs/evasion.md) | Arbitrary Code Guard policy | T1562.001 | Windows 10+ |
| Evasion | [`evasion/blockdlls`](docs/evasion.md) | Block non-Microsoft DLLs | T1562.001 | Windows 10+ |
| Evasion | [`evasion/phant0m`](docs/evasion.md#phant0m-evasionphant0m) | Event Log thread termination | T1562.002 | Windows |
| Evasion | [`evasion/herpaderping`](docs/evasion.md#process-herpaderping-evasionherpaderping----t1055) | Process image tampering | T1055 | Windows 10+ |
| Evasion | [`evasion/antidebug`](docs/evasion.md) | Debugger detection | T1622 | Cross-platform |
| Evasion | [`evasion/antivm`](docs/evasion.md#antivm----parameterizable-config-evasionantivm) | VM/hypervisor detection | T1497.001 | Cross-platform |
| Evasion | [`evasion/sandbox`](docs/evasion.md#sandbox-detection-evasionsandbox) | Multi-factor sandbox detection | T1497 | Cross-platform |
| Evasion | [`evasion/timing`](docs/evasion.md) | CPU-burning delays | T1497.003 | Cross-platform |
| Evasion | [`evasion/preset`](docs/evasion.md#composable-evasion-evasionpreset) | Composable presets (Minimal/Stealth/Aggressive) | -- | Windows |
| Injection | [`inject`](docs/injection.md) | 8 Windows + 5 Linux methods | T1055 | Mixed |
| Process | `process/enum` | Cross-platform process enumeration | T1057 | Cross-platform |
| Process | `process/session` | Cross-session execution | T1134.002 | Windows |
| PE | `pe/parse` | PE file parsing (sections, exports, imports) | -- | Cross-platform |
| PE | `pe/morph` | UPX header mutation | T1027.002 | Cross-platform |
| PE | `pe/srdi` | DLL-to-shellcode conversion (sRDI) | T1055.001 | Cross-platform |
| Cleanup | `cleanup/selfdelete` | Self-deletion (NTFS ADS, script, reboot) | T1070.004 | Windows |
| Cleanup | `cleanup/service` | Service hiding via DACL manipulation | T1564 | Windows |
| Cleanup | `cleanup/wipe` | Multi-pass random overwrite + deletion | T1070.004 | Cross-platform |
| Cleanup | `cleanup/timestomp` | File timestamp manipulation | T1070.006 | Cross-platform |
| C2 | [`c2/transport`](docs/c2.md) | TCP/TLS transport with cert pinning | -- | Cross-platform |
| C2 | [`c2/shell`](docs/c2.md) | Reverse shell with reconnection + evasion | T1059 | Cross-platform |
| C2 | [`c2/meterpreter`](docs/c2.md) | Meterpreter stager (TCP/HTTP/HTTPS) | T1059 | Cross-platform |
| C2 | `c2/cert` | Self-signed X.509 certificate generation | -- | Cross-platform |
| Privilege | `uacbypass` | FODHelper, SLUI, SilentCleanup, EventVwr | T1548.002 | Windows |
| Exploit | `exploit/cve202430088` | Kernel TOCTOU race for LPE to SYSTEM | CVE-2024-30088 | Windows |
| System | `system/drive` | Drive enumeration, monitoring, volume info | -- | Windows |
| System | `system/network` | IP address retrieval, local address detection | -- | Cross-platform |
| System | `system/folder` | Windows special folder paths (CSIDL) | -- | Windows |
| System | `system/ui` | Message boxes and system sounds | -- | Windows |

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
