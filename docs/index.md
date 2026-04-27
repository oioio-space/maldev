---
last_reviewed: 2026-04-27
reflects_commit: 2df4ee4
---

# Documentation Index

[← maldev README](../README.md)

The navigation spine for everything in `docs/`. Three ways in, depending on
what you came for.

> [!TIP]
> If you don't know where to start, pick a **role** first; the role page
> walks you through a curated reading order.

## By role

| Role | What you get |
|---|---|
| 🟥 [**Operator** (red team)](by-role/operator.md) | Production chains, OPSEC, payload delivery, common scenarios |
| 🔬 [**Researcher** (R&D)](by-role/researcher.md) | Architecture, Caller pattern, paper references, Windows-version deltas |
| 🟦 [**Detection engineer** (blue team)](by-role/detection-eng.md) | Per-technique artifacts, telemetry, D3FEND counters, hunt examples |

## By technique area

Each area page lists every technique in the area with a one-liner; click
through for the full template (Primer / How It Works / API / Examples /
OPSEC / MITRE / Limitations / See also).

| Area | Pages | What's covered |
|---|---|---|
| [c2](techniques/c2/README.md) | 6 | reverse shell + reconnect, transport (TLS/JA3), Meterpreter staging, multicat, named pipe |
| [cleanup](techniques/cleanup/README.md) | 7 | self-delete, secure wipe, timestomp, ADS, BSOD, service hide |
| [collection](techniques/collection/README.md) | 5 | keylog, clipboard, screenshot, ADS, LSASS dump |
| [credentials](techniques/credentials/README.md) | 4 | LSASS dump, sekurlsa parser, SAM offline, Golden Ticket |
| [crypto / encode / hash](techniques/crypto/README.md) | 3 | payload encryption (AES-GCM, ChaCha20, XTEA, S-Box), Base64/UTF-16/PowerShell, fuzzy hashes (ssdeep/TLSH) |
| [evasion](techniques/evasion/README.md) | 19 | AMSI/ETW patches, ntdll unhook, sleep mask, ACG, BlockDLLs, callstack spoof, kernel callback removal, anti-VM/sandbox/timing |
| [injection](techniques/injection/README.md) | 12 | CreateThread, EarlyBird APC, ThreadHijack, SectionMap, KernelCallback, Phantom DLL, ThreadPool, NtQueueApcThreadEx, EtwpCreateEtwThread, … |
| [pe](techniques/pe/README.md) | 7 | strip & sanitize, BOF loader, morph, PE-to-shellcode, certificate theft, masquerade |
| [persistence](techniques/persistence/README.md) | 6 | Run/RunOnce, startup folder LNK, scheduled task, service, account creation |
| [runtime](techniques/runtime/README.md) | 2 | BOF / COFF loader, in-process .NET CLR hosting |
| [syscalls](techniques/syscalls/README.md) | 3 | direct & indirect syscalls, API hashing (ROR13, FNV1a, …), SSN resolvers (Hell's / Halo's / Tartarus / Hash Gate) |
| [tokens](techniques/tokens/README.md) | 3 | token theft, impersonation, privilege escalation |

## By MITRE ATT&CK ID

<!-- BEGIN AUTOGEN: mitre-index -->

| T-ID | Packages |
|---|---|
| [T1070](https://attack.mitre.org/techniques/T1070/) | [`cleanup/memory`](../cleanup/memory) |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | [`cleanup/selfdelete`](../cleanup/selfdelete) · [`cleanup/wipe`](../cleanup/wipe) |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | [`cleanup/timestomp`](../cleanup/timestomp) |
| [T1529](https://attack.mitre.org/techniques/T1529/) | [`cleanup/bsod`](../cleanup/bsod) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [`cleanup/service`](../cleanup/service) |
| [T1564](https://attack.mitre.org/techniques/T1564/) | [`cleanup/service`](../cleanup/service) |
| [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | [`cleanup/ads`](../cleanup/ads) |

<!-- END AUTOGEN: mitre-index -->

## By package

Browseable, alphabetical. Click any package to jump to its `pkg.go.dev`
godoc.

<!-- BEGIN AUTOGEN: package-index -->

| Package | Detection | Summary |
|---|---|---|
| [`.`](https://pkg.go.dev/github.com/oioio-space/maldev) | — | is a modular malware development library for offensive
security research and red team operations |
| [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) | — | provides command and control building blocks: reverse shells,
Meterpreter staging, pluggable transports (TCP/TLS/uTLS/NamedPipe), mTLS
certificate helpers, and session multiplexing |
| [`c2/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert) | — | provides self-signed X.509 certificate generation and
fingerprint computation for C2 TLS infrastructure |
| [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) | — | implements Metasploit Framework staging functionality
for receiving and executing second-stage Meterpreter payloads |
| [`c2/multicat`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/multicat) | — | provides a multi-session reverse shell listener for operator use |
| [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) | — | provides a reverse shell implementation with automatic
reconnection, PTY support, and optional Windows evasion techniques |
| [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) | — | provides pluggable network transport implementations
for C2 communication including plain TCP and TLS with certificate pinning |
| [`c2/transport/namedpipe`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe) | — | provides a Windows named pipe transport implementing
the transport.Transport and transport.Listener interfaces |
| [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) | — | provides on-host artifact removal and anti-forensics
utilities used after an operation completes |
| [`cleanup/ads`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads) | quiet | provides CRUD operations for NTFS Alternate Data Streams |
| [`cleanup/bsod`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/bsod) | very-noisy | triggers a Blue Screen of Death via NtRaiseHardError as a
last-resort cleanup primitive |
| [`cleanup/memory`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory) | very-quiet | provides secure memory cleanup primitives for wiping
sensitive data (shellcode, keys, credentials) from process memory |
| [`cleanup/selfdelete`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/selfdelete) | moderate | deletes the running executable from disk while the
process continues to execute from its mapped image |
| [`cleanup/service`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/service) | noisy | hides Windows services from listing utilities by applying
a restrictive DACL on the service object |
| [`cleanup/timestomp`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/timestomp) | quiet | resets a file's NTFS `$STANDARD_INFORMATION` timestamps
so a dropped artifact blends with surrounding files |
| [`cleanup/wipe`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/wipe) | quiet | overwrites file contents with cryptographically random data
before deletion to defeat trivial forensic recovery |
| [`cmd/docgen`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/docgen) | — | Command docgen regenerates the package-table sections of README.md,
docs/index.md, and docs/mitre.md from each public package's doc.go |
| [`cmd/lsass-dump-test`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/lsass-dump-test) | — | Command lsass-dump-test is a one-shot helper for the v0.30.0 VM
validation effort: it runs credentials/lsassdump.DumpToFile against
the local lsass.exe and writes the resulting MINIDUMP to the path
supplied via -out |
| [`cmd/memscan-harness`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/memscan-harness) | — | Command memscan-harness is the target-side companion for the
vm-test-memscan orchestrator |
| [`cmd/memscan-mcp`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/memscan-mcp) | — | Command memscan-mcp is a minimal Model Context Protocol adapter that
exposes the memscan-server HTTP API as MCP tools over stdio JSON-RPC 2.0 |
| [`cmd/memscan-server`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/memscan-server) | — | Command memscan-server exposes a minimal HTTP/JSON inspection API
(ReadProcessMemory, EnumProcessModules, export lookup) on port 50300 so
that host-side test orchestrators can verify byte patterns inside a
running target process |
| [`cmd/rshell`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/rshell) | — | rshell is a minimal reverse shell using c2/shell and c2/transport |
| [`cmd/sleepmask-demo`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/sleepmask-demo) | — | Command sleepmask-demo runs encrypted-sleep scenarios against a
concurrent memory scanner |
| [`cmd/test-report`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/test-report) | — | Command test-report ingests one or more `go test -json` output streams
and emits a per-test / per-package / per-platform matrix report |
| [`cmd/vmtest`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/vmtest) | — | Command vmtest runs the maldev Go test suite inside isolated VMs with
snapshot restore between runs |
| [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) | — | provides data collection techniques for post-exploitation |
| [`collection/clipboard`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/clipboard) | — | provides Windows clipboard monitoring and capture |
| [`collection/keylog`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog) | — | captures keystrokes using a low-level keyboard hook |
| [`collection/screenshot`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/screenshot) | — | captures screen contents via GDI BitBlt |
| [`credentials/goldenticket`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/goldenticket) | — | forges Kerberos Golden Tickets — long-lived
TGTs minted with a stolen krbtgt account hash |
| [`credentials/lsassdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump) | — | produces a MiniDump blob of lsass.exe's memory so
downstream tooling (credentials/sekurlsa, mimikatz, pypykatz) can
extract Windows credentials |
| [`credentials/samdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump) | — | performs offline NT-hash extraction from a SAM
hive (with the SYSTEM hive supplying the boot key) |
| [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) | — | extracts credential material from a Windows LSASS
minidump — the consumer counterpart to credentials/lsassdump |
| [`crypto`](https://pkg.go.dev/github.com/oioio-space/maldev/crypto) | — | provides cryptographic primitives for payload encryption
and decryption |
| [`encode`](https://pkg.go.dev/github.com/oioio-space/maldev/encode) | — | provides encoding and decoding utilities for payload
transformation |
| [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) | — | defines the Technique interface and shared primitives used
by the sub-packages to bypass defensive software (AMSI, ETW, inline hooks,
sandbox/debugger/VM checks) |
| [`evasion/acg`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/acg) | — | provides Arbitrary Code Guard (ACG) process mitigation policy
management for preventing dynamic code generation |
| [`evasion/amsi`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi) | — | provides AMSI (Antimalware Scan Interface) bypass techniques
through runtime memory patching of amsi.dll functions |
| [`evasion/blockdlls`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/blockdlls) | — | provides DLL blocking via process mitigation policies
to prevent non-Microsoft DLLs from being loaded into the process |
| [`evasion/callstack`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack) | — | spoofs the return-address chain seen by a stack
walker at a given call site, so protected-API calls appear to
originate from the expected thread-init sequence rather than from
the caller's own module |
| [`evasion/cet`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/cet) | — | inspects and relaxes Intel CET (Control-flow Enforcement
Technology) shadow-stack enforcement for the current process, and
exposes the ENDBR64 marker required by CET-gated indirect call sites |
| [`evasion/etw`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw) | — | provides ETW (Event Tracing for Windows) bypass techniques
through runtime patching of ntdll event writing functions |
| [`evasion/hook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook) | — | provides x64 inline function hooking — intercept any exported
Windows function by patching its prologue with a JMP to a Go callback |
| [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) | — | provides a bidirectional control channel between a hook
handler running in a target process and the implant that injected it |
| [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) | — | provides pre-fabricated x64 shellcode templates for
use as handlers in RemoteInstall |
| [`evasion/kcallback`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback) | — | enumerates the kernel-mode callback arrays EDR
products register to observe process/thread/image-load events, and
(pluggable future work) provides the surface to remove them |
| [`evasion/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset) | — | provides ready-to-use evasion technique combinations at
three risk levels: Minimal, Stealth, and Aggressive |
| [`evasion/sleepmask`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask) | — | provides encrypted sleep to defeat memory scanning |
| [`evasion/stealthopen`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen) | — | opens files by their NTFS Object ID (a 128-bit GUID
stored in the MFT) rather than by path, bypassing path-based EDR hooks on
NtCreateFile / CreateFile |
| [`evasion/unhook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook) | — | provides techniques to remove EDR/AV hooks from ntdll.dll
by restoring original function bytes from a clean copy |
| [`hash`](https://pkg.go.dev/github.com/oioio-space/maldev/hash) | — | provides hashing utilities for integrity verification,
API hashing, and fuzzy hashing |
| [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) | — | provides unified shellcode injection techniques
for Windows and Linux platforms with automatic fallback support |
| [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) | — | defines the kernel-memory primitive interfaces consumed
by EDR-bypass packages that need arbitrary kernel reads or writes
(kcallback, lsassdump PPL-bypass, callback-array tampering, etc.) |
| [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) | — | wraps the MSI Afterburner RTCore64.sys signed driver
(CVE-2019-16098) as a kernel/driver.ReadWriter primitive |
| [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) | — | provides Portable Executable analysis and manipulation utilities |
| [`pe/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert) | — | provides PE Authenticode certificate manipulation — read,
copy, strip, and write certificate data in PE files |
| [`pe/imports`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports) | — | provides cross-platform PE import table analysis |
| [`pe/masquerade`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade) | — | provides programmatic PE resource extraction and .syso
generation for identity cloning |
| [`pe/morph`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph) | — | provides UPX header mutation for PE files to prevent
automatic unpacking and change file hashes |
| [`pe/parse`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse) | — | provides PE file parsing and modification utilities |
| [`pe/srdi`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi) | — | provides PE/DLL/EXE-to-shellcode conversion using the Donut
framework (github.com/Binject/go-donut) |
| [`pe/strip`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip) | — | provides PE binary sanitization to remove Go-specific
metadata and compilation artifacts that fingerprint the toolchain |
| [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) | — | provides system persistence techniques for maintaining
access across reboots |
| [`persistence/account`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account) | — | provides Windows local user account management via NetAPI32 |
| [`persistence/lnk`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk) | — | creates Windows shortcut (.lnk) files via COM/OLE automation |
| [`persistence/registry`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry) | — | provides Windows registry Run/RunOnce key persistence |
| [`persistence/scheduler`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler) | — | creates, deletes, lists and runs Windows scheduled tasks
via the COM ITaskService API — no schtasks.exe child process |
| [`persistence/service`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service) | — | provides Windows service persistence via the Service Control Manager |
| [`persistence/startup`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup) | — | provides StartUp folder persistence via LNK shortcut files |
| [`privesc/cve202430088`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088) | — | implements CVE-2024-30088, a Windows kernel TOCTOU
race condition in AuthzBasepCopyoutInternalSecurityAttributes that allows
local privilege escalation to SYSTEM |
| [`privesc/uac`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/uac) | — | implements UAC (User Account Control) bypass techniques
for executing programs with elevated privileges without a UAC prompt |
| [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) | — | provides cross-platform process enumeration and management |
| [`process/enum`](https://pkg.go.dev/github.com/oioio-space/maldev/process/enum) | — | provides cross-platform process enumeration for listing
and searching running processes by name or PID |
| [`process/session`](https://pkg.go.dev/github.com/oioio-space/maldev/process/session) | — | provides utilities for executing processes and impersonating
threads in other user sessions on Windows |
| [`process/tamper/fakecmd`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/fakecmd) | — | overwrites the current process PEB CommandLine string so
that process-listing tools (Process Explorer, wmic, Get-Process) display a
fake command line rather than the real one |
| [`process/tamper/herpaderping`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping) | — | implements the Process Herpaderping technique |
| [`process/tamper/hideprocess`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/hideprocess) | — | patches NtQuerySystemInformation in a target process
so it returns STATUS_NOT_IMPLEMENTED, blinding that process's ability to
enumerate running processes |
| [`process/tamper/phant0m`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/phant0m) | — | provides Event Log service thread termination (Phant0m technique)
to suppress Windows Event Log recording |
| [`random`](https://pkg.go.dev/github.com/oioio-space/maldev/random) | — | provides cryptographically secure random generation functions |
| [`recon/antidebug`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug) | — | provides cross-platform debugger detection techniques |
| [`recon/antivm`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm) | — | provides cross-platform virtual machine and hypervisor
detection techniques with configurable check dimensions |
| [`recon/dllhijack`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack) | — | discovers DLL-search-order hijack opportunities on
Windows — places where an application will load a DLL from a
user-writable directory BEFORE reaching the legitimate copy (typically
in System32) |
| [`recon/drive`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/drive) | — | provides drive detection, monitoring, and volume information
retrieval for Windows systems |
| [`recon/folder`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder) | — | provides access to Windows special folder paths via the
SHGetSpecialFolderPath Shell32 API |
| [`recon/hwbp`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/hwbp) | — | provides detection and clearing of hardware breakpoints
set by EDR products on NT function prologues |
| [`recon/network`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network) | — | provides IP address retrieval and local address detection
utilities |
| [`recon/sandbox`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox) | — | provides a configurable sandbox/VM evasion orchestrator
that aggregates multiple detection checks into a single assessment |
| [`recon/timing`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/timing) | — | provides time-based evasion techniques that defeat sandbox
analysis systems which fast-forward Sleep() calls |
| [`runtime/bof`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof) | — | provides a minimal Beacon Object File (BOF) loader for
in-memory COFF execution |
| [`runtime/clr`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr) | — | loads the .NET Common Language Runtime (CLR) in-process via the
ICLRMetaHost / ICorRuntimeHost COM interfaces and executes .NET assemblies
from memory without writing them to disk |
| [`testutil`](https://pkg.go.dev/github.com/oioio-space/maldev/testutil) | — | provides shared test helpers for the maldev project |
| [`ui`](https://pkg.go.dev/github.com/oioio-space/maldev/ui) | — | provides Windows UI utilities such as message boxes and system sounds |
| [`useragent`](https://pkg.go.dev/github.com/oioio-space/maldev/useragent) | — | provides a curated database of real browser User-Agent
strings for realistic HTTP traffic generation |
| [`win`](https://pkg.go.dev/github.com/oioio-space/maldev/win) | — | is the parent umbrella for Windows-only primitives |
| [`win/api`](https://pkg.go.dev/github.com/oioio-space/maldev/win/api) | — | is the single source of truth for all Windows DLL handles,
procedure references, and shared structures used across the maldev library |
| [`win/domain`](https://pkg.go.dev/github.com/oioio-space/maldev/win/domain) | — | provides helpers for querying Windows domain membership |
| [`win/impersonate`](https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate) | — | provides Windows thread impersonation utilities
for executing code under alternate user credentials |
| [`win/ntapi`](https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi) | — | provides typed Go wrappers for Native API functions (ntdll.dll) |
| [`win/privilege`](https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege) | — | provides helpers for querying and obtaining elevated
Windows privileges including administrator detection and RunAs execution |
| [`win/syscall`](https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall) | — | provides multiple strategies for invoking Windows NT syscalls,
from standard WinAPI calls through kernel32 to stealthy direct/indirect
syscall techniques that bypass userland hooks |
| [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) | — | provides Windows token manipulation utilities for
querying and modifying process and thread security tokens |
| [`win/version`](https://pkg.go.dev/github.com/oioio-space/maldev/win/version) | — | provides Windows version detection utilities for
determining OS version, build number, and patch level |

<!-- END AUTOGEN: package-index -->

## Cross-cutting guides

| Guide | What it explains |
|---|---|
| [getting-started.md](getting-started.md) | Concepts, terminology, your first implant |
| [architecture.md](architecture.md) | Layered design, dependency flow, Mermaid diagrams |
| [opsec-build.md](opsec-build.md) | Build pipeline: garble, pe/strip, masquerade |
| [mitre.md](mitre.md) | Full MITRE ATT&CK + D3FEND mapping |
| [testing.md](testing.md) | Per-test-type details: injection matrix, Meterpreter sessions, BSOD |
| [vm-test-setup.md](vm-test-setup.md) | Bootstrap a fresh host (VMs, SSH keys, INIT snapshot) |
| [coverage-workflow.md](coverage-workflow.md) | Reproducible cross-platform coverage collection |

## Conventions

| Doc | Audience |
|---|---|
| [conventions/documentation.md](conventions/documentation.md) | Anyone editing docs (this is the source of truth for templates, GFM features, voice, migration order) |
| [refactor-2026-doc/audit-2026-04-27.md](refactor-2026-doc/audit-2026-04-27.md) | Snapshot of pre-refactor state — how we got here |
