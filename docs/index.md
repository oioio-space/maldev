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
| [crypto](techniques/crypto/README.md) | 1 | payload encryption (AES-GCM, ChaCha20) and signature-breaking transforms (XTEA, S-Box, Matrix, ArithShift, XOR) |
| [encode](techniques/encode/README.md) | 1 | Base64 (std + URL), UTF-16LE, ROT13, PowerShell `-EncodedCommand` |
| [hash](techniques/hash/README.md) | 2 | cryptographic hashes (MD5/SHA-*), ROR13 API hashing, fuzzy hashes (ssdeep, TLSH) |
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
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | [`credentials/lsassdump`](../credentials/lsassdump) · [`credentials/sekurlsa`](../credentials/sekurlsa) |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | [`credentials/samdump`](../credentials/samdump) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | [`c2/transport/namedpipe`](../c2/transport/namedpipe) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | [`crypto`](../crypto) · [`encode`](../encode) · [`evasion/sleepmask`](../evasion/sleepmask) |
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | [`pe`](../pe) · [`pe/morph`](../pe/morph) · [`pe/parse`](../pe/parse) · [`pe/strip`](../pe/strip) |
| [T1027.005](https://attack.mitre.org/techniques/T1027/005/) | [`pe/strip`](../pe/strip) |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | [`crypto`](../crypto) |
| [T1036](https://attack.mitre.org/techniques/T1036/) | [`evasion/callstack`](../evasion/callstack) · [`evasion/stealthopen`](../evasion/stealthopen) |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | [`pe`](../pe) · [`pe/masquerade`](../pe/masquerade) |
| [T1055](https://attack.mitre.org/techniques/T1055/) | [`c2/meterpreter`](../c2/meterpreter) · [`inject`](../inject) |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | [`inject`](../inject) · [`pe`](../pe) · [`pe/srdi`](../pe/srdi) |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | [`inject`](../inject) |
| [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | [`inject`](../inject) |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | [`inject`](../inject) |
| [T1055.015](https://attack.mitre.org/techniques/T1055/015/) | [`inject`](../inject) |
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | [`collection`](../collection) · [`collection/keylog`](../collection/keylog) |
| [T1059](https://attack.mitre.org/techniques/T1059/) | [`c2`](../c2) · [`c2/meterpreter`](../c2/meterpreter) · [`c2/shell`](../c2/shell) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [`c2/shell`](../c2/shell) |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | [`c2/shell`](../c2/shell) |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | [`c2/shell`](../c2/shell) |
| [T1068](https://attack.mitre.org/techniques/T1068/) | [`credentials/lsassdump`](../credentials/lsassdump) |
| [T1070](https://attack.mitre.org/techniques/T1070/) | [`cleanup/memory`](../cleanup/memory) |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | [`cleanup/wipe`](../cleanup/wipe) |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | [`cleanup/timestomp`](../cleanup/timestomp) |
| [T1071](https://attack.mitre.org/techniques/T1071/) | [`c2`](../c2) · [`c2/transport`](../c2/transport) |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | [`c2`](../c2) · [`c2/meterpreter`](../c2/meterpreter) · [`c2/transport/namedpipe`](../c2/transport/namedpipe) · [`useragent`](../useragent) |
| [T1095](https://attack.mitre.org/techniques/T1095/) | [`c2`](../c2) · [`c2/meterpreter`](../c2/meterpreter) · [`c2/transport`](../c2/transport) |
| [T1106](https://attack.mitre.org/techniques/T1106/) | [`pe`](../pe) · [`pe/imports`](../pe/imports) |
| [T1113](https://attack.mitre.org/techniques/T1113/) | [`collection`](../collection) |
| [T1115](https://attack.mitre.org/techniques/T1115/) | [`collection`](../collection) |
| [T1529](https://attack.mitre.org/techniques/T1529/) | [`cleanup/bsod`](../cleanup/bsod) |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | [`credentials/sekurlsa`](../credentials/sekurlsa) |
| [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | [`pe`](../pe) · [`pe/cert`](../pe/cert) |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | [`credentials/goldenticket`](../credentials/goldenticket) |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | [`credentials/sekurlsa`](../credentials/sekurlsa) |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | [`evasion/cet`](../evasion/cet) · [`evasion/kcallback`](../evasion/kcallback) · [`evasion/preset`](../evasion/preset) |
| [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | [`cleanup/ads`](../cleanup/ads) |
| [T1571](https://attack.mitre.org/techniques/T1571/) | [`c2`](../c2) · [`c2/multicat`](../c2/multicat) |
| [T1573](https://attack.mitre.org/techniques/T1573/) | [`c2`](../c2) · [`c2/transport`](../c2/transport) |
| [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | [`c2/cert`](../c2/cert) |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | [`c2`](../c2) · [`c2/cert`](../c2/cert) · [`c2/transport`](../c2/transport) |
| [T1574.012](https://attack.mitre.org/techniques/T1574/012/) | [`evasion/hook`](../evasion/hook) |
| [T1620](https://attack.mitre.org/techniques/T1620/) | [`pe/srdi`](../pe/srdi) |

<!-- END AUTOGEN: mitre-index -->

## By package

Browseable, alphabetical. Click any package to jump to its `pkg.go.dev`
godoc.

<!-- BEGIN AUTOGEN: package-index -->

| Package | Detection | Summary |
|---|---|---|
| [`.`](https://pkg.go.dev/github.com/oioio-space/maldev) | — | is a modular malware development library for offensive
security research and red team operations |
| [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) | Varies | provides command and control building blocks: reverse
shells, Meterpreter staging, pluggable transports (TCP / TLS / uTLS /
named pipe), mTLS certificate helpers, and session multiplexing |
| [`c2/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert) | quiet | provides self-signed X.509 certificate generation and
fingerprint computation for C2 TLS infrastructure |
| [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) | noisy | implements Metasploit Framework staging — pulls
a second-stage Meterpreter payload from a `multi/handler` and
executes it in the current process or a target picked via the
optional `Config.Injector` |
| [`c2/multicat`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/multicat) | quiet | provides a multi-session reverse-shell listener
for operator use |
| [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) | noisy | provides a reverse shell with automatic reconnection,
PTY support, and optional Windows evasion integration |
| [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) | moderate | provides pluggable network transport
implementations for C2 communication: plain TCP, TLS with optional
certificate pinning, and uTLS for JA3/JA4 fingerprint randomisation |
| [`c2/transport/namedpipe`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe) | quiet | provides a Windows named-pipe transport
implementing the [github.com/oioio-space/maldev/c2/transport]
`Transport` and `Listener` interfaces |
| [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) | — | provides on-host artifact removal and anti-forensics
utilities used after an operation completes |
| [`cleanup/ads`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads) | quiet | provides CRUD operations for NTFS Alternate Data Streams |
| [`cleanup/bsod`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/bsod) | very-noisy | triggers a Blue Screen of Death via NtRaiseHardError as a
last-resort cleanup primitive |
| [`cleanup/memory`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory) | very-quiet | provides secure memory cleanup primitives for wiping
sensitive data (shellcode, keys, credentials) from process memory |
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
| [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) | varies | groups local data-acquisition primitives for
post-exploitation: keystrokes, clipboard contents, screen captures |
| [`collection/keylog`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog) | noisy | captures keystrokes via a low-level keyboard hook
(`SetWindowsHookEx(WH_KEYBOARD_LL)`) |
| [`credentials/goldenticket`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/goldenticket) | noisy | forges Kerberos Golden Tickets — long-lived
TGTs minted with a stolen krbtgt account hash |
| [`credentials/lsassdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump) | noisy | produces a MiniDump blob of lsass.exe's memory so
downstream tooling (credentials/sekurlsa, mimikatz, pypykatz) can
extract Windows credentials |
| [`credentials/samdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump) | quiet | performs offline NT-hash extraction from a SAM
hive (with the SYSTEM hive supplying the boot key) |
| [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) | quiet | extracts credential material from a Windows LSASS
minidump — the consumer counterpart to credentials/lsassdump |
| [`crypto`](https://pkg.go.dev/github.com/oioio-space/maldev/crypto) | very-quiet | provides cryptographic primitives for payload
encryption / decryption and lightweight obfuscation |
| [`encode`](https://pkg.go.dev/github.com/oioio-space/maldev/encode) | very-quiet | provides encoding / decoding utilities for payload
transformation: Base64 (standard + URL-safe), UTF-16LE (Windows API
strings), ROT13, and PowerShell `-EncodedCommand` format |
| [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) | — | defines the Technique interface and shared primitives used
by the sub-packages to bypass defensive software (AMSI, ETW, inline hooks,
sandbox/debugger/VM checks) |
| [`evasion/callstack`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack) | quiet | synthesises a return-address chain so a stack
walker at a protected-API call site sees frames that originate from
a benign thread-init sequence rather than from the attacker module |
| [`evasion/cet`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/cet) | noisy | inspects and relaxes Intel CET (Control-flow Enforcement
Technology) shadow-stack enforcement for the current process, and
exposes the ENDBR64 marker required by CET-gated indirect call
sites |
| [`evasion/hook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook) | noisy | installs x64 inline hooks on exported Windows functions:
patch the prologue with a JMP to a Go callback, automatically generate
a trampoline for calling the original, and fix up RIP-relative
instructions in the stolen prologue |
| [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) | — | provides a bidirectional control channel between a hook
handler running in a target process and the implant that injected it |
| [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) | — | provides pre-fabricated x64 shellcode templates for
use as handlers in RemoteInstall |
| [`evasion/kcallback`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback) | very-noisy | enumerates and removes kernel-mode callback
registrations that EDR products use to observe process/thread/image-
load events from the kernel side |
| [`evasion/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset) | varies | bundles `evasion.Technique` primitives into three
validated risk levels for one-shot deployment |
| [`evasion/sleepmask`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask) | quiet | encrypts the implant's payload memory while it
sleeps so concurrent memory scanners cannot recover the original
shellcode bytes or PE headers |
| [`evasion/stealthopen`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen) | quiet | reads files via NTFS Object ID (the 128-bit GUID
stored in the MFT) instead of by path, bypassing path-based EDR
hooks on `NtCreateFile` / `CreateFileW` |
| [`hash`](https://pkg.go.dev/github.com/oioio-space/maldev/hash) | very-quiet | provides cryptographic and fuzzy hash primitives for
integrity verification, API hashing, and similarity detection |
| [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) | noisy | provides unified shellcode injection across Windows
and Linux with a fluent builder, decorator middleware, and automatic
fallback between methods |
| [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) | — | defines the kernel-memory primitive interfaces consumed
by EDR-bypass packages that need arbitrary kernel reads or writes
(kcallback, lsassdump PPL-bypass, callback-array tampering, etc.) |
| [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) | — | wraps the MSI Afterburner RTCore64.sys signed driver
(CVE-2019-16098) as a kernel/driver.ReadWriter primitive |
| [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) | Varies | is the umbrella for Portable Executable analysis,
manipulation, and conversion utilities |
| [`pe/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert) | quiet | manipulates the PE Authenticode security directory
— read, copy, strip, and write WIN_CERTIFICATE blobs without
any Windows crypto API |
| [`pe/imports`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports) | very-quiet | enumerates a PE's import directory — every DLL
dependency and every imported function name — without invoking
any Windows API |
| [`pe/masquerade`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade) | quiet | clones a Windows PE's identity — manifest,
icons, VERSIONINFO, optional Authenticode certificate — into
a linkable `.syso` COFF object so a Go binary picks them up
at compile time |
| [`pe/morph`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph) | moderate | mutates UPX-packed PE headers so automatic
unpackers fail to recognise the input |
| [`pe/parse`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse) | very-quiet | provides PE file parsing and modification utilities |
| [`pe/srdi`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi) | moderate | converts PE / .NET / script payloads into
position-independent shellcode via the Donut framework
(github.com/Binject/go-donut) |
| [`pe/strip`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip) | quiet | sanitises Go-built PE binaries by removing
toolchain artefacts that fingerprint the producer:

  - The Go pclntab (Go 1.16+ magic bytes) — wiped, breaking
    redress, GoReSym, and IDA's `go_parser` plugin |
| [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) | — | provides system persistence techniques for maintaining
access across reboots |
| [`persistence/lnk`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk) | — | creates Windows shortcut (.lnk) files via COM/OLE automation |
| [`persistence/registry`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry) | — | provides Windows registry Run/RunOnce key persistence |
| [`persistence/scheduler`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler) | — | creates, deletes, lists and runs Windows scheduled tasks
via the COM ITaskService API — no schtasks.exe child process |
| [`persistence/service`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service) | — | provides Windows service persistence via the Service Control Manager |
| [`persistence/startup`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup) | — | provides StartUp folder persistence via LNK shortcut files |
| [`privesc/cve202430088`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088) | — | implements CVE-2024-30088, a Windows kernel TOCTOU
race condition in AuthzBasepCopyoutInternalSecurityAttributes that allows
local privilege escalation to SYSTEM |
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
| [`random`](https://pkg.go.dev/github.com/oioio-space/maldev/random) | very-quiet | provides cryptographically secure random generation
helpers backed by `crypto/rand` (OS entropy) |
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
| [`useragent`](https://pkg.go.dev/github.com/oioio-space/maldev/useragent) | very-quiet | provides a curated database of real-world browser
User-Agent strings for HTTP traffic blending |
| [`win/ntapi`](https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi) | — | provides typed Go wrappers for Native API functions (ntdll.dll) |
| [`win/syscall`](https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall) | — | provides multiple strategies for invoking Windows NT syscalls,
from standard WinAPI calls through kernel32 to stealthy direct/indirect
syscall techniques that bypass userland hooks |

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
