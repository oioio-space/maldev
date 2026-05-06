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
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | [`credentials/lsassdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump) · [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | [`credentials/samdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump) |
| [T1014](https://attack.mitre.org/techniques/T1014/) | [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) · [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [`recon/network`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network) · [`win/domain`](https://pkg.go.dev/github.com/oioio-space/maldev/win/domain) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | [`c2/transport/namedpipe`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | [`crypto`](https://pkg.go.dev/github.com/oioio-space/maldev/crypto) · [`encode`](https://pkg.go.dev/github.com/oioio-space/maldev/encode) · [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) · [`evasion/sleepmask`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask) · [`win/api`](https://pkg.go.dev/github.com/oioio-space/maldev/win/api) |
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) · [`pe/morph`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph) · [`pe/parse`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse) · [`pe/strip`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip) |
| [T1027.005](https://attack.mitre.org/techniques/T1027/005/) | [`pe/strip`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip) · [`process/tamper/herpaderping`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping) · [`process/tamper/hideprocess`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/hideprocess) · [`recon/hwbp`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/hwbp) |
| [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | [`win/syscall`](https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall) |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | [`crypto`](https://pkg.go.dev/github.com/oioio-space/maldev/crypto) |
| [T1036](https://attack.mitre.org/techniques/T1036/) | [`evasion/callstack`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack) · [`evasion/stealthopen`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen) |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) · [`pe/masquerade`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade) · [`pe/masquerade/donors`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade/donors) · [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/tamper/fakecmd`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/fakecmd) |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/scheduler`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler) |
| [T1055](https://attack.mitre.org/techniques/T1055/) | [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) · [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) · [`process/tamper/herpaderping`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping) |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) · [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) · [`pe/srdi`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi) |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) |
| [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) |
| [T1055.013](https://attack.mitre.org/techniques/T1055/013/) | [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/tamper/herpaderping`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping) |
| [T1055.015](https://attack.mitre.org/techniques/T1055/015/) | [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) |
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) · [`collection/keylog`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog) |
| [T1057](https://attack.mitre.org/techniques/T1057/) | [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/enum`](https://pkg.go.dev/github.com/oioio-space/maldev/process/enum) |
| [T1059](https://attack.mitre.org/techniques/T1059/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) · [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) · [`runtime/bof`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof) · [`runtime/clr`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) |
| [T1068](https://attack.mitre.org/techniques/T1068/) | [`credentials/lsassdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump) · [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) · [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) · [`privesc/cve202430088`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088) |
| [T1070](https://attack.mitre.org/techniques/T1070/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/memory`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory) |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/selfdelete`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/selfdelete) · [`cleanup/wipe`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/wipe) |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/timestomp`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/timestomp) |
| [T1071](https://attack.mitre.org/techniques/T1071/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) · [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) · [`c2/transport/namedpipe`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe) · [`useragent`](https://pkg.go.dev/github.com/oioio-space/maldev/useragent) |
| [T1078](https://attack.mitre.org/techniques/T1078/) | [`win/privilege`](https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege) |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [`win/domain`](https://pkg.go.dev/github.com/oioio-space/maldev/win/domain) · [`win/version`](https://pkg.go.dev/github.com/oioio-space/maldev/win/version) |
| [T1083](https://attack.mitre.org/techniques/T1083/) | [`recon/drive`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/drive) · [`recon/folder`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder) |
| [T1095](https://attack.mitre.org/techniques/T1095/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) · [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) |
| [T1098](https://attack.mitre.org/techniques/T1098/) | [`persistence/account`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account) |
| [T1106](https://attack.mitre.org/techniques/T1106/) | [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) · [`pe/imports`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports) · [`win/api`](https://pkg.go.dev/github.com/oioio-space/maldev/win/api) · [`win/ntapi`](https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi) · [`win/syscall`](https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall) |
| [T1113](https://attack.mitre.org/techniques/T1113/) | [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) · [`collection/screenshot`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/screenshot) |
| [T1115](https://attack.mitre.org/techniques/T1115/) | [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) · [`collection/clipboard`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/clipboard) |
| [T1120](https://attack.mitre.org/techniques/T1120/) | [`recon/drive`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/drive) |
| [T1134](https://attack.mitre.org/techniques/T1134/) | [`win/privilege`](https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege) · [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) |
| [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | [`privesc/cve202430088`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088) · [`process/session`](https://pkg.go.dev/github.com/oioio-space/maldev/process/session) · [`win/impersonate`](https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate) · [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) |
| [T1134.002](https://attack.mitre.org/techniques/T1134/002/) | [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/session`](https://pkg.go.dev/github.com/oioio-space/maldev/process/session) · [`win/impersonate`](https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate) · [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) |
| [T1134.004](https://attack.mitre.org/techniques/T1134/004/) | [`win/impersonate`](https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate) |
| [T1134.005](https://attack.mitre.org/techniques/T1134/005/) | [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/account`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account) |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/lnk`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk) |
| [T1497](https://attack.mitre.org/techniques/T1497/) | [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) · [`recon/sandbox`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox) |
| [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | [`recon/antivm`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm) |
| [T1497.003](https://attack.mitre.org/techniques/T1497/003/) | [`recon/timing`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/timing) |
| [T1529](https://attack.mitre.org/techniques/T1529/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/bsod`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/bsod) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/service`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/service) · [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) · [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) · [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/service`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service) |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/registry`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry) · [`persistence/startup`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup) |
| [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) · [`persistence/lnk`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk) · [`persistence/startup`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup) |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | [`privesc/uac`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/uac) · [`recon/dllhijack`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack) · [`win/privilege`](https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege) |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) |
| [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) · [`pe/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert) · [`pe/masquerade/donors`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade/donors) |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | [`credentials/goldenticket`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/goldenticket) |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) · [`evasion/acg`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/acg) · [`evasion/amsi`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi) · [`evasion/blockdlls`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/blockdlls) · [`evasion/cet`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/cet) · [`evasion/etw`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw) · [`evasion/kcallback`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback) · [`evasion/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset) · [`evasion/unhook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook) |
| [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/tamper/phant0m`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/phant0m) |
| [T1564](https://attack.mitre.org/techniques/T1564/) | [`cleanup/service`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/service) · [`process/tamper/fakecmd`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/fakecmd) |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) · [`process/tamper/hideprocess`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/hideprocess) |
| [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) · [`cleanup/ads`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads) |
| [T1571](https://attack.mitre.org/techniques/T1571/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/multicat`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/multicat) |
| [T1573](https://attack.mitre.org/techniques/T1573/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) |
| [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | [`c2/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert) |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) · [`c2/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert) · [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | [`pe/dllproxy`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/dllproxy) · [`recon/dllhijack`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack) |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | [`pe/dllproxy`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/dllproxy) |
| [T1574.012](https://attack.mitre.org/techniques/T1574/012/) | [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) · [`evasion/hook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook) · [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) · [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) |
| [T1620](https://attack.mitre.org/techniques/T1620/) | [`pe/srdi`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi) · [`runtime/bof`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof) · [`runtime/clr`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr) |
| [T1622](https://attack.mitre.org/techniques/T1622/) | [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) · [`recon/antidebug`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug) · [`recon/hwbp`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/hwbp) |

<!-- END AUTOGEN: mitre-index -->

## By package

Grouped by area, expandable. Click any package name to jump to its
`pkg.go.dev` godoc; expand an area to scan every package's detection
level and one-line summary in one place.

<!-- BEGIN AUTOGEN: package-index -->

_Each area is collapsed by default — click to expand. Detection level is the canonical 5-level scale (`very-quiet` → `very-noisy`); umbrella / variable packages show as `—`._

<details><summary><strong>Layer 0 — pure-Go primitives (`crypto`, `encode`, `hash`, `random`, `useragent`)</strong> — 5 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`crypto`](https://pkg.go.dev/github.com/oioio-space/maldev/crypto) | very-quiet | provides cryptographic primitives for payload encryption / decryption and lightweight obfuscation |
| [`encode`](https://pkg.go.dev/github.com/oioio-space/maldev/encode) | very-quiet | provides encoding / decoding utilities for payload transformation: Base64 (standard + URL-safe), UTF-16LE (Windows API strings), ROT13, and PowerShell `-EncodedCommand` format |
| [`hash`](https://pkg.go.dev/github.com/oioio-space/maldev/hash) | very-quiet | provides cryptographic and fuzzy hash primitives for integrity verification, API hashing, and similarity detection |
| [`random`](https://pkg.go.dev/github.com/oioio-space/maldev/random) | very-quiet | provides cryptographically secure random generation helpers backed by `crypto/rand` (OS entropy) |
| [`useragent`](https://pkg.go.dev/github.com/oioio-space/maldev/useragent) | very-quiet | provides a curated database of real-world browser User-Agent strings for HTTP traffic blending |

</details>

<details><summary><strong>Windows primitives — `win/*`</strong> — 10 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`win`](https://pkg.go.dev/github.com/oioio-space/maldev/win) | — | is the parent umbrella for Windows-only primitives |
| [`win/api`](https://pkg.go.dev/github.com/oioio-space/maldev/win/api) | very-quiet | is the single source of truth for Windows DLL handles, procedure references, and structures shared across maldev |
| [`win/com`](https://pkg.go.dev/github.com/oioio-space/maldev/win/com) | — | holds Windows COM helpers shared across maldev |
| [`win/domain`](https://pkg.go.dev/github.com/oioio-space/maldev/win/domain) | very-quiet | queries Windows domain-membership state — whether the host is workgroup-only, joined to an Active Directory domain, or in an unknown state |
| [`win/impersonate`](https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate) | moderate | runs callbacks under an alternate Windows security context — by credential, by stolen token, or by piggy- backing on a target PID |
| [`win/ntapi`](https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi) | quiet | exposes a small set of typed Go wrappers over `ntdll!Nt*` functions that maldev components use frequently — memory allocation, write/protect, thread creation, and system information query |
| [`win/privilege`](https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege) | moderate | answers two operational questions: am I admin right now, and how do I run something else as a different principal? It wraps `IsAdmin` / `IsAdminGroupMember` for privilege detection and three execution primitives — `ExecAs`, `CreateProcessWithLogon`, `ShellExecuteRunAs` — for spawning processes under alternate credentials |
| [`win/syscall`](https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall) | quiet | provides five strategies for invoking Windows NT syscalls — from a hookable `kernel32` call to fully indirect SSN dispatch through an in-ntdll `syscall;ret` gadget (heap stub or Go-assembly stub) — under one uniform [Caller] interface |
| [`win/token`](https://pkg.go.dev/github.com/oioio-space/maldev/win/token) | moderate | wraps Windows access-token operations: open/duplicate process and thread tokens, steal a token from another PID, enable or remove individual privileges, query integrity level, and retrieve the active interactive session's primary token |
| [`win/version`](https://pkg.go.dev/github.com/oioio-space/maldev/win/version) | very-quiet | reports the running Windows OS version, build, and patch level — bypassing the manifest-compatibility shim that masks `GetVersionEx` results to the manifest-declared compatibility target |

</details>

<details><summary><strong>Kernel BYOVD — `kernel/driver/*`</strong> — 2 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`kernel/driver`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver) | very-noisy | defines the kernel-memory primitive interfaces consumed by EDR-bypass packages that need arbitrary kernel reads or writes (kcallback, lsassdump PPL-bypass, callback-array tampering, …) |
| [`kernel/driver/rtcore64`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver/rtcore64) | very-noisy | wraps the MSI Afterburner RTCore64.sys signed driver (CVE-2019-16098) as a [kernel/driver.ReadWriter] primitive |

</details>

<details><summary><strong>Evasion — `evasion/*`</strong> — 15 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`evasion`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion) | — | is the umbrella for active EDR / AV evasion |
| [`evasion/acg`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/acg) | quiet | enables Arbitrary Code Guard for the current process so the kernel refuses any further `VirtualAlloc(PAGE_EXECUTE)` / `VirtualProtect(PAGE_EXECUTE)` requests |
| [`evasion/amsi`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi) | noisy | disables the Antimalware Scan Interface in the current process via runtime memory patches on `amsi.dll` |
| [`evasion/blockdlls`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/blockdlls) | quiet | applies the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES` mitigation so the loader refuses any DLL that isn't Microsoft-signed |
| [`evasion/callstack`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/callstack) | quiet | synthesises a return-address chain so a stack walker at a protected-API call site sees frames that originate from a benign thread-init sequence rather than from the attacker module |
| [`evasion/cet`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/cet) | noisy | inspects and relaxes Intel CET (Control-flow Enforcement Technology) shadow-stack enforcement for the current process, and exposes the ENDBR64 marker required by CET-gated indirect call sites |
| [`evasion/etw`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw) | moderate | blinds Event Tracing for Windows in the current process by patching the ETW write helpers in `ntdll.dll` with `xor rax,rax; ret` |
| [`evasion/hook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook) | noisy | installs x64 inline hooks on exported Windows functions: patch the prologue with a JMP to a Go callback, automatically generate a trampoline for calling the original, and fix up RIP-relative instructions in the stolen prologue |
| [`evasion/hook/bridge`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/bridge) | moderate | is the bidirectional control channel between a hook handler installed inside a target process and the implant that placed it |
| [`evasion/hook/shellcode`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook/shellcode) | noisy | ships pre-fabricated x64 position-independent shellcode blobs used as handler bodies for [github.com/oioio-space/maldev/evasion/hook].`RemoteInstall` |
| [`evasion/kcallback`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/kcallback) | very-noisy | enumerates and removes kernel-mode callback registrations that EDR products use to observe process/thread/image- load events from the kernel side |
| [`evasion/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset) | — | bundles `evasion.Technique` primitives into four validated risk levels for one-shot deployment |
| [`evasion/sleepmask`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask) | quiet | encrypts the implant's payload memory while it sleeps so concurrent memory scanners cannot recover the original shellcode bytes or PE headers |
| [`evasion/stealthopen`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/stealthopen) | quiet | reads files via NTFS Object ID (the 128-bit GUID stored in the MFT) instead of by path, bypassing path-based EDR hooks on `NtCreateFile` / `CreateFileW` |
| [`evasion/unhook`](https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook) | noisy | restores the original prologue bytes of `ntdll.dll` functions, removing inline hooks installed by EDR/AV products |

</details>

<details><summary><strong>Injection — `inject`</strong> — 1 package</summary>

| Package | Detection | Summary |
|---|---|---|
| [`inject`](https://pkg.go.dev/github.com/oioio-space/maldev/inject) | noisy | provides unified shellcode injection across Windows and Linux with a fluent builder, decorator middleware, and automatic fallback between methods |

</details>

<details><summary><strong>PE manipulation — `pe/*`</strong> — 11 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`pe`](https://pkg.go.dev/github.com/oioio-space/maldev/pe) | — | is the umbrella for Portable Executable analysis, manipulation, and conversion utilities |
| [`pe/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert) | quiet | manipulates the PE Authenticode security directory — read, copy, strip, and write WIN_CERTIFICATE blobs without any Windows crypto API |
| [`pe/dllproxy`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/dllproxy) | very-quiet | emits a valid Windows DLL — as raw bytes, no external toolchain — that forwards every named export back to a legitimate target DLL |
| [`pe/imports`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports) | very-quiet | enumerates a PE's import surface — both the classic IMAGE_IMPORT_DESCRIPTOR table AND the IMAGE_DELAY_IMPORT_DESCRIPTOR table — without invoking any Windows API |
| [`pe/masquerade`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade) | quiet | clones a Windows PE's identity — manifest, icons, VERSIONINFO, optional Authenticode certificate — into a linkable `.syso` COFF object so a Go binary picks them up at compile time |
| [`pe/masquerade/donors`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade/donors) | very-quiet | lists the reference (donor) PE files the pe/masquerade preset generator and the cmd/cert-snapshot tool share |
| [`pe/masquerade/preset`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade/preset) | — | _(no doc.go summary)_ |
| [`pe/morph`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph) | moderate | mutates UPX-packed PE headers so automatic unpackers fail to recognise the input |
| [`pe/parse`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse) | very-quiet | provides PE file parsing and modification utilities |
| [`pe/srdi`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/srdi) | moderate | converts PE / .NET / script payloads into position-independent shellcode via the Donut framework (github.com/Binject/go-donut) |
| [`pe/strip`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip) | quiet | sanitises Go-built PE binaries by removing toolchain artefacts that fingerprint the producer |

</details>

<details><summary><strong>Runtime loaders — `runtime/*`</strong> — 2 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`runtime/bof`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/bof) | moderate | loads and executes Beacon Object Files (BOFs) — compiled COFF object files (`.o`) — entirely in process memory |
| [`runtime/clr`](https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr) | moderate | hosts the .NET Common Language Runtime in process via the `ICLRMetaHost` / `ICorRuntimeHost` COM interfaces and executes managed assemblies from memory without writing them to disk |

</details>

<details><summary><strong>Recon — `recon/*`</strong> — 9 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`recon/antidebug`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antidebug) | quiet | detects whether a debugger is currently attached to the implant — Windows via `IsDebuggerPresent` (PEB BeingDebugged), Linux via `/proc/self/status TracerPid` |
| [`recon/antivm`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/antivm) | quiet | detects virtual machines and hypervisors via configurable check dimensions: registry keys, files, MAC prefixes, processes, CPUID/BIOS, and DMI info |
| [`recon/dllhijack`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/dllhijack) | moderate | discovers DLL-search-order hijack opportunities on Windows — places where an application loads a DLL from a user-writable directory BEFORE reaching the legitimate copy (typically in System32) |
| [`recon/drive`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/drive) | quiet | enumerates Windows logical drives and watches for newly connected removable / network volumes |
| [`recon/folder`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder) | very-quiet | resolves Windows special folder paths via two Shell32 entry points: [Get] (legacy `SHGetSpecialFolderPathW`, CSIDL-keyed) and [GetKnown] (modern `SHGetKnownFolderPath`, KNOWNFOLDERID-keyed) |
| [`recon/hwbp`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/hwbp) | moderate | detects and clears hardware breakpoints set by EDR products on NT function prologues — surviving the classic ntdll-on-disk-unhook pass |
| [`recon/network`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network) | very-quiet | provides cross-platform IP address retrieval and local-address detection |
| [`recon/sandbox`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox) | quiet | is the multi-factor sandbox / VM / analysis-environment detector — a configurable orchestrator that aggregates checks across `recon/antidebug`, `recon/antivm`, and its own primitives into a single "is this a sandbox?" assessment |
| [`recon/timing`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/timing) | quiet | provides time-based evasion that defeats sandboxes which fast-forward `Sleep()` calls — sandboxes commonly hook `Sleep` / `WaitForSingleObject` to skip the delay and analyse what the implant does next |

</details>

<details><summary><strong>Process — `process/*` + `process/tamper/*`</strong> — 7 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`process`](https://pkg.go.dev/github.com/oioio-space/maldev/process) | — | is the umbrella for cross-platform process enumeration / management, plus the Windows-specific process-tamper sub-tree |
| [`process/enum`](https://pkg.go.dev/github.com/oioio-space/maldev/process/enum) | quiet | provides cross-platform process enumeration — list every running process or find one by name / predicate |
| [`process/session`](https://pkg.go.dev/github.com/oioio-space/maldev/process/session) | moderate | enumerates Windows sessions and creates processes / impersonates threads inside other users' sessions |
| [`process/tamper/fakecmd`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/fakecmd) | quiet | overwrites the current process's PEB `CommandLine` UNICODE_STRING so process-listing tools (Process Explorer, `wmic`, `Get-Process`, Task Manager) display a fake command-line instead of the real one |
| [`process/tamper/herpaderping`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/herpaderping) | moderate | implements Process Herpaderping and the related Process Ghosting variant — kernel image-section cache exploitation that lets the running process execute one PE while the file on disk reads as another (or doesn't exist) |
| [`process/tamper/hideprocess`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/hideprocess) | moderate | patches a target process's user-mode process-enumeration surface so it returns empty / failed results — blinding monitoring tools without killing them |
| [`process/tamper/phant0m`](https://pkg.go.dev/github.com/oioio-space/maldev/process/tamper/phant0m) | noisy | suppresses Windows Event Log recording by terminating the EventLog service threads inside the hosting `svchost.exe` — the service stays "Running" in the SCM listing but no new entries are written |

</details>

<details><summary><strong>Credentials — `credentials/*`</strong> — 4 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`credentials/goldenticket`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/goldenticket) | noisy | forges Kerberos Golden Tickets — long-lived TGTs minted with a stolen krbtgt account hash |
| [`credentials/lsassdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump) | noisy | produces a MiniDump blob of lsass.exe's memory so downstream tooling (credentials/sekurlsa, mimikatz, pypykatz) can extract Windows credentials |
| [`credentials/samdump`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump) | quiet | performs offline NT-hash extraction from a SAM hive (with the SYSTEM hive supplying the boot key) |
| [`credentials/sekurlsa`](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa) | quiet | extracts credential material from a Windows LSASS minidump — the consumer counterpart to credentials/lsassdump |

</details>

<details><summary><strong>Collection — `collection/*`</strong> — 4 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`collection`](https://pkg.go.dev/github.com/oioio-space/maldev/collection) | — | groups local data-acquisition primitives for post-exploitation: keystrokes, clipboard contents, screen captures |
| [`collection/clipboard`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/clipboard) | quiet | reads and watches the Windows clipboard text |
| [`collection/keylog`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/keylog) | noisy | captures keystrokes via a low-level keyboard hook (`SetWindowsHookEx(WH_KEYBOARD_LL)`) |
| [`collection/screenshot`](https://pkg.go.dev/github.com/oioio-space/maldev/collection/screenshot) | quiet | captures the screen via GDI `BitBlt` and returns PNG bytes |

</details>

<details><summary><strong>Cleanup — `cleanup/*`</strong> — 8 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`cleanup`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup) | quiet | is the umbrella for on-host artefact removal / anti-forensics primitives that run after an operation completes |
| [`cleanup/ads`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/ads) | quiet | provides CRUD operations for NTFS Alternate Data Streams |
| [`cleanup/bsod`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/bsod) | very-noisy | triggers a Blue Screen of Death via NtRaiseHardError as a last-resort cleanup primitive |
| [`cleanup/memory`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/memory) | very-quiet | provides secure memory cleanup primitives for wiping sensitive data (shellcode, keys, credentials) from process memory |
| [`cleanup/selfdelete`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/selfdelete) | moderate | deletes the running executable from disk while the process continues to execute from its mapped image |
| [`cleanup/service`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/service) | noisy | hides Windows services from listing utilities by applying a restrictive DACL on the service object |
| [`cleanup/timestomp`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/timestomp) | quiet | resets a file's NTFS `$STANDARD_INFORMATION` timestamps so a dropped artifact blends with surrounding files |
| [`cleanup/wipe`](https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/wipe) | quiet | overwrites file contents with cryptographically random data before deletion to defeat trivial forensic recovery |

</details>

<details><summary><strong>Persistence — `persistence/*`</strong> — 7 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`persistence`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence) | — | is the umbrella for system persistence techniques — mechanisms that re-launch an implant across reboots and user logons |
| [`persistence/account`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account) | noisy | provides Windows local user account management via NetAPI32 — create, delete, set password, manage group membership, enumerate |
| [`persistence/lnk`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/lnk) | quiet | creates Windows shortcut (.lnk) files via COM/OLE automation — fluent builder API, fully Windows-only |
| [`persistence/registry`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry) | moderate | implements Windows registry Run / RunOnce key persistence — the canonical "auto-launch on logon" hook |
| [`persistence/scheduler`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler) | moderate | creates, deletes, lists, and runs Windows scheduled tasks via the COM `ITaskService` API — no `schtasks.exe` child process |
| [`persistence/service`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service) | noisy | implements Windows service persistence via the Service Control Manager — the highest-trust persistence mechanism available, running as SYSTEM at boot |
| [`persistence/startup`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/startup) | moderate | implements StartUp-folder persistence via LNK shortcut files — Windows Shell launches every shortcut in the folder at user logon |

</details>

<details><summary><strong>Privilege escalation — `privesc/*`</strong> — 2 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`privesc/cve202430088`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088) | noisy | implements CVE-2024-30088 — a Windows kernel TOCTOU race in `AuthzBasepCopyoutInternalSecurityAttributes` that yields local privilege escalation to NT AUTHORITY\SYSTEM by overwriting the calling thread's primary token with `lsass.exe`'s SYSTEM token |
| [`privesc/uac`](https://pkg.go.dev/github.com/oioio-space/maldev/privesc/uac) | noisy | implements four classic UAC-bypass primitives that hijack auto-elevating Windows binaries to spawn an elevated process without a consent prompt |

</details>

<details><summary><strong>C2 — `c2/*`</strong> — 7 packages</summary>

| Package | Detection | Summary |
|---|---|---|
| [`c2`](https://pkg.go.dev/github.com/oioio-space/maldev/c2) | — | provides command and control building blocks: reverse shells, Meterpreter staging, pluggable transports (TCP / TLS / uTLS / named pipe), mTLS certificate helpers, and session multiplexing |
| [`c2/cert`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert) | quiet | provides self-signed X.509 certificate generation and fingerprint computation for C2 TLS infrastructure |
| [`c2/meterpreter`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/meterpreter) | noisy | implements Metasploit Framework staging — pulls a second-stage Meterpreter payload from a `multi/handler` and executes it in the current process or a target picked via the optional `Config.Injector` |
| [`c2/multicat`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/multicat) | quiet | provides a multi-session reverse-shell listener for operator use |
| [`c2/shell`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell) | noisy | provides a reverse shell with automatic reconnection, PTY support, and optional Windows evasion integration |
| [`c2/transport`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport) | moderate | provides pluggable network transport implementations for C2 communication: plain TCP, TLS with optional certificate pinning, and uTLS for JA3/JA4 fingerprint randomisation |
| [`c2/transport/namedpipe`](https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe) | quiet | provides a Windows named-pipe transport implementing the [github.com/oioio-space/maldev/c2/transport] `Transport` and `Listener` interfaces |

</details>

<details><summary><strong>UI utilities</strong> — 1 package</summary>

| Package | Detection | Summary |
|---|---|---|
| [`ui`](https://pkg.go.dev/github.com/oioio-space/maldev/ui) | very-quiet | exposes minimal Windows UI primitives — `MessageBoxW` via `Show` and the system alert sound via `Beep` |

</details>

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
