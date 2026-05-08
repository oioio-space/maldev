# Summary

[Introduction](index.md)

# Getting Started

- [Quick start](getting-started.md)
- [Architecture](architecture.md)
- [OPSEC build](opsec-build.md)

# By Role

- [Operator](by-role/operator.md)
- [Researcher](by-role/researcher.md)
- [Detection engineering](by-role/detection-eng.md)

# Reference

- [MITRE ATT&CK + D3FEND](mitre.md)
- [Testing](testing.md)
- [Coverage workflow](coverage-workflow.md)
- [VM test setup](vm-test-setup.md)
- [Documentation conventions](conventions/documentation.md)

# Techniques

- [C2](techniques/c2/README.md)
  - [Reverse shell](techniques/c2/reverse-shell.md)
  - [Transport](techniques/c2/transport.md)
  - [Meterpreter](techniques/c2/meterpreter.md)
  - [Multicat](techniques/c2/multicat.md)
  - [Named pipe](techniques/c2/namedpipe.md)
  - [Malleable profiles](techniques/c2/malleable-profiles.md)

- [Cleanup](techniques/cleanup/README.md)
  - [Memory wipe](techniques/cleanup/memory-wipe.md)
  - [Multi-pass file wipe](techniques/cleanup/wipe.md)
  - [Self-delete](techniques/cleanup/self-delete.md)
  - [Timestomp](techniques/cleanup/timestomp.md)
  - [Alternate data streams](techniques/cleanup/ads.md)
  - [Service unregister](techniques/cleanup/service.md)
  - [BSOD kill switch](techniques/cleanup/bsod.md)

- [Collection](techniques/collection/README.md)
  - [Keylogging](techniques/collection/keylogging.md)
  - [Clipboard](techniques/collection/clipboard.md)
  - [Screenshot](techniques/collection/screenshot.md)
  - [Alternate data streams](techniques/collection/alternate-data-streams.md)
  - [LSASS dump (cross-ref)](techniques/collection/lsass-dump.md)

- [Credentials](techniques/credentials/README.md)
  - [LSASS dump](techniques/credentials/lsassdump.md)
  - [Sekurlsa parser](techniques/credentials/sekurlsa.md)
  - [SAM dump](techniques/credentials/samdump.md)
  - [Golden ticket](techniques/credentials/goldenticket.md)

- [Crypto](techniques/crypto/README.md)
  - [Payload encryption](techniques/crypto/payload-encryption.md)

- [Encode](techniques/encode/README.md)
  - [Encoders](techniques/encode/encode.md)

- [Hash](techniques/hash/README.md)
  - [Cryptographic hashes](techniques/hash/cryptographic-hashes.md)
  - [Fuzzy hashing](techniques/hash/fuzzy-hashing.md)

- [Evasion](techniques/evasion/README.md)
  - [AMSI bypass](techniques/evasion/amsi-bypass.md)
  - [ETW patching](techniques/evasion/etw-patching.md)
  - [NTDLL unhooking](techniques/evasion/ntdll-unhooking.md)
  - [Inline hook](techniques/evasion/inline-hook.md)
  - [Sleep mask](techniques/evasion/sleep-mask.md)
  - [Callstack spoof](techniques/evasion/callstack-spoof.md)
  - [ACG / BlockDLLs](techniques/evasion/acg-blockdlls.md)
  - [CET shadow stack](techniques/evasion/cet.md)
  - [Kernel callback removal](techniques/evasion/kernel-callback-removal.md)
  - [Stealth open](techniques/evasion/stealthopen.md)
  - [Preset stacks](techniques/evasion/preset.md)
  - [PPID spoofing](techniques/evasion/ppid-spoofing.md)

- [Injection](techniques/injection/README.md)
  - [Create remote thread](techniques/injection/create-remote-thread.md)
  - [Early-bird APC](techniques/injection/early-bird-apc.md)
  - [Thread hijack](techniques/injection/thread-hijack.md)
  - [Thread pool](techniques/injection/thread-pool.md)
  - [Module stomping](techniques/injection/module-stomping.md)
  - [Section mapping](techniques/injection/section-mapping.md)
  - [Phantom DLL](techniques/injection/phantom-dll.md)
  - [Callback execution](techniques/injection/callback-execution.md)
  - [Kernel callback table](techniques/injection/kernel-callback-table.md)
  - [EtwpCreateEtwThread](techniques/injection/etwp-create-etw-thread.md)
  - [NtQueueApcThreadEx](techniques/injection/nt-queue-apc-thread-ex.md)
  - [Process arg spoofing](techniques/injection/process-arg-spoofing.md)

- [Kernel BYOVD](techniques/kernel/README.md)
  - [RTCore64 (CVE-2019-16098)](techniques/kernel/byovd-rtcore64.md)

- [PE](techniques/pe/README.md)
  - [Strip + Sanitize](techniques/pe/strip-sanitize.md)
  - [UPX morph](techniques/pe/morph.md)
  - [Masquerade](techniques/pe/masquerade.md)
  - [Imports enumeration](techniques/pe/imports.md)
  - [Certificate theft](techniques/pe/certificate-theft.md)
  - [PE → shellcode](techniques/pe/pe-to-shellcode.md)
  - [DLL proxy generator](techniques/pe/dll-proxy.md)
  - [Packer (Phase 1a–1e)](techniques/pe/packer.md)
  - [Catalog signing](techniques/pe/catalog-signing.md)

- [Persistence](techniques/persistence/README.md)
  - [Registry](techniques/persistence/registry.md)
  - [Startup folder](techniques/persistence/startup-folder.md)
  - [Task scheduler](techniques/persistence/task-scheduler.md)
  - [Service](techniques/persistence/service.md)
  - [Shortcut (LNK)](techniques/persistence/lnk.md)
  - [Local account](techniques/persistence/account.md)

- [Privilege Escalation](techniques/privesc/README.md)
  - [UAC bypass](techniques/privesc/uac.md)
  - [CVE-2024-30088](techniques/privesc/cve202430088.md)

- [Process tampering](techniques/process/README.md)
  - [Enumeration](techniques/process/enum.md)
  - [Sessions](techniques/process/session.md)
  - [FakeCmd](techniques/process/fakecmd.md)
  - [HideProcess](techniques/process/hideprocess.md)
  - [Herpaderping / Ghosting](techniques/process/herpaderping.md)
  - [Phant0m EventLog suspend](techniques/process/phant0m.md)

- [Recon](techniques/recon/README.md)
  - [Anti-analysis](techniques/recon/anti-analysis.md)
  - [Sandbox detection](techniques/recon/sandbox.md)
  - [Timing checks](techniques/recon/timing.md)
  - [Hardware breakpoints](techniques/recon/hw-breakpoints.md)
  - [DLL hijack discovery](techniques/recon/dll-hijack.md)
  - [Drive enumeration](techniques/recon/drive.md)
  - [Special folders](techniques/recon/folder.md)
  - [Network](techniques/recon/network.md)

- [Runtime](techniques/runtime/README.md)
  - [BOF loader](techniques/runtime/bof-loader.md)
  - [CLR host](techniques/runtime/clr.md)

- [Syscalls](techniques/syscalls/README.md)
  - [API hashing](techniques/syscalls/api-hashing.md)
  - [Direct / indirect](techniques/syscalls/direct-indirect.md)
  - [SSN resolvers](techniques/syscalls/ssn-resolvers.md)

- [Tokens](techniques/tokens/README.md)
  - [Token theft](techniques/tokens/token-theft.md)
  - [Impersonation](techniques/tokens/impersonation.md)
  - [Privilege escalation](techniques/tokens/privilege-escalation.md)

- [Windows primitives](techniques/win/README.md)
  - [Domain membership](techniques/win/domain.md)
  - [Version + UBR probe](techniques/win/version.md)

# Worked Examples

- [Basic implant](examples/basic-implant.md)
- [Evasive injection](examples/evasive-injection.md)
- [Full chain](examples/full-chain.md)
- [DLL proxy side-load](examples/dllproxy-side-load.md)
- [UPX-style packer + cover](examples/upx-style-packer.md)

