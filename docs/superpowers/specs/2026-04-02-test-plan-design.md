# Test Plan — maldev

**Date:** 2026-04-02
**Status:** Draft
**Module:** github.com/oioio-space/maldev

---

## 1. Goals

Validate the correctness of every package in the maldev library across Windows and Linux, including intrusive techniques (memory patching, process injection, shellcode execution) that require controlled environments.

**Non-goals:** Kernel-level testing, CI/CD pipeline setup (future work), performance benchmarking.

---

## 2. Architecture

```
go test ./...
    |
    +-- Tier 1: Pure tests (run everywhere)
    |   crypto, encode, hash, random, pe/parse, inject config,
    |   c2/transport, cleanup/wipe, cleanup/timestomp
    |
    +-- Tier 2: Linux intrusive (native on Linux, Podman on Windows)
    |   ptrace injection, memfd exec, procmem self-inject,
    |   purego exec, antidebug TracerPid, process enum /proc
    |
    +-- Tier 3: Windows intrusive (native on Windows, skip on Linux)
    |   AMSI patch, ETW patch, CreateThread inject, CRT inject,
    |   PatchMemory, PatchMemoryWithCaller
    |
    +-- Tier 4: Platform-safe read-only (run on native OS)
        process enum, version detection, token read, network
```

### Gating Mechanisms

| Mechanism | Purpose | Example |
|-----------|---------|---------|
| `//go:build windows` | Compile-time platform gate | AMSI/ETW tests |
| `//go:build linux` | Compile-time platform gate | ptrace tests |
| `testutil.RequireIntrusive(t)` | Runtime gate via `MALDEV_INTRUSIVE=1` | Injection, patching |
| `testutil.RequireLinuxContainer(t)` | Auto-detect: native Linux or Podman | Linux tests on Windows |

### Execution Levels

```bash
# Level 1: Pure tests (safe, fast, any platform)
go test ./...

# Level 2: + platform-specific non-intrusive
go test ./...

# Level 3: + intrusive (injection, patching)
MALDEV_INTRUSIVE=1 go test ./...
```

Level 1 and 2 are the same command — platform-safe tests auto-skip via build tags. Level 3 enables intrusive tests gated by the environment variable.

---

## 3. Test Infrastructure

### 3.1 Package `testutil/`

Shared helpers used across all test files. Internal to tests only.

#### `testutil/skip.go`

```go
package testutil

func RequireWindows(t *testing.T)
func RequireLinux(t *testing.T)
func RequireIntrusive(t *testing.T)    // gates on MALDEV_INTRUSIVE=1
func RequireLinuxContainer(t *testing.T) // on Linux: pass. on Windows: require Podman.
```

#### `testutil/shellcode.go`

Canary shellcodes that verify injection without malicious behavior.

```go
package testutil

// LinuxCanaryX64 writes "MALDEV_OK\n" to stdout then exits cleanly.
// Used to verify injection succeeded by checking process output.
//   mov rax, 1        ; sys_write
//   mov rdi, 1        ; stdout
//   lea rsi, [rip+msg]; pointer to string
//   mov rdx, 10       ; length
//   syscall
//   mov rax, 60       ; sys_exit
//   xor rdi, rdi      ; code 0
//   syscall
//   msg: "MALDEV_OK\n"
var LinuxCanaryX64 []byte

// WindowsCanaryX64 is a minimal NOP+RET stub.
// Verifies injection by successful thread completion (WaitForSingleObject returns).
//   xor eax, eax  ; zero return
//   ret
var WindowsCanaryX64 = []byte{0x31, 0xC0, 0xC3}

```

#### `testutil/process_windows.go`

```go
//go:build windows

package testutil

// SpawnSacrificial creates a suspended notepad.exe process for injection tests.
// Returns the PID, main thread handle, and a cleanup function that terminates
// and closes all handles.
func SpawnSacrificial(t *testing.T) (pid uint32, threadHandle windows.Handle, cleanup func())

// SpawnAndResume creates a running process (for CRT/APC injection).
func SpawnAndResume(t *testing.T) (pid uint32, cleanup func())
```

#### `testutil/container.go`

```go
package testutil

// LinuxContainer manages a Podman/Docker container for Linux tests on Windows.
// On Linux, this is a no-op wrapper that runs tests directly.
type LinuxContainer struct { ... }

// NewLinuxContainer creates a golang:1.21-bookworm container with:
//   --cap-add=SYS_PTRACE
//   --security-opt seccomp=unconfined
// The maldev source tree is bind-mounted into the container.
func NewLinuxContainer(t *testing.T) *LinuxContainer

// RunTest compiles and runs a specific test inside the container.
// Returns stdout and whether the test passed.
func (lc *LinuxContainer) RunTest(t *testing.T, pkg string, testName string) (string, bool)

// RunGoTest runs `go test` for a package inside the container.
func (lc *LinuxContainer) RunGoTest(t *testing.T, pkg string, args ...string) error
```

**Container strategy:** Uses `testcontainers-go` which auto-detects Podman or Docker. On Linux, `NewLinuxContainer` returns a thin wrapper that calls `exec.Command("go", "test", ...)` directly.

### 3.2 Test Data

```
testutil/testdata/
    ├── hello.exe          # Minimal PE (64-bit, does nothing, for pe/parse tests)
    ├── hello.dll          # Minimal DLL (64-bit, exports one function)
    ├── canary_linux_x64   # Compiled canary shellcode (raw bytes)
    └── canary_win_x64     # Compiled canary shellcode (raw bytes)
```

Generated once via a helper script or Go generate. Small (<4KB each).

---

## 4. Tier 1 — Pure Tests

Tests that run anywhere with `go test`. No system dependencies.

### 4.1 `crypto/`

| Test | What it validates |
|------|------------------|
| `TestAESGCMRoundTrip` | Encrypt then decrypt with 32-byte key returns original |
| `TestAESGCMInvalidKey` | 16, 24-byte keys rejected with clear error |
| `TestAESGCMTampered` | Modified ciphertext fails auth with wrapped error |
| `TestChaCha20RoundTrip` | Encrypt then decrypt returns original |
| `TestChaCha20InvalidKey` | Wrong key size rejected |
| `TestRC4RoundTrip` | Encrypt then decrypt returns original |
| `TestRC4EmptyKey` | Empty key rejected |
| `TestXORRoundTrip` | `XOR(XOR(data, key), key) == data` |
| `TestXOREmptyKey` | Empty key returns error (no panic) |
| `TestXOREmptyData` | Empty data returns empty result |

### 4.2 `encode/`

| Test | What it validates |
|------|------------------|
| `TestBase64RoundTrip` | Encode then decode = original |
| `TestBase64URLRoundTrip` | URL-safe variant round-trip |
| `TestROT13Involution` | `ROT13(ROT13(x)) == x` for all printable ASCII |
| `TestUTF16LE` | Known string → known bytes |
| `TestPowerShellEncode` | Output matches PowerShell -EncodedCommand format |

### 4.3 `hash/`

| Test | What it validates |
|------|------------------|
| `TestSHA256Known` | `SHA256("hello")` matches RFC vector |
| `TestMD5Known` | `MD5("hello")` matches known value |
| `TestROR13Canonical` | `ROR13("LoadLibraryA")` matches Metasploit shellcode value |
| `TestROR13ModuleNull` | `ROR13Module(x) != ROR13(x)` (null terminator difference) |
| `TestROR13ByteLevel` | No case folding: `ROR13("A") != ROR13("a")` |

### 4.4 `random/`

| Test | What it validates |
|------|------------------|
| `TestRandomStringLength` | Output length matches requested |
| `TestRandomStringUnique` | Two calls produce different results |
| `TestRandomBytesLength` | Output length matches requested |
| `TestRandomIntRange` | Result within [min, max) |
| `TestRandomIntInvalidRange` | `max <= min` returns error |
| `TestFileExists` | Existing file → true, non-existing → false |

### 4.5 `pe/parse/` (NEW)

| Test | What it validates |
|------|------------------|
| `TestParseValidPE` | `Open(hello.exe)` succeeds, `Is64Bit() == true` |
| `TestParseValidDLL` | `Open(hello.dll)` succeeds, `IsDLL() == true` |
| `TestParseSections` | Sections contain `.text` |
| `TestParseExports` | DLL exports contain the known function |
| `TestParseTruncated` | Truncated PE → error, no panic |
| `TestParseInvalid` | Random bytes → error, no panic |
| `TestParseFromBytes` | `OpenBytes(data)` works identically to file |

### 4.6 `inject/` — config & validation only

| Test | What it validates |
|------|------------------|
| `TestValidateMethodValid` | Known methods pass validation |
| `TestValidateMethodInvalid` | Unknown string returns error |
| `TestAvailableMethods` | Returns non-empty list |
| `TestFallbackChainOrder` | Fallback tries methods in declared order |
| `TestRead` | Read from temp file matches written content |
| `TestValidateShellcodeEmpty` | Empty bytes rejected |
| `TestValidateShellcodeValid` | Valid shellcode bytes accepted |

### 4.7 `c2/transport/` (NEW)

| Test | What it validates |
|------|------------------|
| `TestTCPRoundTrip` | Start local listener → Connect → Write → Read → Close |
| `TestTCPReconnect` | Close → Connect again → no leak (previous conn closed) |
| `TestTLSSelfSigned` | Generate cert → TLS listener → Connect → Write → Read |
| `TestTLSFingerprint` | Correct fingerprint → pass; wrong → error |
| `TestTLSFingerprintWithInsecure` | Fingerprint still checked even with InsecureSkipVerify |
| `TestTCPContextCancel` | Cancelled context → Connect returns error |

### 4.8 `cleanup/wipe/` — fix + test

| Test | What it validates |
|------|------------------|
| `TestFileOverwrite` | After wipe, reading file returns random (not original content) |
| `TestFileSinglePass` | Single pass overwrites entire file |
| `TestFileMultiPass` | 3 passes, file still overwritten |
| `TestFileDeleted` | File is removed after wipe |
| `TestFileHandleClosed` | No "file in use" error on Windows (fix handle leak) |

### 4.9 `cleanup/timestomp/`

| Test | What it validates |
|------|------------------|
| `TestSetTime` | Set mtime/atime → Stat → times match |
| `TestCopyFrom` | Source times copied to dest |

---

## 5. Tier 2 — Linux Intrusive Tests

Build tag: `//go:build linux`. Gated by `MALDEV_INTRUSIVE=1`.
On Windows: executed inside Podman container via `testutil.LinuxContainer`.

### 5.1 `inject/linux_test.go`

| Test | Technique | What it validates |
|------|-----------|------------------|
| `TestPtraceSelfInject` | Ptrace | Fork child → attach → write canary → set RIP → cont → "MALDEV_OK" on stdout |
| `TestMemFDExec` | MemFD | memfd_create → write ELF canary → fexecve → output |
| `TestProcMemSelfInject` | ProcMem | mmap RWX → copy canary → call → verify return |
| `TestPureGoExec` | PureGo | purego.SyscallN on canary → verify |
| `TestPureGoAsync` | PureGo | Async variant → verify via channel |

Each test:
1. Calls `testutil.RequireIntrusive(t)`
2. Uses `testutil.LinuxCanaryX64` shellcode
3. Verifies output or return value
4. Cleans up (kill child, unmap, close fd)

### 5.2 `evasion/antidebug/antidebug_test.go`

```go
//go:build linux

func TestTracerPidDetection(t *testing.T) {
    // Without tracer: IsDebuggerPresent() == false
    // With self-trace: ptrace(TRACEME) → re-check → true
}

func TestIsDebuggerPresentNoDebugger(t *testing.T) {
    // Normal process: TracerPid should be 0
    require.False(t, antidebug.IsDebuggerPresent())
}
```

### 5.3 `evasion/antivm/antivm_test.go`

```go
//go:build linux

func TestDetectDMI(t *testing.T) {
    // Read /sys/class/dmi/id/product_name if accessible
    // In a container, DMI may not be available → skip or verify empty
}

func TestDetectNicHasPrefix(t *testing.T) {
    // Verify MAC prefix matching uses HasPrefix, not Contains
    found, _, _ := antivm.DetectNic([]string{"FF:FF:FF"})
    require.False(t, found) // no real NIC has broadcast prefix
}
```

### 5.4 `process/enum/enum_test.go`

```go
//go:build linux

func TestListContainsSelf(t *testing.T) {
    procs, err := enum.List()
    require.NoError(t, err)
    // PID 1 (init/systemd) should exist
    // Current process PID should exist
}
```

---

## 6. Tier 3 — Windows Intrusive Tests

Build tag: `//go:build windows`. Gated by `MALDEV_INTRUSIVE=1`.

### 6.1 `evasion/amsi/amsi_test.go`

```go
//go:build windows

func TestPatchScanBufferWinAPI(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Load amsi.dll
    amsiDLL := windows.NewLazySystemDLL("amsi.dll")
    if err := amsiDLL.Load(); err != nil {
        t.Skip("amsi.dll not available")
    }
    proc := amsiDLL.NewProc("AmsiScanBuffer")
    proc.Find()
    addr := proc.Addr()

    // Patch with nil caller (WinAPI path)
    err := amsi.PatchScanBuffer(nil)
    require.NoError(t, err)

    // Verify: first 3 bytes at addr should be 0x31, 0xC0, 0xC3
    patched := (*[3]byte)(unsafe.Pointer(addr))
    assert.Equal(t, byte(0x31), patched[0]) // xor eax, eax
    assert.Equal(t, byte(0xC0), patched[1])
    assert.Equal(t, byte(0xC3), patched[2]) // ret
}

func TestPatchScanBufferWithCaller(t *testing.T) {
    testutil.RequireIntrusive(t)
    caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
    err := amsi.PatchScanBuffer(caller)
    require.NoError(t, err)
    // Same byte verification
}
```

### 6.2 `evasion/etw/etw_test.go`

```go
//go:build windows

func TestPatchETW(t *testing.T) {
    testutil.RequireIntrusive(t)
    err := etw.PatchETW(nil)
    require.NoError(t, err)
    // Verify EtwEventWrite first bytes are xor rax,rax; ret
    proc := api.Ntdll.NewProc("EtwEventWrite")
    proc.Find()
    patched := (*[4]byte)(unsafe.Pointer(proc.Addr()))
    assert.Equal(t, byte(0x48), patched[0]) // REX.W
    assert.Equal(t, byte(0x33), patched[1]) // xor
    assert.Equal(t, byte(0xC0), patched[2]) // rax, rax
    assert.Equal(t, byte(0xC3), patched[3]) // ret
}
```

### 6.3 `inject/windows_test.go`

```go
//go:build windows

func TestCreateThreadSelfInject(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Inject WindowsCanaryX64 (xor eax,eax; ret) into self via CreateThread
    cfg := &inject.Config{Method: inject.MethodCreateThread}
    injector, err := inject.NewInjector(cfg)
    require.NoError(t, err)
    err = injector.Inject(testutil.WindowsCanaryX64)
    require.NoError(t, err)
}

func TestCreateRemoteThreadInject(t *testing.T) {
    testutil.RequireIntrusive(t)
    pid, _, cleanup := testutil.SpawnSacrificial(t)
    defer cleanup()
    cfg := &inject.Config{Method: inject.MethodCreateRemoteThread, PID: int(pid)}
    injector, err := inject.NewInjector(cfg)
    require.NoError(t, err)
    err = injector.Inject(testutil.WindowsCanaryX64)
    require.NoError(t, err)
}

func TestSyscallCallerInjection(t *testing.T) {
    testutil.RequireIntrusive(t)
    wcfg := &inject.WindowsConfig{
        Config:        inject.Config{Method: inject.MethodCreateThread},
        SyscallMethod: wsyscall.MethodDirect,
    }
    injector, err := inject.NewWindowsInjector(wcfg)
    require.NoError(t, err)
    err = injector.Inject(testutil.WindowsCanaryX64)
    require.NoError(t, err)
}
```

### 6.4 `win/api/patch_test.go`

```go
//go:build windows

func TestPatchMemory(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Allocate RW memory, write known bytes, patch, verify
    addr, _ := windows.VirtualAlloc(0, 64,
        windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
    defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
    original := []byte{0xAA, 0xBB, 0xCC}
    copy((*[3]byte)(unsafe.Pointer(addr))[:], original)

    patch := []byte{0x11, 0x22, 0x33}
    err := api.PatchMemory(addr, patch)
    require.NoError(t, err)
    result := (*[3]byte)(unsafe.Pointer(addr))
    assert.Equal(t, patch, result[:])
}

func TestPatchMemoryWithCaller(t *testing.T) {
    testutil.RequireIntrusive(t)
    // Same test but via NtProtectVirtualMemory path
    caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
    // ... allocate, write, patch via caller, verify
}

func TestErrProcNotFound(t *testing.T) {
    proc := windows.NewLazySystemDLL("nonexistent.dll").NewProc("Foo")
    err := api.PatchProc(proc, []byte{0x90})
    assert.True(t, errors.Is(err, api.ErrProcNotFound))
}
```

### 6.5 `win/version/version_test.go` (non-intrusive)

```go
//go:build windows

func TestCurrent(t *testing.T) {
    v, err := version.Current()
    require.NoError(t, err)
    assert.True(t, v.MajorVersion >= 10)
    assert.True(t, v.BuildNumber > 0)
}

func TestWindows(t *testing.T) {
    wv, err := version.Windows()
    require.NoError(t, err)
    assert.NotEmpty(t, wv.String())
    // Server 2019/2022 disambiguation
    if wv.Build >= 20348 {
        assert.Contains(t, wv.String(), "2022")
    }
}
```

### 6.6 `win/token/token_test.go` (non-intrusive)

```go
//go:build windows

func TestOpenCurrentProcessToken(t *testing.T) {
    tok, err := token.OpenCurrentProcessToken()
    require.NoError(t, err)
    defer tok.Close()
    assert.NotNil(t, tok)
}

func TestTokenPrivileges(t *testing.T) {
    tok, err := token.OpenCurrentProcessToken()
    require.NoError(t, err)
    defer tok.Close()
    privs, err := tok.Privileges()
    require.NoError(t, err)
    assert.NotEmpty(t, privs)
}
```

### 6.7 `process/enum/enum_test.go` (non-intrusive)

```go
//go:build windows

func TestListWindows(t *testing.T) {
    procs, err := enum.List()
    require.NoError(t, err)
    assert.NotEmpty(t, procs)
    // Current process should be in the list
    myPID := os.Getpid()
    found := false
    for _, p := range procs {
        if p.PID == myPID { found = true; break }
    }
    assert.True(t, found, "current process not found in list")
}
```

---

## 7. Coverage Matrix

| Package | Pure | Linux | Windows | Windows Intrusive |
|---------|------|-------|---------|-------------------|
| `crypto/` | 10 | - | - | - |
| `encode/` | 5 | - | - | - |
| `hash/` | 5 | - | - | - |
| `random/` | 6 | - | - | - |
| `pe/parse/` | 7 | - | - | - |
| `inject/` (config) | 7 | - | - | - |
| `inject/` (exec) | - | 5 | - | 3 |
| `c2/transport/` | 6 | - | - | - |
| `cleanup/wipe/` | 5 | - | - | - |
| `cleanup/timestomp/` | 2 | - | - | - |
| `evasion/amsi/` | - | - | - | 2 |
| `evasion/etw/` | - | - | - | 1 |
| `evasion/antidebug/` | - | 2 | - | - |
| `evasion/antivm/` | - | 2 | - | - |
| `win/api/` (patch) | - | - | - | 3 |
| `win/version/` | - | - | 2 | - |
| `win/token/` | - | - | 2 | - |
| `process/enum/` | - | 1 | 1 | - |
| **Total** | **53** | **10** | **5** | **9** |

**Grand total: ~77 tests**

---

## 8. Dependencies

**New test dependency:**
```
github.com/testcontainers/testcontainers-go  (for Podman container management)
github.com/stretchr/testify                  (assert/require helpers)
```

**Container image:**
```
golang:1.21-bookworm  (for Linux tests, ~850MB, pulled once)
```

**No other infrastructure required.** No VMs, no CI setup, no external services.

---

## 9. File Creation Summary

| File | Status | Lines (est.) |
|------|--------|-------------|
| `testutil/skip.go` | NEW | ~30 |
| `testutil/shellcode.go` | NEW | ~60 |
| `testutil/process_windows.go` | NEW | ~50 |
| `testutil/container.go` | NEW | ~80 |
| `pe/parse/parse_test.go` | NEW | ~120 |
| `inject/inject_test.go` | NEW | ~80 |
| `inject/shellcode_test.go` | NEW | ~40 |
| `inject/linux_test.go` | NEW | ~100 |
| `inject/windows_test.go` | NEW | ~100 |
| `evasion/amsi/amsi_test.go` | NEW | ~60 |
| `evasion/etw/etw_test.go` | NEW | ~40 |
| `evasion/antidebug/antidebug_test.go` | NEW | ~40 |
| `evasion/antivm/antivm_test.go` | NEW | ~40 |
| `win/api/patch_test.go` | NEW | ~70 |
| `win/version/version_test.go` | NEW | ~30 |
| `win/token/token_test.go` | NEW | ~40 |
| `process/enum/enum_test.go` | NEW | ~50 |
| `c2/transport/transport_test.go` | NEW | ~120 |
| `cleanup/wipe/wipe_test.go` | MODIFY | ~30 (fix) |
| `crypto/crypto_test.go` | MODIFY | ~40 (enrich) |
| **Total** | **18 new, 2 modify** | **~1220** |
