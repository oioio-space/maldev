# Sleepmask Variants — Design Spec

**Date:** 2026-04-23
**Author:** Claude + Mathieu (brainstorming session)
**Target release:** v0.12.0
**Status:** Design approved, implementation pending

## Goal

Evolve `evasion/sleepmask` from a single XOR+inline strategy into a composable package that exposes the real sophistication spectrum of sleep masking: pluggable ciphers, three Windows sleep strategies (including a full Ekko port), a cross-process variant, and a concrete runnable demo.

## Scope of this spec

- **Cipher interface** (XOR / RC4 / AES-CTR) — already implemented this session, kept as-is
- **Strategy interface + three implementations**: `InlineStrategy` (L1), `TimerQueueStrategy` (L2 light), `EkkoStrategy` (L2 full, real Ekko)
- **RemoteMask + RemoteInlineStrategy** — cross-process variant for masking shellcode that lives in another process
- **`cmd/sleepmask-demo`** — runnable demonstration supporting both self-process (scenario A) and host-injection (scenario B) modes
- **Breaking API changes** (pre-1.0 minor bump to v0.12.0):
  - `Sleep(d time.Duration)` → `Sleep(ctx context.Context, d time.Duration) error`
  - `SleepMethod`, `MethodNtDelay`, `MethodBusyTrig`, `WithMethod` removed
- **Documentation rewrite** for `docs/techniques/evasion/sleep-mask.md`

### Out of scope (deferred)

- **L3** (Foliage / Deathsleep / Cronos — APC/fiber redirection for stack masking)
- **L4** (BOF-style user-provided sleepmask)
- **Remote L2/L3** (Ekko cross-process) — requires a fundamentally different design; may never be worth the complexity
- **Stack masking** of the calling thread (Hunt-Sleeping-Beacons evasion) — noted as future work

## The Four Levels of Sophistication

| Level | Name | Implementation | Ship in v0.12.0 |
|-------|------|----------------|-----------------|
| L1 | Static XOR / inline | Caller goroutine does encrypt → sleep → decrypt | ✅ `InlineStrategy` |
| L2 light | Thread-pool sleep | Pool thread does encrypt/wait/decrypt, caller waits on event | ✅ `TimerQueueStrategy` |
| L2 full | Ekko (Winter-Smith 2022) | ROP chain via `RtlCaptureContext` + 6 CONTEXTs + `NtContinue` as timer callback; beacon thread's RIP inside `VirtualProtect`/`SystemFunction032`/`WaitForSingleObjectEx` during sleep | ✅ `EkkoStrategy` |
| L3 | Foliage / Deathsleep / Cronos | APC/fiber redirection to mask call stack origin | ❌ deferred |
| L4 | Cobalt 4.7+ BOF sleep_mask | User-provided C/Go shellcode drives the cycle | ❌ deferred |

**Why "L2 light" and "L2 full" at the same level?** Both improve over L1 on the "beacon thread is in a Sleep syscall" detection vector. TimerQueueStrategy shifts the sleep to a pool thread (main caller still in a Wait syscall, but on an event that doesn't scream "beacon"). EkkoStrategy takes the actual Ekko approach: the beacon's own thread is diverted via `NtContinue` so its RIP is inside a syscall like `VirtualProtect`, not a sleep. Both are meaningful improvements, each with different costs.

## API surface

### New public exports

```go
// Cipher: symmetric transform applied twice per cycle. Stateless between cycles.
type Cipher interface {
    KeySize() int
    Apply(buf, key []byte)  // symmetric: Apply twice with same key is a no-op
}
type XORCipher struct{ Size int }     // default 32
type RC4Cipher struct{ Size int }     // default 16
type AESCTRCipher struct{}            // 48 bytes: 16 IV + 32 key

func NewXORCipher() *XORCipher
func NewRC4Cipher() *RC4Cipher
func NewAESCTRCipher() *AESCTRCipher

// Strategy: encapsulates the encrypt → wait → decrypt cycle.
// Mask owns the key (random per call, wiped with SecureZero); Strategy
// receives it by value.
type Strategy interface {
    Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error
}
type InlineStrategy struct{ UseBusyTrig bool }
type TimerQueueStrategy struct{}      // windows only; stub elsewhere
type EkkoStrategy struct{}            // windows+amd64 only; stub elsewhere

// Mask: same shape as today, now composed of Cipher + Strategy.
type Mask struct { /* unexported */ }
func New(regions ...Region) *Mask
func (m *Mask) WithCipher(c Cipher) *Mask
func (m *Mask) WithStrategy(s Strategy) *Mask
func (m *Mask) Sleep(ctx context.Context, d time.Duration) error

// Cross-process variant.
type RemoteRegion struct {
    Handle windows.Handle
    Addr   uintptr
    Size   uintptr
}
type RemoteStrategy interface {
    Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error
}
type RemoteInlineStrategy struct{ UseBusyTrig bool }
type RemoteMask struct { /* unexported */ }
func NewRemote(regions ...RemoteRegion) *RemoteMask
func (m *RemoteMask) WithCipher(c Cipher) *RemoteMask
func (m *RemoteMask) WithStrategy(s RemoteStrategy) *RemoteMask
func (m *RemoteMask) Sleep(ctx context.Context, d time.Duration) error
```

### Breaking removals (from v0.11.0 API)

- `type SleepMethod int`
- `const ( MethodNtDelay, MethodBusyTrig )`
- `func (*Mask) WithMethod(m SleepMethod) *Mask`
- `func (*Mask) Sleep(d time.Duration)` — signature changed to return `error` and accept `context.Context`

Migration for existing callers:
```go
// before (v0.11.0):
mask := sleepmask.New(region).WithMethod(sleepmask.MethodBusyTrig)
mask.Sleep(30 * time.Second)

// after (v0.12.0):
mask := sleepmask.New(region).WithStrategy(&sleepmask.InlineStrategy{UseBusyTrig: true})
if err := mask.Sleep(ctx, 30*time.Second); err != nil { /* handle */ }
```

## Strategy implementations

### InlineStrategy (L1)

Single-goroutine flow, no thread-pool involvement. Extraction of the current `Mask.Sleep` with cipher parameterization:

```
Cycle(ctx, regions, cipher, key, d):
    for i, r := range regions:
        VirtualProtect(r.Addr, r.Size, PAGE_READWRITE, &origProtect[i])
        cipher.Apply(unsafe.Slice(r.Addr, r.Size), key)

    select {
        case <-timer(d) or BusyWaitTrig(d) via goroutine:
        case <-ctx.Done():
    }

    for i, r := range regions:   // always runs, even on ctx cancellation
        VirtualProtect(r.Addr, r.Size, PAGE_READWRITE, &tmp)
        cipher.Apply(unsafe.Slice(r.Addr, r.Size), key)
        VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)

    return ctx.Err() if cancelled else nil
```

**Critical invariant**: `VirtualProtect(RW)` always precedes `cipher.Apply` in the encrypt phase — preserves the v0.11.0 bug fix (RX pages are not writable, `Apply` would fault).

**Thread**: caller's goroutine. No `runtime.LockOSThread` needed.

### TimerQueueStrategy (L2 light)

Pool-thread variant. The encrypt/wait/decrypt cycle runs entirely on a thread-pool worker via `CreateTimerQueueTimer`; caller blocks on a Windows event.

```
Main goroutine                  Pool thread (timer callback)
──────────────                  ────────────────────────────
Cycle:
    hEvent := CreateEventW(auto-reset)
    cb := packageTimerCallback   // package-level syscall.NewCallback
    CreateTimerQueueTimer(&hTimer, NULL, cb, statePtr,
                          0 /* fire now */, 0 /* one-shot */,
                          WT_EXECUTELONGFUNCTION | WT_EXECUTEDEFAULT)

    select {
        case <-waitOnHandle(hEvent):
        case <-ctx.Done():
            DeleteTimerQueueTimer(NULL, hTimer, INVALID_HANDLE_VALUE)
            // blocks until callback finishes (incl. decrypt via defer)
    }
    CloseHandle(hEvent)
    return state.err or ctx.Err() or nil

                                timerCallback(param, fired):
                                    state := (*workerState)(param)
                                    defer SetEvent(state.hEvent)
                                    for r: VirtualProtect(RW); cipher.Apply(r)
                                    WaitForSingleObject(state.hDummy, d_ms)
                                    for r: VirtualProtect(RW); cipher.Apply(r); VirtualProtect(orig)
```

**Key property**: the pool thread is the one in `WaitForSingleObject`. Its stack contains ntdll/kernel32 return addresses, not shellcode return addresses. The caller is in an event wait, which is a different signature from a `Sleep`/`SleepEx`.

**Not true Ekko**: the caller goroutine is still in a Wait syscall during the sleep. For "beacon thread RIP not visible on a sleeping thread", use `EkkoStrategy`.

**Callback allocation**: `syscall.NewCallback` is called **once** at package init time to produce the trampoline; subsequent Cycle calls reuse it. The trampoline is never freed (Go runtime holds it for the process lifetime).

### EkkoStrategy (L2 full)

Real Ekko as described by Peter Winter-Smith. Uses a chain of 6 `CreateTimerQueueTimer` callbacks where the callback IS `NtContinue`, each with a pre-crafted `CONTEXT` that makes the pool thread jump to a specific Windows API (`VirtualProtect`, `SystemFunction032`, `WaitForSingleObjectEx`, ...). The caller's main thread ends up redirected via the last `NtContinue(mainCtx)`.

```
Caller goroutine:
    runtime.LockOSThread()
    hCompletion := CreateEventW(auto-reset)
    hDummy      := CreateEventW(manual-reset, never signalled)
    hQueue      := CreateTimerQueue()

    RtlCaptureContext(&ctxMain)             // resume RIP = next instruction
    if atomic.LoadInt32(&chainDone) == 1:   // second pass (pool thread)
        proc_SetEvent.Call(uintptr(hCompletion))
        proc_ExitThread.Call(0)
        /* unreachable from Go */

    atomic.StoreInt32(&chainDone, 1)

    # Clone ctxMain into 6 CONTEXTs, each with Rip pointing at a target
    # Windows API and Rcx/Rdx/R8/R9 set to the call arguments per the x64
    # ABI. One CONTEXT per gadget:
    #   ctxProtRW    — Rip=VirtualProtect,        args: addr, size, PAGE_READWRITE, &origProtect
    #   ctxEncrypt   — Rip=SystemFunction032,     args: &dataUSTR, &keyUSTR
    #   ctxWait      — Rip=WaitForSingleObjectEx, args: hDummy, d_ms, FALSE
    #   ctxDecrypt   — Rip=SystemFunction032      (self-inverse RC4)
    #   ctxProtRX    — Rip=VirtualProtect         args: addr, size, origProtect, &tmp
    #   ctxResume    — Rip=&resumeStub            (see below)
    #
    # Each timer is scheduled as a standalone one-shot whose callback is
    # NtContinue itself. When the timer fires, the pool thread enters
    # NtContinue(&ctxN, fired) and is diverted to gadget N. The gadget's
    # `ret` pops a return address off ctxN.Rsp — in real Ekko this points
    # at a small trampoline (raw bytes we allocate, or a dedicated asm
    # function) that loads RCX with &ctxN+1 and tail-calls NtContinue so
    # the chain continues. The exact trampoline (pure asm `.s` or RWX
    # buffer filled at runtime) is an implementation-phase choice; the
    # spec-level contract is just "each gadget returns into a call of
    # NtContinue(&ctxN+1, fired)".

    CreateTimerQueueTimer(&hT0, hQueue, NtContinue, &ctxProtRW,  100, 0, 0)
    CreateTimerQueueTimer(&hT1, hQueue, NtContinue, &ctxEncrypt, 200, 0, 0)
    ...
    CreateTimerQueueTimer(&hT5, hQueue, NtContinue, &ctxResume,  totalMs, 0, 0)

    WaitForSingleObject(hCompletion, d + 5s /* watchdog */)
    DeleteTimerQueueEx(hQueue, INVALID_HANDLE_VALUE)
    CloseHandle(hDummy); CloseHandle(hCompletion)
    runtime.UnlockOSThread()
    return nil (or ctx.Err() or state.err)
```

**Resume stub** (`strategy_ekko_amd64.s`):
```asm
TEXT ·resumeStub(SB), NOSPLIT|NOFRAME, $0
    MOVQ ·resumeEvent(SB), CX
    MOVQ ·procSetEventAddr(SB), AX
    CALL AX
    MOVQ $0, CX
    MOVQ ·procExitThreadAddr(SB), AX
    CALL AX
    INT3   // unreachable
```

Pure asm because the pool thread running the stub is unknown to the Go runtime; any Go function call (including safe-point preemption) is UB.

**Cipher requirement**: `EkkoStrategy.Cycle` fails with an explicit error if `cipher` is not a `*RC4Cipher` — the chain hardcodes `SystemFunction032` (Windows RC4 primitive). Other ciphers cannot be wired into the ROP chain without additional gadgets, which is out of scope.

**Build constraints**:
- `strategy_ekko_windows.go` — `//go:build windows && amd64`
- `strategy_ekko_amd64.s` — `//go:build windows && amd64`
- `strategy_ekko_stub.go` — `//go:build !(windows && amd64)` — Cycle returns `errors.New("EkkoStrategy requires windows/amd64")`

**Windows APIs to add** to `win/api/dll_windows.go`:
- `ProcNtContinue` (ntdll)
- `ProcRtlCaptureContext` (ntdll)
- `ProcSystemFunction032` (advapi32)
- `ProcExitThread` (kernel32)
- `ProcDeleteTimerQueueTimer` (kernel32) — used by L2 light too
- `ProcDeleteTimerQueueEx` (kernel32) — used by L2 full

Already present: `ProcCreateTimerQueueTimer`, `ProcDeleteTimerQueue`, `ProcWaitForSingleObject`, `api.Context64`.

### RemoteInlineStrategy

Cross-process analog of `InlineStrategy`. Replaces `VirtualProtect` with `VirtualProtectEx`, reads/writes via `ReadProcessMemory`/`WriteProcessMemory` (cipher applied on a local copy, then written back). Only L1 cross-process ships in v0.12.0; remote L2 is not planned.

```
Cycle(ctx, regions, cipher, key, d):
    for each region:
        VirtualProtectEx(region.Handle, region.Addr, region.Size, PAGE_READWRITE, &orig)
        buf := make([]byte, region.Size)
        ReadProcessMemory(region.Handle, region.Addr, &buf[0], region.Size)
        cipher.Apply(buf, key)
        WriteProcessMemory(region.Handle, region.Addr, &buf[0], region.Size)

    select { case <-timer(d): ; case <-ctx.Done(): }

    for each region:
        VirtualProtectEx(region.Handle, region.Addr, region.Size, PAGE_READWRITE, &tmp)
        ReadProcessMemory → cipher.Apply → WriteProcessMemory
        VirtualProtectEx(region.Handle, region.Addr, region.Size, orig, &tmp)

    return ctx.Err() if cancelled else nil
```

## cmd/sleepmask-demo

Runnable command to demonstrate the mechanism end-to-end.

### Flags

```
-scenario={self|host}         default: self
-host-binary=string           default: C:\Windows\System32\notepad.exe
-cipher={xor|rc4|aes}         default: xor
-strategy={inline|timerqueue|ekko}  default: inline
-inline-busytrig=bool         default: false
-cycles=int                   default: 3
-sleep=duration               default: 5s
-scanner=bool                 default: true
-scanner-interval=duration    default: 100ms
-verbose=bool                 default: true
```

### Output contract (scenario=self)

```
[0000ms] allocating 19-byte canary region at 0xADDR (RX)
[0001ms] scanner started (interval 100ms)
[0002ms] cycle 1/3 begin — strategy=ekko cipher=rc4 sleep=5s
[0003ms] scanner HIT at 0xADDR+3 (marker "MALDEV_CANARY!!\n" found)
[0103ms] scanner HIT
[0200ms] mask.Sleep begin
[0201ms] scanner MISS (region not executable)
...
[5201ms] mask.Sleep returned nil
[5301ms] scanner HIT at 0xADDR+3
[5302ms] cycle 1/3 end (0 hits during masked window)
...
```

### Scenario B (host=notepad)

1. Spawn `notepad.exe` suspended via existing `inject/` primitives.
2. Allocate + write canary in notepad via `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx(PAGE_EXECUTE_READ)`.
3. Report the remote address.
4. Build `RemoteMask` with `RemoteRegion{Handle: hNotepad, Addr: remoteAddr, Size: 19}`.
5. Run 3-cycle beacon loop, optionally scan remote process memory from demo via `ReadProcessMemory` polling (scanner-ish).

## Testing plan

### Cross-platform unit tests

| File | Scope |
|------|-------|
| `cipher_test.go` (existing) | XOR/RC4/AES round-trip, edge cases |
| `mask_test.go` [new] | `New`, `WithCipher`, `WithStrategy`, default values, nil guards |
| `strategy_inline_test.go` [new] | InlineStrategy against a FakeStrategy test double |
| `remote_mask_test.go` [new] | RemoteMask builder surface |

### Windows VM tests

| File | Scope |
|------|-------|
| `strategy_inline_windows_test.go` [new] | Real VirtualProtect round-trip, preserves bytes, restores protection |
| `strategy_timerqueue_windows_test.go` [new] | Spy callback fires exactly once, event signalled, cancellation via DeleteTimerQueueTimer(INVALID_HANDLE_VALUE) |
| `strategy_ekko_windows_test.go` [new, amd64] | `chainDone` flag set by pool thread, `resumeStub` hit, bytes restored, protection restored; intrusive gate |
| `remote_mask_windows_test.go` [new] | `RemoteInlineStrategy` against a spawned notepad, intrusive gate |
| `sleepmask_e2e_windows_test.go` (existing) | Extended: each e2e test loops `strategy = {Inline, TimerQueue, Ekko}` |

### Dedicated tests

- `TestEkkoStrategy_RejectsNonRC4Cipher` — calling Cycle with `*XORCipher` returns a specific error
- `TestEkkoStrategy_ResumeStubIsHit` — intrusive, runs 1 short cycle, asserts `chainDone == 1` and `resumeEvent` was signalled
- `TestMask_DefaultCipherIsXOR` — `New(r).Sleep(ctx, d)` with no WithCipher uses XOR
- `TestMask_DefaultStrategyIsInline` — same for Strategy

## Documentation plan

### Code comments

Package-level comment in `mask.go` points at `docs/techniques/evasion/sleep-mask.md` for detailed levels discussion. Each strategy file has a docstring explaining its threading model and when to pick it. `.s` file has a comment explaining why pure asm (Go runtime can't be entered from an unknown thread).

### `docs/techniques/evasion/sleep-mask.md` rewrite

Full outline:

1. **Primer** — reuse current analogy
2. **The four levels of sophistication** — taxonomy table + which levels maldev ships
3. **How it works** — Mermaid diagram of Cipher + Region + Strategy composition
4. **Strategies** — one subsection each:
   - `InlineStrategy` (L1)
   - `TimerQueueStrategy` (L2 light) with threading diagram
   - `EkkoStrategy` (L2 full) with ROP chain diagram
5. **Ciphers** — XOR vs RC4 vs AES tradeoffs
6. **Cross-process: RemoteMask** — flow diagram, current limitations
7. **Running the demo** — `cmd/sleepmask-demo` walkthrough
8. **Limitations for Go implants** — runtime not masked; focus on PIC shellcode; stack masking not implemented
9. **Verifying it works** — e2e test commands
10. **Compared to other implementations** — maldev vs Cobalt vs Sliver vs original Ekko
11. **API reference** — updated for Cipher / Strategy / Mask / RemoteMask

### CHANGELOG.md

Entry in `[Unreleased]`, sealed to `[v0.12.0]` at release time. Breaking-change section lists every signature change and provides a migration snippet.

### README

No change. The package description in the main README table still fits: the new capabilities are additive variants of the existing "sleep mask" entry.

## Implementation commit ordering

| # | Commit | Scope |
|---|--------|-------|
| 1 | `feat(sleepmask): Cipher interface + Mask refactor` | Cipher integration (XOR/RC4/AES), InlineStrategy extracted, Sleep(ctx, d) error signature, removal of SleepMethod/WithMethod, existing tests updated |
| 2 | `feat(sleepmask): TimerQueueStrategy (L2 light)` | TimerQueueStrategy + `ProcDeleteTimerQueueTimer` addition + unit + VM tests |
| 3 | `feat(sleepmask): EkkoStrategy (L2 full, pure Go + plan9 asm)` | EkkoStrategy + resumeStub asm + 5 missing procs + unit + VM tests |
| 4 | `feat(sleepmask): RemoteMask + RemoteInlineStrategy` | Cross-process variant + unit + VM intrusive test |
| 5 | `feat(sleepmask): cmd/sleepmask-demo + doc rewrite + v0.12.0` | Demo command, sleep-mask.md rewrite, CHANGELOG, tag v0.12.0 |

Each commit is individually reviewable and the branch stays green after each.

## Deferred / future work

- **L3** — APC/fiber redirection (Foliage, Deathsleep, Cronos). Requires understanding APC queue, alertable waits, and fiber switching. Meaningful only when you want to also mask the stack call origin, not just the bytes.
- **L4** — BOF sleep mask. Requires a BOF loader + ABI definition for what a user-provided sleep mask callback receives. Cobalt Strike 4.7+ uses `SLEEPMASK_INFO` struct; we would define our own Go interface that mirrors it.
- **RemoteEkkoStrategy** — cross-process Ekko. The ROP chain executes in our process but the region is in another. Several non-trivial problems: (a) `SystemFunction032` would encrypt a buffer in our process, requiring `ReadProcessMemory` before and `WriteProcessMemory` after, breaking the ROP chain's purity; (b) `VirtualProtectEx` has a different signature; (c) protecting the remote chain from inspection would require masking in the remote process too. Probably not worth the complexity.
- **Stack masking of the calling thread** — for evading Hunt-Sleeping-Beacons. Would zero/scramble the thread's stack during sleep and restore on wake. Interacts badly with Go's movable goroutine stacks; probably requires `runtime.LockOSThread` + manipulation of the OS thread stack via `GetCurrentThread()` context read. L3 territory.

## Open questions

None remaining after the brainstorming session. Every design decision has an explicit pointer in the relevant section above.
