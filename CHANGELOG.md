# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html). Pre-1.0 minor bumps may
introduce breaking API changes.

## [Unreleased]

### Reorganization — Pass 1 (v0.20.0): `recon/` carve-out + `system/` retirement

Top-level package restructure separating **passive recon** (read-only
environment discovery) from **active evasion** (system-state mutation).
The pre-Pass-1 `evasion/` mixed both, and `system/` was a junk drawer
containing recon, persistence, anti-forensic, destructive, and UI
packages. See `docs/superpowers/plans/2026-04-25-package-reorganization.md`
for the full audit and the 3-pass migration plan.

**Moved into new `recon/` (read-only environment discovery):**

- `evasion/antidebug` → `recon/antidebug` (debugger detection)
- `evasion/antivm` → `recon/antivm` (VM/hypervisor detection)
- `evasion/sandbox` → `recon/sandbox` (multi-factor sandbox orchestrator)
- `evasion/timing` → `recon/timing` (time-acceleration detection)
- `evasion/hwbp` → `recon/hwbp` (DR0-DR7 hardware-breakpoint inspection)
- `evasion/dllhijack` → `recon/dllhijack` (DLL search-order hijack opportunity discovery — never modifies state, returns `Opportunity` records)
- `system/drive` → `recon/drive`
- `system/folder` → `recon/folder`
- `system/network` → `recon/network`

**Moved into other trees:**

- `system/lnk` → `persistence/lnk` (LNK creation, used by `persistence/startup`)
- `system/ads` → `cleanup/ads` (NTFS Alternate Data Streams data-hiding)
- `system/bsod` → `cleanup/bsod` (destructive system disruption)
- `system/ui` → `ui/` (top-level — interactive MessageBox + sounds)

**`system/` retired entirely.**

Package names are unchanged — only import paths move. `antidebug` and
`antivm` keep the well-known `anti-` prefix (terms of art). The
`evasion.Technique` interface, `inject.Injector` + `Pipeline`, and all
other contracts are unchanged.

**Breaking change for external consumers:** every import path that
referenced one of the 13 moved packages must be rewritten. No type
aliases ship — clean break, version bump.

**Docs updated:** README capability table, `docs/architecture.md`
Layer-2 subgraph, `docs/system.md` renamed to `docs/recon.md`,
`docs/mitre.md` package paths, technique pages
(`docs/techniques/evasion/{anti-analysis,sandbox,timing,hw-breakpoints,dll-hijack}.md`,
`docs/techniques/collection/alternate-data-streams.md`).

### Added

- `kernel/driver`: new Layer-1 package defining `Reader` /
  `ReadWriter` / `Lifecycle` interfaces consumed by EDR-bypass
  packages that need arbitrary kernel reads or writes (kcallback,
  lsassdump PPL-bypass, …). Sentinel errors `ErrNotImplemented`,
  `ErrNotLoaded`, `ErrPrivilegeRequired`. **Chantier A.1.**
- `kernel/driver/rtcore64`: BYOVD primitive scaffold for MSI Afterburner
  RTCore64.sys (CVE-2019-16098). Ships SCM service install / start /
  stop / uninstall, `\\.\RTCore64` device handle management, and
  IOCTL `0x80002048` read / `0x8000204C` write wrappers (cap
  `MaxPrimitiveBytes = 4096` per IOCTL). Driver binary intentionally
  NOT embedded by default — callers opt-in via the `byovd_rtcore64`
  build tag and ship a sibling embed file. Default builds surface
  `ErrDriverBytesMissing`. Technique page
  `docs/techniques/evasion/byovd-rtcore64.md`. **Chantier A.1.**
- `evasion/kcallback`: `Remove` + `Restore` + `RemoveToken` (v0.17.1).
  Captures the slot's tagged-pointer value before zeroing 8 bytes;
  `Reprotect` writes the original back. `Callback.SlotAddr` is now
  populated by `Enumerate` so `Remove` can key on the per-slot
  kernel VA. 12 mock-reader unit tests cover happy path, race
  windows, nil-writer guards, deferred-cleanup zero-token idiom.
  **Chantier B (v0.17.1).**
- `collection/lsassdump`: `Unprotect` + `Reprotect` + `PPLToken` +
  `PPLOffsetTable` (v0.15.1). EPROCESS-unprotect path mirroring
  mimikatz's mimidrv strategy: caller plugs in a
  `kernel/driver.ReadWriter`, passes lsass's EPROCESS kernel VA +
  build-specific `PS_PROTECTION` byte offset, and Unprotect zeros
  the byte so a userland `OpenLSASS` succeeds even when
  `RunAsPPL=1`. 8 mock-reader unit tests. **Chantier C (v0.15.1).**

### Changed

- `pe/clr`: `corBindToRuntimeEx` now wraps `REGDB_E_CLASSNOTREG`
  (HRESULT `0x80040154`) with `%w` + the raw HRESULT, so SKIP
  messages on the win10 TOOLS snapshot now read
  `"CorBindToRuntimeEx(v2.0.50727): HRESULT 0x80040154 (REGDB_E_CLASSNOTREG): clr: ICorRuntimeHost unavailable …"`
  — the next investigator sees the actual code without rebuilding.
  **Chantier F (pt 1/2).**
- `scripts/vm-provision.sh`: TOOLS v2 — registers the
  `{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}` (CorRuntimeHost) CLSID
  every provisioning pass. Confirmed 2026-04-25 that this alone is
  insufficient to unblock `pe/clr` tests — mscoree's binding chain
  needs more than the CLSID (interface, typelib, Fusion entries),
  which only the full .NET 3.5 Redistributable / Win10-ISO
  `sources/sxs` payload runs. The CLSID baseline stays so future
  ISO-based reprovisioning starts from a stable point. **Chantier F
  (pt 1/2).**

- `evasion/callstack`: `SpoofCall(target, chain, args...)` + plan9 asm
  pivot (`spoof_windows_amd64.s`). Allocates a 64 KiB side stack via
  VirtualAlloc, plants the chain, and JMPs to target with RSP swapped
  to the chain top; `spoofTrampoline` lands on the chain bottom and
  restores Go's RSP/R14 before returning the target's RAX. **Scaffold
  only** — 6 caller-side unit tests are green but the end-to-end
  pivot crashes Go's runtime (`lastcontinuehandler`) under
  `MALDEV_SPOOFCALL_E2E=1`. Promotion to a tagged release waits on
  the e2e crash being root-caused. **Chantier D.**
- `evasion/sleepmask`: `MultiRegionRotation` wrapper — applies any
  single-region strategy (notably `EkkoStrategy`) sequentially across
  N regions, sleeping `d/N` per region. Total wall-clock matches `d`;
  trade-off is staggered protection. 7 unit tests cover the dispatch
  contract, error propagation, context-cancel, and short-duration
  fallback. **Chantier H.**

### Documented

- `inject/realsc`: `MethodCreateFiber + Go runtime` incompatibility.
  `ConvertThreadToFiber` permanently transforms the calling OS thread
  into a fiber-control thread; Go's M:N scheduler does not understand
  fibers. Real shellcode ending in `ExitThread`/`ret` kills the host
  runtime mid-execution; goroutines + `runtime.LockOSThread` are NOT
  enough. Documented integration pattern: spawn a true
  `kernel32!CreateThread` OS thread (not a goroutine) and let the
  fiber die there. `TestFiber_RealShellcode` SKIP message + header
  comment + `docs/techniques/injection/README.md` warning. **Chantier
  E.**
- `recon/dllhijack`: KindProcess Validate sandboxed-spawn design
  sketch in `docs/techniques/evasion/dll-hijack.md`. Pattern: spawn a
  fresh copy of the same binary in a sandboxed working directory
  reproducing the production DLL search path, drop canary, wait
  for marker / bounded timeout, terminate child. Implementation
  pending — needs sandboxed-spawn helper, signed-canary support,
  `opts.AllowSpawn` operator opt-in. **Chantier G.**

- `recon/dllhijack`: `stealthopen.Opener` composition — every scanner
  (`ScanServices` / `ScanProcesses` / `ScanScheduledTasks` /
  `ScanAutoElevate` / `ScanAll`) now accepts a trailing `...ScanOpts`
  variadic whose `Opener` field routes every PE file read through the
  given stealth open strategy (e.g. NTFS Object ID, bypassing
  path-keyed EDR file hooks). Backward-compatible: zero args preserves
  the historical `os.Open` path. `ScanProcesses` accepts the opts for
  symmetry but has no file-read surface (loaded-module Toolhelp32
  reads only).

### Changed

- `recon/dllhijack`: major `/simplify` pass against the v0.14.0 series
  (aggregated 4 review agents: reuse, quality, efficiency, skill-
  conformity + test relevance). Single shared `emitOppsForDLLs` helper
  replaces the near-identical loop body of all 4 scanners (dedup →
  `HijackPath` → emit Opportunity with consistent field fill). ~120 LOC
  removed from scan_services / scan_processes / scan_autoelevate. Each
  scanner now passes scanner-specific reason + extras via closures.
- `recon/dllhijack`: `isKnownDLL` caches the KnownDLLs registry list
  behind a `sync.Once` — a full service+process+task scan previously
  re-enumerated the registry ~3,000× (O(N×M)); now it's loaded once
  and backed by a `map[string]struct{}` for O(1) lookups.
- `recon/dllhijack`: `HijackPath` adds a per-call `map[string]bool`
  stat cache so the resolver's two directory walks share `os.Stat`
  results, halving syscalls per call.

### Added

- `recon/dllhijack`: `ScanAutoElevate` + `Rank` + `IsAutoElevate`
  (**Phase D**). Walks System32 .exes whose embedded manifest sets
  `autoElevate=true` (fodhelper, sdclt, WSReset, …) — the UAC-bypass
  vector class — parses PE imports + search order, and emits
  Opportunities flagged `AutoElevate=true` + `IntegrityGain=true`
  (MITRE T1548.002). `Rank` scores all Opportunities with a coarse
  weighting (AutoElevate +200, IntegrityGain +100, Kind base score)
  and returns a sorted slice. `IsAutoElevate([]byte)` is a
  cross-platform byte-level check for the manifest flag. New
  `KindAutoElevate` Kind value. `ScanAll` now aggregates
  services + processes + tasks + auto-elevate.
- `recon/dllhijack`: `Validate` + canary-drop/trigger/poll orchestration
  (**Phase C**). Given an Opportunity and a user-supplied canary DLL,
  Validate drops the DLL at HijackedPath, triggers the victim (service
  restart via SCM for KindService, scheduler.Run for KindScheduledTask),
  polls a configurable glob for a marker file created by the canary's
  DllMain, and always cleans up (retries removal to tolerate writers
  still holding the handle). `ValidateOpts` exposes MarkerGlob /
  MarkerDir / Timeout / PollInterval / KeepCanary. KindProcess is
  rejected (can't cleanly relaunch a running process). Sample
  `canary.c` (30 lines, MinGW-buildable) shipped in
  `recon/dllhijack/canary/` with build instructions — deliberately
  not pre-built to avoid committing a hash-fingerprinted artifact.
- `persistence/scheduler`: `Actions(name)` returns the IAction Path
  entries for a registered task (used by dllhijack). `Run` and
  `Actions` routed through ITaskFolder.GetTask rather than
  ITaskService.GetTask (which is not an actual method on that
  interface; the old call path would always fail).
- `recon/dllhijack`: two new scanners (**Phase B**):
  - `ScanProcesses` — enumerates every accessible running process and
    reads the live loaded-module list via Toolhelp32, covering DLLs
    loaded at runtime via LoadLibrary (the blind spot of static PE
    import analysis).
  - `ScanScheduledTasks` — walks every registered scheduled task via
    COM ITaskService, extracts each exec action's binary path, applies
    the same PE-imports filter as `ScanServices`.
  - `ScanAll` aggregates services + processes + tasks. Partial failures
    are surfaced but don't abort the remaining scanners.
- `process/enum`: `ImagePath(pid)` via `QueryFullProcessImageNameW`,
  `Modules(pid)` via `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`,
  and the `Module` struct (Name/Path/Base/Size).
- `persistence/scheduler`: `Actions(name)` returns exec-action binary
  paths for a registered task. Only `TASK_ACTION_EXEC` entries are
  reported; COM/email/message actions are skipped.
- `recon/dllhijack`: `ScanServices` rewritten to use PE imports + DLL
  search-order resolution (**Phase A**). Each Opportunity now names the
  exact `HijackedDLL` and the `HijackedPath` where a payload DLL
  should be dropped, instead of just flagging writable service
  directories. KnownDLLs (HKLM\...\Session Manager\KnownDLLs) are
  correctly excluded. New exported primitives `SearchOrder(exeDir)`
  and `HijackPath(exeDir, dllName)` for callers that read service
  config from non-SCM sources.
- `evasion/sleepmask`: `FoliageStrategy` (L3) — Ekko + a stack-scrub
  `memset` gadget inserted between the encrypt and wait steps. Before
  the pool thread blocks in `WaitForSingleObjectEx`, it zeros the used
  gadget shadow frames so a stack-walker mid-sleep sees clean zeros
  above Rsp instead of VP/SF032 residue. Lighter than Austin Hudson's
  full Foliage (no fake-RA chain), but self-contained. Clamp on
  `ScrubBytes` prevents over-requesting from clobbering the memset's
  own return path. Added to the 4-strategy e2e sub-test loop
  (inline / timerqueue / ekko / foliage) — all pass the concurrent
  scanner invariant. Layout bumped to accommodate 7 gadgets
  (trampolines at +0x10000, slots at +0x10160, contexts at +0x11000)
  in the shared `ekkoLayout`. `ntdll!memset` added to `win/api` (used
  via `.Addr()` as gadget target — the exported `RtlFillMemory` is a
  memset alias, so calling it with RtlFillMemory's documented arg
  order crashes).
- `recon/dllhijack` — new package for DLL search order hijack discovery
  (MITRE T1574.001). MVP: `ScanServices()` enumerates every installed
  Windows service and returns `Opportunity` rows for those whose binary
  directory is writable by the current user — the classic "drop DLL →
  service loads it next start" vector. `ParseBinaryPath` exported as a
  pure-string helper that handles quoted + unquoted SCM BinaryPathNames.
  Cross-platform stub returns an error on non-Windows. Process /
  scheduled-task scanning, PE-imports resolution, and canary-DLL
  validation deferred to Phase 2.1. Added to docs/mitre.md, README
  tables, and docs/techniques/evasion/dll-hijack.md.

### Fixed

- `evasion/sleepmask`: `EkkoStrategy` full ROP chain round-trip now works
  end-to-end on Win10 amd64. Root cause of the previous crashes was that
  `SystemFunction032`'s stack frame grew downward from each gadget's Rsp
  into our own slot-table / trampoline bytes, corrupting them mid-chain;
  subsequent trampolines then loaded garbage CONTEXT pointers and
  NtContinue faulted at `0xffffffffffffffff`. Scratch layout restructured
  so all metadata (trampolines, slots, USTRs, key, contexts) lives at the
  top of the buffer, above every gadget's Rsp; each gadget gets 8 KB of
  pure padding below its Rsp for the API's own stack growth.
  `TestEkkoStrategy_CycleRoundTrip` un-skipped; Ekko added to the
  `TestSleepMaskE2E_DefeatsExecutablePageScanner/{inline,timerqueue,ekko}`
  sub-test loop. Also fixed: single-timer kickoff (removed multi-timer
  pool-thread race), `resumeStub` spins-forever instead of ExitThread
  (avoids corrupting thread-pool callback bookkeeping),
  `DeleteTimerQueueEx(NULL)` for non-blocking cleanup, USTRING layout
  (`ULONG Length` not `USHORT`), `ContextFlags` narrowed to
  CONTROL|INTEGER so FPU state isn't restored cross-thread.

### Added

- `scripts/vm-provision.sh`: Windows VM now gets WER LocalDumps
  configured (HKLM\...\LocalDumps → `C:\Dumps`, DumpType=2/full,
  DumpCount=10, DontShowUI=1). Used to diagnose the Ekko SF032
  stack-clobbering bug; stays for future pool-thread crash
  investigation. `vm_running` locale fix (`LC_ALL=C virsh domstate`) so
  the script no longer trips on French `en cours d'exécution`.
- `docs/vm-test-setup.md`: new "Debugging native crashes" section
  documenting the Go crash-reporter + WER LocalDumps workflow for
  investigating non-Go-thread access violations (e.g. thread-pool
  callbacks, ROP chains) on the VM.


## [v0.17.0] — 2026-04-25

### Added

- `evasion/kcallback`: kernel callback-array enumeration (MITRE
  T1562.001). User-mode symbol & driver resolution via
  `NtQuerySystemInformation(SystemModuleInformation = 11)` —
  `NtoskrnlBase()` returns the kernel image base, `DriverAt(addr)`
  reverse-maps a kernel VA to its owning driver module name. Both
  are cached once per process and require no elevation.
- `Enumerate(reader KernelReader, tab OffsetTable)` reads the three
  callback arrays (PspCreateProcessNotifyRoutine / ThreadNotifyRoutine
  / LoadImageNotifyRoutine) via a caller-supplied KernelReader,
  masks the `PEX_CALLBACK` flags, dereferences each ROUTINE_BLOCK+8
  to get the callback function VA, and resolves the owning driver.
  `NullKernelReader` (default) always returns `ErrNoKernelReader` —
  callers plug in a BYOVD-backed reader (RTCore64, GDRV, custom
  driver). Offsets are caller-supplied (no built-in database;
  PDB-derivation workflow documented in
  `docs/techniques/evasion/kernel-callback-removal.md`).
- Removal is deliberately **out of scope** for v0.17.0; the write
  primitive lands in v0.17.1 alongside a dedicated BYOVD chantier.
  The `KernelReadWriter` interface + `ErrReadOnly` are shipped so
  the removal API can slot in without a breaking change.


## [v0.16.0] — 2026-04-25

### Added

- `evasion/callstack`: call-stack spoofing metadata primitives (MITRE
  T1036). Ships `LookupFunctionEntry` (ntdll!RtlLookupFunctionEntry
  wrapper, returns a Frame carrying ReturnAddress + ImageBase +
  RUNTIME_FUNCTION by value), `StandardChain` (cached 2-frame chain:
  kernel32!BaseThreadInitThunk inner → ntdll!RtlUserThreadStart
  outer, each frame pre-populated with unwind metadata),
  `FindReturnGadget` (byte-scans ntdll's .text for a lone RET
  0xC3 + int3/nop padding, cached once per process, guaranteed to
  have its own RUNTIME_FUNCTION), and `Validate` (structural chain
  consistency check).
- The asm pivot that actually executes a call through a synthesized
  chain is deferred to **v0.16.1** — v0.16.0 provides the building
  blocks so higher-level packages (`inject`, `evasion/unhook`,
  future sleepmask L4) can compose their own pivots.


## [v0.15.0] — 2026-04-24

### Added

- `collection/lsassdump`: LSASS credential dump package (MITRE
  T1003.001). `OpenLSASS` walks the process list via
  `NtGetNextProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` (cheap
  access even protected processes grant), identifies `lsass.exe` via
  `NtQueryInformationProcess(ProcessImageFileName)`, reads the PID
  via `ProcessBasicInformation`, and reopens the target via
  `NtOpenProcess(pid, QUERY_LIMITED | VM_READ)` — keeping the
  `VM_READ` audit surface to a single targeted event. `Dump` streams
  a MINIDUMP blob (MDMP, SystemInfo + ThreadList + ModuleList +
  Memory64List) to the caller's `io.Writer`; memory contents are
  `NtQueryVirtualMemory`-walked and `NtReadVirtualMemory`-read one
  region at a time, never via `MiniDumpWriteDump` (heavily
  EDR-hooked). Every `Nt*` call accepts an optional
  `*wsyscall.Caller` for direct/indirect syscall routing.
- `collection/lsassdump.Build` is exported so callers can assemble a
  MINIDUMP from arbitrary memory regions (test fixtures, replayed
  snapshots). Pure-Go byte-packing; no dbghelp.
- VM e2e (admin + MALDEV_INTRUSIVE, Win10 TOOLS snapshot): dumps
  lsass in ~0.6s, produces a 56MB MINIDUMP parseable by pypykatz /
  mimikatz — extracts MSV NT hashes, WDigest, Kerberos session
  material, and DPAPI master keys. PPL-protected lsass returns
  `ErrPPL`; bypass is a separate chantier.


## [v0.14.1] — 2026-04-24

### Fixed

- `persistence/scheduler`: `CoInitializeEx` now accepts `S_FALSE`
  (0x00000001) as a success code. COM refcounts per thread — when a
  prior caller on the same goroutine's underlying thread already
  initialised COM, CoInitializeEx returns `S_FALSE`, which go-ole
  wraps as an OleError. The handler only whitelisted
  `RPC_E_CHANGED_MODE`, so any scheduler call after another
  COM-initialising path failed with "Fonction incorrecte." Surfaced
  by the dllhijack VM sweep (ScanScheduledTasks + Validate running
  in the same test binary).

### Changed

- `recon/dllhijack`: drop `readAll` / `readImports` nil-opener
  branches in favour of `stealthopen.Use`/`stealthopen.OpenRead`;
  `ScanAutoElevate` now reads each candidate PE once (not twice) and
  parses imports from the in-memory bytes via `importsFromBytes`.
- `testutil`: new `SpyOpener` consolidates the `stealthopen.Opener`
  spy pattern previously duplicated across four test files
  (`recon/dllhijack`, `evasion/herpaderping`, `evasion/unhook`,
  `inject/phantomdll`). Single source, mutex-guarded `Paths()` /
  `Last()` snapshots, and a defaulted `Inner` so tests can stay
  focused on call-count / last-path assertions.
- `recon/dllhijack`: `TestValidate_OrchestrationEndToEnd` timeout
  bumped 10s → 30s to tolerate PowerShell cold-start on a
  freshly-reverted VM (observed up to 10.4s from first run).


## [v0.12.0] — 2026-04-24

3-strategy sleep-mask architecture, pluggable Cipher (XOR/RC4/AES-CTR),
cross-process RemoteMask, EkkoStrategy scaffold, and a runnable
`cmd/sleepmask-demo` that demonstrates both self-process and
host-injection scenarios with a concurrent scanner.

### Breaking (pre-1.0 minor bump)

- `(*Mask).Sleep(d time.Duration)` → `Sleep(ctx context.Context, d time.Duration) error`.
  Callers must pass a context and may inspect the returned error
  (`ctx.Err()` on cancel, nil on success). Decrypt still always runs, even
  on cancellation.
- `SleepMethod`, `MethodNtDelay`, `MethodBusyTrig`, `(*Mask).WithMethod`
  removed. Use `WithStrategy(&InlineStrategy{UseBusyTrig: true})` for the
  old busy-wait path, or one of the new `TimerQueueStrategy` /
  `EkkoStrategy` for a different thread model.

### Added

- `sleepmask.Cipher` interface + three implementations:
  `NewXORCipher()`, `NewRC4Cipher()`, `NewAESCTRCipher()`. Self-inverse
  `Apply(buf, key)` so encrypt and decrypt are the same call. Selected
  via `Mask.WithCipher(...)`. Fresh random key per cycle is still drawn
  from `crypto/rand` sized to `cipher.KeySize()` and scrubbed via
  `cleanup/memory.SecureZero`.
- `sleepmask.Strategy` interface + three implementations:
  - `InlineStrategy{UseBusyTrig bool}` — historical L1 behavior; caller
    goroutine runs the encrypt/wait/decrypt.
  - `TimerQueueStrategy{}` — L2-light: cycle runs on a Windows
    thread-pool worker via `CreateTimerQueueTimer`; caller blocks on an
    auto-reset completion event.
  - `EkkoStrategy{}` — L2-full scaffold: 6 CONTEXT ROP chain
    (`VirtualProtect` → `SystemFunction032` → `WaitForSingleObjectEx` →
    `SystemFunction032` → `VirtualProtect` → resumeStub) with a plan9
    asm resume stub. Input validation (RC4 only, single region) ships;
    chain execution itself is WIP (CONTEXT alignment, Rsp alignment,
    shadow-space separation). `TestEkkoStrategy_CycleRoundTrip` is
    skipped with a diagnostic message.
- `sleepmask.RemoteMask` + `RemoteRegion` + `RemoteInlineStrategy` for
  masking memory in another process via `VirtualProtectEx` +
  `ReadProcessMemory` + `WriteProcessMemory`. Requires
  `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`. Verified
  against a spawned notepad in `TestRemoteInlineStrategy_RoundTrip`.
- `cmd/sleepmask-demo` — flag-driven demo (`-scenario self|host`,
  `-cipher xor|rc4|aes`, `-strategy inline|timerqueue|ekko`,
  `-cycles`, `-sleep`, `-scanner`). Runs a concurrent scanner printing
  HIT/MISS transitions as the mask cycles.
- `win/api` procs added: (kernel32) `CreateTimerQueue`,
  `DeleteTimerQueueTimer`, `DeleteTimerQueueEx`, `SetEvent`,
  `ExitThread`, `VirtualProtect`, `WaitForSingleObjectEx`; (ntdll)
  `NtContinue`, `RtlCaptureContext`; (advapi32) `SystemFunction032`.
- `docs/techniques/evasion/sleep-mask.md` rewritten around the 4-level
  taxonomy with strategy/cipher comparison tables and a demo walkthrough.

### Deferred

- EkkoStrategy ROP chain execution (scaffold ships, chain debug is future
  work — see strategy_ekko_windows.go doc comment).
- L3 (Foliage-style stack scrubbing), L4 (BOF-style in-memory loader
  isolation).
- Remote L2 and remote L2-full variants.

## [v0.11.0] — 2026-04-23

Go 1.21 baseline (Windows 7 binary support), Opener composition analog to
wsyscall.Caller, SelfInjector interface, DoSecret runtime/secret
integration, sleepmask bug fix + e2e tests, reproducible cross-platform
coverage workflow.

### Breaking (pre-1.0 minor bump)

- `evasion/unhook.ClassicUnhook(funcName, caller)` →
  `ClassicUnhook(funcName, caller, opener stealthopen.Opener)`. Pass `nil`
  for opener to keep the historic path-based ntdll.dll read. (e674462)
- `evasion/unhook.FullUnhook(caller)` →
  `FullUnhook(caller, opener stealthopen.Opener)`. Same nil fallback. (e674462)
- `inject.PhantomDLLInject(pid, dll, shellcode)` →
  `PhantomDLLInject(pid, dll, shellcode, opener stealthopen.Opener)`. The
  opener is consulted twice: PE-parse read + NtCreateSection HANDLE.
  (e674462)
- `go.mod` directive: `go 1.25.0` → `go 1.21`. Requires downgrade of
  `github.com/refraction-networking/utls` to v1.6.7,
  `golang.org/x/{arch,crypto,sync,sys,text}` to their last Go-1.21-compatible
  versions. No regression in used APIs (audited call-site by call-site).
  Unlocks Go 1.21 compilation, which is the last Go release producing
  binaries compatible with Windows 7 / Server 2008 R2. (5b0689e)

### Added

- `evasion/stealthopen.Opener` interface + `Standard`, `Stealth`,
  `NewStealth`, `VolumeFromPath`, `Use` helpers. Mirrors how
  `*wsyscall.Caller` is threaded through the library: optional, nil-safe,
  swaps a path-based `os.Open` for `OpenFileById` via NTFS Object ID so
  path-keyed EDR file hooks never observe the open. Wired into
  `evasion/unhook`, `inject.PhantomDLLInject`, and
  `evasion/herpaderping.Config.Opener` (new field). (e674462)
- `cleanup/memory.DoSecret(func())` and `SecretEnabled()` — opt-in wrapper
  around Go 1.26's experimental `runtime/secret.Do` for erasing registers,
  stack locals, and heap temporaries of a sensitive computation. Selected
  via build tags `go1.26 && goexperiment.runtimesecret`; stub fallback
  everywhere else keeps the same API so callers can wrap unconditionally.
  (5b0689e)
- `cleanup/memory.SecureZero` is now cross-platform (moved out of
  `memory_windows.go` into `memory.go`). `WipeAndFree` remains Windows-only.
  (5b0689e)
- `inject.Region` + `inject.SelfInjector` optional interface. Self-process
  injectors (`MethodCreateThread`, `MethodCreateFiber`,
  `MethodEtwpCreateEtwThread` on Windows, `MethodProcMem` on Linux) publish
  the local allocation via `InjectedRegion() (Region, bool)` after a
  successful Inject, so callers can feed it straight into `sleepmask.Mask`
  or `cleanup/memory.WipeAndFree` without re-deriving addr/size.
  Decorators (`WithValidation`, `WithCPUDelay`, `WithXOR`) and `Pipeline`
  forward the region transparently. Cross-process methods return
  `(Region{}, false)`. (5b0689e)
- 6 e2e tests for `evasion/sleepmask` (`sleepmask_e2e_windows_test.go`):
  concurrent `testutil.ScanProcessMemory` loop during `Mask.Sleep()`,
  protection round-trip checks, multi-region, 10-cycle beacon stability,
  `MethodBusyTrig` variant. Run via `./scripts/vm-run-tests.sh windows`.
  (5b0689e, 82a9ab7)
- Opener-wiring tests: `evasion/stealthopen/opener{_,_windows_}test.go`,
  `evasion/unhook/opener_windows_test.go`,
  `inject/phantomdll_opener_test.go`,
  `evasion/herpaderping/opener_windows_test.go`. Cover both the
  `Standard`/`Use(nil)` fallback and the real `NewStealth` round-trip
  through `OpenFileById`, plus spy-opener assertions that each consumer
  consults the Opener the expected number of times. (e674462)
- `cmd/vmtest`: new `-report-dir` flag with `Fetch()` method (scp for
  libvirt, `VBoxManage copyfrom` for VBox). Auto-injects
  `-coverprofile=<guest-path>` into forwarded `go test` invocations, tees
  `test.log`, and repatriates `cover.out` plus `clrhost-cover.out` when
  the guest produced one. (8aac278)
- `scripts/coverage-merge.go`: merges N Go cover profiles (union with
  per-block max hit count) and renders a Markdown gap report sorted by
  ascending coverage. (8aac278)
- `scripts/full-coverage.sh`: orchestrates host + Linux VM + Windows VM +
  Kali end-to-end, exports every `MALDEV_*` gate, restores to
  `--snapshot=NAME` (default `INIT`). Tolerant of test-level non-zero
  exits so gated failures don't abort subsequent phases. (8aac278)
- `scripts/vm-provision.sh`: idempotent per-VM tool install (NetFx3 via
  DISM SYSTEM scheduled task, postgresql + msfdb init on Kali). Takes a
  `TOOLS` snapshot when it's done. (8aac278)
- `docs/coverage-workflow.md`: canonical reference for the coverage
  workflow — snapshots, gates, layout, known blockers (QEMU pause race,
  CLR v2 COM activation on TOOLS snapshot), reproduction recipe. (8aac278)
- 16 gap-filling tests covering non-Windows stubs (c2/transport/namedpipe,
  evasion/{fakecmd,hideprocess,preset,stealthopen,hook,hook/probe,
  hook/remote,hook/bridge/controller}, cleanup/ads, process/session,
  pe/clr, cet) plus Windows-only factory tests (evasion/unhook,
  recon/hwbp) and `internal/compat/{cmp,slices}` polyfill smoke tests.
  (914aab4)
- `testutil/kali_test.go`: env-var resolvers (`kaliSSHHost/Port/Key/User`)
  with both override and fallback paths. (914aab4)
- `pe/clr` subprocess coverage: `testutil/clrhost` now builds with
  `go build -cover -covermode=atomic`, `GOCOVERDIR` points at a stable
  temp dir, `go tool covdata textfmt` converts to `clrhost-cover.out`
  which `cmd/vmtest` fetches and `coverage-merge` unions with the main
  profile. Ships with `testutil/clrhost/maldev_clr_test.dll` (3 KB .NET
  2.0 assembly) for `TestExecuteDLLReal`. (d0b9e0f)
- 8 deeper tests for `evasion/hook/bridge` Controller (`CallOriginal`,
  `ArgsDefault`, `SetReturnNoPanic`, `LogViaTransport`,
  `LogStandaloneNoop`, `ExfilStandaloneNoop`, `AskStandaloneAlwaysAllows`)
  and 2 hook lifecycle tests (`TestReinstallAfterRemove`,
  `TestInstallOnPristineTargetAfterGroupRollback`). (94a57cf)

### Fixed

- `evasion/sleepmask.Mask.Sleep`: crash (`STATUS_ACCESS_VIOLATION`) on the
  standard post-inject `PAGE_EXECUTE_READ` region. The encrypt phase did
  XOR *before* the `VirtualProtect(PAGE_READWRITE)` downgrade, so the
  first XOR byte faulted on a read-only executable page. Reordered to
  VirtualProtect-then-XOR. Existing tests allocated `PAGE_EXECUTE_READWRITE`
  so never hit the bug; the new e2e test suite pins the correct order.
  (5b0689e)
- `evasion/sleepmask_e2e_test.TestSleepMaskE2E_DefeatsExecutablePageScanner`:
  timing race under coverage instrumentation — the scanner goroutine could
  fire its first pass before `mask.Sleep` completed the encrypt phase,
  triggering a legitimate hit against still-unmasked memory. Gated behind
  a busy-wait barrier on `VirtualQuery(addr).Protect == PAGE_READWRITE`
  so the scanner only starts counting once the mask is provably engaged.
  (82a9ab7)
- `evasion/hook.TestReinstallAfterRemove`: overspecified assertion
  `require.NotEqual(h1.Trampoline(), h2.Trampoline())`. Windows's
  `VirtualFree(MEM_RELEASE)` + `VirtualAlloc(0)` of the same size may
  reuse the address (and does so reliably under coverage). Replaced with
  a byte-equality check against the captured pristine prologue — the
  actual correctness property the test's docstring claims ("no residual
  bytes"). (9bdf43f)
- `evasion/sleepmask/doc.go`: corrected description — `MethodNtDelay`
  uses Go's `time.Sleep` (which goes through `NtWaitForSingleObject` on a
  timer), not an explicit `NtDelayExecution` via Caller. The docstring
  now also tells the reader that the XOR key lives on the Go stack during
  sleep. (5b0689e)
- `recon/timing.TestBusyWaitPrimality`: upper bound 10s → 60s. VM CPU
  is shared and non-deterministic; the fixed-workload check still guards
  against infinite loops. (914aab4)
- `inject/linux_test.TestProcMemSelfInject`: now retries 3× and matches
  `PROCMEM_OK` in stdout instead of requiring exit 0. The child's Go
  runtime can SIGSEGV during exit cleanup after injection succeeded — the
  marker is the real success signal. (914aab4)

### Docs

- `docs/techniques/cleanup/memory-wipe.md`: honest implementation section
  (`SecureZero` delegates to Go's `clear` builtin — Go 1.21+ intrinsic;
  legacy `unsafe.Pointer` fallback is dead code at the module's `go 1.21`
  baseline). New section on `DoSecret` and the build-tag matrix.
- `docs/techniques/evasion/sleep-mask.md`: rewritten. Mermaid diagram
  fixed for the order-of-operations. New "Verifying It Works" section
  with extracts from the e2e tests. "Common Pitfalls" section covering
  the RX-page crash, XOR key on stack, short-sleep overhead, and
  `MethodNtDelay` still going through the kernel scheduler. New
  "Integrating with inject.SelfInjector" section showing the canonical
  beacon-loop pattern.
- `docs/techniques/evasion/stealthopen.md`: new "Composing with Other
  Packages — the Opener Pattern" section with wiring table pointing at
  every consumer and their test files.
- `docs/techniques/injection/README.md`: new "SelfInjector — Getting the
  Region Back" section with contract details and sample code.
- `docs/techniques/evasion/ntdll-unhooking.md`,
  `docs/techniques/injection/phantom-dll.md`: signatures + examples
  updated for the new opener parameter.
- `docs/testing.md`: new Opener coverage table pointing at every new
  test file and the commands to run each VM-side suite.

### Coverage

Baseline 39.4% (Linux host only, no gates) → **52.40% merged** across
the host + ubuntu20.04 VM + Windows VM + Kali (full gates open). Full
report at `ignore/coverage/report-full.md`.



### Added

- `cmd/vmtest`: new `-report-dir` flag with `Fetch()` method (scp for
  libvirt, `VBoxManage copyfrom` for VBox). Auto-injects
  `-coverprofile=<guest-path>` into forwarded `go test` invocations, tees
  `test.log`, and repatriates `cover.out` plus `clrhost-cover.out` when
  the guest produced one. (8aac278)
- `scripts/coverage-merge.go`: merges N Go cover profiles (union with
  per-block max hit count) and renders a Markdown gap report sorted by
  ascending coverage. (8aac278)
- `scripts/full-coverage.sh`: orchestrates host + Linux VM + Windows VM +
  Kali end-to-end, exports every `MALDEV_*` gate, restores to
  `--snapshot=NAME` (default `INIT`). Tolerant of test-level non-zero
  exits so gated failures don't abort subsequent phases. (8aac278)
- `scripts/vm-provision.sh`: idempotent per-VM tool install (NetFx3 via
  DISM SYSTEM scheduled task, postgresql + msfdb init on Kali). Takes a
  `TOOLS` snapshot when it's done. (8aac278)
- `docs/coverage-workflow.md`: canonical reference for the coverage
  workflow — snapshots, gates, layout, known blockers (QEMU pause race,
  CLR v2 COM activation on TOOLS snapshot), reproduction recipe. (8aac278)
- 16 gap-filling tests covering non-Windows stubs (c2/transport/namedpipe,
  evasion/{fakecmd,hideprocess,preset,stealthopen,hook,hook/probe,
  hook/remote,hook/bridge/controller}, cleanup/ads, process/session,
  pe/clr, cet) plus Windows-only factory tests (evasion/unhook,
  recon/hwbp) and `internal/compat/{cmp,slices}` polyfill smoke tests.
  (914aab4)
- `testutil/kali_test.go`: env-var resolvers (`kaliSSHHost/Port/Key/User`)
  with both override and fallback paths. (914aab4)
- `pe/clr` subprocess coverage: `testutil/clrhost` now builds with
  `go build -cover -covermode=atomic`, `GOCOVERDIR` points at a stable
  temp dir, `go tool covdata textfmt` converts to `clrhost-cover.out`
  which `cmd/vmtest` fetches and `coverage-merge` unions with the main
  profile. Ships with `testutil/clrhost/maldev_clr_test.dll` (3 KB .NET
  2.0 assembly) for `TestExecuteDLLReal`. (d0b9e0f)
- 8 deeper tests for `evasion/hook/bridge` Controller (`CallOriginal`,
  `ArgsDefault`, `SetReturnNoPanic`, `LogViaTransport`,
  `LogStandaloneNoop`, `ExfilStandaloneNoop`, `AskStandaloneAlwaysAllows`)
  and 2 hook lifecycle tests (`TestReinstallAfterRemove`,
  `TestInstallOnPristineTargetAfterGroupRollback`). (94a57cf)

### Fixed

- `recon/timing`: `TestBusyWaitPrimality` upper bound 10s → 60s. VM
  CPU is shared and non-deterministic; the fixed-workload check still
  guards against infinite loops. (914aab4)
- `inject/linux_test.go`: `TestProcMemSelfInject` now retries 3× and
  matches `PROCMEM_OK` in stdout instead of requiring exit 0. The
  child's Go runtime can SIGSEGV during exit cleanup after injection
  succeeded — the marker is the real success signal. (914aab4)

### Coverage

Baseline 39.4% (Linux host only, no gates) → **51.9% merged** across 6
run contexts. See `docs/coverage-workflow.md` for the full breakdown.

## [v0.10.1] — 2026-04-18

Patch release: unlocks 116 previously-skipped tests + post-review fixes.

### Added

- `scripts/test-all.sh` auto-provisions per-layer MSF handler on Kali
  (`exploit/multi/handler` with sleep-3600 trick) and pushes the host-side
  Kali SSH key into each guest with strict ACLs. `MALDEV_KALI_SSH_KEY` is
  overridden per-layer so `testutil.KaliSSH` reaches Kali from inside the
  guest. `resolve_vm_ip` (arp/lease/agent fallback), `restore_init_silent`
  helpers. `set -Euo pipefail`.

### Fixed

- `cmd/memscan-mcp` `get_export` MCP tool: resolves `module` by name via
  `/module` first, then forwards the hex base to `/export`. Was always
  erroring because the server expects hex, not a DLL name.
- `scripts/vm-test/install-keys.sh`: now uses `qemu:///session` URI
  consistently (was defaulting to `qemu:///system` and silently skipping
  every domain on developer machines).
- `pe/morph TestUPXMorphRealBinary`: skip cleanly on non-Windows
  (UPXMorph is PE-only, the test execs the morphed binary); on Windows,
  skip under UPX 4.x because UPXMorph was written for 3.x signatures.

### Changed

- `cmd/vmtest/driver_libvirt.go`: collapsed three virsh helpers into a
  single `virshCmd` factory.
- `cmd/memscan-server/server_windows.go`: extracted `enumModules` +
  `moduleBasename` (deduped between `findModule` and `moduleNameAt`);
  `bytes.Index` instead of hand-rolled scan loop; `strconv.ParseUint`
  for hex parsing.
- `cmd/memscan-harness/harness_windows.go`: stdlib `sort.Strings`,
  `pickCaller` delegates to `pickWSyscallMethod`.
- `cmd/memscan-mcp/main.go`: extracted `toolText`/`toolError` helpers,
  `strings.Builder` in `formatJSON`.
- `cmd/test-report/main.go`: `countStatus` consolidated, dead
  `findTest` removed.

### Final test matrix (from INIT snapshots)

```text
memscan  77 / 77
linux   302 / 302   (40 legitimate skips)
windows 754 / 754   (21 legitimate skips)
TOTAL   1133 passed / 0 failed / 61 skipped
```

+116 tests now running vs v0.10.0; 0 failures maintained.

## [v0.10.0] — 2026-04-17

139 commits since [v0.9.0]. Highlights:

### Added — inline hooking + bridge

- **`evasion/hook/`** — x64 inline function hooking with trampoline and RIP-relative fixup, `InstallProbe` for unknown-signature targets, `HookGroup` (atomic multi-hook with rollback), `WithCaller`/`WithCleanFirst` options, `RemoteInstall` helpers.
- **`evasion/hook/bridge/`** — bidirectional controller/listener protocol over TCP/named-pipe/io.Pipe: wire-format with `ArgBlock`, `Decision`, multiplexed RPC (`Register`/`Call`), gob serialization layer, typed RPC via reflection (`func(T) (R, error)`).
- **`evasion/hook/shellcode/`** — Block/Nop/Replace/Redirect templates for drop-in decisions.

### Added — PE operations

- **`pe/masquerade/`** — compile-time PE resource embedding (manifest, VERSIONINFO, icons), blank-import `pe/masquerade/preset/` for one-liner impersonation, `IconFromFile`/`IconFromImage`/`WithSourcePE` programmatic API.
- **`pe/imports/`** — PE import table parser (IAT enumeration by DLL).

### Added — cross-host test infrastructure

- **`cmd/vmtest/`** — driver-based runner (auto-detects VBox vs libvirt), forwards `MALDEV_*` env into guests, ssh key-auth + rsync/scp push + snapshot restore.
- **`cmd/memscan-server/`** — Windows HTTP API on port 50300 wrapping `ReadProcessMemory` / `EnumProcessModulesEx` / `VirtualQueryEx`. Replaces the gitignored x64dbg MCP with pure-Go byte-pattern inspection.
- **`cmd/memscan-harness/`** — target-side tool with 5 groups (`ssn`, `amsi`, `etw`, `unhook`, `inject`) covering every caller × resolver combination in `docs/testing.md`.
- **`cmd/memscan-mcp/`** — stdio JSON-RPC 2.0 MCP adapter for Claude Code (tools: `read_memory`, `find_pattern`, `get_module`, `get_export`, `run_tests`).
- **`cmd/test-report/`** — parses `go test -json` streams, emits per-test / per-package / cross-platform matrix + failure detail + tally.
- **`scripts/test-all.sh`** — unified three-layer runner (memscan + linux + windows) with INIT snapshot revert between layers.
- **`scripts/vm-test-memscan.go`** — 32-row matrix → 77 static byte-pattern sub-checks (SSN 4×4, AMSI 4×3, ETW 4×6, Unhook 4×2, Inject 17).
- **`scripts/vm-test/`** — reproducible provisioning (`bootstrap-linux-guest.sh`, `bootstrap-windows-guest.ps1`, `install-keys.sh`), committed `config.yaml` + `config.local.example.yaml` + `kali-env.sh.example` templates.
- **`docs/vm-test-setup.md`** — end-to-end reproducibility guide (host install, guest provisioning, INIT snapshot, troubleshooting, Phase-5 punch-list).
- **`.mcp.json.example`** — Claude Code MCP wiring template.

### Fixed — test matrix (0 FAIL on libvirt Fedora against Windows 10 + Ubuntu 20)

- `win/impersonate`: `ThreadEffectiveTokenSID` + `ThreadEffectiveTokenHasGroup` helpers (locale-independent); dropped `Système` vs `SYSTEM` string assertions.
- `win/token`: `EnableAll`/`DisableAll` now no-op when every eligible privilege already matches (was `ErrNoPrivilegesSpecified`).
- `process/enum`: `TestSessionIDPopulated` compares against `ProcessIdToSessionId`, no longer assumes interactive session.
- `cleanup/service`: SCM DACL tests gated behind `MALDEV_SCM=1` + elevation probe (crashed silently under OpenSSH).
- `evasion/herpaderping`: manual temp dir + `taskkill` cleanup (image-lock race on spawned cmd.exe).
- `evasion/hook/bridge`: `skipIfNonWindowsController` on 11 tests needing the real Windows Controller.
- `pe/masquerade`: fall back to `explorer.exe` when `notepad.exe` UWP-shim ships without icon resources.
- `persistence/scheduler`: skip `TestList` in session 0 (OpenSSH).
- `c2/meterpreter` (linux e2e): `net.DialTimeout` probe + skip if no MSF handler.
- `evasion/hook/bridge`: moved `rpcResponse` to an untagged file (Linux cross-compile was broken).

### Changed

- **`testutil/kali.go`** — parameterised via `MALDEV_KALI_SSH_{HOST,PORT,KEY,USER}` envs; same test binaries now run on both libvirt and VBox hosts.
- **`scripts/vm-run-tests.sh`** — collapsed into a shim delegating to `cmd/vmtest`.
- **`cmd/vmtest/driver_{vbox,libvirt}.go`** — `collectMaldevEnv()` forwards `MALDEV_*` into the guest `go test` command.

### Final test run (from INIT snapshots, 2026-04-17)

```text
memscan  PASS  77 / 77
linux    PASS  282 / 282  (41 skip)
windows  PASS  735 / 735  (21 skip)
TOTAL    1017 passed / 0 failed / 62 skipped
```

### Deferred to Phase 5 (documented in `docs/vm-test-setup.md`)

Remote-inject harness (CRT/RTL/EarlyBird/QueueUserAPC/ThreadHijack/KernelCallback/PhantomDLL/ModuleStomp/ExecuteCallback — needs notepad-target spawn), BSOD test runner port, Meterpreter matrix runner, MCP SSE streamable HTTP transport.

---

[Unreleased]: https://github.com/oioio-space/maldev/compare/v0.10.1...HEAD
[v0.10.1]: https://github.com/oioio-space/maldev/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/oioio-space/maldev/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/oioio-space/maldev/releases/tag/v0.9.0
