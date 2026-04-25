# Ship-Blockers + Follow-Ups — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use `- [ ]` checkbox tracking.

**Goal:** Close every ship-blocker surfaced by the 2026-04-25 deferred-work audit (6 items) and the three priority follow-ups proposed afterward. The shipping order is engineered so foundation work (BYOVD) lands early enough to unblock dependent chantiers (kcallback Remove, lsassdump PPL-bypass).

**Working directory:** `/home/mathieu/GolandProjects/maldev` (master, clean at tag `v0.17.0`).

**Inputs:** Inventory of 55 deferred items audited 2026-04-25 (commits, code, markdown, plans). Six items are ship-blockers; this doc plans them plus the three follow-ups (`callstack v0.16.1`, BYOVD foundation, `sleepmask L3/L4`).

---

## Status snapshot — 2026-04-25 session

| Chantier | State | Tag/SHA | Notes |
|---|---|---|---|
| **F** — pe/clr env | ✅ Partial (pt 1/2) | `092ce14` | TOOLS v2 CLSID baseline + HRESULT diag in clrhost. Pt 2/2 (full ISO sources/sxs) still requires a Win10 ISO. |
| **A** — BYOVD foundation | ✅ A.1 (scaffold) | `66d80d5` | `kernel/driver` + `kernel/driver/rtcore64` shipped; driver binary embedding behind `byovd_rtcore64` build tag (not in default repo). A.2-A.5 (real e2e, embedded driver, IOCTL stress) deferred. |
| **B** — kcallback Remove | ✅ Shipped | `1c93d87` (tag `v0.17.1`) | Remove/Restore/RemoveToken + 12 mock tests; VM e2e waits on `byovd_rtcore64` build path. |
| **C** — lsassdump PPL | ✅ Shipped | `0d31c50` (tag `v0.15.1`) | Unprotect/Reprotect/PPLToken/PPLOffsetTable + 8 mock tests; VM e2e on RunAsPPL=1 lsass waits on `byovd_rtcore64`. |
| **E** — realsc Fiber | ✅ Diagnosed + documented | `f915563` | ConvertThreadToFiber consumes the OS thread; Go runtime fights it; correct integration is `kernel32!CreateThread`-spawned OS thread, not a goroutine. Skip message + README warning ship the diagnosis. |
| **G** — dllhijack KindProcess | ✅ Design sketch | `e07bdd8` | Sandboxed-spawn pattern designed (clean-env spawn + bounded timeout + signed-canary + AllowSpawn opt-in); implementation deferred. |
| **D** — callstack v0.16.1 | ✅ Scaffold | `674c661` | SpoofCall + asm pivot wired; 6 unit tests green; e2e (`MALDEV_SPOOFCALL_E2E=1`) crashes via Go's `lastcontinuehandler` — root-cause analysis required before tagging v0.16.1. |
| **F pt 2/2** — ISO sources/sxs | ✅ Partial | `674c661` | DISM `/Add-Package` of the ISO's NetFx3 OnDemand cab + Win7-era `dotnetfx35.exe` redist both insufficient. `vm-provision.sh` now stages the cab when `MALDEV_NETFX3_CAB` is set; full unblock still needs `install.wim` mount. |
| **H** — sleepmask multi-region | ✅ Shipped | `294acad` | `MultiRegionRotation` wrapper unblocks Ekko for N-region scenarios via sequential per-region rotation. Foliage L3 fake-RA, BOF L4, Hunt-Sleeping-Beacons stack-mask remain queued for v0.19.0. |

---

## Ordering rationale

We tackle in three waves, ordered by dependency and unblocking value:

**Wave 1 — Foundation + quick wins (parallelisable)**

| # | Chantier | Type | Why first |
|---|---|---|---|
| A | **BYOVD foundation** (`kernel/driver` new package) | Foundation | Unblocks B (kcallback Remove) and C (lsassdump PPL-bypass). Heaviest research load, biggest payoff. |
| D | **`callstack` v0.16.1** (asm pivot) | Self-contained | Needs no other package. Closes the explicit "v0.16.1 deferred" debt without coordination cost. |
| F | **`pe/clr` environmental fix** | Environmental | One-off VM-snapshot rebuild; .NET 3.5 offline installer. Unblocks 4 tests. |

**Wave 2 — Consumes Wave 1 (sequential after A)**

| # | Chantier | Type | Depends on |
|---|---|---|---|
| B | **`kcallback` v0.17.1** (Remove API) | Feature | A (KernelReadWriter primitive) |
| C | **`lsassdump` PPL-bypass** (new mode) | Feature | A (driver-mode unprotect or kernel-mode VM_READ) |

**Wave 3 — Investigation + scope re-eval**

| # | Chantier | Type | Notes |
|---|---|---|---|
| E | **`inject/realsc` CreateFiber deadlock** | Investigation | Go runtime M:N scheduler interaction with real shellcode CreateFiber; may need a Go-side workaround or a documented "do not use Fiber for that target" warning. |
| G | **`dllhijack` KindProcess Validate** | Scope re-eval | Originally rejected as "too destructive for reconnaissance helper". Revisit with safer pattern (separate process spawn instead of in-process kill+relaunch). |
| H | **`sleepmask` L3/L4 + Remote multi-region** | Research | Foliage real (full fake-RA chain), Cobalt-style BOF sleep_mask, Hunt-Sleeping-Beacons stack-mask, multi-region Ekko/Foliage. |

---

## Chantier A — BYOVD Foundation (target `kernel/driver` v0.18.0)

**MITRE ATT&CK:** [T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/) (kernel-mode access enablement) + [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) (signed-driver service install).
**Detection:** **High** during driver load (Win10/11 HVCI blocks unsigned drivers; the attested driver list is audited).

### Scope

Ship a **driver-pluggable** `kernel/driver` package that exposes the `KernelReader` / `KernelReadWriter` interfaces consumed by `evasion/kcallback` (and future packages). The package SHIPS one concrete implementation — the **RTCore64** vulnerable driver primitive (CVE-2019-16098, MSI Afterburner) — because it is the most-studied, well-documented BYOVD target and a known signed Microsoft-attested binary.

- `kernel/driver` — interface package, no driver bundled.
- `kernel/driver/rtcore64` — RTCore64 reader/writer, drops the signed driver, opens its DOS device, issues IOCTL `0x80002048` for read and `0x8000204C` for write.
- `kernel/driver/_/embed.go` — embeds the signed driver bytes (build-tag gated to keep the binary lean by default).

### File structure

| Path | Action |
|---|---|
| `kernel/driver/doc.go` | create |
| `kernel/driver/driver.go` | create — KernelReader/KernelReadWriter interfaces re-exported from kcallback for cross-package consumption |
| `kernel/driver/rtcore64/doc.go` | create |
| `kernel/driver/rtcore64/rtcore64_windows.go` | create — install service, open device, IOCTL read/write |
| `kernel/driver/rtcore64/rtcore64_stub.go` | create |
| `kernel/driver/rtcore64/rtcore64_windows_test.go` | create — VM e2e (admin + intrusive) |
| `kernel/driver/rtcore64/embed_windows.go` | create — `//go:embed RTCore64.sys`, build-tag `byovd_rtcore64` |
| `docs/techniques/evasion/byovd-rtcore64.md` | create |

### Commit train

- **A.1** scaffold (interface package, RTCore64 doc.go + types, no impl).
- **A.2** RTCore64 service install/uninstall via `OpenSCManager` + `CreateService` + `StartService`. Test: install → query state → uninstall.
- **A.3** RTCore64 IOCTL read primitive + tests (read ntoskrnl base bytes, verify "MZ" magic).
- **A.4** RTCore64 IOCTL write primitive + safety scaffolding (no-op write loopback test only).
- **A.5** docs/techniques + CHANGELOG + tag `v0.18.0`.

### Risk

- **Detection on driver load**: HVCI / blocklist may refuse RTCore64 on patched Win10/11. Document expected blocklist behavior in the technique page.
- **Driver hash drift**: Microsoft updates the attested-driver block list. Embed a known-good hash but warn callers to verify on deployment.
- **Privilege**: requires `SeLoadDriverPrivilege` (admin). Test SKIPs without admin.

### Aggregate estimate

~600 LOC, 5 commits, 1 tag. Heaviest debug load (driver service lifecycle on a test VM is finicky).

---

## Chantier B — `kcallback` Remove API (target v0.17.1)

**Depends on:** Chantier A.

### Scope

- `Remove(cb Callback, writer KernelReadWriter) error` — locates the matching slot in the array, NULLs it under refcount-aware logic.
- Refcount-aware remove: read the slot, save the original value, write zero, return a `RemoveToken` so callers can `Restore(token, writer)` post-operation.
- Documented limitations: no thread synchronization with the kernel reader-side (race window of ~µs between read-original and write-zero).

### File structure

| Path | Action |
|---|---|
| `evasion/kcallback/remove_windows.go` | create — Remove + Restore + RemoveToken |
| `evasion/kcallback/remove_windows_test.go` | create — mock KernelReadWriter exercises both paths |
| `evasion/kcallback/kcallback.go` | modify — drop `// Experimental:` from interfaces |
| `docs/techniques/evasion/kernel-callback-removal.md` | modify — Remove section moves from "Future" to "Usage" |

### Commit train

- **B.1** Remove + Restore impl + mock-reader unit tests
- **B.2** VM e2e using RTCore64 from chantier A
- **B.3** docs + CHANGELOG + tag `v0.17.1`

**Estimate:** ~250 LOC, 3 commits.

---

## Chantier C — `lsassdump` PPL-bypass (target `lsassdump` v0.15.1 OR new sub-mode)

**Depends on:** Chantier A.

### Scope

Two viable paths — pick at design time per the threat model:

1. **Driver-assisted VM_READ**: use BYOVD KernelReader to memcpy lsass VM directly, bypassing the user-mode `NtReadVirtualMemory` PPL gate.
2. **EPROCESS unprotect-then-open**: BYOVD writes zero to lsass's `EPROCESS.Protection` field, then a normal user-mode `NtOpenProcess(VM_READ)` succeeds. Re-protect afterward.

Path 2 (unprotect) is mimikatz's `mimidrv` strategy — better composition with the existing `Dump` pipeline (still uses `NtReadVirtualMemory`, just with the PPL gate dropped).

### File structure

| Path | Action |
|---|---|
| `collection/lsassdump/ppl_windows.go` | create — `OpenLSASSWithDriver(rw KernelReadWriter)` + Restore |
| `collection/lsassdump/ppl_windows_test.go` | create |
| `docs/techniques/collection/lsass-dump.md` | modify — PPL section moves to "Usage / Driver-assisted" |

### Commit train

- **C.1** EPROCESS unprotect/reprotect + KernelReadWriter consumer
- **C.2** VM e2e on a PPL-enabled lsass (requires test VM reconfig: `RunAsPPL=1` reg key)
- **C.3** docs + CHANGELOG

**Risk:** EPROCESS layout offset shifts every cumulative update — same `OffsetTable`-style dependency as kcallback. Reuse the OffsetTable pattern.

**Estimate:** ~300 LOC, 3 commits.

---

## Chantier D — `callstack` v0.16.1 (asm pivot)

**Independent — no upstream dependencies.**

### Scope

Ship the active spoof pivot deferred from v0.16.0:

- `SpoofCall(target unsafe.Pointer, chain []Frame, args ...uintptr) uintptr` — plants a multi-frame return chain on the goroutine's stack, JMPs to target, recovers via the cached real return.
- `callstack_windows_amd64.s` (plan9 asm) — pivot gadget. Stack layout: `[realRetGo | fakeRetN | ... | fakeRet1]` then JMP target.
- Hardware-breakpoint variant (`hw-call-stack` style) — separate file, gated behind `WithHardware()` option. **OR** defer to v0.16.2 if asm pivot debug spike runs long.

### File structure

| Path | Action |
|---|---|
| `evasion/callstack/spoof_windows.go` | create — public SpoofCall + chain plumbing |
| `evasion/callstack/spoof_windows_amd64.s` | create — plan9 asm pivot |
| `evasion/callstack/spoof_stub.go` | create |
| `evasion/callstack/spoof_windows_test.go` | create — VM test asserting CaptureStackBackTrace from a 2nd thread reports the spoofed chain, not the real call site |

### Commit train

- **D.1** asm pivot single-frame + sanity test (target = NopFn returning a known sentinel)
- **D.2** multi-frame chain plumbing + StandardChain composition
- **D.3** VM e2e: spoof a `kernel32!Sleep` call, suspend that thread mid-sleep from a worker, walk its stack, assert top frames are `BaseThreadInitThunk → RtlUserThreadStart`
- **D.4** docs (callstack-spoof.md becomes "Active Spoof") + CHANGELOG + tag `v0.16.1`

### Risk

**HIGH** — Plan9 asm pivot interacting with Go's M:N scheduler. Allocate budget for a debug spike similar to the Ekko ROP-chain incident (`memory/rop_chain_stack_clobbering_diagnosis.md`). Have `GOTRACEBACK=crash` + WER LocalDumps ready from the start.

**Estimate:** ~400 LOC + significant debug time, 4 commits.

---

## Chantier E — `inject/realsc` CreateFiber deadlock (investigation only)

**Tags:** Investigation, no version target until root cause identified.

### Scope

`inject/realsc_windows_test.go:214` SKIPs because `CreateFiber` with real shellcode deadlocks Go's M:N scheduler. Hypothesis: real shellcode + Go-runtime fiber state corruption.

### Plan

- **E.1** Reproduce in isolation (cmd-line tool that mimics the failing test).
- **E.2** Capture full crash with `GOTRACEBACK=crash`, attach WinDbg, identify which fiber state Go's scheduler stomps.
- **E.3** Decision: code-side workaround (LockOSThread + careful fiber sequence), Go-runtime upstream issue, or document-and-skip permanently.

**Estimate:** open-ended; budget 1 day spike, write up findings, then decide whether to ship a fix.

---

## Chantier F — `pe/clr` environmental fix

**Environmental — no code change anticipated.**

### Scope

`docs/coverage-workflow.md:178-227` documents that 4 `pe/clr` tests SKIP on Win10 TOOLS snapshot because ICorRuntimeHost CLSID isn't registered. Root cause: .NET 3.5 enabled via DISM but offline installer never ran.

### Plan

- **F.1** Download .NET 3.5 offline installer (`dotnetfx35.exe` from Microsoft), drop it into a new TOOLS-builder script.
- **F.2** Reprovision the TOOLS snapshot via `scripts/vm-provision.sh` updates: install offline .NET 3.5 first, then DISM, then snapshot.
- **F.3** Verify all 4 `pe/clr` tests pass on the new TOOLS snapshot.
- **F.4** Update `docs/coverage-workflow.md` "Known blockers" section to mark resolved; bump TOOLS snapshot version note.

**Estimate:** ~1 hour wall-clock once the .NET 3.5 binary is in hand. Zero LOC.

---

## Chantier G — `dllhijack` KindProcess Validate (scope re-eval)

**Tags:** Scope decision required before implementation.

### Scope

Original rejection (`recon/dllhijack/validate_windows.go:174`): "triggering a DLL reload in a running process requires killing + relaunching it, which is out of scope (too destructive for a reconnaissance helper)."

**Re-eval angle:** instead of killing the live process, spawn a **fresh** copy of the same binary in a sandboxed environment (e.g. via `process/session`'s cross-session spawn), drop canary, validate the hijack, then terminate the spawn. The live process is never touched.

### Plan

- **G.1** Brainstorm alternative trigger modes; pick one (sandboxed spawn vs. fresh-process scenario).
- **G.2** Implement chosen mode behind a `KindProcess` Validate path.
- **G.3** Tests + docs.

**Estimate:** ~150 LOC if the sandboxed spawn pattern works. Brainstorm first.

---

## Chantier H — `sleepmask` L3/L4 + Remote multi-region

**Tags:** Research — multiple sub-features, prioritise by impact.

### Scope (in suggested priority)

1. **Multi-region Ekko + Foliage** — current MVP supports 1 region. Real beacons mask the heap + image + several .data ranges. Generalize the strategy to walk a `[]Region` slice.
2. **Foliage L3 — fake-RA chain** — ship Austin Hudson's full Foliage (currently we ship "Ekko + memset stack-scrub" which we labeled L3, but the academic L3 is fake-RA chains).
3. **BOF sleep_mask (L4)** — Cobalt-Strike-compatible: caller passes opaque shellcode bytes; we run them in a controlled context.
4. **Hunt-Sleeping-Beacons stack-mask** — zero-out the calling thread's stack frames during sleep; restore on wake. Requires CONTEXT capture + SetThreadContext.
5. **Remote L2/L3 (Ekko cross-process)** — flagged "may never ship" in the original spec due to complexity. Skip unless a concrete need arises.

### Plan

Each sub-feature ships as its own commit + docs update. Tag `v0.19.0` (after BYOVD's v0.18.0 lands).

**Estimate:** 800-1200 LOC across 8-10 commits. Several VM debug spikes likely.

---

## Aggregate

| Chantier | Tag | LOC | Commits | Wave |
|---|---|---|---|---|
| A — BYOVD | v0.18.0 | 600 | 5 | 1 |
| B — kcallback Remove | v0.17.1 | 250 | 3 | 2 |
| C — lsassdump PPL | v0.15.1 | 300 | 3 | 2 |
| D — callstack pivot | v0.16.1 | 400 | 4 | 1 |
| E — Fiber deadlock | (investigation) | 0-200 | 0-2 | 3 |
| F — CLR env | (snapshot) | 0 | 0 | 1 |
| G — KindProcess Validate | (TBD after brainstorm) | 0-150 | 0-3 | 3 |
| H — sleepmask roadmap | v0.19.0 | 800-1200 | 8-10 | 3 |

**Total:** 2,350-3,100 LOC across 23-30 commits + 4 new tags. Six ship-blockers closed (or explicitly downgraded for E/G), three follow-ups landed.

### Suggested kickoff order

1. **F** (clr env, ~1h, zero risk) — clears 4 SKIPs, gains coverage immediately.
2. **D** (callstack pivot) — independent, contained, closes the most public deferred-version reference.
3. **A** (BYOVD) — heaviest, but unblocks **B** + **C**.
4. Parallel **B** + **C** once **A** lands.
5. **E** spike when ready.
6. **G** brainstorm + decide.
7. **H** as long-running roadmap.

---

## Annex — Triage of the 24 environmental test SKIPs

Each `t.Skip` site flagged in the 2026-04-25 audit, classified by what it
takes to actually unblock it. **Not** a separate chantier — these get
absorbed into existing waves where applicable, or marked as accept-as-is.

### Tier 1 — Quick wins via TOOLS snapshot v2 (~3h, zero LOC)

Folded into chantier F or a sibling provisioning bump. Each unblocks
the test as soon as the new snapshot is in place.

| Site | Fix | Est. |
|---|---|---|
| `evasion/etw/etw_test.go:56` "NtTraceEvent not present" | Verify ntdll export is reachable on Win10 22H2; likely already there — test logic bug to investigate. | 30 min |
| `evasion/amsi/caller_test.go:19,32,71` "amsi.dll / AmsiScanBuffer not available" | amsi.dll ships with Windows 10+; AmsiScanBuffer requires AMSI provider registration. Provisioning bump: ensure Windows Defender is enabled + AMSI registered. | 30 min |
| `evasion/phant0m/phant0m_test.go:45` "No EventLog threads with service tags" | EventLog service must be running with full tags. Snapshot bump: verify `Get-Service eventlog` is `Running`. | 15 min |
| `recon/dllhijack/search_order_windows_test.go:44` "winhttp.dll is a KnownDLL" | Test-design fix: pick a different sentinel that is NOT a KnownDLL on Win10/11 (e.g. `samcli.dll`). | 15 min |
| `signtool` (`TestBuildWithCertificate`) | Snapshot bump: install Windows SDK signtool.exe path. | 30 min |
| `cleanup/service` skeleton tests | Snapshot bump: pre-create a sacrificial Windows service that tests can mutate. | 30 min |
| `exploit/cve202430088/cve_test.go:58,104` "System not vulnerable" | Pin TOOLS to a known-vulnerable Win10 build (pre-2024-06 CU). Currently 22H2 19045.6093 — research which subbuild is still vulnerable. | 1h research + reprovision |

**All seven get bundled into a single "TOOLS snapshot v2" delivery: rebuild
once, document in `docs/coverage-workflow.md`, snapshot, push.**

### Tier 2 — Test refactor (LOC fix, no env change)

| Site | Fix | Est. |
|---|---|---|
| `evasion/cet/cet_test.go:42,53` "Stub-only test" | Cosmetic — the stub-on-non-Windows behavior is correct. Either delete the SKIP and rely on build tags, or accept as documentation. | accept-as-is |
| `evasion/hook/bridge/bridge_test.go:18` "Controller round-trip needs Windows impl" | Same as above — cross-platform stub is correct. | accept-as-is |

### Tier 3 — Already covered by an active chantier

| Site | Chantier | Status |
|---|---|---|
| `collection/lsassdump/lsassdump_windows_test.go:38,40,59,61` "lsass refuses VM_READ / runs as PPL" | **C** (lsassdump PPL-bypass) | Will pass once chantier C lands. |
| `inject/realsc_windows_test.go:214` "CreateFiber deadlock with real shellcode" | **E** (Fiber deadlock investigation) | Resolves E one way or the other (fix or document-and-skip). |

### Tier 4 — Privilege escalation needed (SSH-vs-elevated mismatch)

These sites work locally as Administrator but fail under our SSH-driven
test runner because OpenSSH on Windows hands medium-integrity tokens
even to admin accounts. Options:

| Option | Pros | Cons |
|---|---|---|
| **(a) `runas /trustlevel:0x40000`** wrapper in `scripts/vm-test.ps1` | Re-elevates per-test, no infra change | Each test pays ~200ms re-spawn cost; UAC prompts in non-headless mode |
| **(b) Schedule task with `LogonType=InteractiveOrPassword`** to run the test binary | True high-integrity context | More provisioning work |
| **(c) Drop SSH, use WinRM with CredSSP** | Standard high-integrity path | Refactor of `cmd/vmtest/driver_libvirt.go` |

Affected sites:

| Site | Reason |
|---|---|
| `cleanup/service/service_test.go:28` | "Requires elevated (high-integrity) token — SSH sessions are medium-integrity" |
| `cleanup/service/service_test.go:31` | `MALDEV_SCM=1` — SCM DACL mutation |
| `evasion/stealthopen/stealthopen_windows_test.go:59,76,97` | `SetObjectID` requires admin (NTFS reparse) |
| `persistence/service/service_test.go:18` | SCM access denied without elevation |

**Recommendation:** option (b) — provisioning bump in TOOLS v2 adds a
"high-integrity test runner" scheduled task. Affected tests skip the
medium-integrity path and submit themselves to the scheduled task,
which writes results back to a shared folder. Estimated 1 day of
runner refactor; pays back across all 4-6 sites.

### Tier 5 — Genuinely interactive-only (RDP-required)

These need a real interactive desktop session and cannot be unblocked
without a different test mode entirely:

| Site | What's needed |
|---|---|
| `collection/clipboard/clipboard_test.go:41` | Interactive logon session for `OpenClipboard`. |
| `collection/screenshot/screenshot_test.go:15` | Interactive logon for GDI desktop access. |
| `persistence/scheduler/scheduler_test.go:105` | Task that runs on a logged-in user session (session 1+, not session 0). |

**Recommendation:** accept-as-skip. These techniques have working VM
e2e ONLY in interactive scenarios; we document the constraint, ship
the test as is, and validate by hand on a live RDP session before
each release. **Document this in `docs/testing.md` — "Tests that
require interactive desktop"**.

### Tier 6 — Cross-environment Kali integration

| Site | Fix |
|---|---|
| `c2/meterpreter/meterpreter_e2e_test.go:28` "Kali VM not reachable via SSH" | Snapshot bump: ensure Kali SSH service auto-starts; document `MALDEV_KALI_SSH_HOST` env var. |
| `c2/meterpreter/meterpreter_e2e_linux_test.go:51` "No MSF handler" | Provisioning: auto-start MSF handler service on Kali at boot. |

**Folded into TOOLS v2 provisioning bump (Tier 1).**

### Tier 7 — Genuinely-other-OS-only

| Site | Fix |
|---|---|
| `evasion/stealthopen/opener_windows_test.go:77,111` "NewStealth unavailable on non-NTFS or missing admin" | Snapshot bump: ensure C: drive is NTFS (it always is on Win10/11 default install). The "missing admin" branch is Tier 4. |
| `evasion/unhook/opener_windows_test.go:65` "Cannot build Stealth opener for ntdll" | Same root cause — NTFS Object ID setting requires admin. Tier 4 fix unblocks. |

### Roll-up

| Tier | Count | Resolution |
|---|---|---|
| 1 — TOOLS v2 provisioning | 7 | bundled chantier (~3h) |
| 2 — accept-as-is (cross-platform stubs) | 2 | document |
| 3 — covered by C / E | 5 | wait for chantier |
| 4 — high-integrity test runner | 4-6 | 1d refactor of `cmd/vmtest` |
| 5 — interactive-only | 3 | accept-as-skip + doc |
| 6 — Kali infra | 2 | bundled into Tier 1 |
| 7 — bleeds into Tier 4 | 2 | covered |

**Total recoverable: 18 of 24 SKIPs** (Tiers 1, 3, 4, 6, 7). The 3
interactive-only sites stay skipped; the 2 cross-platform stubs are
correct as-is. Net lift: ~75% of currently-skipped tests start
running in CI / coverage runs after Wave 1+2 lands.
