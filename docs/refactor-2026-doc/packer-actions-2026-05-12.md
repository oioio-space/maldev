---
status: in-progress
created: 2026-05-12
last_reviewed: 2026-05-16
reflects_commit: 1.B.1.a refactor
---

# Packer — action plan tracker (2026-05-12)

> Live tracker for the prioritised improvements coming out of
> [`packer-improvements-2026-05-12.md`](./packer-improvements-2026-05-12.md).
> Update on every commit that ships a row.

## Active priority queue

| # | Item | Effort | Status | Tag |
|---|---|---|---|---|
| **1** | **Mode 8 args injection — `DefaultArgs` opt + `RunWithArgs` export** | ~200 LOC | 🟢 in progress (1.A done, 1.B scoped) | v0.130/0.131 |
| **9** | **E2E PrivEsc DLL hijack proof** — VM provisioning + probe + orchestrator + driver + doc, demonstrating full chain from `lowuser` shell to SYSTEM whoami marker | ~600 LOC | 🟢 in progress | — |
| 2 | Mode 7 + Compress symmetry with Mode 8 | ~80 LOC | ⏳ scoped | — |
| 3 | `RandomizeStubSectionName` ON by default (OPSEC quick win) | ~5 LOC + tests | ⏳ scoped | — |
| 4 | PE32+ Machine check explicite (silent breakage guard) | ~10 LOC | ⏳ scoped | — |
| 5 | Walker interface unifié (R2 in audit) | ~150 LOC | ⏳ scoped | — |
| 6 | SGN body dedup (R1 in audit) | ~100 LOC | ⏳ scoped | — |
| 7 | MSVC fixture provisioning on Win10 VM | ~setup + 1 fixture | ⏳ scoped | — |
| 8 | Cert preservation opt-out (Z4 in audit) | ~30 LOC | ⏳ scoped | — |

## Item #1 — design notes

**User concerns:**
- (a) "verify args passed to a packed EXE are received by payload"
  → ✅ **VALIDATED** for Mode 3 (vanilla + RandomizeAll) via
    `TestPackBinary_Args_Vanilla_E2E` + `_RandomizeAll_E2E`
    (commit `0cfee1b`).
- (b) "set default args for a program transformed into a DLL"
  → 🟢 **IN PROGRESS** — implementing `DefaultArgs` opt for Mode 8.

### Two-part feature

**Part A — pack-time default args** (`PackBinaryOptions.ConvertEXEtoDLLDefaultArgs string`):
The operator bakes a default command-line into the packed DLL.
On `DllMain(PROCESS_ATTACH)`, before `CreateThread` spawns the
OEP, the stub patches `PEB.ProcessParameters.CommandLine` to
point at the baked args. Payload's `GetCommandLineW` /
`os.Args` returns operator-controlled values.

**Part B — runtime `RunWithArgs` export**:
The packed DLL also exposes a `RunWithArgs(LPCWSTR args)`
exported function. Operator can invoke it via
`GetProcAddress` + indirect call to spawn the payload with
custom args at any time, regardless of the default. Useful
for repeat invocations or when the operator wants to chain
the payload with their own args mid-attack.

### Implementation slices

| Slice | Scope | LOC | Status |
|---|---|---|---|
| 1.A.1 | PEB-patch asm helper (`stage1.EmitPEBCommandLinePatch`) | ~80 | ✅ shipped (2a89369) |
| 1.A.2 | Wire DefaultArgs into `EmitConvertedDLLStub`: emit PEB patch BEFORE CreateThread, append args buffer to stub section | ~60 | ✅ shipped |
| 1.A.3 | Plumb `PackBinaryOptions.ConvertEXEtoDLLDefaultArgs` → `stubgen.Options` → `stage1.EmitOptions` | ~20 | ✅ shipped |
| 1.A.4 | Win10 VM E2E: pack `probe_args.exe` with DefaultArgs="custom one two", LoadLibrary, assert marker contains "custom\|one\|two" | ~50 | ✅ PASS on Win10 VM (after asm pivot) |
| 1.A.5 | **Harden: runtime overflow guard.** Asm reads existing `MaximumLength` at +0x72 BEFORE memcpy; if `argsLen+2 > existing`, skip patch. Asm 43→48 B (+ MOVZX/CMP/JB; dropped MaxLength write — capacity is OS-allocated, not ours). | ~30 LOC | ✅ shipped |
| 1.A.6 | **Test-surface gaps.** (a) Tighten 1.A.4 to exact equality. (b) Pack-time bound (`maxConvertEXEtoDLLDefaultArgsRunes = 1500`) with readable error. (c) `LargeButValid` E2E — empirically PROVED guard fires on rundll32 with 1400 chars (loader has only ~135 B cmdline, our patch needs 2800 B → JB taken, payload safely sees rundll32 cmdline). Win11 VM not provisioned on this host — skipped. Custom small-cmdline fixture turned out unnecessary since rundll32 already triggered the path. | ~80 LOC | ✅ shipped (Win11 deferred) |
| 1.B.1.a | **Refactor**: extract resolver + PEB-patch + CreateThread block from `EmitConvertedDLLStub` into `emitConvertedSpawnBlock(b, plan, opts, args convertedSpawnArgs)` helper. Sealed-iface `convertedSpawnArgs` with one impl `convertedSpawnArgsTrailing{lenBytes}`. Byte-for-byte identical output — pinned 509-B test still passes. | ~130 | ✅ shipped |
| 1.B.1.b | Add `EmitPEBCommandLinePatchRCX` (runtime wcslen + src=RCX variant) + plumb the second `convertedSpawnArgs` impl (`convertedSpawnArgsFromRCX`). | ~140 | ⏳ next |
| 1.B.1.c | Emit `RunWithArgs` entry inside the stub (own prologue + spawn block via helper + WaitForSingleObject). Plumb `Plan.RunWithArgsRVA` + `PackBinaryOptions.ConvertEXEtoDLLRunWithArgs bool` → `stubgen.Options` → `stage1.EmitOptions`. | ~180 | ⏳ |
| 1.B.1.d | Direct-RVA export table builder in `pe/packer/transform/` (mirrors `dllproxy.BuildExportData` shape but `AddressOfFunctions[i]` points at code RVA, not forwarder string). Wire into `stubgen.go` after `EmitConvertedDLLStub` via `transform.AppendExportSection`. | ~150 | ⏳ |
| 1.B.2 | Win10 + Win11 VM E2E: pack, LoadLibrary, GetProcAddress("RunWithArgs"), call with custom args, WaitForSingleObject, assert marker. Also: regsvr32 sanity (DllRegisterServer alias path). | ~80 | ⏳ |

Each slice ships its own commit. Tags every successful slice
end (1.A complete = v0.130.0, 1.B complete = v0.131.0).

**Design decisions (locked 2026-05-16):**
- `RunWithArgs` calls `CreateThread` then `WaitForSingleObject` and returns the OEP exit code via `GetExitCodeThread`. Synchronous, blocks the caller.
- Shared inner emitter at the Go level (`emitConvertedSpawnBlock`) — DllMain and RunWithArgs each emit their own asm site, but both go through the same Go function to keep the spawn shape in lockstep.
- Opt-in via `PackBinaryOptions.ConvertEXEtoDLLRunWithArgs bool`. Off by default — no extra IOC when the operator doesn't need the runtime entry.

### Cross-machine resume — current state

## Item #9 — E2E PrivEsc DLL hijack chain

**Goal.** Validate the entire packer chain (Mode 8 ConvertEXEtoDLL,
optional Mode 10 PackProxyDLL) end-to-end on a real Win10 VM:
attacker is a non-admin shell (`lowuser`), defender is a SYSTEM
scheduled task running a deliberately-vulnerable EXE that
`LoadLibrary`s a DLL from a user-writable directory. Success =
the marker file shows `nt authority\system` (or the elevated user)
written by code that originated as a packed maldev EXE the
attacker compiled.

### Sub-slices

| # | Scope | LOC | Status |
|---|---|---|---|
| 9.1 | **VM provisioning.** Add `lowuser` (non-admin), `C:\Vulnerable\` (lowuser-writable), `victim.exe` (LoadLibrary("hijackme.dll")), scheduled task SYSTEM-context running victim.exe with ACL granting lowuser /Run rights, Defender exclusions for `C:\Vulnerable\` + `C:\ProgramData\maldev-marker\`. Snapshot as `INIT-PRIVESC`. | ~150 (PowerShell) | ⏳ next |
| 9.2 | **Probe.** Tiny Go EXE `whoami_marker` → execs `whoami`, writes output + timestamp + PID to `C:\ProgramData\maldev-marker\whoami.txt`. | ~30 | ⏳ |
| 9.3 | **Orchestrator.** Single Go EXE `cmd/privesc-e2e` runnable from lowuser shell — bundles probe bytes (//go:embed), packs to DLL via `packer.PackBinary{ConvertEXEtoDLL:true}`, plants at `C:\Vulnerable\hijackme.dll`, triggers task via `schtasks /Run`, polls marker, prints SUCCESS/FAIL. | ~250 | ⏳ |
| 9.4 | **Driver.** Bash script `scripts/vm-privesc-e2e.sh` — VBoxManage snapshot restore INIT-PRIVESC, SCP orchestrator as lowuser, SSH lowuser to run, fetch marker, assert SYSTEM. | ~80 | ⏳ |
| 9.5 | **User doc.** New section in `docs/techniques/pe/packer.md` (or sibling `dll-hijack-e2e.md`) walking the operator chain step by step, citing the orchestrator + screenshots of marker. Only if 9.1-9.4 PASS. | ~150 (md) | ⏳ |

### Open answers (confirmed defaults)

- Hijack vector: DLL search-order (victim's own dir first).
- Trigger: `schtasks /Run` with lowuser-writable ACL on the task.
- Snapshot: NEW `INIT-PRIVESC` (do not mutate existing INIT).
- Pack mode: 8 (ConvertEXEtoDLL) — victim only LoadLibrary's, no exports needed.
- Bitness: x64 only.
- Marker dir: `C:\ProgramData\maldev-marker\` (default ACL).

### Cross-machine resume

After commit, pickup at next unticked sub-slice.

### Sub-slice 9.6 — close all open gaps from session 2026-05-12

Identified after the dec0466 / 8b1a1ec checkpoints. Each gap gets
its own commit so cross-machine resume always picks up at the next
checkbox.

| # | Gap | Approach | Status |
|---|---|---|---|
| 9.6.a | Add Defender exclusions for `C:\Vulnerable\` and `C:\ProgramData\maldev-marker\` via direct registry write (HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths). Provisioning step. | Go program, run as test admin during provisioning. Falls back to AMSI-bypass PowerShell if registry write blocked by Tamper Protection. | ⏳ next |
| 9.6.b | AMSI bypass via `evasion/amsi.PatchAll` integrated in orchestrator. Demonstrates eating-our-own-dog-food even though scope (per-process) doesn't help spawned PowerShell. | Wrap orchestrator startup with PatchAll + log success/failure. | ⏳ |
| 9.6.c | Marker 0-byte mystery: probe `FlushFileBuffers` before CloseHandle + sleep 200 ms before SleepInfinite. Plus orchestrator polls more aggressively (50 ms). | Modify `cmd/privesc-e2e/probe/probe.c`. | ⏳ |
| 9.6.d | Big binary AS lowuser RC=1: install Defender exclusion FIRST (9.6.a), then re-test. If still bites, sign the orchestrator binary or bisect via stripping symbols/sections. | Validate after 9.6.a. | ⏳ |
| 9.6.e | Go probe in injected thread: write a tiny Go probe with `runtime.LockOSThread` + minimal init, OR document Go-incompatibility loudly in `pe/packer/packer.md` Mode 8 limitations. | Try Go probe with `os.Exit(0)` as first line — if even that doesn't trigger marker, document hard incompat. | ⏳ |
| 9.6.f | Final E2E run with all of the above. Both Mode 8 and Mode 10. STRONG verdict (marker shows SYSTEM). Tag v0.132.0. | Run both modes. | ⏳ |
| 9.6.g | User-facing doc: walkthrough in `docs/techniques/pe/packer-privesc-e2e.md` (or sibling) with screenshots + decision tree. | After 9.6.f green. | ⏳ |

### Sub-slice 9.7 — extract reusable helpers from privesc-e2e patterns

Audit revealed two patterns in `cmd/privesc-e2e` that should become
exported helpers in their respective packages so the next operator
tool doesn't reinvent them.

| # | Helper | Lives in | Replaces |
|---|---|---|---|
| 9.7.a | `packer.PackProxyDLLFromTarget(payload, targetDLLBytes, packOpts)` — parses targetDLLBytes for named exports, builds `ProxyDLLOptions{TargetName, Exports}` from the parsed export list, calls `PackProxyDLL`. Returns the same `(proxy, key, err)` triple. | `pe/packer/proxy_fused.go` | The 30-LOC chunk in `cmd/privesc-e2e/main.go` Mode-10 branch (parse.FromBytes -> ExportEntries -> filter -> PackProxyDLL). |
| 9.7.b | `dllhijack.PickBestWritable(opts ScanOpts) (*Opportunity, error)` — ScanAll + Rank + return first Writable && (IntegrityGain \|\| AutoElevate) opportunity, with fallback to any Writable. | `recon/dllhijack/dllhijack.go` | The discovery loop in `cmd/privesc-e2e/main.go` `-discover` branch. |

### Sub-slice 9.8 — close gaps 2 (probe race) + 3 (Defender) + 4 (verdict)

| # | Gap | Approach | Status |
|---|---|---|---|
| 9.8.a | **Probe race**: spawned thread killed mid-flight when victim.exe returns. Solution: victim sleeps 5 s after LoadLibrary so the spawned thread has time to write its marker + flush. Real-world legitimate-victim sideload chains often have similarly long-running hosts (services, scheduled tasks). | Add `time.Sleep(5*time.Second)` to `cmd/privesc-e2e/victim/main.go` after the LoadLibrary log. | ⏳ |
| 9.8.b | **Defender flagging the orchestrator binary**: signature on the unpacked Go binary. Solution: stronger runtime evasion (preset.Aggressive instead of Stealth) — adds ACG + BlockDLLs on top of AMSI+ETW+unhook. | Replace `preset.Stealth()` with `preset.Aggressive()` in `cmd/privesc-e2e/amsi_windows.go`. | ⏳ |
| 9.8.c | **Verdict ADEQUATE -> STRONG**: auto-resolves once 9.8.a fixes the probe race. The probe successfully writes whoami.txt, the driver fetches it, the verdict promotes from ADEQUATE to STRONG. | No code change; validate after 9.8.a. | ⏳ |

### Sub-slice 9.7 — design notes per helper

**9.7.a `packer.PackProxyDLLFromTarget(payload, targetDLLBytes, opts) (proxy, key []byte, err error)`**

Lives next to `PackProxyDLL` in `pe/packer/proxy_fused.go`. Body:

```go
func PackProxyDLLFromTarget(payload []byte, targetDLLBytes []byte, opts ProxyDLLOptions) (proxy, key []byte, err error) {
    pf, err := parse.FromBytes(targetDLLBytes, "<embedded-target>")
    if err != nil {
        return nil, nil, fmt.Errorf("packer: PackProxyDLLFromTarget parse target: %w", err)
    }
    entries, err := pf.ExportEntries()
    if err != nil {
        return nil, nil, fmt.Errorf("packer: PackProxyDLLFromTarget exports: %w", err)
    }
    var exports []dllproxy.Export
    for _, e := range entries {
        if e.Name == "" { continue } // skip ordinal-only
        exports = append(exports, dllproxy.Export{Name: e.Name, Ordinal: e.Ordinal})
    }
    if len(exports) == 0 {
        return nil, nil, fmt.Errorf("packer: PackProxyDLLFromTarget target has no named exports")
    }
    o := opts
    if o.TargetName == "" {
        return nil, nil, fmt.Errorf("packer: PackProxyDLLFromTarget TargetName required (cannot infer from binary)")
    }
    o.Exports = exports
    return PackProxyDLL(payload, o)
}
```

Tests: `TestPackProxyDLLFromTarget_MirrorsExports` (pack a known fixture, parse the proxy, assert exports match input).
Doc: extend the comment block on `PackProxyDLL` with a reference to this helper.

**9.7.b `dllhijack.PickBestWritable(opts ScanOpts) (*Opportunity, error)`**

Lives in `recon/dllhijack/dllhijack.go`. Body:

```go
func PickBestWritable(opts ScanOpts) (*Opportunity, error) {
    all, err := ScanAll(opts)
    if err != nil {
        return nil, fmt.Errorf("dllhijack: PickBestWritable ScanAll: %w", err)
    }
    ranked := Rank(all)
    // Prefer writable + integrity-gain
    for i := range ranked {
        if ranked[i].Writable && (ranked[i].IntegrityGain || ranked[i].AutoElevate) {
            return &ranked[i], nil
        }
    }
    // Fallback: any writable
    for i := range ranked {
        if ranked[i].Writable {
            return &ranked[i], nil
        }
    }
    return nil, fmt.Errorf("dllhijack: PickBestWritable found no writable opportunity (scanned %d total)", len(ranked))
}
```

Tests: stub on non-windows, real test on windows VM gates.

**9.7.c (BONUS) `evasion.ApplyAllAggregated(techs []Technique, caller *wsyscall.Caller) error`**

Companion to existing `ApplyAll` which returns `map[string]error`. Aggregates failures into single sortable-message error. Saves the same boilerplate we wrote in `cmd/privesc-e2e/amsi_windows.go`.

Lives in `evasion/evasion.go`. Tests: assert single-error path equals nil when all OK, and contains all failure names when ≥1 fails.

### Sub-slice 9.8 — brainstorm matrix per gap

**Gap 2 (probe race) — six options:**

| ID | Option | Cost | Risk |
|---|---|---|---|
| 2A | Victim sleeps 5 s after LoadLibrary | 1 LOC | none — chosen |
| 2B | Probe writes whoami.txt FIRST then breadcrumbs (single critical write) | 5 LOC | doesn't fix the race, just makes the surviving write the important one |
| 2C | Probe spawns whoami.exe via CreateProcess with redirected stdout — child outlives victim | 30 LOC C | adds advapi32-style imports to probe |
| 2D | Probe registers async I/O completion / DPC — survives ExitProcess | high LOC | Windows kernel APIs from user-mode are sketchy |
| 2E | Probe calls ExitProcess(0) itself after writes — preempts victim's cleanup race | 1 LOC | victim never gets to print its post-LoadLibrary log line; cosmetic |
| 2F | Mode 8 stub patches: DllMain blocks until spawned thread signals done | medium LOC in packer | deepest fix, benefits everyone using Mode 8 |

Recommended: **2A first (cheapest), keep 2F as a future packer enhancement**.

**Gap 3 (Defender on orchestrator binary) — six options:**

| ID | Option | Cost | Risk |
|---|---|---|---|
| 3A | preset.Aggressive (Stealth + ACG + BlockDLLs) | 1 LOC swap | ACG blocks subsequent VirtualAlloc(PAGE_EXECUTE) — must apply AFTER all our pack calls. Order matters. |
| 3B | Pack the orchestrator itself with `packer.PackBinary{Compress, AntiDebug, RandomizeAll}` (Mode 3) | host build script change | adds a build step; orchestrator becomes a packed EXE |
| 3C | Strip + UPX + reorder sections | 1 LOC ldflags | weaker than 3A/3B |
| 3D | Split orchestrator: stage1 (tiny ~10 KB loader) + stage2 (full 12 MB payload). Stage1 applies preset.Aggressive, allocates RX, decrypts + jumps stage2 | 200+ LOC | most operationally realistic; mirrors real maldev shape |
| 3E | Self-sign + add cert to Trusted Root | requires admin to install cert; fragile per machine | not portable |
| 3F | Live with no exclusions, document Defender behaviour as expected (operator tier) | 0 LOC | accepts the gap |

Recommended: **3A as a quick win** (move patchAMSI() AFTER all our VirtualAlloc-needing calls — packer is one). If 3A still flagged, **3B**.

**Gap 4 (verdict)** — auto-resolves with 2A.

**Gap 5 (driver bash quoting)** — three options:

| ID | Option | Cost | Risk |
|---|---|---|---|
| 5A | Write the full PS invocation as a heredoc-built .ps1 on the host, SCP to VM, invoke as a single argument (already partially done at scripts/vm-privesc-e2e.sh:108-110 but the heredoc still has `\${SSH_USER}` escape bugs we fixed) | 10 LOC bash | Same approach we tried; needs careful verification of heredoc expansion |
| 5B | Encode the parameters as base64, decode in PS (no quoting hell) | 15 LOC | adds a debug-unfriendly indirection |
| 5C | Replace the bash driver entirely with a Go program in `cmd/privesc-e2e-driver/` that uses crypto/ssh to SCP+exec. No shell quoting. | 200 LOC | clean but big |

Recommended: **5A first verify carefully** with `cat > tmp/run.ps1 <<EOF` then `cat /tmp/run.ps1` to inspect, then `scp` then SSH `powershell -File`. If still flaky, **5C is the proper fix**.

### Master execution order — status 2026-05-13

```
1. 9.7.a + 9.7.c (packer.PackProxyDLLFromTarget + evasion.ApplyAllAggregated)        ✅ shipped (commit 12cc47c)
2. 9.7.b (dllhijack.PickBestWritable + sentinel)                                     ✅ shipped (commit bb5549a)
   bonus: dllhijack ApiSet filter (zerotracelab/itm4n)                               ✅ shipped (commit 41cb0fc)
   bonus: dllhijack.ScanPATHWritable + KindPathHijack (MareBackup chain)             ✅ shipped (commit e94858b)
3. Refactor cmd/privesc-e2e/main.go to use the 3 helpers                             ✅ shipped (commit 73146aa)
4. 9.8.a (victim sleep 5 s after LoadLibrary)                                        ✅ shipped (commit d75e9c4)
5. 9.8.b (preset.Aggressive, audited order-of-ops)                                   ✅ shipped (commit 1b7da1e)
6. vm-privesc-e2e.sh on libvirt — STRONG verdict on -m 8                             ✅ shipped (commit 3a67ae9)
7. Mode-10 STRONG verdict (PackProxyDLLFromTarget end-to-end)                        ✅ verified live
8. tag v0.132.0                                                                      ✅ shipped (tag 99e7dd7)
9. user-facing doc — cmd/privesc-e2e/README rewritten thrice                         ✅ shipped (commits 2f9c5da, 2c9579a, 1a4aec2, 9397acc)
10. (deferred) 9.7.b extension: same scan-and-pick pattern for AutoElevate-only flows ⏳ backlog
```

**Bonus completed during this slice (out of original plan):**

- v0.133.0 — `InjectStubPE` MEM_WRITE fix unblocks `Compress` packs on large
  Go binaries. End-to-end verified: `cmd/privesc-e2e` packed with
  `-rounds 5 -compress -randomize`, Defender real-time protection ON,
  no exclusions, AS lowuser → STRONG SUCCESS marker. Two regression
  tests in `pe/packer/transform/pe_test.go`
  (`TestInjectStubPE_StubSectionWriteBit`).
- `cmd/packer` gains `-compress` / `-antidebug` / `-randomize` CLI flags
  (commit b4aa4b9 + simplify pass 21d3b81).
- `pe/packer/transform/peconst.go` exports `ScnMemWrite` / `ScnMemExec` /
  `ScnCntCode` (kills 3 magic-number sites; simplify pass).
- `cmd/privesc-e2e/README.md` gains §7-bis Detection & Forensics with
  built-in-Windows-only commands (wevtutil, Get-WinEvent, schtasks,
  certutil, fsutil USN, auditpol) + §8-bis Defender bypass via dropper
  packing.
- DiagHub SYSTEM-DLL loader (Project Zero 2018 primitive B) queued in
  memory `diaghub_privesc_loader.md` for a future slice.

**Authorship hygiene:** all 15 session commits rewritten as
`oioio-space <oioio-space@users.noreply.github.com>`, tags v0.132.0 +
v0.133.0 re-pointed, master force-pushed 2026-05-13.

### Cross-machine resume — exhaustive context dump

State at handoff:
- HEAD = 7f25ec2 (this commit will land at HEAD after the planning-doc commit).
- All 14 lessons captured in `docs/refactor-2026-doc/privesc-e2e-lessons-2026-05-12.md`.
- `cmd/privesc-e2e/probe/probe.exe` and `cmd/privesc-e2e/fakelib/fakelib.dll` are gitignored;
  rebuild via the README's host-side commands or just re-run `bash scripts/vm-privesc-e2e.sh`.
- Win10 VM is at INIT snapshot (clean); driver auto-restores.
- Manual SSH commands proven working at this point in time:
  - `ssh -i ~/.ssh/vm_windows_key test@192.168.56.102 'net user lowuser MaldevLow42x'` then
  - `ssh ... 'powershell -ExecutionPolicy Bypass -File C:\Users\test\run-as-lowuser.ps1 -Binary "C:\Users\Public\maldev\privesc-e2e.exe" -BinaryArgs "-mode 8" -UserName lowuser -Password MaldevLow42x -TimeoutSeconds 180'`
  - That manual flow produces full orchestrator output AND `LoadLibrary succeeded:
    handle=0x140000000` in `C:\ProgramData\maldev-marker\victim.log` after the next
    minute-trigger fires.
- The probe payload reaches main() (probe-started.txt + probe-root-marker.txt produced)
  but the third WriteFile (whoami.txt) races victim's ExitProcess. 9.8.a fixes this.

Pickup at 1. above.

---

**Slice 1.A FULLY HARDENED.** v0.130.0 shipped the feature;
follow-up slices 1.A.5 + 1.A.6 (in response to "il n'y a pas
de contournement ?") added:
- runtime asm guard (CMP existing MaxLength vs needed; JB skip)
- pack-time bound at 1500 chars with readable error
- exact-equality assertion (was Contains)
- empirical guard-firing proof (LargeButValid test on Win10 VM)

Win11 VM not provisioned on this host — deferred to whenever
the user provisions one (see `feedback_vm_testing.md`). Tag
v0.131.0 follows. Pickup at **slice 1.B.1** (`RunWithArgs`
export emitted in stub section + registered via
`transform.AppendExportSection`).

Big lesson from 1.A.4 (saved as `feedback_getcommandline_cache.md`):
the original PEB-patch design (rewrite `CommandLine.Buffer` pointer)
was a no-op because `kernel32!GetCommandLineW` caches its result on
first call — every subsequent caller (Go runtime, MSVC CRT, etc.)
reads the cache, NOT PEB. Pivoted to **in-place memcpy** at the
existing buffer pointer (43 B asm: PEB → ProcessParameters → load
existing Buffer into RDI → REP MOVSB from stub-baked args → update
Length/MaximumLength). Limitation: assumes existing buffer ≥
argsLenBytes+2; documented on the field.

The Win64 PEB layout used by the asm patch:
- `gs:[0x60]` → PEB pointer (TEB+0x60)
- `PEB+0x20` → ProcessParameters pointer
- `ProcessParameters+0x70` → CommandLine UNICODE_STRING:
  - +0x00: Length (uint16, bytes excluding null)
  - +0x02: MaximumLength (uint16, bytes including null)
  - +0x08: Buffer (PWSTR)

The patch overwrites Length, MaximumLength, Buffer with the
operator's args. Does NOT save/restore — the host process's
CommandLine stays clobbered for the duration. Documented as
an OPSEC trade-off.
