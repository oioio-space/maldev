---
status: in-progress
created: 2026-05-12
last_reviewed: 2026-05-12
reflects_commit: d8ed9a3 (v0.130.0 + docs)
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
| 1.B.1 | `RunWithArgs` export — emitted in the stub section, registered in the DLL's export table via `transform.AppendExportSection` | ~100 | after 1.A.6 |
| 1.B.2 | Win10 + Win11 VM E2E: pack, LoadLibrary, GetProcAddress("RunWithArgs"), call with custom args, assert marker. Also: regsvr32 sanity (DllRegisterServer alias path). | ~70 | after 1.B.1 |

Each slice ships its own commit. Tags every successful slice
end (1.A complete = v0.130.0, 1.B complete = v0.131.0).

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
