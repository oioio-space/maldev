---
status: pipeline complete + Compress shipped (slice 5.7 ✅ v0.124.0)
created: 2026-05-11
last_reviewed: 2026-05-11
constraint: pure-Go pack-time (no toolchain, no CGO, no linker, no Go runtime in the stub)
---

# `PackBinaryOptions.ConvertEXEtoDLL` — EXE → DLL conversion plan

## Why this exists

Slices 1–4 of the FormatWindowsDLL chantier let the packer pack a
*native* DLL into a packed DLL. Slice 5 is the more interesting
follow-up: **convert an EXE into a DLL at pack time** so the same
payload can ride into the target as a side-loaded module instead
of a standalone process.

## Operational rationale

| Use case | Why DLL-shaped helps |
|---|---|
| DLL sideloading | Drop the converted DLL next to a signed legitimate EXE that LoadLibrary's it. The payload runs inside the signed host. AppLocker / WDAC bypass surface in certain configs. |
| Classic injection (CreateRemoteThread + LoadLibraryA) | Every textbook injection technique targets DLLs. An EXE-only payload forces operators into reflective-loader gymnastics. |
| Living-off-the-land via `rundll32.exe` / `regsvr32.exe` / `odbcconf.exe` | These loaders only execute DLL exports — they refuse EXE-shaped inputs. |
| Detection lane diversification | An EXE-shaped output triggers different YARA / static-classifier paths than a DLL-shaped one. Same payload, two delivery shapes the operator can choose between. |

The existing `PackBinaryBundle` + `cmd/bundle-launcher` workflow
produces a DLL that LoadLibrary's the unwrapped EXE
**in-memory** — different shape (the EXE binary lives inside the
DLL's `.payload` section, decrypted at runtime). The slice-5
conversion is more aggressive: there is no separate EXE inside;
the EXE's `.text` IS the DLL's `.text`, and the DllMain stub
spawns the EXE's original entry point on a dedicated thread.
One file, no nested binary, smaller surface, no `cmd/bundle-launcher`
intermediary.

## The stub design

EXE-as-DLL stub layout (~350 bytes):

```text
.exe_as_dll_stub_start (= StubRVA):
  ; --- prologue: standard Windows DllMain ABI ---
  push rbp
  mov  rbp, rsp
  sub  rsp, 0x40                ; 0x40 = 6 × 8B + 16 align
  mov  [rbp-0x08], rcx          ; save hInst (= our HMODULE)
  mov  [rbp-0x10], rdx          ; save reason
  mov  [rbp-0x18], r8           ; save reserved
  mov  [rbp-0x20], r15          ; preserve callee-saved

  ; --- CALL+POP+ADD: R15 = textRVA at runtime (shared idiom) ---
  call .after_call
.after_call:
  pop  r15
  add  r15, sentinel(0xCAFEBABE)

  ; --- reason != DLL_PROCESS_ATTACH → forward (return TRUE) ---
  cmp  edx, 1
  jne  .return_true

  ; --- decrypted_flag check (decrypt-once sentinel) ---
  lea  rax, [r15 + flag_disp_sentinel]
  cmp  byte ptr [rax], 0
  jne  .return_true            ; already decrypted, just return TRUE
  mov  byte ptr [rax], 1

  ; --- SGN rounds (shared body with EmitStub / EmitDLLStub) ---
  ; ... for each round[i]: MOVZBQ→subst→MOVB→ADD→DEC→JNZ ...

  ; --- resolve kernel32!CreateThread via PEB walk ---
  ; PEB at gs:[0x60], walk InLoadOrderModuleList until name = "kernel32.dll",
  ; then walk export directory to find CreateThread. We have
  ; pe/packer/stubgen/stage1/fingerprint.go infrastructure for the
  ; PEB walk; need a new EmitResolveKernel32Export helper.
  mov  rax, gs:[0x60]                    ; PEB
  mov  rax, [rax + 0x18]                 ; PEB_LDR_DATA
  mov  rax, [rax + 0x10]                 ; InLoadOrderModuleList.Flink
  ; ... walk to kernel32 entry by Unicode name compare ...
  mov  r12, [rax + 0x30]                 ; kernel32 base → r12
  ; ... walk r12's EAT for CreateThread ASCII name compare ...
  mov  r13, <CreateThread_VA>            ; r13 = CreateThread function pointer

  ; --- CALL CreateThread(NULL, 0, OEP, NULL, 0, NULL) ---
  xor  ecx, ecx                          ; lpThreadAttributes = NULL
  xor  edx, edx                          ; dwStackSize = 0
  lea  r8,  [r15 + oep_disp]             ; lpStartAddress = OEP (absolute VA via R15+disp)
  xor  r9d, r9d                          ; lpParameter = NULL
  sub  rsp, 0x10                         ; shadow space for stack args 5,6
  mov  qword ptr [rsp+0x20], 0           ; dwCreationFlags = 0
  mov  qword ptr [rsp+0x28], 0           ; lpThreadId = NULL
  ; ABI: rcx, rdx, r8, r9 + 32B shadow space + stack-passed args
  sub  rsp, 0x20                         ; standard shadow space
  call r13                               ; CreateThread
  add  rsp, 0x30                         ; restore stack
  ; (rax = HANDLE to spawned thread; we drop it — leaks 1 handle until process exit)

.return_true:
  ; --- restore args + r15 + frame, return TRUE ---
  mov  rax, 1                            ; BOOL TRUE
  mov  rcx, [rbp-0x08]
  mov  rdx, [rbp-0x10]
  mov  r8,  [rbp-0x18]
  mov  r15, [rbp-0x20]
  add  rsp, 0x40
  pop  rbp
  ret                                    ; back to ntdll → loader sees TRUE

; trailing data:
.decrypted_flag:  db 0
```

Key differences from the slice-2 DllMain stub:

1. **No tail-call to an original DllMain** — the input was an EXE,
   there is no DllMain to forward to. Instead `CreateThread(OEP)`
   spawns the EXE's entry point as a parallel thread and we
   immediately return TRUE.
2. **PEB walk to resolve `kernel32!CreateThread`** — we can't link
   against an import because the input EXE doesn't import it
   (and even if it did, we'd be sharing the import table with
   the original — not necessarily desirable). Pure-Go means the
   stub must resolve the API at runtime via the PEB.
3. **Thread leaks its HANDLE** — drop it. The thread terminates
   when the EXE's OEP calls `ExitProcess`, which tears down the
   whole host process. Operationally that's usually what the
   operator wants (sideloaded payload kills the host signed EXE
   when done); if not, the operator gates with `opts.NoExitProcess`.
4. **No reloc entry for the slot** — there's no DllMain VA slot;
   the OEP is referenced as `R15 + oep_disp` (R15-relative,
   same trick as `flag_disp_sentinel`, no absolute pointer).

## Pure-Go constraints (reinforced)

- All asm via `pe/packer/stubgen/amd64.Builder` — no `.s` files,
  no inline assembly via cgo.
- PE mutations via `pe/packer/transform/` byte-native layer.
- Reloc table synthesis: the source EXE may have **no `.reloc`
  section** (Go static-PIE EXEs often don't, since they're not
  relocated by Microsoft's loader the same way). The conversion
  must synthesise a `.reloc` section ex nihilo when the input
  lacks one, since the converted DLL is now subject to ASLR.
- No CGO. No system toolchain. No external linker. No Go runtime
  in the stub (the stub is hand-assembled bytes; the EXE's
  original Go runtime still runs once CreateThread reaches OEP).

## Sub-slice tracker

| Sub-slice | Surface | LOC | Status | Tag |
|---|---|---|---|---|
| 5.1 | `PackBinaryOptions.ConvertEXEtoDLL` + `transform.PlanConvertedDLL` (accepts EXE inputs, returns `Plan{IsDLL: false, IsConvertedDLL: true}`). Cross-check in `PackBinary` (refactored into `validatePackBinaryInput` — kills duplicated `transform.IsDLL` calls) + `stubgen.ErrConvertEXEtoDLLUnsupported` sentinel for the in-flight state. **Simplify bonus:** extraction of the admission helper consolidates Format / IsDLL / ConvertEXEtoDLL gates into one place; sentinel located with the future implementation (stubgen), consistent with `ErrCompressDLLUnsupported` precedent. | ~150 | ✅ shipped | v0.114.0 |
| 5.2 | `stage1.EmitResolveKernel32Export(b, exportName)` — pure-Go ROR-13 hash resolver (PEB walk → InMemoryOrderModuleList → BaseDllName hash + EAT walk → name hash → ordinal → function VA in R13). 196 B emitted asm, no IAT entry. Companion `Ror13HashASCII` / `Ror13HashUnicodeUpper` / `Kernel32DLLHash` Go-side hashers. 11 unit tests. **Simplify bonus:** byte-budget test pinned at exact 196 B (drift catches asm regressions a loose window would absorb). Deferred (separate cleanup commit): `gsLoadPEBBytes` dedup across 5 stage1 emitters. | ~200 | ✅ shipped | v0.115.0 |
| 5.3 | `stage1.EmitConvertedDLLStub(b, plan, rounds)` — DllMain prologue → SGN rounds → `EmitResolveKernel32Export("CreateThread")` → `CreateThread(NULL, 0, OEP, NULL, 0, NULL)` → return TRUE. 465 B asm for 3 rounds. Reuses `emitTextBasePrologue`. + `PatchConvertedDLLStubDisplacements` (flag-disp imm32 rewriter) + `ConvertedDLLStubFlagByteOffsetFromEnd` + `ErrConvertedDLLPlanMissing`. 7 unit tests including pinned byte count. **Simplify pass:** named the `convertedDLLFrameSize` / `createThreadCallFrameSize` magic numbers, doc'd the OEP-disp ≤ 2 GiB invariant, dropped a test-only `EnsureNoSlotSentinel` helper from prod, pinned the byte budget. **Deferred:** SGN-rounds body (3 copies) + DllMain spill/restore (2 copies) dedup → separate Tier 🟡 cleanup commit (memory `stage1_stub_helpers_dedup_backlog.md`). | ~290 | ✅ shipped | v0.116.0 |
| 5.4 | `transform.InjectConvertedDLL` — delegate-and-flip approach: runs the full EXE injection pipeline via `InjectStubPE` (write encrypted .text, mark .text RWX, append stub section, rewrite OEP) then ORs IMAGE_FILE_DLL on COFF Characteristics. + `transform.SetIMAGEFILEDLL(buf)` shared helper (also adopted by test fixtures `BuildDLLWithReloc` + `setDLLBit` — 3 sites dedup'd). + `ErrPlanNotConverted` + `ErrConvertedStubLeak` admission sentinels guarding plan + stub mismatches. 6 tests including the slice-2 native-DLL stub leak guard. **Defer (slice 4.5 / future):** `.reloc` synthesis + DYNAMIC_BASE flip — the slice-5.3 stub has no absolute pointers baked at pack time, and Go static-PIE inputs typically ship without relocs already; output loads at preferred ImageBase. | ~60 | ✅ shipped | v0.118.0 |
| 5.5 | `stubgen.Generate` dispatch on `ConvertEXEtoDLL` (Plan.IsConvertedDLL routes through EmitConvertedDLLStub + PatchConvertedDLLStubDisplacements + InjectConvertedDLL) + `stubgen.Options.ConvertEXEtoDLL` forwarding from packer + remove the `ErrConvertEXEtoDLLUnsupported` gate from PackBinary. Pack-time happy-path test confirms a minimal EXE round-trips to a parseable PE32+ DLL with IMAGE_FILE_DLL set and entry point inside the stub section. **Win VM EXE-regression E2E green** (7 TestPackBinary_WindowsPE_*_E2E + 16 multi-seed) — the new dispatch doesn't touch the EXE path. | ~30 | ✅ shipped | v0.119.0 |
| 5.5.x | **Real-loader LoadLibrary E2E — root causes 1/4** — shipped harness + probe + 3 root-cause fixes uncovered by the trip: (a) clear DYNAMIC_BASE + HIGH_ENTROPY_VA on converted output (loader was failing with STATUS_CONFLICTING_ADDRESSES because we declare ASLR-capable but synthesise no relocs), (b) derive popOffset from sentinel position in `PatchTextDisplacement` (hardcoded 5 worked only for EXE stubs; DLL stubs sit behind a 24-B prologue so R15 was 24 B off → all flag/slot accesses missed), (c) OR MEM_WRITE on the appended stub section in `InjectConvertedDLL` (the flag-latch MOVB inside .mldv was hitting a read-only mapping). Each fix is unit-tested + the test progresses past the previous crash mode. LoadLibrary still fails on the 4th cause with abrupt process death (no Exception trace, even logs lost) — needs slice 5.5.y instrumentation (file-based diag or no-CreateThread probe). | ~100 (fixes) + harness | ✅ shipped | v0.120.0 |
| 5.5.y | **Real-loader LoadLibrary E2E — root cause 4 (callee-saved spill)** — bisected via three ablation flags (`DiagSkipConvertedPayload`, `DiagSkipConvertedResolver`, `DiagSkipConvertedSpawn`) routed through stage1.EmitOptions → stubgen.Options → PackBinaryOptions. Diagnostic E2E uses `fmt.Fprintln(os.Stderr, ...)` (stdlib t.Logf buffers were lost on Win32 process abort; vmtest captures stderr eagerly into its host log). NoPayload PASS + NoSpawn FAIL with ERROR_DLL_INIT_FAILED (no AV, just BOOL=FALSE) → narrowed to non-volatile register corruption. **Fix:** the shared DllMain prologue only spilled RCX/RDX/R8/R15 — the Win64 ABI requires DllMain to preserve RBX/RBP/RDI/RSI/R12-R15. The kernel32 resolver clobbers RBX + R12 (and the SGN poly engine churns R12-R14), so the loader observed corrupted non-volatile state on return and flagged DllMain as failed. Added `convertedExtraSpills` (RBX/RDI/RSI/R12/R13/R14) at `[rbp-0x28..0x50]`, frame grew 0x40→0x60, pinned byte count 465→509 (3 rounds, +44 B for 12 mov ops). Win10 VM E2E full suite GREEN: `LoadLibrary_E2E` PASS (2.96s, marker `"OK\n"` written by spawned thread), `_NoPayload_E2E` / `_SGNOnly_E2E` / `_NoSpawn_E2E` all PASS — confirms the full pipeline `pack EXE → DllMain stub → SGN-decrypt .text → PEB-walk kernel32 → resolve CreateThread → spawn thread on OEP → original main() runs`. | ~170 (ablation + fix) | ✅ shipped | v0.121.0 |
| 5.6 | **AntiDebug for converted-DLL stub** — `emitAntiDebug` placed BEFORE the converted-DLL prologue. On positive detection (BeingDebugged byte / NtGlobalFlag heap-validation triad / RDTSC ↔ CPUID delta > 1000 cycles) the bare RET inside antidebug returns to the loader with RAX non-zero — loader reads BOOL TRUE → DllMain "succeeded" → DLL loads silently without ever decrypting .text or spawning. Bare-metal undebugged hosts fall through to the full pipeline. Win10 VM E2E `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_AntiDebug_E2E` PASS (KVM VMEXIT trips the CPUID-RDTSC check by design — loader OK + marker NOT written confirms the silent-exit path is wired correctly). Unit tests pin the prefix behaviour. | ~50 | ✅ shipped | v0.122.0 |
| 5.7 | **Compress for converted-DLL stub — pack-time + runtime green.** `EmitConvertedDLLStub` emits the LZ4 register-setup + inline inflate + memcpy block between the SGN rounds and the kernel32 resolver, mirroring `EmitStub`'s EXE-path emission. Independent `InjectStubPE` fix: `SizeOfImage` includes `StubScratchSize` (Win10 DLL loader hard-rejects with STATUS_INVALID_IMAGE_FORMAT / ERROR_BAD_EXE_FORMAT 193 when the scratch region overflows declared image bounds; the EXE loader had been silently lenient). **2026-05-12 promotion:** the wedge that originally classified this slice as 🟠 partial cleared upstream — re-running the gated E2E showed a clean green pass on first attempt. Hypothesis: the slice 5.5.y callee-save spill fix + the SizeOfImage scratch-region fix (both in place by v0.123.0) had collectively eliminated the register-corruption / loader-rejection conditions that were producing the wedge. The `stubgen.ErrConvertEXEtoDLLUnsupported` gate is REMOVED, the `t.Skip` on `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_Compress_E2E` is REMOVED, and 3 consecutive Win10 VM runs all pass (~2.1 s each). Pack-time admission test `TestPackBinary_ConvertEXEtoDLL_AcceptsCompress` (replaces the previous `_RejectsCompress`) confirms the happy path produces a parseable PE32+ DLL with IMAGE_FILE_DLL set. | ~200 (stub + SizeOfImage) | ✅ shipped | v0.124.0 |

Total estimate: ~970 LOC over 5 sub-sessions.

## Tests & validation

Pack-time (Linux, fast):
- `TestPackBinary_ConvertEXEtoDLL_HappyPath` — pack `winhello.exe`,
  parse output with `debug/pe`, assert IMAGE_FILE_DLL set,
  `.reloc` present, entry point at stub RVA, original entry RVA
  reachable via R15+disp.
- `TestPackBinary_ConvertEXEtoDLL_RejectsDLLInput` — convert flag
  + DLL input → error.
- `TestEmitResolveKernel32Export_AssemblesCleanly` — the new
  emitter compiles asm round-trippable through `x86asm.Decode`.

Win VM E2E (slow, real loader):
- `TestPackBinary_ConvertEXEtoDLL_E2E` — build harness, pack
  winhello, run harness, assert stdout contains `"hello"`.
- `TestPackBinary_ConvertEXEtoDLL_PanicE2E` — pack `winpanic.exe`,
  assert the spawned thread's panic/recover still works.

## Out of scope for slice 5

- **DLL → EXE conversion.** The reverse direction is ill-defined
  (a DLL's payload is rarely in DllMain; usually in a named
  export the operator must specify). If/when an operator needs
  this, scope a separate `packer-dll-to-exe-plan.md` with a
  `PackBinaryOptions.DLLEntryExport string` field.
- **TLS callbacks in the source EXE.** Same restriction as the
  EXE path today (`transform.ErrTLSCallbacks`).
- **CFG-protected source EXEs.** Same restriction (cookie
  validation refuses modified .text — empirical finding from
  v0.105.0 winver.exe testing).
- **Compress=true.** Same reason as slice 4
  (`stubgen.ErrCompressDLLUnsupported`); LZ4 inflate doesn't
  thread through the converted-DLL layout in slice 5 v1.
- ~~**Anti-debug prologue.**~~ ✅ Shipped v0.122.0 (slice 5.6) — `PackBinaryOptions.AntiDebug=true` now applies to converted-DLL packs. Reuses `emitAntiDebug` placed BEFORE the prologue: on positive detection the bare RET inside antidebug returns to the loader with RAX non-zero (BeingDebugged byte / NtGlobalFlag mask / RDTSC delta all positive on hit), so LoadLibrary reads BOOL TRUE and the DLL silently no-ops without ever decrypting or spawning. VM E2E `TestPackBinary_ConvertEXEtoDLL_LoadLibrary_AntiDebug_E2E` validates the silent-exit path (KVM VMEXIT trips the CPUID-RDTSC check by design). Bare-metal undebugged hosts fall through to the full pipeline. Easy add via the original plan — reuse `emitAntiDebug`
  before the DllMain prologue, same as the EXE stub does. Defer.

## What's already shipped that this builds on

- Slices 1–4 of the native-DLL flow: `PlanDLL`, `EmitDLLStub`,
  `InjectStubDLL`, the shared `emitTextBasePrologue` /
  `patchSentinel` helpers, `testutil.BuildDLLWithReloc`.
- `stage1/fingerprint.go` PEB walking primitives.
- `transform.IsDLL` + `transform.DirBaseReloc` exports.
- `stubgen.ErrCompressDLLUnsupported` model for surfacing
  slice-5 limitations as named sentinels.

## Composition with `pe/dllproxy` — two integration paths

`pe/dllproxy` already emits forwarder-only or forwarder + DllMain
DLLs (see `pe/dllproxy/doc.go` + `assembleWithPayload`). The slice-5
converted-DLL composes with it in two ways:

### Path A — chained (✅ shipped v0.127.0 as `packer.PackChainedProxyDLL`)

```text
packer.PackBinary(winhello.exe, {ConvertEXEtoDLL: true})
                                                   ↓
                                            payload.dll
dllproxy.Generate("version", exports, {PayloadDLL: "payload.dll"})
                                                   ↓
                                            version.dll (proxy)
```

Drop `{version.dll, payload.dll}` in the victim's app directory.
The proxy DLL's DllMain `LoadLibraryA("payload.dll")` triggers our
converted-DLL's DllMain, which decrypts + `CreateThread(OEP)` —
the Go runtime spins up in the host's address space while the
proxy forwards every export back to the real `version.dll`.

**Cost:** zero — emerges naturally from slice 5 + the existing
`dllproxy.Options.PayloadDLL`. **v0.127.0 ships
`packer.PackChainedProxyDLL`** — a one-call orchestrator that
returns `(proxyBytes, payloadBytes, key, err)`. 4 unit tests pin
admission + happy-path. Operators get the two-file drop without
having to wire the two emitters themselves.

**Drawback:** two-file drop, IAT entry on `kernel32!LoadLibraryA`
in the proxy is a detectable IOC.

### Path B — fused emitter (slice 6) ✅ shipped v0.129.0 as `packer.PackProxyDLL`

One file: a single DLL that IS both the proxy AND the packed
payload.

```text
packer.PackProxyDLL(winhello.exe, "version", exports, opts)
                                                   ↓
                                            version.dll (1 file)
```

The output PE contains:

- Export table mirroring the real `version.dll`, with each export
  forwarded via the perfect-dll-proxy absolute path
  (`\\.\GLOBALROOT\SystemRoot\System32\version.<export>`) — taken
  from `dllproxy.buildExportData`.
- Hidden encrypted `.text` of the Go EXE (slice-5 layout).
- `.mldrel` section with the DllMain-slot reloc cover.
- DllMain composed from slice-5 emitter: decrypt-once → resolve
  CreateThread via PEB → spawn the OEP thread → return TRUE.
- **No IAT entry on LoadLibraryA**. CreateThread is resolved at
  runtime via PEB walk (same as slice 5), so the proxy doesn't
  even import kernel32 explicitly.

**Slice 6 sub-slices:**

| Sub-slice | Surface | LOC | Status |
|---|---|---|---|
| 6.1 + 6.2 | **Composition route** (vs the originally-scoped 450 LOC merge): `dllproxy.BuildExportData` exposed as a public wrapper around the existing internal builder. New `transform.AppendExportSection` + `transform.NextAvailableRVA` (~120 LOC) glue an export table onto a converted-EXE-as-DLL output. New `packer.PackProxyDLL` orchestrator (~80 LOC) chains `PackBinary{ConvertEXEtoDLL: true}` → `NextAvailableRVA` → `BuildExportData` → `AppendExportSection` in 3 calls. **Total ~200 LOC actually shipped vs the ~450 LOC originally estimated** — no need to re-implement `assembleWithPayload`'s tiny LoadLibraryA stub because the converted-DLL stub already self-contains the payload via PEB-walk-resolved CreateThread. | ~200 | ✅ v0.129.0 |
| 6.3 | Win VM E2E: `TestPackProxyDLL_LoadLibrary_E2E` packs the synthetic minimal-EXE fixture as a `version.dll` proxy, writes it to `%TEMP%\version.dll`, calls `LoadLibrary`. Asserts no error + non-NULL handle. PASS on Win10 VM (h=0x140000000). Doesn't yet cover (a) GetProcAddress on the exported forwarders or (b) payload spawning the original OEP — those need a probe harness with marker-file side effects (deferred). | n/a | ✅ v0.129.0 |

Total slice 6: ~650 LOC.

## What this plan deliberately does NOT promise

- That every EXE converts cleanly. CFG-protected, TLS-callback-
  bearing, and unusual-runtime EXEs are out of scope (same as
  the EXE pack path today). Operators get a clear error at
  pack time.
- That the converted DLL has the same anti-fingerprint footprint
  as a native DLL. The output is recognisably "an EXE-shaped
  binary with the DLL bit flipped + a synthetic .reloc". Junk
  cover sections, fake imports, and `RandomizeAll` still apply
  and round out the surface — but a determined reverse engineer
  can spot the conversion. Slice 5 ships the capability;
  blending into "natural DLL" shape is a separate research path.
