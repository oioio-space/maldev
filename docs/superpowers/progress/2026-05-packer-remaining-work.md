---
title: Packer — remaining work inventory (post-v0.88.0)
last_updated: 2026-05-10 (Tier 1 closed — #1.4 c61d511, #1.5 e1d99ae)
session_origin: 13ddbfbb-2239-47f5-a19c-2021dee94c64
---

# What's left for `pe/packer/` and friends

Inventory ordered by operational priority. As work lands, tick the
box + record commit short-SHA + bump front-matter `last_updated`.

## Companion docs

- `docs/superpowers/specs/2026-05-10-bundle-stub-negate-and-winbuild.md`
- `docs/superpowers/specs/2026-05-10-bundle-stub-builder-migration-audit.md`
- `docs/superpowers/progress/2026-05-bundle-stub-builder-migration.md`
  (Phases 1-4 complete; this doc supersedes for forward-looking work)

## 🔴 Tier 1 — High priority (features inaccessible aux opérateurs)

- [x] **#1.1 Wire V2-Negate into `WrapBundleAsExecutableLinux*`** (commit pending)
  All Linux E2E tests stay green; bundle sizes shifted +29 B (V2-Negate adds ~30 B vs V1).
  V2-Negate exists since v0.88.0 but the public Linux wrap still uses
  V1. Operators can't set `Negate: true` on a FingerprintPredicate
  and see it honored end-to-end. Fix: switch `bundleStubVendorAware()`
  call inside `WrapBundleAsExecutableLinuxWithSeed` to call
  `bundleStubVendorAwareV2Negate()`. Re-run all
  `TestWrapBundleAsExecutableLinux_*` runtime tests to confirm
  green. ~30 min.

- [x] **#1.2 Wire V2NW into `WrapBundleAsExecutableWindows*`** (commit pending)
  Win VM E2E TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows
  passed FIRST DISPATCH with V2NW wired in. StubLayoutSanity test
  updated to V2NW's structure (offset-115 V1+§2-patch byte check
  replaced with "len ≥ 400" sanity bound).
  Same as #1.1 for Windows. Currently uses V1+§2-patch (no negate, no
  PT_WIN_BUILD). Switch to `bundleStubV2NegateWinBuildWindows`. Win
  VM E2E re-dispatch. ~30 min.

- [x] **#1.3 PT_CPUID_FEATURES predicate** (commit pending)
  Added CPUID EAX=1 to V2-Negate + V2NW prologues; ECX features
  saved to [rsi+12]. Per-entry test (`test r9b, 4`; mask + value
  compare) inserted before .entry_done in both stubs.
  Tests (all PASS):
    - TestBundleStubV2N_E2E_PTCpuidFeaturesMatchExit42 (SSE3 match)
    - TestBundleStubV2N_E2E_PTCpuidFeaturesMismatchExitClean (SSE3 mismatch → fallback)
    - TestBundleStubV2NW_E2E_PTCpuidFeaturesWindows (Win VM SSE3 match)
  Bit 2 of `PredicateType` documented in wire format but never wired
  into any stub. Pattern same as PT_WIN_BUILD: `test r9b, 4; jz
  .skip_features; cmp ecx_from_cpuid, [r8+24] AND [r8+28]; if
  mismatch xor r12b, r12b`. ~30 B asm. Plus Linux test +
  Win VM test. ~1.5h.

- [x] **#1.4 CLI flag for Negate** (c61d511)
  Extended `-pl` spec to `<file>:<vendor>:<min>-<max>[:negate]`.
  TestParseBundleSpec_NegateFlag (4 cases) + bogus-keyword error
  case green. Usage text updated with `exclude-vm.exe` example.

- [x] **#1.5 docs/techniques/pe/packer.md update for v0.88.0** (e1d99ae)
  Negate subsection now records all 3 paths operational + CLI
  example; Mode 5 predicate row upgraded; Limitations § collapsed
  to the single remaining PT_WIN_BUILD-on-Linux edge.

Total Tier 1: ~3-4h supervised.

## 🟡 Tier 2 — Medium priority (polish)

- [x] **#2.1 Builder migration of decrypt-loop 8-bit ops** (pending commit)
  Added 3 new Builder primitives: ANDB (8-bit imm AND), MOVZBL
  (byte-reg → dword zero-extend), XORB (8-bit XOR with SIB-mem).
  Reused existing MOVBReg / MOVB / regToByteReg for the 3 already-
  shaped ops. Replaced both V2-Negate (Linux) and V2NW (Windows)
  decrypt blocks. Byte-identical emission pinned by encoder unit
  tests (`TestBuilder_ANDB` / `TestBuilder_MOVZBL` / `TestBuilder_XORB`)
  + Linux runtime E2E green.

- [ ] **#2.2 Multi-cipher support (`CipherType` field)**
  `PayloadEntry.CipherType` is hardcoded `=1` (XOR-rolling). Wire
  format reserves the field; spec mentions AES/ChaCha as planned.
  Implement `CipherType=2` (AES-CTR via AES-NI; uses crypto/
  primitives already shipped in v0.79+). ~50 B asm. Win VM test.
  ~2-3h.

- [ ] **#2.3 Polymorphic slots B & C**
  `injectStubJunk` operates only on slot A (offset 14). Add slot B
  (between CPUID prologue and loop body, offset ~36) and slot C
  (between matched body and decrypt tail). Multiplies stub
  byte-pattern surface vs YARA across packs. Slot offsets must
  stay reachable post-injection (the Jcc displacements behind them
  are auto-resolved by Builder labels in V2/V2N/V2NW — easy).
  ~1.5h.

- [ ] **#2.4 PackBinaryOptions.CipherKey wire-in**
  Currently marked "Reserved for future AES wrapping". Lands with
  #2.2. ~30 min after #2.2.

Total Tier 2: ~6-8h.

## 🟢 Tier 3 — Lower priority

- [ ] **#3.1 Per-build SBox derivation in stub**
  Currently SBox transform is build-time only (operator pre-
  substitutes bytes before pack). Add stub-time derivation via
  `HKDF(secret, "stub-sbox-PER-PACK", 256)` + Fisher-Yates in
  emitted asm. Extra unmasking layer at runtime. ~2-3h.

- [ ] **#3.2 `packerscope decrypt -bundle X -secret SECRET`**
  Defensive helper that dumps decrypted payloads given the secret.
  Mirrors operator's pack-time crypto in reverse. ~1.5h.

- [ ] **#3.3 V1 → V2 retirement**
  Once #1.1 #1.2 land, V1 (`bundleStubVendorAware`) becomes dead
  code. Delete + simplify. ~30 min cleanup.

- [ ] **#3.4 Consolidate V2 / V2-Negate / V2NW into a single
  parametrized function**
  3 functions with ~80% shared code. `bundleStub(opts ScanStubOpts)`
  with feature toggles (negate, winbuild, exitVia). Pure refactor;
  no behavior change. ~2h.

Total Tier 3: ~6-7h.

## 🔵 Tier 4 — Infrastructure (long-term, brainstorm sessions)

- [ ] **#4.1 Solution D — pure-Go x86-64 stepper**
  Pre-brainstorm notes at `docs/superpowers/specs/draft-2026-05-10-asm-stepper-notes.md`.
  Implementation = `superpowers:brainstorming` session + ~2-3 days.
  Eliminates VM dispatches for asm validation.

- [ ] **#4.2 asmtrace harness Linux variant**
  Windows version (commit 4f2f159+ era) uses VEH. Linux equivalent
  via sigaction + sigjmp catch SIGSEGV with register context.
  Required for unattended Linux asm debug (currently we use gdb
  on core dumps — works but interactive). ~3-4h.

- [ ] **#4.3 Documentation: tech md vulgarisation pass**
  User asked earlier for "plus de vulgarisation" on technical
  terms. Glossary exists; could expand. Also: link first-mention
  terms in body back to Glossary entries. Pure docs.

Total Tier 4: ~3-5 days.

## Cross-session resumption checklist

1. Pull latest master.
2. Open this file. Find first unchecked row in highest-priority Tier.
3. Verify dev env:
    - `go test -count=1 -short ./pe/packer/...` green
    - `virsh -c qemu:///system list` shows win10 reachable (libvirt)
4. Pick up at first unchecked Tier 1 row.

## Last-known-good signposts

| Aspect | State as of 2026-05-10 |
|---|---|
| Latest tag | v0.88.0 |
| HEAD commit | ef71e1f (Phase 4b V2NW shipped) |
| Linux scan stub | V1 (bundleStubVendorAware) — operational, runtime-green |
| Linux scan stub V2 | bundleStubVendorAwareV2 — runtime-green, NOT WIRED |
| Linux scan stub V2-Negate | bundleStubVendorAwareV2Negate — runtime-green, NOT WIRED |
| Windows scan stub | V1+§2-patch — operational |
| Windows scan stub V2NW | bundleStubV2NegateWinBuildWindows — runtime-green, NOT WIRED |
| asmtrace harness | Windows-only VEH; Linux variant queued (#4.2) |
| amd64.Builder API | complete for current scan-stub mnemonics |
