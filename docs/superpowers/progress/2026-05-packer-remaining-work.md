---
title: Packer — remaining work inventory (post-v0.92.0)
last_updated: 2026-05-10 (v0.92.0 shipped — Tier 🔴 + most of 🟡 closed)
session_origin: 13ddbfbb-2239-47f5-a19c-2021dee94c64
---

# What's left for `pe/packer/` and friends

Inventory ordered by operational priority. As work lands, tick the
box + record commit short-SHA + bump front-matter `last_updated`.

## Session-end checkpoint — 2026-05-10 (post v0.92.0)

**Repo state:** master at `8e309d9`, all 4 SEMVER tags pushed
(v0.89.0, v0.90.0, v0.91.0, v0.92.0). 27 commits this session, every
author verified `oioio-space@users.noreply.github.com`, every test
green on Linux + Win VM E2E for V2NW (incl. AES-CTR runtime).

**What shipped:**
- 🔴 Tier 1 fully closed (5/5 items) — Negate flag, CLI, docs
- 🟡 Tier 2 mostly closed — #2.1 (Builder migration), #2.3 (slots
  B/C), #2.2 (full multi-cipher AES-CTR, 7 phases), #2.4
  (BundlePayload.Key)
- 🟢 Tier 3 mostly closed — #3.2 (packerscope extract tests),
  #3.3 (V1+V2-plain retirement, −1019 LOC), #3.4 (shared prefix
  emitters)
- 🔵 Tier 4 partial — #4.3 vulgarisation callout expansion

**What remains:** see boxes below; only the long-form items left
are #3.1 (per-build SBox in stub, ~2-3h asm work), Linux V2-Negate
AES-CTR parity, and Tier 4 long-form work (#4.1 solution D stepper,
#4.2 asmtrace Linux, #4.3 full vulgarisation pass).

**Resume on another machine:**
1. `git pull` (master at `8e309d9` or later)
2. Open this file — find first unchecked row in highest tier
3. The "Win VM validation" block below has the exact tarball-deploy
   recipe that worked this session (scripts/vm-run-tests.sh was
   timing out at 16 min on Windows OpenSSH sftp; tar+scp+tar -xzf
   on the Windows side is the proven workaround).
4. Memory note `packer_session_close_2026-05-10.md` carries the
   one-line orientation pointer.

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

- [x] **#2.1 Builder migration of decrypt-loop 8-bit ops** (2f529c5 + simplify pass)
  Added 3 new Builder primitives: ANDB (8-bit imm AND), MOVZBL
  (byte-reg → dword zero-extend), XORB (8-bit XOR with SIB-mem).
  Reused existing MOVBReg / MOVB / regToByteReg for the 3 already-
  shaped ops. Extracted `emitDecryptStep` shared helper used by
  V2 + V2-Negate + V2NW (–52 LOC). Migrated `and r9b, 1` x2 to
  ANDB. Byte-identical emission pinned by encoder unit tests
  (`TestBuilder_ANDB` / `TestBuilder_MOVZBL` / `TestBuilder_XORB`)
  + Linux runtime E2E green.

- [~] **#2.2 Multi-cipher (`CipherType` field) — Phases 1+2 of 3** (pending commits)
  **Phase 1 (7505407):** AES-NI Builder primitives — `XmmReg` type
  (X0..X15) + `AESENC` / `AESENCLAST` / `PXOR` / `MOVDQULoad` /
  `MOVDQUStore`, all byte-pinned.
  **Phase 2 (pending commit):** wire-format `CipherType=2` dispatch
  + pack-time AES-CTR encrypt + unpack-time decrypt. New surface:
  `CipherTypeXORRolling` / `CipherTypeAESCTR` constants,
  `BundlePayload.CipherType` field (zero = legacy XOR-rolling for
  backward compat), `ErrCipherTypeFixedKey` sentinel (AES-CTR's IV
  randomness can't coexist with `BundleOptions.FixedKey`). On-disk
  layout for CipherType=2: `IV (16 B) || AES-CTR ciphertext` —
  `DataSize` includes IV, `PlaintextSize` does not. Tests cover
  round-trip, mixed XOR + AES-CTR within one bundle, FixedKey
  rejection, and legacy backward compat.
  **Phase 3a (27453db):** `emitAESCTRBlockDecrypt` helper +
  byte-pin test. 148-byte single-block AES-128-CTR decryption asm
  sequence composed from Phase 1 primitives.
  **Phase 3a' (d2499eb):** `crypto.ExpandAESKey` — pure-Go
  FIPS 197 § 5.2 AES-128 round-key expansion. Stdlib hides round
  keys; the all-asm stub needs them in-wire so AES-NI decrypt can
  MOVDQU directly. Pinned against the FIPS 197 Appendix A.1 test
  vector + bad-key-length guard + stdlib AES-CTR cross-validation.
  **Phase 3b/host (pending commit):** wire-format extension — every
  CipherType=2 entry now carries [IV(16)|ciphertext|round keys(176)].
  `AESCTRRoundKeysSize` + `CPUIDFeatureAES` constants exported.
  Pack-time auto-injects the AES bit (0x02000000) into the entry's
  PT_CPUID_FEATURES mask + value (strict OR — operator-supplied
  feature constraints survive). UnpackBundle strips round keys
  before DecryptAESCTR. 3 new pin tests (round-key tail layout +
  auto-inject + auto-inject-is-OR) + existing 4 round-trip tests
  all green.
  **Phase 3c-prep (788decb):** BSWAP Builder primitive.
  **Phase 3c-loop (pending commit):** `emitAESCTRDecryptLoop` —
  243-byte stub-side AES-CTR loop helper. Composes 32 B setup
  (load IV → XMM0, derive R8 round-keys pointer, RSI in-place
  source, R9 remaining bytes) + loop body (test r9, jz aes_done,
  emitAESCTRBlockDecrypt 148 B, BE counter increment via BSWAP
  ~40 B, advance pointers, jmp aes_loop). Length sentinel + setup
  prefix pinned by `TestEmitAESCTRDecryptLoop`. Padded plaintext
  assumption: pack-time pads to 16-byte multiple (Phase 3c-wire).
  **Phase 3c-wire (pending commit):** V2NW dispatch shipped + Win VM
  E2E GREEN. CipherType byte at [RCX+12] drives the branch
  (movzx + cmp + je); CipherType=2 → .aes_ctr_path block at stub
  tail (between .jmp_payload and .exit_block) which composes
  emitAESCTRDecryptLoop + plaintext-start JMP. Pack-time pads
  plaintext to 16-byte multiple; UnpackBundle trims back to
  PlaintextSize. V2NW stub grew from 458 B → 739 B
  (+281 B for the AES-CTR path). New test:
  `TestBundleStubV2NW_E2E_AESCTR` → exit=42 on win10 VM
  (2048 B wrapped PE, full AES-NI decrypt round-trip).

- [x] **#2.3 Polymorphic slots B & C** (pending commit)
  Added `emitNopJunk` helper (Builder-time RawBytes NOP-run with
  caller rng). Wired into V2-Negate and V2NW at slot B
  (post-CPUID-prologue / pre-loop) and slot C (post-matched-pointer-
  computation / pre-decrypt). Builder labels auto-resolve all Jcc
  displacements crossing the slots. Production callers split seed
  into `bRng` (slots B/C) + `aRng` (slot A) so adding slots
  doesn't reshuffle the others' choices. Tests:
  `TestBundleStub_V2Negate_SlotsBC_Polymorphism` and
  `TestBundleStub_V2NW_SlotsBC_Polymorphism` pin determinism per
  seed + difference across seeds + growth vs no-junk baseline.

- [x] **#2.4 BundlePayload.Key wire-in** (pending commit)
  Added `BundlePayload.Key []byte` for operator-supplied
  deterministic per-payload keys. 16-byte length enforced via
  `ErrBundleBadKeyLen`. Precedence: `BundleOptions.FixedKey` (test
  determinism) > `BundlePayload.Key` (per-payload) > random. Tests:
  `TestBundlePayloadKey_Deterministic` (same Key → same XOR-rolling
  bundle bytes), `TestBundlePayloadKey_BadLen` (1/8/15/17/24/32 →
  rejected), `TestBundlePayloadKey_FixedKeyWins` (precedence pin).
  Closes the multi-cipher chantier.

Total Tier 2: ~6-8h.

## 🟢 Tier 3 — Lower priority

- [ ] **#3.1 Per-build SBox derivation in stub**
  Currently SBox transform is build-time only (operator pre-
  substitutes bytes before pack). Add stub-time derivation via
  `HKDF(secret, "stub-sbox-PER-PACK", 256)` + Fisher-Yates in
  emitted asm. Extra unmasking layer at runtime. ~2-3h.

- [x] **#3.2 packerscope decrypt — shipped as `extract` verb** (pending commit)
  The `packerscope extract <file> -out <dir>` verb already
  decrypts every payload in a bundle and writes them under
  `<dir>/payload-NN.bin` (calls `packer.UnpackBundleWith`
  per entry). Round-trip + per-build-secret round-trip + wrong-
  secret negative path now covered by `TestRunExtract_RoundTrip`
  and `TestRunExtract_SecretRoundTrip`. Naming kept as `extract`
  (closer to standard CLI vocabulary) rather than the speculative
  `decrypt`/`-bundle` from this tracker row.

- [x] **#3.3 V1 → V2 retirement** (pending commit)
  Deleted V1 stubs (`bundleStubVendorAware`,
  `bundleStubVendorAwareWindows`) + V2-plain (`bundleStubVendorAwareV2`)
  + 5 test files exercising the dead paths (665 LOC net). V2-Negate
  inherits the imm32 / PIC-prefix contracts; new pin tests
  `TestBundleStubV2N_PICOffsetMatchesConst` and
  `TestBundleStubV2N_PICTrampolinePrefix` guard the canonical shape
  directly (no longer via V1 byte-for-byte comparison).

- [~] **#3.4 Consolidate V2-Negate / V2NW shared prefix** (pending commit)
  V2 plain already deleted in #3.3. The remaining V2-Negate and V2NW
  share an identical prefix (§1 PIC + §2 CPUID vendor + §2.5 CPUID
  features + §3 loop setup); extracted to 4 shared emitters in
  pe/packer/bundle_stub_helpers.go. Per-platform divergence (PEB read
  on Windows, syscall vs jmp on no_match, PT_WIN_BUILD per-entry
  check) intentionally NOT consolidated — those are where the
  platforms truly differ, and folding them under a callback table
  would obscure the asm shape that operators must reason about.
  Net effect: V2-Negate −80 LOC, V2NW −72 LOC, helpers +123 LOC.

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

## Win VM validation (2026-05-10, post-v0.91 baseline)

Direct ssh dispatch on `win10` libvirt VM (192.168.122.122, INIT
snapshot) — bypassed `scripts/vm-run-tests.sh` (scp of full tree was
timing out at 16 min on Windows OpenSSH sftp) via tarball-deploy:

  1. `tar czf maldev.tgz . --exclude=.git --exclude=ignore`     (30 MB)
  2. `tar czf gomodcache.tgz -C ~/go/pkg/mod/cache download`    (266 MB)
  3. `scp` both → C:/
  4. `tar -xzf` on Windows (Win10 1803+ ships tar.exe)
  5. `cd C:\maldev && set GOPROXY=off && set GOFLAGS=-mod=mod && go test ./pe/packer/ -run TestBundleStubV2N`

All 7 V2N + V2NW tests green:
- TestBundleStubV2NW_E2E_PTCpuidFeaturesWindows  → exit=42 (SSE3 bit)
- TestBundleStubV2NW_E2E_PTMatchAllWindows       → exit=42
- TestBundleStubV2NW_E2E_PTWinBuildWindows       → exit=42 (PEB build match)
- TestBundleStubV2N_PICOffsetMatchesConst        → pass
- TestBundleStubV2N_PICTrampolinePrefix          → pass
- TestBundleStubV2NW_PICTrampolinePrefix         → pass
- TestBundleStubV2NWBuilds                       → 458 B emit + immPos=10

Conclusion: every refactor + new primitive shipped this session
(Tier 🟡 #2.1 / #2.3, Tier 🟢 #3.3 / #3.4, Tier 🟡 #2.2 Phases 1+2+3a)
preserved Win runtime correctness. v0.91 is a safe baseline for
Phase 3b stub-side AES-CTR wiring.

## Last-known-good signposts

| Aspect | State as of 2026-05-10 |
|---|---|
| Latest tag | v0.92.0 (Tier 🟡 #2.2 complete — AES-CTR end-to-end Win VM) |
| HEAD commit | ef71e1f (Phase 4b V2NW shipped) |
| Linux scan stub | V1 (bundleStubVendorAware) — operational, runtime-green |
| Linux scan stub V2 | bundleStubVendorAwareV2 — runtime-green, NOT WIRED |
| Linux scan stub V2-Negate | bundleStubVendorAwareV2Negate — runtime-green, NOT WIRED |
| Windows scan stub | V1+§2-patch — operational |
| Windows scan stub V2NW | bundleStubV2NegateWinBuildWindows — runtime-green, NOT WIRED |
| asmtrace harness | Windows-only VEH; Linux variant queued (#4.2) |
| amd64.Builder API | complete for current scan-stub mnemonics |
