---
title: Bundle stub Builder migration — live progress
last_updated: 2026-05-10 (Phase 1 complete @ 4f2f159)
session_origin: 13ddbfbb-2239-47f5-a19c-2021dee94c64
---

# Bundle scan stub → amd64.Builder migration — progress tracker

> **Purpose:** persistent record of where the migration stands so a
> different session, machine, or post-crash recovery can pick up
> without re-deriving context.
>
> **Update protocol:** every commit that advances a row → tick the
> box, paste the commit short-SHA, bump `last_updated` in front-matter.

## Companion docs

- `docs/superpowers/specs/2026-05-10-bundle-stub-builder-migration-audit.md`
  — instruction-by-instruction Builder/RawBytes mapping
- `docs/superpowers/specs/2026-05-10-bundle-stub-negate-and-winbuild.md`
  — final §5+§4-PHASE-B-2 byte layout (lands AFTER the migration)

## Phase 1 — Builder API gaps (~1h, 5 primitives)

Builder methods needed by the audit but missing from the API today.

- [x] **INC / CMP / TEST / JGE / JL** — added 2026-05-10 (commit 82132da)
- [x] **MOVL / AND** — added 2026-05-10 (commit 0d87fdb)
- [x] **CMPL** (32-bit CMP) — added 2026-05-10 (commit 4f2f159)
- [x] **SHL imm** — added 2026-05-10 (commit 4f2f159)
- [x] **JMPReg** (indirect jump through register) — added 2026-05-10 (commit 4f2f159)
- [x] **MOVBReg** (8-bit MOV reg-as-dst) — added 2026-05-10 (commit 4f2f159)
- [x] **SYSCALL** — added 2026-05-10 (commit 4f2f159)

**Phase 1 ✅ COMPLETE** as of commit 4f2f159. Builder API now covers
every instruction in the migration audit except CPUID, gs-segment
override, and TEST r/m,imm (all RawBytes).

Tests required: byte-shape pin via x86asm decode, mirroring the
existing TestBuilder_AllMnemonics pattern.

## Phase 2 — V2 scan stub implementation (~1.5h)

`pe/packer/bundle_stub.go` — new function alongside the existing
hand-encoded `bundleStubVendorAware()`:

```go
func bundleStubVendorAwareV2() ([]byte, error) {
    // emits the same scan stub via amd64.Builder per the audit table
}
```

- [ ] Section 1 (PIC trampoline) — 1 Builder call + 2 RawBytes blocks
- [ ] Section 2 (CPUID prologue) — 7 Builder calls + CPUID raw
- [ ] Section 3 (Loop setup) — 4 Builder calls
- [ ] Section 4 (Loop body) — ~24 Builder calls + 2 test-imm raws
- [ ] Section 5 (.no_match) — 2 Builder calls + SYSCALL
- [ ] Section 6 (.matched + decrypt + JMP) — ~15 Builder calls + ~10 RawBytes (8-bit ops + SHL + JMP r/m)

Bundle offset constants for post-encode patches:
- `bundleOffsetImm32Pos` — already exists; the V2 emission must
  produce its `add r15, imm32` at an offset reachable from the
  patch site (likely needs a labeled Marker concept in Builder).

## Phase 3 — Functional equivalence validation (~30 min)

- [ ] `TestBundleStubV2_FunctionallyEquivalent` test — wraps the
  same bundle via V1 and V2, runs both through
  `TestWrapBundleAsExecutableLinux_RunsExit42`-style runtime check.
  Byte-equivalence is NOT required (golang-asm picks valid encodings
  that may differ from hand-encoded V1).
- [ ] Existing `TestWrapBundleAsExecutableLinux_*` runtime tests
  green when V1 internally calls V2.
- [ ] Win VM E2E `TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows`
  green (Windows variant uses V1 + patch; once V1 swaps to V2-internal,
  same behavior).

## Phase 4 — Layer §5 + §4-PHASE-B-2 onto V2 (~2h, the unlock)

Once V2 ships, Builder labels handle Jcc displacements
automatically. The negate-flag + PT_WIN_BUILD additions become
**structural changes** instead of byte-recompute exercises.

- [ ] Add `EmitPEBBuildRead` to V2 prologue + save EAX→R12 (3 bytes)
- [ ] Restructure per-entry test: `mov al, 1` → AND-of-checks → XOR-with-negate
- [ ] PT_WIN_BUILD bit check: `test r9b, 2` + EmitBuildRangeCheck
- [ ] Negate XOR: `movzx r9d, byte [r8+1]; and r9b, 1; xor al, r9b`
- [ ] Branch on AL: `jnz .matched` else `jmp .next`

Per the negate+winbuild spec, this adds ~80 bytes of new asm.
With Builder labels, no displacement recomputation needed.

- [ ] Win VM E2E green (same E2E as today, plus negate-specific
  2-entry test, plus PT_WIN_BUILD-specific test).

## Cross-session resumption checklist

When resuming on a different machine / new session:

1. Pull latest master.
2. Read this file's checkbox state to find the next unchecked row.
3. Read the companion specs:
    - audit doc (instruction map)
    - negate-and-winbuild doc (final byte layout for Phase 4)
4. Verify the dev environment:
    - `go test -count=1 -short ./pe/packer/...` green
    - `go test -count=1 -short ./pe/packer/stubgen/amd64/` green
    - libvirt VM `win10` reachable for the runtime gate
      (`virsh -c qemu:///system list` should show win10)
5. Pick up at the first unchecked Phase 1 row.

## Last-known-good signposts

| Aspect | State as of 2026-05-10 |
|---|---|
| Latest tag | v0.87.0 (§4 PHASE B-1 ImageBase) |
| HEAD commit | 4f2f159 (Phase 1 of migration complete) |
| Linux scan-stub bytes | hand-encoded in `bundle_stub.go::bundleStubVendorAware()` — UNCHANGED, runtime-green |
| Windows scan-stub | composes Linux bytes + §2 ExitProcess + 4-byte add-rsp patch — RUNTIME GREEN on win10 |
| Builder API | INC/CMP/TEST/JGE/JL/MOVL/AND/CMPL/SHL/JMPReg/MOVBReg/SYSCALL — all primitives needed for the migration ARE PRESENT |
| asmtrace VEH harness | shipped + working (debugged §2 + §4-A bugs already) |

## Open questions for the next session

1. Should V2 replace V1 in-place (single function) or coexist
   (V1 stays, V2 is the new path)? Audit doc recommends coexistence
   for incremental confidence; V1 retires once §5+§4-B-2 land.
2. The PIC trampoline's `call 0; pop r15; add r15, imm32` pattern
   stays RawBytes per the audit. The `imm32` patch site at byte
   offset 10 is critical — V2 must produce its bytes at the same
   offset for `bundleOffsetImm32Pos` to remain valid. Verify with a
   byte-offset assertion in Phase 2's first commit.
3. `injectStubJunk` (Intel multi-byte NOP polymorphism) inserts at
   slot A (offset 14, between PIC and CPUID prologue). After the
   migration this slot must remain at the same offset — Phase 2
   needs an integration test asserting `bundleStubVendorAwareV2`
   has the same slot-A offset as V1.
