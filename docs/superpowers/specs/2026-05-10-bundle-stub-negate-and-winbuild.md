# Bundle scan stub — §5 negate + §4 PHASE-B-2 PT_WIN_BUILD merged refactor — byte layout spec

> **Status:** mechanical execution spec for the supervised pickup.
> Locks every byte change in `bundleStubVendorAwareWindows` with its
> offset, encoding, and Jcc displacement so the implementer doesn't
> have to recompute anything during the asm work.
>
> **Why this format:** §2 ExitProcess (1-byte REX bug) and §4 PHASE A
> (1-byte stack discipline bug) showed that hand-encoded asm without
> upfront layout discipline costs multiple VM dispatches per fix.
> Locking the layout up front collapses 6+ debug iterations into a
> single careful keystroke pass.
>
> **Implementation order:** §5 first (smaller, validates the
> compute_negate plumbing), then §4 PHASE B-2 on top (adds
> PT_WIN_BUILD check inside the same per-entry test).

## Reference: existing Windows stub layout (post v0.87.0)

| Section | Offsets | Length | Source |
|---|---|---|---|
| PIC trampoline | 0..13 | 14 | `bundleStubVendorAware` linux[0:14] |
| CPUID prologue | 14..35 | 22 | linux[14:36] |
| Loop setup | 36..49 | 14 | linux[36:50] |
| Loop body | 50..114 | 65 | linux[50:115] |
| jmp rel32 → §2 block | 115..119 | 5 | new in Windows variant |
| Matched section + decrypt + JMP | 120..189 | 70 | linux[124:end] + 4-byte `add rsp, 16` patch |
| §2 ExitProcess block | 190..332 | 143 | `EmitNtdllRtlExitUserProcess(0)` |

Total: ~333 bytes (varies ±1 with seed-driven NOP injection).

## §5 — Negate flag refactor

### Goal

Each per-entry test currently branches DIRECTLY to `.matched`
(success) or `.next` (failure). With negate support, the per-entry
must compute a "raw match" boolean → AL, XOR with the entry's
negate flag, then branch on the final result.

### Strategy

**Don't refactor every branch site.** Instead replace each direct
Jcc with a 13-byte sequence that sets AL and falls through to a
shared `.compute_negate` block at the end of the loop body.

### Patch sites (5 sites, each +7 bytes net)

For each direct match-branch (PATCH SITES 1, 3, 5):

```asm
; Original (2 bytes):
;   jnz .matched           ; or je / jz
; Replacement (9 bytes):
;   jz   +7                ; skip the set-and-jump (2 B: 74 07)
;   mov  al, 1             ; raw match = true (2 B: b0 01)
;   jmp  rel32 .compute_negate (5 B: e9 dd dd dd dd)
```

For each direct fail-branch (PATCH SITES 2, 4):

```asm
; Original (2 bytes):
;   jz   .next             ; or jnz
; Replacement (9 bytes):
;   jnz  +7                ; skip if PT_* present (the original would
;                            have continued; we want to fall through
;                            to "raw match = false" only when the test
;                            said the entry doesn't match by this check)
;   xor  al, al            ; raw match = false (2 B: 30 c0)
;   jmp  rel32 .compute_negate (5 B: e9 dd dd dd dd)
```

**WAIT:** the fail-branch case is subtle. The `.next` branch fires
when the predicate has FAILED the test (e.g. PT_CPUID_VENDOR
fingerprint doesn't match). Before negate, `.next` immediately
goes to the next entry. With negate, we still want negate=1 to
flip a fail into a match — so we must route through `.compute_negate`
first.

But "raw match = false" is the right semantics for the fail
branches: AL=0 means "no match according to the predicate". XOR
with negate=1 → AL=1 → goes to `.matched`.

So replacement is correct: jcc-not (skip), xor al, al, jmp
.compute_negate.

Hmm, but this logic might double-count: for a PT_CPUID_VENDOR-only
entry, we'd hit the "test r9b, 1; jz .next" → if PT_CPUID_VENDOR
NOT set, this fires AL=0 + .compute_negate. But the entry might
have OTHER bits set (e.g. PT_WIN_BUILD). The current loop ONLY
checks PT_MATCH_ALL and PT_CPUID_VENDOR, ignoring PT_WIN_BUILD —
so for an entry with PT_WIN_BUILD only, the flow would treat it
as "no match" then negate-flip it.

**This subtlety means §5 alone (without §4-B-2) implementing PT_*
ANDed correctly requires the per-entry test to evaluate ALL
enabled PT_* bits and AND them — the current "first matching test
wins" is not negate-compatible.**

### Refined approach

Restructure the per-entry test to a sequence of enabled-bit checks
that ALL must pass. AL accumulates the AND. Then XOR with negate.

```asm
.entry_test:
mov  al, 1                 ; assume "match" until proven otherwise (b0 01)
movzx r9d, byte [r8]       ; predType (45 0f b6 08)

; PT_MATCH_ALL bit short-circuits the rest
test r9b, 8                ; (41 f6 c1 08)
jnz  .entry_done           ; AL=1 already (75 ??)

; PT_CPUID_VENDOR check
test r9b, 1                ; (41 f6 c1 01)
jz   .skip_vendor          ; if not set, skip the vendor compare (74 ??)
; ... existing 8+4-byte vendor compare logic, set AL=0 on fail ...
.skip_vendor:

; PT_WIN_BUILD check (§4 PHASE-B-2 wires it in)
test r9b, 2                ; (41 f6 c1 02)
jz   .skip_winbuild        ; (74 ??)
; ... build-range compare against R12 (saved OSBuildNumber) ...
; on out-of-range: xor al, al
.skip_winbuild:

.entry_done:
movzx r9d, byte [r8+1]     ; negate flag (45 0f b6 48 01)
and  r9b, 1                ; (41 80 e1 01)
xor  al, r9b               ; flip if negate (44 30 c8)
test al, al                ; (84 c0)
jnz  .matched              ; rel32 (0f 85 dd dd dd dd)
jmp  .next                 ; rel32 (e9 dd dd dd dd)
```

This is cleaner than the patch-existing approach. Total per-entry
asm: ~80 bytes including all enabled-bit checks.

### Implementation strategy

**Don't patch the existing bundleStubVendorAware loop body.**
Build a new function `bundleStubScanLoopWithNegateAndBuild()` that
emits the entire entry-test block as ONE byte array, and assemble
the new Windows stub by composing:

```
PIC trampoline (14 B from linux[0:14])
+ CPUID prologue (22 B from linux[14:36])
+ EmitPEBBuildRead (15 B from stage1 primitive)
+ mov r12d, eax (3 B: 41 89 c4) — save OSBuildNumber to callee-saved
+ Loop setup (14 B from linux[36:50] — UPDATE: needs to walk count etc.)
+ NEW per-entry test block (~80 B emitted via Builder for label
  resolution)
+ .next: add r8, 48; inc eax; jmp .loop (existing 8 B)
+ jmp rel32 → §2 ExitProcess fallback (5 B)
+ .matched section + decrypt + JMP + add rsp, 16 + jmp rdi (74 B)
+ §2 ExitProcess block (143 B)
```

Total: ~378 B (vs ~333 B without negate/build → +45 B).

### Test plan

1. **Byte-shape unit test** — pin the new stub bytes against an
   expected layout. Catches off-by-one in any encoding.
2. **asmtrace VEH harness** — route the new stub bytes through the
   diagnostic harness with a 1-payload PT_MATCH_ALL bundle. If any
   instruction faults, the VEH dump pinpoints it.
3. **Win VM E2E** — wrap a real bundle, run on win10, assert exit 42.
4. **§5-specific test** — bundle with 2 entries:
    - entry 0: PT_CPUID_VENDOR + Negate=1, vendor="GenuineIntel"
    - entry 1: PT_MATCH_ALL fallback
   On Intel host: entry 0 matches "GenuineIntel" but Negate=1 flips
   it → fail. Entry 1 matches via PT_MATCH_ALL → its payload runs.
5. **§4-B-2-specific test** — bundle with PT_WIN_BUILD entry that
   matches the host build → its payload runs.

## §4 PHASE B-2 — PT_WIN_BUILD predicate

### What's needed

Already covered in the §5 refined approach above. The PT_WIN_BUILD
check is a 5-instruction block inside the per-entry test:

```asm
; r12 holds OSBuildNumber (saved at prologue exit)
test r9b, 2                ; PT_WIN_BUILD bit
jz   .skip_winbuild
mov  r9d, [r8+16]          ; BuildMin
cmp  r12d, r9d             ; (45 39 cc — actually 44 39 e1)
jl   .winbuild_fail        ; signed less-than
mov  r9d, [r8+20]          ; BuildMax
cmp  r12d, r9d
jg   .winbuild_fail        ; signed greater-than
jmp  .skip_winbuild
.winbuild_fail:
xor  al, al                ; AND-zero into AL
.skip_winbuild:
```

Total: ~30 bytes.

The `cmp` against memory + `jl/jg` use the new amd64.Builder.JGE/JL
mnemonics added in v0.87.0+1 (commit 82132da). 

### Existing primitives to reuse

- `stage1.EmitPEBBuildRead(b)` — 15 bytes, sets EAX = OSBuildNumber
- `stage1.EmitBuildRangeCheck(b)` — 34 bytes, currently expects
  EAX vs [r8+16/20]. Adapt or call manually.

## Sequencing for the supervised pickup

1. **Migrate `bundleStubVendorAwareWindows` to amd64.Builder API**
   — use Builder.New() + Builder.Label() for `.matched`,
   `.no_match`, `.next`, `.compute_negate`, `.loop`. Builder
   handles all Jcc displacements automatically. RawBytes for
   CPUID + segment overrides (the 2 instructions Builder doesn't
   support).
2. **Validate byte-equivalent to v0.87.0 stub** for the
   no-negate, no-build case. Single byte-shape test compares
   the new emission to the old emission.
3. **Add negate path** (§5) — restructure per-entry test as
   AL-accumulator, XOR with negate, branch.
4. **Add PT_WIN_BUILD check** (§4-B-2) — insert build-range check
   inside the per-entry test, use R12 for the saved build value.
5. **Win VM E2E for both new code paths.**

## Why this sequencing matters

Step 1 (Builder migration) is the high-leverage step. Once the
stub is Builder-driven, every Jcc displacement becomes
auto-resolved. §5 + §4-B-2 then become structural changes
(adding/removing instructions) instead of byte-recompute exercises.

The Builder API adds (commit 82132da) provided the missing
mnemonics: INC, CMP, TEST, JGE, JL. Combined with existing
MOV/LEA/XOR/SUB/ADD/MOVZX/MOVB/DEC/POP/RawBytes/JMP/JNZ/JE/CALL/RET/NOP,
the scan stub can be expressed entirely via Builder calls.

Estimated effort: ~3-4 hours of careful Builder work +
2-3 VM dispatches via VEH harness for any encoding bug. Investment
amortises across §5, §4-B-2, and any future scan-stub refactor.
