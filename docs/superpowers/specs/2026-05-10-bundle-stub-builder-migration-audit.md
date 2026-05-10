# Bundle scan stub → amd64.Builder migration — instruction-by-instruction audit

> **Status:** mechanical execution audit. Maps every instruction in
> `bundleStubVendorAware()` to the Builder method (or RawBytes) that
> emits it. The next session executes the migration mechanically:
> walk the table top-to-bottom, replace each row's bytes with the
> mapped call.
>
> **Pre-requisite:** Builder API additions in commits 82132da
> (INC/CMP/TEST/JGE/JL) and 0d87fdb (MOVL/AND). All present on
> master.

## Why this audit instead of the migration code itself

Earlier in the session I attempted to write the migration in a
single pass. Two obstacles surfaced that justify the audit-first
approach:

  1. **golang-asm encoding non-determinism.** `b.MOV(rdi, rsp)` may
     emit `48 89 e7` or `48 8b fc` (both valid, different bytes).
     Strict byte-equivalence vs the existing hand-encoded stub
     isn't a reliable validation gate. Functional equivalence
     (Linux runtime test passes) is the only reliable gate, which
     means each migration commit needs a VM dispatch.
  2. **Builder gaps for our specific shapes.** `test r/m, imm`
     silently fails through `binaryOp`. `mov [rdi], ebx` (32-bit
     mem-to-reg) requires `MOVL` distinct from `MOV`. The
     gs-segment override doesn't have a Builder verb at all.

The audit table below pre-resolves these gaps so the migration
itself is mechanical.

## Scan stub layout (current bundleStubVendorAware bytes)

| Section | Offsets | Length | Description |
|---|---|---|---|
| PIC trampoline | 0..13 | 14 | `call 0; pop r15; add r15, imm32` |
| CPUID prologue | 14..35 | 22 | sub rsp 16 + cpuid + spill |
| Loop setup | 36..49 | 14 | read count + fpTable from header |
| Loop body | 50..114 | 65 | per-entry test + `.next` |
| .no_match (Linux variant) | 115..123 | 9 | `mov eax,231; xor edi,edi; syscall` |
| .matched + decrypt + JMP | 124..end | ~72 | dispatch + per-byte XOR |

## Instruction-by-instruction migration mapping

### Section 1 — PIC trampoline (offsets 0..13)

| Off | Bytes | Asm | Builder mapping |
|---|---|---|---|
| 0 | `e8 00 00 00 00` | `call .pic` (rel32 = 0, target = next instr) | **RawBytes** — Builder.CALL takes a label, but the "call to next instruction" idiom needs an explicit forward-call-to-self that the label system doesn't model cleanly. Keep raw. |
| 5 | `41 5f` | `pop r15` | `b.POP(amd64.R15)` |
| 7 | `49 81 c7 XX XX XX XX` | `add r15, imm32` (imm patched at wrap time) | **RawBytes** — the imm32 is patched POST-encode at `bundleOffsetImm32Pos`. Encoding via `b.ADD(R15, Imm(0))` would emit `add r15, 0` which is fine but the POST-encode patch needs to know the byte offset. Keep raw + record offset. |

**Section 1 → 1 Builder call + 2 RawBytes blocks.**

### Section 2 — CPUID prologue (offsets 14..35)

| Off | Bytes | Asm | Builder mapping |
|---|---|---|---|
| 14 | `48 83 ec 10` | `sub rsp, 0x10` | `b.SUB(amd64.RSP, amd64.Imm(16))` |
| 18 | `48 89 e7` | `mov rdi, rsp` | `b.MOV(amd64.RDI, amd64.RSP)` |
| 21 | `31 c0` | `xor eax, eax` | `b.XOR(amd64.RAX, amd64.RAX)` — **CAVEAT:** Builder.XOR uses XORQ (64-bit). The hand-encoded `31 c0` is XOR with operand-size 32 (zero-extends). Functionally equivalent on AMD64 (32-bit reg ops zero-extend the upper half). golang-asm may still emit XORQ form; verify. |
| 23 | `0f a2` | `cpuid` | **RawBytes** — Builder lacks CPUID. |
| 25 | `89 1f` | `mov [rdi], ebx` | `b.MOVL(amd64.MemOp{Base: amd64.RDI}, amd64.EBX)` — uses the new MOVL primitive (commit 0d87fdb). EBX is the 32-bit reg. |
| 27 | `89 57 04` | `mov [rdi+4], edx` | `b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 4}, amd64.EDX)` |
| 30 | `89 4f 08` | `mov [rdi+8], ecx` | `b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 8}, amd64.ECX)` |
| 33 | `48 89 fe` | `mov rsi, rdi` | `b.MOV(amd64.RSI, amd64.RDI)` |

**Section 2 → 7 Builder calls + 1 RawBytes block.** Verify the
32-bit MOV emissions vs hand-encoded bytes; if they differ, both
forms are valid AMD64 but the byte-shape unit test will fail (and
is fine — we update the test).

### Section 3 — Loop setup (offsets 36..49)

| Off | Bytes | Asm | Builder mapping |
|---|---|---|---|
| 36 | `41 0f b7 4f 06` | `movzx ecx, word [r15+6]` | `b.MOVZX(amd64.RCX, amd64.MemOp{Base: amd64.R15, Disp: 6, Width: 16})` — needs MOVZX with word-source, verify Builder.MOVZX accepts that |
| 41 | `45 8b 47 08` | `mov r8d, [r15+8]` | `b.MOVL(amd64.R8, amd64.MemOp{Base: amd64.R15, Disp: 8})` |
| 45 | `4d 01 f8` | `add r8, r15` | `b.ADD(amd64.R8, amd64.R15)` |
| 48 | `31 c0` | `xor eax, eax` | `b.XOR(amd64.RAX, amd64.RAX)` (same caveat as §2) |

**Section 3 → 4 Builder calls.** Verify MOVZX-with-word and 32-bit
reg-to-mem emissions.

### Section 4 — Loop body (offsets 50..114) — THE CRITICAL ZONE

This is where §5 (negate flag) and §4-PHASE-B-2 (PT_WIN_BUILD)
will plug in. Migration here gives the highest leverage.

| Off | Bytes | Asm | Builder mapping |
|---|---|---|---|
| 50 | `39 c8` | `cmp eax, ecx` (.loop label here) | `loop := b.Label("loop"); b.CMP(amd64.RAX, amd64.RCX)` — XOR uses 32-bit, CMP defaults to 64-bit. Same caveat. |
| 52 | `7d 3d` | `jge .no_match` | `b.JGE(noMatch)` — Builder auto-resolves rel8/rel32 |
| 54 | `45 0f b6 08` | `movzx r9d, byte [r8]` | `b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8, Width: 8})` |
| 58 | `41 f6 c1 08` | `test r9b, 8` | **RawBytes** — `test reg-imm` Plan-9 quirk (silently fails through binaryOp). 4 bytes raw. |
| 62 | `75 3c` | `jnz .matched` | `b.JNZ(matched)` |
| 64 | `41 f6 c1 01` | `test r9b, 1` | **RawBytes** (same reason) |
| 68 | `74 25` | `jz .next` | `b.JE(next)` |
| 70 | `4d 8b 50 04` | `mov r10, [r8+4]` | `b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4})` |
| 74 | `4c 3b 16` | `cmp r10, [rsi]` | `b.CMP(amd64.R10, amd64.MemOp{Base: amd64.RSI})` — verify CMP accepts mem operand |
| 77 | `75 0a` | `jne .vendor_zero_check` | `b.JNZ(vendorZeroCheck)` |
| 79 | `45 8b 50 0c` | `mov r10d, [r8+12]` | `b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12})` |
| 83 | `44 3b 56 08` | `cmp r10d, [rsi+8]` | `b.CMP(amd64.R10, amd64.MemOp{Base: amd64.RSI, Disp: 8})` (32-bit cmp variant — possibly needs a CMPL primitive added) |
| 87 | `74 23` | `je .matched` | `b.JE(matched)` |

… (continue for offsets 89..114, same pattern — 14 more rows)

**Section 4 → ~24 Builder calls + 2 RawBytes blocks (the test-imm
forms).** Labels: `.loop`, `.matched` (external), `.no_match`
(external), `.next`, `.vendor_zero_check`. Builder resolves
displacements automatically — eliminates the entire class of bug
that hit §2 and §4 PHASE A.

### Section 5 — .no_match (offsets 115..123, Linux variant)

For the Linux variant, this is `sys_exit_group(0)`:
```
mov eax, 231        ; b8 e7 00 00 00
xor edi, edi        ; 31 ff
syscall             ; 0f 05
```

| Off | Builder mapping |
|---|---|
| `mov eax, 231` | `b.MOVL(amd64.RAX, amd64.Imm(231))` |
| `xor edi, edi` | `b.XOR(amd64.RDI, amd64.RDI)` |
| `syscall` | **RawBytes** — Builder lacks SYSCALL |

For the Windows variant, this becomes `jmp rel32 → §2 block`:
```
e9 XX XX XX XX
```
That's a single `b.JMP(exitProcessLabel)` with an external label.
Builder auto-resolves rel8 vs rel32 based on distance.

### Section 6 — .matched + decrypt + JMP (offsets 124..end)

This is the longest section but mostly mechanical:

```
; .matched body — compute payload entry pointer
mov r9d, [r15+12]               b.MOVL(R9, MemOp{R15, 12})
mov r10d, eax                   b.MOVL(R10, RAX)
shl r10d, 5                     ** RawBytes — Builder lacks SHL **
add r9d, r10d                   b.ADD(R9, R10) — but 32-bit form
add r9, r15                     b.ADD(R9, R15)
mov rcx, r9                     b.MOV(RCX, R9)

; Decrypt loop
mov edi, [rcx]                  b.MOVL(RDI, MemOp{RCX})
add rdi, r15                    b.ADD(RDI, R15)
mov esi, [rcx+4]                b.MOVL(RSI, MemOp{RCX, 4})
lea r8, [rcx+16]                b.LEA(R8, MemOp{RCX, 16})
xor r9d, r9d                    b.XOR(R9, R9)

.dec:                           dec := b.Label("dec")
test esi, esi                   b.TEST(RSI, RSI)
jz .jmp_payload                 b.JE(jmpPayload)
mov al, [rdi]                   ** RawBytes — 8-bit MOV not in Builder **
mov dl, r9b                     ** RawBytes **
and dl, 15                      ** RawBytes — AND r/m, imm8 plan 9 quirk **
movzx edx, dl                   b.MOVZX(RDX, MemOp ... — wait, MOVZX needs mem source today, not reg-source)
xor al, [r8+rdx]                ** RawBytes — 8-bit XOR not in Builder **
mov [rdi], al                   b.MOVB(MemOp{RDI}, AL_REG) — Builder.MOVB exists
inc rdi                         b.INC(RDI)
inc r9d                         b.INC(R9)
dec esi                         b.DEC(RSI)
jmp .dec                        b.JMP(dec)

.jmp_payload:                   jmpPayload := b.Label("jmp_payload")
mov edi, [rcx]                  b.MOVL(RDI, MemOp{RCX})
add rdi, r15                    b.ADD(RDI, R15)
add rsp, 16                     ** Windows-only patch — RawBytes **
jmp rdi                         ** RawBytes — JMP r/m not in Builder **
```

**Section 6 →** dominated by RawBytes for the 8-bit ops + SHL +
the JMP-r/m. Builder still buys us the .dec, .jmp_payload labels.

## Total Builder coverage estimate

| Section | Builder calls | RawBytes blocks |
|---|---|---|
| §1 PIC | 1 | 2 |
| §2 CPUID prologue | 7 | 1 (cpuid) |
| §3 Loop setup | 4 | 0 |
| §4 Loop body | 24 | 2 (test r-imm) |
| §5 .no_match Linux | 2 | 1 (syscall) |
| §6 Matched + decrypt + JMP | ~15 | ~10 (8-bit ops + SHL + JMP r/m) |

**~53 Builder calls + ~16 RawBytes blocks.** Builder wins us
auto-displacement for ~12 conditional + unconditional jumps —
exactly the bug class that bit §2 and §4 PHASE A.

## Migration sequencing

1. **Implement `bundleStubVendorAwareV2()` in pe/packer/bundle_stub.go.**
   Keep V1 untouched. V2 uses the audit table verbatim.
2. **Test: write `TestBundleStubV2_FunctionallyEquivalent`** that
   wraps the same bundle with V1-driven and V2-driven flows and
   asserts byte-identical PE output OR, if bytes differ but
   semantically equivalent, runs both through TestWrapBundleAsExecutableLinux_RunsExit42.
3. **Once V2 green, swap `bundleStubVendorAware` to call V2 internally.**
   Linux runtime tests stay green.
4. **Then layer §5 + §4-PHASE-B-2 onto V2** per
   docs/superpowers/specs/2026-05-10-bundle-stub-negate-and-winbuild.md.
   The Builder labels make displacement updates automatic; the new
   `.compute_negate` / build-range-check blocks are pure additions.

## Builder gaps to add

If we encounter an instruction the audit flags as RawBytes that
turns out to be needed in a Builder-friendly position (i.e. with a
label), we can add the primitive. Specific gaps identified:

- **CMPL** (32-bit CMP) — add `binaryOp(x86.ACMPL, ...)`. Used at
  `cmp r10d, [rsi+8]` and similar.
- **SHL imm** — add `binaryOp(x86.ASHLQ, ...)` for `shl r10d, 5`.
- **JMP r/m** — add a `JMP(target Op)` overload that handles
  register/memory operand. Used at `jmp rdi` (final dispatch).
- **MOV 8-bit** (`mov al, [rdi]`, `mov dl, r9b`) — Builder.MOVB
  handles mem-to-reg only today; would need `MOVB r,r/m` shape.
- **SYSCALL** — trivial 2-byte raw.

These are 5-line additions each, ~50 LOC total.

## Estimated effort for the supervised pickup

- Builder gap fills (CMPL/SHL/JMP-r/m/MOVB-variants/SYSCALL): 1 hour
- bundleStubVendorAwareV2 implementation: 1.5 hours
- Functional-equivalence test + Linux runtime green: 30 min
- Swap V1→V2 + Win VM E2E: 30 min

**Total: ~3.5 hours** for the migration alone, then §5+§4-B-2 on
top is a structural change (labels handle the displacements).
