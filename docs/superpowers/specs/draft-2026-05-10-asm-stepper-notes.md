# Draft notes — pure-Go x86-64 stepper for asm primitive validation

> **Status:** pre-brainstorm notes, NOT a finalized spec. Captures
> the constraints, options, and open questions that a future
> `superpowers:brainstorming` session will turn into a proper
> design + implementation plan.
>
> **Related:** Solution D from the 2026-05-10 asm-debug trade-off
> analysis (see this session's chat log + the v0.84.0 commit
> message for §2 ExitProcess via PEB walk).

## Problem statement

Maldev's `pe/packer/stubgen/stage1` package emits hand-encoded
asm primitives (`EmitPEBBuildRead`, `EmitCPUIDVendorRead`,
`EmitVendorCompare`, `EmitBuildRangeCheck`, `EmitNtdllRtlExitUserProcess`,
+ the bundle scan stub). Each primitive is byte-shape pinned via
unit tests, but **byte-shape ≠ semantic correctness**.

The §2 ExitProcess primitive proved this: the byte-shape test
passed but the runtime crashed because a single REX byte (`0x4c`)
encoded `add rdx, r10` instead of the intended `add r10, rdx`.
Caught only by a Windows VM dispatch + VEH harness — ~5 minutes
per debug iteration.

The §4 PHASE A scan stub now suffers the same symptom: byte-shape
green, runtime ACCESS_VIOLATION, no in-process VEH possible
because the kernel-loaded PE bypasses our test process.

## Goal

A **pure-Go x86-64 instruction stepper** that:

1. Reads emitted asm bytes.
2. Decodes the ~8-12 mnemonics maldev actually uses.
3. Steps through them against a **fake host model** (fake PEB,
   fake CPUID, fake module list, fake export table).
4. Asserts the asm reaches its intended exit state, OR pinpoints
   the faulting instruction with full register state.

Test cycle: **unit-speed (microseconds), no VM round-trip**.

## Mnemonics in current scope

Auditing the existing stage1 byte arrays + the v0.84.0 `assembleExitProcess`:

| Mnemonic | Forms used | Notes |
|---|---|---|
| `MOV r/m, r` | reg-to-reg, reg-to-mem with disp8/disp32 | Includes gs-segment override (`mov rax, gs:[0x60]`) |
| `MOV r, imm32/imm64` | with REX.W for 64-bit | |
| `MOVZX r32, r/m16` | for export-name word reads | |
| `MOVZX r32, r/m8` | for predType byte reads | |
| `ADD r/m, r` | typical reg-to-reg add | REX.B/R asymmetry pitfall (see §2 lesson) |
| `SUB r/m, imm8` | `sub rsp, 0x28` for ABI shadow space | |
| `XOR r/m, r` | zeroing pattern (`xor eax, eax`) | |
| `INC r/m` | loop counter | |
| `CMP r/m, r` | both directions (`cmp rbx, [rax]` and `cmp [rax], rbx`) | |
| `TEST r/m, imm8` / `TEST r/m, r` | bit checks (`test r9b, 8`) | |
| `Jcc rel8` | jge, jne, je, jz, jnz, jl | Mostly rel8; one rel32 in §4 |
| `JMP rel8` / `rel32` | loop back / fallthrough | |
| `CALL rel32` (PIC trampoline) | `e8 00 00 00 00` | |
| `CALL r/m` (indirect) | `ff d0` for §2's `call rax` | |
| `POP r` | PIC trampoline `pop r15` | |
| `CPUID` | `0f a2` | Side effect on RAX/RBX/RCX/RDX |
| `RET` | bare exit | |
| `INT3` / `UD2` | trap / backstop | |
| `Syscall` | `0f 05` (Linux only) | Side effect on RAX (return value), RCX/R11 (clobbered) |

**Total: ~20 mnemonic forms.** Implementing each as a Go function
that reads bytes, updates a state struct, and returns "stepped N
bytes" is bounded.

## Fake host model

The stepper needs to satisfy the asm's memory reads / CPU instruction
side effects:

- **Memory regions:**
  - Stub bytes themselves (RX)
  - Bundle blob (R, immediately after the stub)
  - Stack (RW, ~64 KiB scratch)
  - Fake PEB at gs:[0x60] (1 KiB)
  - Fake `PEB_LDR_DATA` linked from PEB.Ldr (1 KiB)
  - Fake `LDR_DATA_TABLE_ENTRY` chain (3 entries: EXE, ntdll, kernel32)
  - Fake ntdll PE base with a minimal export directory pointing at
    "RtlExitUserProcess" → fake function address
  - Fake "code" at the fake function address that signals "this is
    where we'd have called RtlExitUserProcess"

- **CPUID model:**
  - EAX=0 → returns "GenuineIntel" in EBX/EDX/ECX
  - EAX=1 → returns realistic feature bits
  - Other leaves → unimplemented (panic with clear message)

- **Stack model:**
  - 64 KiB scratch starting at a chosen base address
  - Push/pop adjust RSP and read/write through the stack region
  - SP-alignment tracking — the stepper can ASSERT the stub
    maintains 16-byte alignment at call boundaries (the very thing
    a VEH harness can't easily verify).

## Operational shape (sketch)

```go
package asmstep

type Stepper struct {
    Code []byte         // the asm bytes
    PC   uint64         // RIP equivalent
    Regs [16]uint64     // RAX..R15
    Stack [65536]byte
    PEB  []byte         // fake PEB image
    // ... module list, export table fakes ...
    History []StepLog   // every executed instruction + register diff
}

func (s *Stepper) Step() (cont bool, err error)
//   true, nil  → executed one instruction, can step again
//   false, nil → reached a terminal (call to fake-Exit, ret with stack=0)
//   _,    err  → faulted — err describes what (decode failure,
//                page-fault on memory access, alignment violation, etc.)

func (s *Stepper) Run(maxSteps int) error
//   bounded run; returns the same error shape as Step().
```

Test pattern:

```go
func TestEmitNtdllRtlExitUserProcess_StepperReachesExit(t *testing.T) {
    asm := stage1.AssembleExitProcess(42)
    s := asmstep.NewStepper(asm).WithFakeWindowsPEB()
    if err := s.Run(1000); err != nil {
        t.Fatalf("step %d: %v\n%s", s.PC, err, s.History.Format())
    }
    if !s.ReachedExit(42) {
        t.Errorf("did not reach fake-Exit(42); last RIP = %#x", s.PC)
    }
}
```

## Open questions for brainstorm

1. **Scope creep — do we model the full instruction set or just
   what we use today?** Today is bounded; tomorrow may add SSE
   for fingerprint hashing or SHA-NI for HMAC primitives. Options:
   - A. Strict whitelist + panic on unknown opcode (forces
     explicit additions when scope grows).
   - B. Best-effort decode + skip unknown (slow drift toward
     under-coverage).
   - C. Use an existing Go x86-64 disassembler (e.g.
     `golang.org/x/arch/x86/x86asm`) for decoding, only
     hand-implement the stepping side effects.

2. **Memory-access realism.** Do we model page-faults
   (read from unmapped memory → panic) or treat all addresses as
   readable returning 0?
   - The §4 PHASE A bug is exactly the kind of thing a strict
     model would catch (unintended RVA dereference returns
     "address 0x15479c not mapped" instead of garbage).

3. **CPU-state side effects.** RFLAGS after CMP/TEST is critical
   for Jcc correctness. Tracking just ZF/SF/CF/OF is enough for
   our mnemonic set; full RFLAGS modeling is overkill.

4. **OS-call interception.** When the stub does
   `call rax` to a fake-RtlExitUserProcess address, we want the
   stepper to treat that as a "process exit with code = arg1".
   Mark fake function addresses in the host model with handlers.

5. **Debug history granularity.** Per-instruction (every step
   logs RIP + opcode + register diff) is verbose but actionable.
   Compressed (only on fault) is fast but loses replay capability.

6. **Coverage with the existing VEH harness.** The asmtrace VEH
   harness catches RUNTIME bugs on real Windows. Stepper catches
   ENCODING bugs at unit-speed. They're complementary, not
   redundant. Workflow:
   - Stepper green → byte-shape green → VEH harness on real VM
     for the final integration check.

## Estimated investment

- ~2-3 days for a minimum viable stepper covering current mnemonics
  with strict-whitelist decoder.
- Payback: every future asm primitive (§5 negate refactor, §4 PHASE B
  PT_WIN_BUILD wire-up, future syscall stubs, future shellcode
  primitives) gets unit-speed validation.

## Related code

- `pe/packer/stubgen/stage1/exitprocess.go` — first asm primitive
  whose bug was caught by VEH after escaping byte-shape tests.
- `pe/packer/stubgen/stage1/asmtrace/main_windows.go` — VEH harness;
  the stepper should produce trace output in a similar format so
  operators don't have to learn two diagnostic dialects.
- `pe/packer/bundle_stub.go` + `bundle_stub_winwrap.go` — the bundle
  scan stubs; the §4 PHASE A runtime bug is the immediate use case
  for the stepper once it lands.

---

**Next action when ready:** invoke `superpowers:brainstorming` with
this draft as input to produce the canonical
`docs/superpowers/specs/2026-05-1?-asm-stepper-design.md`.
