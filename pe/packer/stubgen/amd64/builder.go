package amd64

import (
	"fmt"

	asm "github.com/twitchyliquid64/golang-asm"
	"github.com/twitchyliquid64/golang-asm/obj"
	"github.com/twitchyliquid64/golang-asm/obj/x86"
)

// branchPatch records a branch prog that needs its target resolved
// after all instructions are emitted.
type branchPatch struct {
	prog  *obj.Prog
	label string
}

// Builder collects instructions and resolves labels. Encode walks
// the prog list, applies golang-asm's lowering pass, and produces
// machine bytes. Builder is single-use; create a new one per stub.
type Builder struct {
	b        *asm.Builder
	labels   map[string]*obj.Prog // label name → target prog
	branches []branchPatch        // branch progs awaiting label resolution
}

// New returns a fresh amd64 Builder.
func New() (*Builder, error) {
	b, err := asm.NewBuilder("amd64", 128)
	if err != nil {
		return nil, fmt.Errorf("amd64: init assembler: %w", err)
	}
	return &Builder{
		b:      b,
		labels: make(map[string]*obj.Prog),
	}, nil
}

// Label declares a label at the current instruction position and
// returns a LabelRef that can be passed to JMP / Jcc. The label
// is anchored by an obj.ANOP prog that emits zero bytes; golang-asm
// assigns it a Pc and includes it in the branchBackwards detection
// walk, which is required for correct branch-offset computation.
func (bb *Builder) Label(name string) LabelRef {
	p := bb.b.NewProg()
	p.As = obj.ANOP
	bb.b.AddInstruction(p)
	bb.labels[name] = p
	return LabelRef(name)
}

// MOV emits a MOV instruction. dst is the destination operand,
// src is the source.
//
// Phase 1e (v0.61.x) only needs MOV reg, imm and MOV reg, mem and
// MOV mem, reg — the SGN decoder loop reads/writes one byte at a
// time and loads constants.
func (bb *Builder) MOV(dst, src Op) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVQ
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: MOV src: %w", err)
	}
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: MOV dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// MOVL emits a 32-bit MOV (mov dst, src as r/m32 / r32). Distinct
// from [MOV] which forces 64-bit. Required when the source is a
// 32-bit register that comes from CPUID (EAX/EBX/ECX/EDX bottom
// halves) — using the 64-bit MOVQ form would write 8 bytes,
// clobbering the next 4 bytes of the destination buffer.
func (bb *Builder) MOVL(dst, src Op) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVL
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: MOVL src: %w", err)
	}
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: MOVL dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// AND emits AND dst, src (64-bit bitwise AND). Same operand-order
// convention as the rest of binaryOp. Useful for masked-bit checks
// inside the bundle scan loop's per-entry test.
func (bb *Builder) AND(dst, src Op) error {
	return bb.binaryOp(x86.AANDQ, "AND", dst, src)
}

// SHL emits SHL dst, count (64-bit shift-left). count must be an
// [Imm] (immediate); register count (CL) form is not exposed since
// the bundle scan stub only needs constant shifts (e.g. `shl r10d, 5`
// when computing the matched-payload-entry pointer).
func (bb *Builder) SHL(dst Op, count Op) error {
	return bb.binaryOp(x86.ASHLQ, "SHL", dst, count)
}

// JMPReg emits JMP r/m (indirect jump through a register). Distinct
// from [JMP] which takes a label and emits rel8/rel32. Used by the
// bundle stub's final dispatch (`jmp rdi` after the decrypt loop
// finishes — JMPs into the matched payload bytes).
func (bb *Builder) JMPReg(target Reg) error {
	p := bb.b.NewProg()
	p.As = obj.AJMP
	if err := setOperand(&p.To, target); err != nil {
		return fmt.Errorf("amd64: JMPReg target: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// MOVBReg emits an 8-bit MOV with a register destination, mirror of
// [MOVB] (which has a memory destination). Used by the bundle
// stub's per-byte XOR loop: `mov al, [rdi]` (load) and `mov dl, r9b`
// (reg-to-reg).
func (bb *Builder) MOVBReg(dst Reg, src Op) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVB
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: MOVBReg src: %w", err)
	}
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: MOVBReg dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// SYSCALL emits the Linux/AMD64 syscall instruction (`0f 05`).
// Used by the Linux .no_match path's `sys_exit_group(0)` and any
// future Linux-side asm primitive that needs to issue a direct
// syscall.
func (bb *Builder) SYSCALL() error {
	return bb.RawBytes([]byte{0x0f, 0x05})
}

// LEA emits LEA dst, [mem]. Common shape: LEA dst, [base+disp] for
// address computation inside the decoder loop.
func (bb *Builder) LEA(dst Reg, src MemOp) error {
	p := bb.b.NewProg()
	p.As = x86.ALEAQ
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: LEA src: %w", err)
	}
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: LEA dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// XOR emits XOR dst, src.
func (bb *Builder) XOR(dst, src Op) error { return bb.binaryOp(x86.AXORQ, "XOR", dst, src) }

// SUB emits SUB dst, src.
func (bb *Builder) SUB(dst, src Op) error { return bb.binaryOp(x86.ASUBQ, "SUB", dst, src) }

// ADD emits ADD dst, src.
func (bb *Builder) ADD(dst, src Op) error { return bb.binaryOp(x86.AADDQ, "ADD", dst, src) }

// MOVZX emits MOVZX dst, byte ptr [src] — zero-extends one byte from
// memory into a 64-bit register, zeroing the upper 56 bits. This is the
// correct instruction for the SGN decoder loop's byte load: it gives the
// substitution a clean 64-bit destination without polluting upper bits.
func (bb *Builder) MOVZX(dst Reg, src MemOp) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVBQZX
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: MOVZX src: %w", err)
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = regToObj(dst)
	bb.b.AddInstruction(p)
	return nil
}

// MOVZWL emits MOVZX r32, word ptr [src] — zero-extending word load
// into a 32-bit destination register. Distinct from [MOVZX] which
// uses byte-source. Used by the bundle scan stub at
// `movzx ecx, word [r15+6]` (read FingerprintEntry count) and
// `movzx eax, word [rax+r11*2]` (read AddressOfNameOrdinals entry).
func (bb *Builder) MOVZWL(dst Reg, src MemOp) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVWLZX
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: MOVZWL src: %w", err)
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = regToObj(dst)
	bb.b.AddInstruction(p)
	return nil
}

// MOVB emits MOVB byte ptr [dst], src — stores the low 8 bits of src
// into the memory location pointed to by dst. Used as the write-back in
// the SGN decoder loop after the substitution has updated the byte register.
// golang-asm requires the byte-sized alias of src (AL, BL, …); regToByteReg
// handles the mapping so callers pass the same Reg they use everywhere else.
func (bb *Builder) MOVB(dst MemOp, src Reg) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVB
	p.From.Type = obj.TYPE_REG
	p.From.Reg = regToByteReg(src)
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: MOVB dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// ANDB emits AND r/m8, imm8 — 8-bit AND with sign-extended-not-applicable
// immediate. Used by the bundle scan stub's decrypt loop (`and dl, 15`)
// to mask the SBox index, and by the predicate path (`and r9b, 1`) to
// isolate a bitmask bit. Plan 9 wart: AANDB encodes correctly only when
// the destination is written via [regToByteReg]; without it, golang-asm
// rejects the full 64-bit GPR as illegal.
func (bb *Builder) ANDB(dst Reg, imm Imm) error {
	p := bb.b.NewProg()
	p.As = x86.AANDB
	p.From.Type = obj.TYPE_CONST
	p.From.Offset = int64(imm)
	p.To.Type = obj.TYPE_REG
	p.To.Reg = regToByteReg(dst)
	bb.b.AddInstruction(p)
	return nil
}

// MOVZBL emits MOVZX r32, r8 — zero-extend a byte register into a 32-bit
// register (upper 32 bits implicitly cleared by x86-64). Distinct from
// [MOVZX] which takes a memory source. Used by the SGN decoder loop to
// widen the low-4-bit substitution index (`movzx edx, dl`) before the
// SIB-indexed SBox lookup.
func (bb *Builder) MOVZBL(dst Reg, src Reg) error {
	p := bb.b.NewProg()
	p.As = x86.AMOVBLZX
	p.From.Type = obj.TYPE_REG
	p.From.Reg = regToByteReg(src)
	p.To.Type = obj.TYPE_REG
	p.To.Reg = regToObj(dst)
	bb.b.AddInstruction(p)
	return nil
}

// XORB emits XOR r8, byte ptr [mem] — 8-bit XOR with memory source.
// Used by the bundle decrypt loop's SBox indirection
// (`xor al, [r8+rdx]`); src must be a [MemOp] (callers wanting reg-reg
// XOR should use the 64-bit [XOR] with byte-aliased regs).
func (bb *Builder) XORB(dst Reg, src MemOp) error {
	p := bb.b.NewProg()
	p.As = x86.AXORB
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: XORB src: %w", err)
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = regToByteReg(dst)
	bb.b.AddInstruction(p)
	return nil
}

// binaryOp is the shared emitter for two-operand arithmetic (XOR/SUB/ADD).
// golang-asm's Plan-9 convention is From=src, To=dst — same as MOV.
func (bb *Builder) binaryOp(as obj.As, name string, dst, src Op) error {
	p := bb.b.NewProg()
	p.As = as
	if err := setOperand(&p.From, src); err != nil {
		return fmt.Errorf("amd64: %s src: %w", name, err)
	}
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: %s dst: %w", name, err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// DEC emits DEC dst (64-bit decrement).
func (bb *Builder) DEC(dst Op) error {
	p := bb.b.NewProg()
	p.As = x86.ADECQ
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: DEC dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// INC emits INC dst (64-bit increment).
func (bb *Builder) INC(dst Op) error {
	p := bb.b.NewProg()
	p.As = x86.AINCQ
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: INC dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// CMP emits CMP dst, src (64-bit compare; sets flags based on
// `dst - src`). Order matches Intel syntax: first operand is the
// LHS of the subtraction.
//
// Plan 9 wart: `binaryOp` puts the second arg into From (src) and
// the first into To (dst), but Plan 9's CMPQ flag-direction is
// `From - To` — the OPPOSITE of what the docstring promises. We
// swap the operands at call time so the public CMP/CMPL API
// matches Intel semantics (and the doc) regardless of golang-asm's
// internal convention. See [TestCMP_PlanFlagDirection] for the
// pinned semantic.
func (bb *Builder) CMP(dst, src Op) error {
	return bb.binaryOp(x86.ACMPQ, "CMP", src, dst)
}

// CMPL emits a 32-bit CMP. Same Intel-semantics swap as [CMP].
// Used by the bundle scan loop's `cmp r10d, [rsi+8]` and similar
// 32-bit comparisons where the 64-bit form would over-read.
func (bb *Builder) CMPL(dst, src Op) error {
	return bb.binaryOp(x86.ACMPL, "CMPL", src, dst)
}

// TEST emits TEST dst, src (64-bit AND-then-discard; sets flags).
// Same operand order as [CMP].
func (bb *Builder) TEST(dst, src Op) error {
	return bb.binaryOp(x86.ATESTQ, "TEST", dst, src)
}

// POP emits POP dst (64-bit pop from stack). Used by the CALL+POP+ADD
// PIC prologue in the UPX-style stub to read the return address pushed
// by CALL into a callee-saved register.
func (bb *Builder) POP(dst Op) error {
	p := bb.b.NewProg()
	p.As = x86.APOPQ
	if err := setOperand(&p.To, dst); err != nil {
		return fmt.Errorf("amd64: POP dst: %w", err)
	}
	bb.b.AddInstruction(p)
	return nil
}

// RawBytes emits raw machine bytes verbatim into the output stream.
// Used for instructions golang-asm cannot express (e.g. CALL rel32=0
// for the CALL+POP+ADD PIC prologue — a forward CALL whose target is
// the immediately following instruction).
func (bb *Builder) RawBytes(bs []byte) error {
	for _, b8 := range bs {
		p := bb.b.NewProg()
		p.As = x86.ABYTE
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(b8)
		bb.b.AddInstruction(p)
	}
	return nil
}

// JMP emits an unconditional jump. target must be a LabelRef
// (resolved before Encode), a MemOp (indirect jump through memory),
// or a Reg (indirect jump through register, e.g. JMP r15).
func (bb *Builder) JMP(target Op) error { return bb.branchOp(obj.AJMP, "JMP", target) }

// JNZ emits a jump-if-not-zero (JNE). target must be LabelRef or MemOp.
func (bb *Builder) JNZ(target Op) error { return bb.branchOp(x86.AJNE, "JNZ", target) }

// JE emits a jump-if-equal (JE/JZ). target must be LabelRef or MemOp.
func (bb *Builder) JE(target Op) error  { return bb.branchOp(x86.AJEQ, "JE", target) }

// JGE emits a signed-greater-or-equal conditional jump. Used by the
// bundle scan loop's index-vs-count check at the top of each iteration.
func (bb *Builder) JGE(target Op) error { return bb.branchOp(x86.AJGE, "JGE", target) }

// JL emits a signed-less-than conditional jump.
func (bb *Builder) JL(target Op) error { return bb.branchOp(x86.AJLT, "JL", target) }

// CALL emits a CALL instruction. target must be LabelRef or MemOp.
func (bb *Builder) CALL(target Op) error { return bb.branchOp(obj.ACALL, "CALL", target) }

// branchOp is the shared emitter for branch/call instructions.
// LabelRef targets are deferred — Encode patches them before Assemble().
// Reg targets produce an indirect jump/call through the register (FF /4
// for JMP r/m64; FF /2 for CALL r/m64), needed by the stub epilogue's
// JMP r15.
func (bb *Builder) branchOp(as obj.As, name string, target Op) error {
	p := bb.b.NewProg()
	p.As = as
	switch v := target.(type) {
	case LabelRef:
		// TYPE_BRANCH with a nil Val is valid; Encode patches Val to the
		// target prog before handing off to golang-asm's Assemble.
		p.To.Type = obj.TYPE_BRANCH
		bb.branches = append(bb.branches, branchPatch{prog: p, label: string(v)})
	case MemOp:
		if err := setOperand(&p.To, v); err != nil {
			return fmt.Errorf("amd64: %s target: %w", name, err)
		}
	case Reg:
		p.To.Type = obj.TYPE_REG
		p.To.Reg = regToObj(v)
	default:
		return fmt.Errorf("amd64: %s target must be LabelRef, MemOp, or Reg, got %T", name, target)
	}
	bb.b.AddInstruction(p)
	return nil
}

// RET emits a near return.
func (bb *Builder) RET() error {
	p := bb.b.NewProg()
	p.As = obj.ARET
	bb.b.AddInstruction(p)
	return nil
}

// NOP emits `width` 1-byte NOPs (0x90). Width must be 1..9.
// Each 0x90 is encoded as XCHGL EAX, EAX — the canonical Intel
// single-byte NOP idiom that golang-asm folds to the 0x90 opcode.
// Naïve chaining is sufficient for junk insertion; a future pass
// can fold runs into Intel SDM Vol-2 multi-byte NOP forms.
func (bb *Builder) NOP(width int) error {
	if width < 1 || width > 9 {
		return fmt.Errorf("amd64: NOP width %d out of range [1,9]", width)
	}
	for i := 0; i < width; i++ {
		p := bb.b.NewProg()
		p.As = x86.AXCHGL
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x86.REG_AX
		p.To.Type = obj.TYPE_REG
		p.To.Reg = x86.REG_AX
		bb.b.AddInstruction(p)
	}
	return nil
}

// Encode resolves label references, runs golang-asm's lowering pass,
// and returns machine bytes. golang-asm signals encoding errors via
// DiagFunc (which prints) and panics; the recover converts panics to
// returned errors.
func (bb *Builder) Encode() (out []byte, err error) {
	// Two-pass label resolution: patch branch targets before Assemble.
	for _, patch := range bb.branches {
		target, ok := bb.labels[patch.label]
		if !ok {
			return nil, fmt.Errorf("amd64: undefined label %q", patch.label)
		}
		patch.prog.To.SetTarget(target)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("amd64: golang-asm Assemble panic: %v", r)
		}
	}()
	out = bb.b.Assemble()
	return out, nil
}

// setOperand maps a typed Op to a golang-asm obj.Addr in place.
// Kept strict — unsupported shapes return an error to fail loudly
// rather than emit a bogus instruction.
func setOperand(addr *obj.Addr, op Op) error {
	switch v := op.(type) {
	case Reg:
		addr.Type = obj.TYPE_REG
		addr.Reg = regToObj(v)
	case Imm:
		addr.Type = obj.TYPE_CONST
		addr.Offset = int64(v)
	case MemOp:
		if v.RIPRelative {
			addr.Type = obj.TYPE_MEM
			addr.Name = obj.NAME_NONE
			addr.Reg = x86.REG_NONE
			addr.Offset = int64(v.Disp)
			return nil
		}
		addr.Type = obj.TYPE_MEM
		addr.Reg = regToObj(v.Base)
		if v.Scale != 0 {
			addr.Index = regToObj(v.Index)
			addr.Scale = int16(v.Scale)
		}
		addr.Offset = int64(v.Disp)
	case LabelRef:
		// LabelRef is only valid as a branch target (JMP/Jcc/CALL).
		return fmt.Errorf("amd64: LabelRef %q is only valid as a branch target", string(v))
	default:
		return fmt.Errorf("unsupported operand type %T", op)
	}
	return nil
}

// regToObj maps our Reg to golang-asm's x86.REG_* constants.
func regToObj(r Reg) int16 {
	switch r {
	case RAX:
		return x86.REG_AX
	case RBX:
		return x86.REG_BX
	case RCX:
		return x86.REG_CX
	case RDX:
		return x86.REG_DX
	case RSI:
		return x86.REG_SI
	case RDI:
		return x86.REG_DI
	case R8:
		return x86.REG_R8
	case R9:
		return x86.REG_R9
	case R10:
		return x86.REG_R10
	case R11:
		return x86.REG_R11
	case R12:
		return x86.REG_R12
	case R13:
		return x86.REG_R13
	case R14:
		return x86.REG_R14
	case R15:
		return x86.REG_R15
	case RSP:
		return x86.REG_SP
	case RBP:
		return x86.REG_BP
	}
	panic(fmt.Sprintf("amd64: unknown Reg %d", r))
}

// regToByteReg maps a 64-bit GPR to its 8-bit low-byte alias, which is
// required by MOVB's source operand. golang-asm's x86 assembler
// treats MOVB with a full 64-bit register as an error ("illegal register")
// because the Plan 9 byte-register encoding differs from the full GPR encoding.
func regToByteReg(r Reg) int16 {
	switch r {
	case RAX:
		return x86.REG_AL
	case RBX:
		return x86.REG_BL
	case RCX:
		return x86.REG_CL
	case RDX:
		return x86.REG_DL
	case RSI:
		return x86.REG_SIB
	case RDI:
		return x86.REG_DIB
	case R8:
		return x86.REG_R8B
	case R9:
		return x86.REG_R9B
	case R10:
		return x86.REG_R10B
	case R11:
		return x86.REG_R11B
	case R12:
		return x86.REG_R12B
	case R13:
		return x86.REG_R13B
	case R14:
		return x86.REG_R14B
	case R15:
		return x86.REG_R15B
	}
	panic(fmt.Sprintf("amd64: unknown Reg %d for byte alias", r))
}
