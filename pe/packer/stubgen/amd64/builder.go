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
// Phase 1e-A only needs MOV reg, imm and MOV reg, mem and
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

// JMP emits an unconditional jump. target must be a LabelRef
// (resolved before Encode) or a MemOp (indirect jump).
func (bb *Builder) JMP(target Op) error { return bb.branchOp(obj.AJMP, "JMP", target) }

// JNZ emits a jump-if-not-zero (JNE). target must be LabelRef or MemOp.
func (bb *Builder) JNZ(target Op) error { return bb.branchOp(x86.AJNE, "JNZ", target) }

// JE emits a jump-if-equal (JE/JZ). target must be LabelRef or MemOp.
func (bb *Builder) JE(target Op) error { return bb.branchOp(x86.AJEQ, "JE", target) }

// CALL emits a CALL instruction. target must be LabelRef or MemOp.
func (bb *Builder) CALL(target Op) error { return bb.branchOp(obj.ACALL, "CALL", target) }

// branchOp is the shared emitter for branch/call instructions.
// LabelRef targets are deferred — Encode patches them before Assemble().
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
	default:
		return fmt.Errorf("amd64: %s target must be LabelRef or MemOp, got %T", name, target)
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
