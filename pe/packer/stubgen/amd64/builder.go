package amd64

import (
	"fmt"

	asm "github.com/twitchyliquid64/golang-asm"
	"github.com/twitchyliquid64/golang-asm/obj"
	"github.com/twitchyliquid64/golang-asm/obj/x86"
)

// Builder collects instructions and resolves labels. Encode walks
// the prog list, applies golang-asm's lowering pass, and produces
// machine bytes.
type Builder struct {
	b *asm.Builder
}

// New returns a fresh amd64 Builder.
func New() (*Builder, error) {
	b, err := asm.NewBuilder("amd64", 64)
	if err != nil {
		return nil, fmt.Errorf("amd64: init assembler: %w", err)
	}
	return &Builder{b: b}, nil
}

// MOV emits a MOV instruction. dst is the destination operand,
// src is the source.
//
// Phase 1e-A only needs MOV reg, imm and MOV reg, mem and
// MOV mem, reg — the SGN decoder loop reads/writes one byte at a
// time and loads constants. Other forms can be added when callers
// need them.
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

// Encode runs golang-asm's lowering pass and returns machine bytes.
// Errors propagate from the assembler via panic recovery (golang-asm
// signals errors through its DiagFunc + panics rather than return values).
func (bb *Builder) Encode() (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("amd64: golang-asm Assemble panic: %v", r)
		}
	}()
	out = bb.b.Assemble()
	return out, nil
}

// setOperand maps a typed Op to a golang-asm obj.Addr in place.
// Unsupported shapes return an error (kept tight to fail loudly
// rather than emit a bogus instruction).
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
			// Label resolution wired in Task 2 when JMP/Jcc land.
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
		// LabelRef is only valid as a branch target (JMP/Jcc), not
		// as a MOV/arithmetic operand. Task 2 wires the branch emitters.
		return fmt.Errorf("amd64: LabelRef %q requires a branch instruction (JMP/Jcc), not implemented yet", string(v))
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
