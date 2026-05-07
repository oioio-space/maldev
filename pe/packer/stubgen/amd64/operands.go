package amd64

// Reg names a general-purpose 64-bit x86 register. RSP and RBP
// are reserved for stack discipline and not exposed; the SGN
// engine never needs them.
type Reg uint8

const (
	RAX Reg = iota
	RBX
	RCX
	RDX
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// AllGPRs returns every Reg the encoder can use as a generic GPR.
// Used by poly.RegPool to seed its shuffle.
func AllGPRs() []Reg {
	return []Reg{RAX, RBX, RCX, RDX, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15}
}

// Op marks any value that can appear as an instruction operand.
// Reg, Imm, MemOp, and LabelRef implement it.
type Op interface{ isOp() }

func (Reg) isOp()      {}
func (Imm) isOp()      {}
func (MemOp) isOp()    {}
func (LabelRef) isOp() {}

// Imm is a sign-extended immediate. Width handling is per-instruction.
type Imm int64

// MemOp is an effective-address operand. RIPRelative + Label are
// the common shape for "RIP-relative reference to a labeled
// location"; Base + Index + Scale + Disp covers the [base+idx*s+disp]
// general form.
type MemOp struct {
	Base, Index Reg
	Scale       uint8 // 1, 2, 4, 8 (0 means no SIB)
	Disp        int32
	RIPRelative bool
	Label       string // only valid when RIPRelative is true
}

// LabelRef points at a Label instruction in the same Builder.
// Used as a JMP / Jcc target.
type LabelRef string
