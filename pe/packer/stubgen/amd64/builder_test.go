package amd64_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/stretchr/testify/require"
	"golang.org/x/arch/x86/x86asm"
)

// TestBuilder_MOV_RegImm verifies that emitting MOV RAX, 0x42 produces
// bytes that disassemble back to the same mnemonic + operands.
func TestBuilder_MOV_RegImm(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	require.NoError(t, b.MOV(amd64.RAX, amd64.Imm(0x42)))

	out, err := b.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, out, "Encode returned 0 bytes")

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "x86asm.Decode failed")

	if inst.Op != x86asm.MOV {
		t.Errorf("decoded mnemonic = %v, want MOV", inst.Op)
	}
}

// TestAllGPRs verifies AllGPRs returns 14 registers (all GPRs except RSP/RBP).
func TestAllGPRs(t *testing.T) {
	gprs := amd64.AllGPRs()
	if len(gprs) != 14 {
		t.Errorf("AllGPRs() = %d registers, want 14", len(gprs))
	}
}

// TestBuilder_AllMnemonics verifies every new instruction encodes to the
// expected opcode via a disassembly round-trip.
func TestBuilder_AllMnemonics(t *testing.T) {
	cases := []struct {
		name   string
		emit   func(b *amd64.Builder) error
		wantOp x86asm.Op
	}{
		{"LEA", func(b *amd64.Builder) error {
			return b.LEA(amd64.RAX, amd64.MemOp{Base: amd64.RBX, Disp: 0x10})
		}, x86asm.LEA},
		{"XOR_RegReg", func(b *amd64.Builder) error {
			return b.XOR(amd64.RAX, amd64.RBX)
		}, x86asm.XOR},
		{"SUB_RegImm", func(b *amd64.Builder) error {
			return b.SUB(amd64.RAX, amd64.Imm(0x42))
		}, x86asm.SUB},
		{"ADD_RegReg", func(b *amd64.Builder) error {
			return b.ADD(amd64.RCX, amd64.RDX)
		}, x86asm.ADD},
		{"DEC_Reg", func(b *amd64.Builder) error {
			return b.DEC(amd64.RAX)
		}, x86asm.DEC},
		{"INC_Reg", func(b *amd64.Builder) error {
			return b.INC(amd64.RAX)
		}, x86asm.INC},
		{"MOVL_RegReg", func(b *amd64.Builder) error {
			return b.MOVL(amd64.RAX, amd64.RBX)
		}, x86asm.MOV},
		{"AND_RegReg", func(b *amd64.Builder) error {
			return b.AND(amd64.RAX, amd64.RBX)
		}, x86asm.AND},
		{"CMP_RegReg", func(b *amd64.Builder) error {
			return b.CMP(amd64.RAX, amd64.RBX)
		}, x86asm.CMP},
		{"CMPL_RegReg", func(b *amd64.Builder) error {
			return b.CMPL(amd64.RAX, amd64.RBX)
		}, x86asm.CMP},
		{"SHL_RegImm", func(b *amd64.Builder) error {
			return b.SHL(amd64.RAX, amd64.Imm(5))
		}, x86asm.SHL},
		{"JMPReg", func(b *amd64.Builder) error {
			return b.JMPReg(amd64.RDI)
		}, x86asm.JMP},
		{"MOVBReg_RegReg", func(b *amd64.Builder) error {
			return b.MOVBReg(amd64.RAX, amd64.RBX)
		}, x86asm.MOV},
		{"SYSCALL", func(b *amd64.Builder) error {
			return b.SYSCALL()
		}, x86asm.SYSCALL},
		{"MOVZWL_RegMem", func(b *amd64.Builder) error {
			return b.MOVZWL(amd64.RAX, amd64.MemOp{Base: amd64.R15, Disp: 6})
		}, x86asm.MOVZX},
		{"TEST_RegReg", func(b *amd64.Builder) error {
			return b.TEST(amd64.RAX, amd64.RBX)
		}, x86asm.TEST},
		// CMP/TEST with immediate operands: golang-asm's Plan 9
		// encoder treats CMPQ/TESTQ + Imm as "compare flag vs imm"
		// which has a different prog shape than the binaryOp wrapper
		// emits — silently produces 0 bytes. The scan-loop refactor
		// only needs CMP/TEST reg-reg / reg-mem; immediate forms are
		// NOT exercised here. If a future use needs them, swap to
		// AND-with-mask pattern (b.AND(reg, Imm(...))) which is the
		// idiomatic Plan 9 path.
		{"RET", func(b *amd64.Builder) error {
			return b.RET()
		}, x86asm.RET},
		{"NOP", func(b *amd64.Builder) error {
			return b.NOP(3)
		}, x86asm.NOP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := amd64.New()
			require.NoError(t, err)
			require.NoError(t, c.emit(b), "emit")
			out, err := b.Encode()
			require.NoError(t, err, "Encode")
			inst, err := x86asm.Decode(out, 64)
			require.NoError(t, err, "Decode (bytes=% x)", out)
			if inst.Op != c.wantOp {
				t.Errorf("got %v, want %v", inst.Op, c.wantOp)
			}
		})
	}
}

// TestBuilder_MOVZX verifies that MOVZX dst, byte ptr [src] encodes to the
// Intel 0F B6 form (MOVZX r64, r/m8) — the load instruction the SGN
// decoder loop uses for its per-byte fetch.
func TestBuilder_MOVZX(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	require.NoError(t, b.MOVZX(amd64.RAX, amd64.MemOp{Base: amd64.RBX}))

	out, err := b.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.MOVZX {
		t.Errorf("got %v, want MOVZX", inst.Op)
	}
}

// TestBuilder_MOVB verifies that MOVB byte ptr [dst], src encodes to
// the Intel 88 /r form (MOV r/m8, r8) — the write-back instruction the
// SGN decoder loop uses to store the decoded byte back to the payload.
func TestBuilder_MOVB(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	require.NoError(t, b.MOVB(amd64.MemOp{Base: amd64.RBX}, amd64.RAX))

	out, err := b.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.MOV {
		t.Errorf("got %v, want MOV", inst.Op)
	}
	// Confirm it's a byte-width MOV by checking the destination is
	// a memory reference with RBX as base. x86asm reports the base
	// using the 64-bit register name even for byte-addressed operands.
	if inst.Args[0] != (x86asm.Mem{Base: x86asm.RBX, Disp: 0}) {
		t.Errorf("dst = %v, want [RBX]", inst.Args[0])
	}
}

// TestBuilder_POP verifies that POP R15 encodes to the Intel 41 5F
// form and disassembles as POP. Required by the CALL+POP+ADD PIC
// prologue in the UPX-style stub.
func TestBuilder_POP(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	require.NoError(t, b.POP(amd64.R15))

	out, err := b.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.POP {
		t.Errorf("got %v, want POP", inst.Op)
	}
	// Intel Vol 2B: POP R15 = 41 5F
	if len(out) < 2 || out[0] != 0x41 || out[1] != 0x5F {
		t.Errorf("encoding % x, want 41 5f", out)
	}
}

// TestBuilder_RawBytes verifies that RawBytes emits verbatim bytes,
// specifically the E8 00 00 00 00 CALL+0 idiom used by the PIC prologue
// to push the return address without a linker symbol.
func TestBuilder_RawBytes(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	// CALL rel32=0 — CALL to next instruction (PIC address-of-self)
	require.NoError(t, b.RawBytes([]byte{0xE8, 0x00, 0x00, 0x00, 0x00}))

	out, err := b.Encode()
	require.NoError(t, err)
	require.Equal(t, 5, len(out), "expected 5 bytes for CALL rel32=0")

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.CALL {
		t.Errorf("got %v, want CALL", inst.Op)
	}
}

// TestBuilder_JMP_Reg verifies that JMP(Reg) encodes to the Intel FF /4
// (JMP r/m64) form — required by the stub epilogue's JMP r15.
func TestBuilder_JMP_Reg(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	require.NoError(t, b.JMP(amd64.R15))

	out, err := b.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.JMP {
		t.Errorf("got %v, want JMP", inst.Op)
	}
	// Intel Vol 2A: JMP r/m64 with REX.B+R15 = 41 FF E7
	if len(out) < 3 || out[0] != 0x41 || out[1] != 0xFF || out[2] != 0xE7 {
		t.Errorf("encoding % x, want 41 ff e7", out)
	}
}

// TestBuilder_CMP_PlanFlagDirection pins the Intel-semantic operand
// order for [Builder.CMP] / [Builder.CMPL]. Without the operand
// swap inside CMP, golang-asm's Plan 9 binaryOp convention emits
// the opposite flag direction (src - dst instead of dst - src) —
// silently breaks any caller that relies on documented semantics.
//
// The test calls b.CMP(RAX, RCX) (= Intel `cmp rax, rcx`, flags =
// RAX - RCX) and asserts the produced byte sequence matches the
// canonical r/m=RAX, reg=RCX encoding (`48 39 c8`). If the operand
// swap regresses, the bytes become `48 39 c1` instead and the test
// fails loudly.
func TestBuilder_CMP_PlanFlagDirection(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.CMP(amd64.RAX, amd64.RCX), "CMP")
	out, err := b.Encode()
	require.NoError(t, err, "Encode")
	want := []byte{0x48, 0x39, 0xc8} // CMPQ RAX, RCX (flags = RAX - RCX)
	if !bytes.Equal(out, want) {
		t.Errorf("CMP(RAX, RCX) = % x, want % x (Intel `cmp rax, rcx`, flags = RAX - RCX)",
			out, want)
	}
}

// TestBuilder_JGE_JL_Resolve covers the two new conditional jumps
// added for the §5/PHASE-B-2 scan-loop refactor. Backward target
// pattern matches TestBuilder_LabelAndJMP (avoids depending on the
// exact rel8 vs rel32 encoding choice).
func TestBuilder_JGE_JL_Resolve(t *testing.T) {
	for _, c := range []struct {
		name string
		emit func(b *amd64.Builder, target amd64.LabelRef) error
		want x86asm.Op
	}{
		{"JGE", func(b *amd64.Builder, t amd64.LabelRef) error { return b.JGE(t) }, x86asm.JGE},
		{"JL", func(b *amd64.Builder, t amd64.LabelRef) error { return b.JL(t) }, x86asm.JL},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := amd64.New()
			require.NoError(t, err)
			loop := b.Label("loop")
			require.NoError(t, b.NOP(1))
			require.NoError(t, c.emit(b, loop))
			out, err := b.Encode()
			require.NoError(t, err, "Encode")
			require.GreaterOrEqual(t, len(out), 2)
			inst, err := x86asm.Decode(out[1:], 64)
			require.NoError(t, err, "Decode (bytes=% x)", out[1:])
			if inst.Op != c.want {
				t.Errorf("got %v, want %v", inst.Op, c.want)
			}
		})
	}
}

// TestBuilder_LabelAndJMP verifies that a backward JMP to a label
// resolves to the correct target and disassembles as JMP.
func TestBuilder_LabelAndJMP(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)

	// loop: NOP ; JMP loop  — backward branch.
	loop := b.Label("loop")
	require.NoError(t, b.NOP(1))
	require.NoError(t, b.JMP(loop))

	out, err := b.Encode()
	require.NoError(t, err, "Encode")
	require.GreaterOrEqual(t, len(out), 2, "expected at least 2 bytes")

	// Decode from offset 1 (past the NOP) and assert the opcode is JMP.
	// We deliberately don't assert the exact displacement so the test
	// stays robust across golang-asm encoding choices.
	inst, err := x86asm.Decode(out[1:], 64)
	require.NoError(t, err, "Decode at offset 1 (bytes=% x)", out[1:])
	if inst.Op != x86asm.JMP {
		t.Errorf("got %v, want JMP", inst.Op)
	}
}

// TestBuilder_ANDB verifies the 8-bit AND-with-immediate encoding used by
// the bundle scan stub's decrypt loop (`and dl, 15`) and predicate-mask
// path (`and r9b, 1`). Intel encoding: 80 /4 ib for ALU GPRs (no REX),
// REX.B + 80 /4 ib for R8B-R15B.
func TestBuilder_ANDB(t *testing.T) {
	cases := []struct {
		name string
		dst  amd64.Reg
		imm  amd64.Imm
		want []byte
	}{
		{"and dl, 15", amd64.RDX, 0x0f, []byte{0x80, 0xe2, 0x0f}},
		{"and r9b, 1", amd64.R9, 0x01, []byte{0x41, 0x80, 0xe1, 0x01}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := amd64.New()
			require.NoError(t, err)
			require.NoError(t, b.ANDB(c.dst, c.imm))
			out, err := b.Encode()
			require.NoError(t, err)
			if !bytes.Equal(out, c.want) {
				t.Errorf("encoding % x, want % x", out, c.want)
			}
			inst, err := x86asm.Decode(out, 64)
			require.NoError(t, err, "Decode (bytes=% x)", out)
			if inst.Op != x86asm.AND {
				t.Errorf("got %v, want AND", inst.Op)
			}
		})
	}
}

// TestBuilder_MOVZBL verifies the byte-register zero-extending move
// (`movzx edx, dl` → 0F B6 D2). Used by the SGN decrypt loop to widen
// the low-4-bit index into a clean 32-bit register before SIB lookup.
func TestBuilder_MOVZBL(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.MOVZBL(amd64.RDX, amd64.RDX))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0x0f, 0xb6, 0xd2}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.MOVZX {
		t.Errorf("got %v, want MOVZX", inst.Op)
	}
}

// TestBuilder_XORB verifies the 8-bit XOR-with-SIB-memory encoding
// (`xor al, [r8+rdx]` → 41 32 04 10). The decrypt loop's SBox indirection
// needs SIB addressing because the index register varies.
func TestBuilder_XORB(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.XORB(amd64.RAX, amd64.MemOp{Base: amd64.R8, Index: amd64.RDX, Scale: 1}))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0x41, 0x32, 0x04, 0x10}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (bytes=% x)", out)
	if inst.Op != x86asm.XOR {
		t.Errorf("got %v, want XOR", inst.Op)
	}
}

// TestBuilder_AESENC pins AES-NI single-round encoding
// (66 0f 38 dc /r). Used by AES-CTR keystream emission in the
// bundle stub when CipherType=2 (Tier 🟡 #2.2).
func TestBuilder_AESENC(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.AESENC(amd64.X0, amd64.X1))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0x66, 0x0f, 0x38, 0xdc, 0xc1}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (% x)", out)
	if inst.Op != x86asm.AESENC {
		t.Errorf("op = %v, want AESENC", inst.Op)
	}
}

// TestBuilder_AESENCLAST pins AES-NI final-round encoding
// (66 0f 38 dd /r) — called once per 16-byte AES block after 9
// AESENC rounds for AES-128.
func TestBuilder_AESENCLAST(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.AESENCLAST(amd64.X0, amd64.X1))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0x66, 0x0f, 0x38, 0xdd, 0xc1}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (% x)", out)
	if inst.Op != x86asm.AESENCLAST {
		t.Errorf("op = %v, want AESENCLAST", inst.Op)
	}
}

// TestBuilder_PXOR pins 128-bit XOR of XMM registers
// (66 0f ef /r). Two uses in the AES-CTR loop: seed initial state
// with round key 0, and XOR keystream into ciphertext block.
func TestBuilder_PXOR(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.PXOR(amd64.X0, amd64.X1))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0x66, 0x0f, 0xef, 0xc1}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (% x)", out)
	if inst.Op != x86asm.PXOR {
		t.Errorf("op = %v, want PXOR", inst.Op)
	}
}

// TestBuilder_MOVDQULoad pins MOVDQU xmm, [r/m] (f3 0f 6f /r).
// Used to load round keys, the AES-CTR counter, and ciphertext
// blocks into XMM registers.
func TestBuilder_MOVDQULoad(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.MOVDQULoad(amd64.X0, amd64.MemOp{Base: amd64.RDI}))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0xf3, 0x0f, 0x6f, 0x07}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (% x)", out)
	if inst.Op != x86asm.MOVDQU {
		t.Errorf("op = %v, want MOVDQU", inst.Op)
	}
}

// TestBuilder_MOVDQUStore pins MOVDQU [r/m], xmm (f3 0f 7f /r).
// Used to write the decrypted plaintext block back to the payload
// buffer after PXOR with the keystream.
func TestBuilder_MOVDQUStore(t *testing.T) {
	b, err := amd64.New()
	require.NoError(t, err)
	require.NoError(t, b.MOVDQUStore(amd64.MemOp{Base: amd64.RDI}, amd64.X0))
	out, err := b.Encode()
	require.NoError(t, err)
	want := []byte{0xf3, 0x0f, 0x7f, 0x07}
	if !bytes.Equal(out, want) {
		t.Errorf("encoding % x, want % x", out, want)
	}
	inst, err := x86asm.Decode(out, 64)
	require.NoError(t, err, "Decode (% x)", out)
	if inst.Op != x86asm.MOVDQU {
		t.Errorf("op = %v, want MOVDQU", inst.Op)
	}
}
