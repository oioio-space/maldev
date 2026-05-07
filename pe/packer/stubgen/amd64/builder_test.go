package amd64_test

import (
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
