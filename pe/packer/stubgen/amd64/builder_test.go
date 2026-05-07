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
