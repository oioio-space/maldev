package stage1_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	x86asm "golang.org/x/arch/x86/x86asm"
)

func emitPEBPatch(t *testing.T, argsLen uint16) []byte {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitPEBCommandLinePatch(b, argsLen); err != nil {
		t.Fatalf("EmitPEBCommandLinePatch: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}

func TestEmitPEBCommandLinePatch_ByteBudget(t *testing.T) {
	got := emitPEBPatch(t, 28)
	if len(got) != stage1.EmitPEBCommandLinePatch_ByteBudget {
		t.Errorf("emitted %d B, want %d (drift)", len(got), stage1.EmitPEBCommandLinePatch_ByteBudget)
	}
}

// TestEmitPEBCommandLinePatch_AssemblesCleanly decodes every
// emitted instruction via x86asm.Decode. Catches encoding
// regressions a pure byte-count pin would miss.
func TestEmitPEBCommandLinePatch_AssemblesCleanly(t *testing.T) {
	emitted := emitPEBPatch(t, 28)

	off := 0
	count := 0
	for off < len(emitted) {
		inst, err := x86asm.Decode(emitted[off:], 64)
		if err != nil {
			t.Fatalf("instr %d at off 0x%x decode failed: %v\nbytes: %x",
				count, off, err, emitted[off:])
		}
		off += inst.Len
		count++
	}
	// Expect 8 instructions: GS-PEB load (1), +0x20 deref (2),
	// load existing Buffer into RDI (3), LEA src into RSI (4),
	// MOV ECX count (5), REP MOVSB (6), Length store (7),
	// MaximumLength store (8).
	if count != 8 {
		t.Errorf("decoded %d instructions, want 8", count)
	}
}

func TestEmitPEBCommandLinePatch_LengthFieldsMatchInput(t *testing.T) {
	const wantLen uint16 = 0x4242
	emitted := emitPEBPatch(t, wantLen)

	// Length imm16 sits 4 bytes after `66 C7 40 70` opcode.
	for i := 0; i+5 < len(emitted); i++ {
		if emitted[i] == 0x66 && emitted[i+1] == 0xC7 &&
			emitted[i+2] == 0x40 && emitted[i+3] == 0x70 {
			gotLen := binary.LittleEndian.Uint16(emitted[i+4 : i+6])
			if gotLen != wantLen {
				t.Errorf("Length imm16 = 0x%x, want 0x%x", gotLen, wantLen)
			}
			return
		}
	}
	t.Errorf("Length store opcode (66 C7 40 70) not found in emitted bytes")
}

func TestPatchPEBCommandLineDisp_RewritesSentinel(t *testing.T) {
	stubBytes := emitPEBPatch(t, 28)

	const sentinelExpected uint32 = 0xCAFEDADE
	needle := binary.LittleEndian.AppendUint32(nil, sentinelExpected)
	if !bytes.Contains(stubBytes, needle) {
		t.Fatalf("sentinel 0x%x not present in emitted bytes", sentinelExpected)
	}

	// Patch with stubRVA=0x3000, textRVA=0x1000, argsBufferOff=0x100.
	// Expected disp = (0x3000 + 0x100) - 0x1000 = 0x2100.
	n, err := stage1.PatchPEBCommandLineDisp(stubBytes, 0x3000, 0x1000, 0x100)
	if err != nil {
		t.Fatalf("PatchPEBCommandLineDisp: %v", err)
	}
	if n != 1 {
		t.Errorf("patched %d sentinels, want 1", n)
	}
	if bytes.Contains(stubBytes, needle) {
		t.Error("sentinel still present after patch")
	}
	wantBytes := binary.LittleEndian.AppendUint32(nil, 0x2100)
	if !bytes.Contains(stubBytes, wantBytes) {
		t.Errorf("patched value 0x2100 not found in stub bytes")
	}
}
