package stage1_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	x86asm "golang.org/x/arch/x86/x86asm"
)

func emitPEBPatchRCX(t *testing.T) []byte {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitPEBCommandLinePatchRCX(b); err != nil {
		t.Fatalf("EmitPEBCommandLinePatchRCX: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}

func TestEmitPEBCommandLinePatchRCX_ByteBudget(t *testing.T) {
	got := emitPEBPatchRCX(t)
	if len(got) != stage1.EmitPEBCommandLinePatchRCX_ByteBudget {
		t.Errorf("emitted %d B, want %d (drift)", len(got), stage1.EmitPEBCommandLinePatchRCX_ByteBudget)
	}
}

// TestEmitPEBCommandLinePatchRCX_AssemblesCleanly decodes every
// emitted instruction. Catches encoding regressions a pure
// byte-count pin would miss.
func TestEmitPEBCommandLinePatchRCX_AssemblesCleanly(t *testing.T) {
	emitted := emitPEBPatchRCX(t)

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
	// Expect 16 instructions:
	//   wcslen loop (5): xor r10d, cmp word [rcx+r10],0, je, add r10,2, jmp
	//   PEB + guard (6): mov rax gs:[0x60], mov rax [rax+0x20], movzx r8d [rax+0x72],
	//                    lea r9 [r10+2], cmp r8w r9w, jb .skip
	//   patch block (6): mov rdi [rax+0x78], mov rsi rcx, mov rcx r10,
	//                    add rcx 2, rep movsb, mov word [rax+0x70] r10w
	const want = 17 // 5 + 6 + 6
	if count != want {
		t.Errorf("decoded %d instructions, want %d", count, want)
	}
}

// TestEmitPEBCommandLinePatchRCX_NoSentinels asserts the runtime
// variant never embeds the pebCommandLineDispSentinel
// (0xCAFEDADE) — it reads src from RCX at runtime, not from a
// patched stub-trailing buffer.
func TestEmitPEBCommandLinePatchRCX_NoSentinels(t *testing.T) {
	emitted := emitPEBPatchRCX(t)

	// Walk the bytes for the 4-byte sentinel value.
	const sentinel uint32 = 0xCAFEDADE
	for i := 0; i+3 < len(emitted); i++ {
		val := uint32(emitted[i]) |
			uint32(emitted[i+1])<<8 |
			uint32(emitted[i+2])<<16 |
			uint32(emitted[i+3])<<24
		if val == sentinel {
			t.Errorf("runtime variant leaked pebCommandLineDispSentinel at offset %d — "+
				"should read src from RCX, not from R15+disp", i)
		}
	}
}
