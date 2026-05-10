package stage1_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// TestEmitNtdllRtlExitUserProcess_BytesShape pins the encoding for
// exit code 42. Catches drift in any of:
//   - Hand-encoded asm bytes (a typo in any byte breaks the runtime).
//   - JCC displacements (recomputing them is the most error-prone
//     operation in this file; a wrong rel8 sends the loop into
//     never-never land at runtime, surfacing as ACCESS_VIOLATION
//     indistinguishable from any other stub bug).
//   - The exit-code immediate position (drift here means the
//     emitted code calls RtlExitUserProcess with garbage).
//
// Runtime exercise NOT YET GREEN — see the doc comment in
// exitprocess.go for the open-suspects list. Adding a runtime VM
// test back is the natural next step in a supervised debug session.
func TestEmitNtdllRtlExitUserProcess_BytesShape(t *testing.T) {
	b := mustBuilder(t)
	if err := stage1.EmitNtdllRtlExitUserProcess(b, 42); err != nil {
		t.Fatalf("EmitNtdllRtlExitUserProcess: %v", err)
	}
	got := mustEncode(t, b)

	// Pin the full 143-byte encoding for exit code 42 (0x2a).
	want := []byte{
		// 0x00: mov rax, gs:[0x60]
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		// 0x09: mov rax, [rax+0x18]
		0x48, 0x8b, 0x40, 0x18,
		// 0x0d: mov rax, [rax+0x10]   ; InLoadOrderModuleList.Flink
		0x48, 0x8b, 0x40, 0x10,
		// 0x11: mov rax, [rax]
		0x48, 0x8b, 0x00,
		// 0x14: mov rdx, [rax+0x30]   ; DllBase (entry+0x30)
		0x48, 0x8b, 0x50, 0x30,
		// 0x18: mov eax, [rdx+0x3c]
		0x8b, 0x42, 0x3c,
		// 0x1b: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x1e: mov eax, [rax+0x88]
		0x8b, 0x80, 0x88, 0x00, 0x00, 0x00,
		// 0x24: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x27: mov r8, rax
		0x49, 0x89, 0xc0,
		// 0x2a: mov r9d, [r8+0x18]
		0x45, 0x8b, 0x48, 0x18,
		// 0x2e: mov r10d, [r8+0x20]
		0x45, 0x8b, 0x50, 0x20,
		// 0x32: add r10, rdx (REX.B=1 destination, was 4c which was add rdx, r10)
		0x49, 0x01, 0xd2,
		// 0x35: xor r11, r11
		0x4d, 0x31, 0xdb,

		// 0x38: .loop — cmp r11d, r9d
		0x45, 0x39, 0xcb,
		// 0x3b: jge .notfound +0x2b
		0x7d, 0x2b,
		// 0x3d: mov eax, [r10+r11*4]
		0x43, 0x8b, 0x04, 0x9a,
		// 0x41: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x44: mov rbx, "RtlExitU"
		0x48, 0xbb, 0x52, 0x74, 0x6c, 0x45, 0x78, 0x69, 0x74, 0x55,
		// 0x4e: cmp [rax], rbx
		0x48, 0x39, 0x18,
		// 0x51: jne .next +0x10
		0x75, 0x10,
		// 0x53: mov rbx, "serProce"
		0x48, 0xbb, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x63, 0x65,
		// 0x5d: cmp [rax+8], rbx
		0x48, 0x39, 0x58, 0x08,
		// 0x61: je .found +0x08
		0x74, 0x08,

		// 0x63: .next — inc r11
		0x49, 0xff, 0xc3,
		// 0x66: jmp .loop -0x30
		0xeb, 0xd0,

		// 0x68: .notfound — int3
		0xcc,
		// 0x69: ud2
		0x0f, 0x0b,

		// 0x6b: .found — mov eax, [r8+0x24]
		0x41, 0x8b, 0x40, 0x24,
		// 0x6f: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x72: movzx eax, word [rax+r11*2]
		0x42, 0x0f, 0xb7, 0x04, 0x58,
		// 0x77: mov esi, [r8+0x1c]
		0x41, 0x8b, 0x70, 0x1c,
		// 0x7b: add rsi, rdx
		0x48, 0x01, 0xd6,
		// 0x7e: mov eax, [rsi+rax*4]
		0x8b, 0x04, 0x86,
		// 0x81: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x84: sub rsp, 0x28
		0x48, 0x83, 0xec, 0x28,
		// 0x88: mov ecx, 42 (LE)
		0xb9, 0x2a, 0x00, 0x00, 0x00,
		// 0x8d: call rax
		0xff, 0xd0,
	}

	if !bytes.Equal(got, want) {
		t.Errorf("EmitNtdllRtlExitUserProcess(42) bytes mismatch:\n  len got=%d want=%d\n  got:  %x\n  want: %x",
			len(got), len(want), got, want)
	}
	if len(got) != 143 {
		t.Errorf("len(emitted) = %d, want 143", len(got))
	}
}

// TestEmitNtdllRtlExitUserProcess_ImmediatePatching asserts that
// the exit-code immediate lands at [stage1.ExitProcessImmediateOffset]
// and varies with the exitCode parameter while the rest of the
// stream is byte-identical.
func TestEmitNtdllRtlExitUserProcess_ImmediatePatching(t *testing.T) {
	cases := []uint32{0, 1, 42, 0x80000003, 0xc0000005, 0xffffffff}

	var prev []byte
	for i, code := range cases {
		b := mustBuilder(t)
		if err := stage1.EmitNtdllRtlExitUserProcess(b, code); err != nil {
			t.Fatalf("EmitNtdllRtlExitUserProcess(%#x): %v", code, err)
		}
		got := mustEncode(t, b)

		// Verify immediate is at the documented offset.
		off := stage1.ExitProcessImmediateOffset
		want := []byte{byte(code), byte(code >> 8), byte(code >> 16), byte(code >> 24)}
		if !bytes.Equal(got[off:off+4], want) {
			t.Errorf("exit code %#x: immediate at offset %#x = %x, want %x",
				code, off, got[off:off+4], want)
		}

		// Verify the rest of the stream is unchanged across exit codes.
		if i > 0 {
			diffSafe := append([]byte(nil), got...)
			copy(diffSafe[off:off+4], prev[off:off+4])
			if !bytes.Equal(diffSafe, prev) {
				t.Errorf("exit code %#x changed bytes outside the immediate slot", code)
			}
		}
		prev = got
	}
}

func mustBuilder(t *testing.T) *amd64.Builder {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	return b
}

func mustEncode(t *testing.T, b *amd64.Builder) []byte {
	t.Helper()
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}
