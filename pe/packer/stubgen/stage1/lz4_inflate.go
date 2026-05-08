package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// lz4DecodeBytes holds the hand-assembled LZ4 block-format inflate decoder.
//
// Calling convention (Go register ABI, Go 1.17+):
//
//	RAX = src      compressed data pointer
//	RBX = dst      output buffer pointer
//	RCX = src_size number of compressed bytes
//
// This maps to the Go func signature:
//
//	func(src, dst unsafe.Pointer, srcSize uint64)
//
// The decoder runs to completion; no return value. The caller must guarantee
// that dst is large enough for the uncompressed output.
//
// Register map during execution:
//
//	R10 = src_end  = RAX + RCX, loop bound
//	R11 = src cursor
//	R12 = dst cursor
//	RAX = token byte (reused as scratch in match loop)
//	RBX = literal_length / match_length (extended)
//	RCX = rep-movsb counter (literal copy) / match_offset (match copy)
//	RDX = scratch for match-length extension
//	RSI = temporary src for rep movsb / match src pointer
//	RDI = temporary dst for rep movsb
//
// Algorithm — LZ4 block format (https://lz4.org/lz4_Block_format.html):
//
// Each sequence = token + optional lit-len extension + literals +
// match-offset (little-endian u16) + optional match-len extension.
// The last sequence has no match (src == src_end after literals).
//
// Byte count: 136 bytes (fits the ≤200 byte budget).
var lz4DecodeBytes = [...]byte{
	// emit_entry:
	//   mov   r10, rax      ; r10 = src
	//   add   r10, rcx      ; r10 = src_end
	//   mov   r11, rax      ; r11 = src cursor
	//   mov   r12, rbx      ; r12 = dst cursor
	0x49, 0x89, 0xc2, // mov r10, rax
	0x49, 0x01, 0xca, // add r10, rcx
	0x49, 0x89, 0xc3, // mov r11, rax
	0x49, 0x89, 0xdc, // mov r12, rbx

	// decode_loop:
	//   movzx eax, byte [r11]  ; al = token
	//   inc   r11
	0x41, 0x0f, 0xb6, 0x03, // movzbl (%r11), %eax
	0x49, 0xff, 0xc3,        // inc r11

	// literal_length = token >> 4
	//   mov   ebx, eax
	//   shr   ebx, 4
	//   cmp   ebx, 15
	//   jne   lit_done
	0x89, 0xc3,       // mov ebx, eax
	0xc1, 0xeb, 0x04, // shr ebx, 4
	0x83, 0xfb, 0x0f, // cmp ebx, 15
	0x75, 0x11,       // jne +17 → lit_done

	// lit_extend:   ; if high nibble == 15, read extra bytes until < 0xff
	//   movzx ecx, byte [r11]
	//   inc   r11
	//   add   ebx, ecx
	//   cmp   ecx, 255
	//   je    lit_extend
	0x41, 0x0f, 0xb6, 0x0b, // movzbl (%r11), %ecx
	0x49, 0xff, 0xc3,        // inc r11
	0x01, 0xcb,              // add ebx, ecx
	0x81, 0xf9, 0xff, 0x00, 0x00, 0x00, // cmp ecx, 255
	0x74, 0xef,              // je -17 → lit_extend

	// lit_done:   ; copy ebx literals using rep movsb (src/dst don't overlap)
	//   mov rsi, r11   ; rsi = src cursor
	//   mov rdi, r12   ; rdi = dst cursor
	//   mov rcx, rbx   ; rcx = literal count
	//   rep movsb
	//   mov r11, rsi   ; update src cursor
	//   mov r12, rdi   ; update dst cursor
	0x4c, 0x89, 0xde, // mov rsi, r11
	0x4c, 0x89, 0xe7, // mov rdi, r12
	0x48, 0x89, 0xd9, // mov rcx, rbx
	0xf3, 0xa4,       // rep movsb
	0x49, 0x89, 0xf3, // mov r11, rsi
	0x49, 0x89, 0xfc, // mov r12, rdi

	// termination check: last sequence has no match (LZ4 block spec §Last sequence)
	//   cmp r11, r10
	//   jae done
	0x4d, 0x39, 0xd3, // cmp r11, r10
	0x73, 0x43,       // jae +67 → done

	// match offset: read u16 little-endian; range [1, 65535]
	//   movzx ecx, word [r11]
	//   add   r11, 2
	0x41, 0x0f, 0xb7, 0x0b, // movzwl (%r11), %ecx
	0x49, 0x83, 0xc3, 0x02, // add r11, 2

	// match_length = (token & 0x0f) + 4; extend if low nibble == 15
	//   mov   ebx, eax
	//   and   ebx, 0x0f
	//   cmp   ebx, 15
	//   jne   mat_done
	0x89, 0xc3,       // mov ebx, eax
	0x83, 0xe3, 0x0f, // and ebx, 0x0f
	0x83, 0xfb, 0x0f, // cmp ebx, 15
	0x75, 0x11,       // jne +17 → mat_done

	// mat_extend:
	//   movzx edx, byte [r11]
	//   inc   r11
	//   add   ebx, edx
	//   cmp   edx, 255
	//   je    mat_extend
	0x41, 0x0f, 0xb6, 0x13, // movzbl (%r11), %edx
	0x49, 0xff, 0xc3,        // inc r11
	0x01, 0xd3,              // add ebx, edx
	0x81, 0xfa, 0xff, 0x00, 0x00, 0x00, // cmp edx, 255
	0x74, 0xef,              // je -17 → mat_extend

	// mat_done:   ; actual match_length = low-nibble + 4
	//   add ebx, 4
	0x83, 0xc3, 0x04, // add ebx, 4

	// match copy: byte-by-byte — NOT rep movsb — so offset=1 RLE works.
	// When match_offset == 1 each output byte depends on the byte just written,
	// so the copy pointer must advance through already-written data.
	//   mov rsi, r12    ; rsi = dst cursor
	//   sub rsi, rcx   ; rsi = dst - match_offset = match source
	0x4c, 0x89, 0xe6, // mov rsi, r12
	0x48, 0x29, 0xce, // sub rsi, rcx

	// mat_copy:
	//   test ebx, ebx
	//   jz   decode_loop_jmp
	//   movzx eax, byte [rsi]
	//   mov   byte [r12], al
	//   inc   rsi
	//   inc   r12
	//   dec   ebx
	//   jmp   mat_copy
	0x85, 0xdb,              // test ebx, ebx
	0x74, 0x11,              // je +17 → decode_loop_jmp
	0x0f, 0xb6, 0x06,        // movzbl (%rsi), %eax
	0x41, 0x88, 0x04, 0x24,  // mov %al, (%r12)  [SIB required for r12]
	0x48, 0xff, 0xc6,        // inc rsi
	0x49, 0xff, 0xc4,        // inc r12
	0xff, 0xcb,              // dec ebx
	0xeb, 0xeb,              // jmp -21 → mat_copy

	// decode_loop_jmp: (trampoline — jmp mat_copy falls here when ebx==0)
	//   jmp decode_loop
	0xeb, 0x85, // jmp -123 → decode_loop

	// done:
	0xc3, // ret
}

// EmitLZ4Inflate appends the LZ4 block-format inflate decoder to b as raw bytes.
//
// The emitted function uses the Go register ABI (Go 1.17+). The Go func
// signature to cast to is:
//
//	func(src, dst unsafe.Pointer, srcSize uint64)
//
// Registers at entry:
//
//	RAX = src pointer (compressed data)
//	RBX = dst pointer (output buffer, caller-allocated)
//	RCX = src_size   (number of compressed bytes)
//
// The decoder does not return a value. The caller is responsible for
// pre-allocating a dst buffer large enough to hold the decompressed output.
// Inputs are not bounds-checked; the caller must ensure the data is well-formed
// LZ4 block format (https://lz4.org/lz4_Block_format.html).
//
// Decoder size: 136 bytes. The emitted bytes are tested in isolation via an
// mmap'd executable page in lz4_inflate_test.go (TestEmitLZ4Inflate_*).
//
// This function ships in isolation — it is NOT yet wired into [EmitStub].
// Wiring (Compress flag, memsz accounting) is the C3-stage-2 chantier.
func EmitLZ4Inflate(b *amd64.Builder) error {
	if err := b.RawBytes(lz4DecodeBytes[:]); err != nil {
		return fmt.Errorf("stage1: EmitLZ4Inflate: %w", err)
	}
	return nil
}
