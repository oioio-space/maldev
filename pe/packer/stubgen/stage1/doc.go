// Package stage1 emits the polymorphic stage-1 decoder asm that
// reverses pe/packer/stubgen/poly's N-round encoding at runtime.
//
// Each round's decoder is a small loop:
//
//	MOV  cnt = payloadLen
//	MOV  key = round.Key
//	LEA  src = [rip + payload_offset]
//	loop:
//	  MOVZX byte_reg, byte ptr [src]
//	  <subst applied: e.g. byte_reg ^= key>
//	  MOVB  byte ptr [src], byte_reg
//	  ADD   src, 1
//	  DEC   cnt
//	  JNZ   loop
//
// The engine assembles N decoders back-to-back, then emits a final
// JMP into the now-decoded data's entry point. Junk insertion
// happens between any two adjacent instructions per the engine's
// density setting.
//
// # Detection level
//
// N/A — pack-time only.
package stage1
