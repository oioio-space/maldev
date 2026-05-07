// Package amd64 wraps github.com/twitchyliquid64/golang-asm into a
// focused builder API for the polymorphic stage-1 decoder Phase 1e-A
// emits. Only the instruction subset the SGN algorithm uses is
// exposed: MOV / LEA / XOR / SUB / ADD / JMP / Jcc / DEC / CALL /
// RET / NOP. Operands are typed (Reg / Imm / MemOp) rather than
// raw obj.Addr structs.
//
// Why golang-asm and not a from-scratch encoder: golang-asm is a
// fork of cmd/internal/obj/x86, the same encoder Go's own
// toolchain uses. Mature, BSD-3 licensed, Plan 9 syntax matches
// the .s files already in this repo (pe/packer/runtime/
// runtime_linux_amd64.s, evasion/callstack/spoof_windows_amd64.s,
// etc.). Used in production by simdjson-go and ebpf-go.
//
// # Detection level
//
// N/A — pure-Go pack-time encoder, never runs on a target.
//
// # See also
//
//   - github.com/twitchyliquid64/golang-asm — the encoder backend
//   - golang.org/x/arch/x86/x86asm — the disassembler we cross-check against in tests
package amd64
