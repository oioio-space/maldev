// Package amd64 wraps github.com/twitchyliquid64/golang-asm into a
// focused builder API for the polymorphic stage-1 decoder Phase 1e (v0.61.x)
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
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) —
//     instruction emitter for the parent
//     [github.com/oioio-space/maldev/pe/packer] package's stage-1
//     decoder.
//
// # Detection level
//
// quiet.
//
// Pure-Go pack-time encoder — never runs on a target. Detection
// profile of the emitted bytes is owned by the calling
// [github.com/oioio-space/maldev/pe/packer/stubgen/stage1] package.
//
// # Required privileges
//
// unprivileged.
//
// # Platform
//
// Cross-platform pack-time; output is amd64-only.
//
// # Example
//
// See builder_test.go (TestBuilder_RoundTrips* / TestEncode_*).
//
// # See also
//
//   - [github.com/twitchyliquid64/golang-asm] — encoder backend
//   - [golang.org/x/arch/x86/x86asm] — disassembler used in tests
//   - [github.com/oioio-space/maldev/pe/packer/stubgen/stage1] — direct
//     consumer
package amd64
