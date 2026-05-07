// Package stubgen drives the UPX-style transform pipeline for
// Phase 1e:
//
//  1. transform.PlanPE / PlanELF — compute layout RVAs from input
//  2. poly.Engine.EncodePayload — N-round SGN-encode the input's .text bytes
//  3. stage1.EmitStub — emit the polymorphic decoder asm
//  4. stage1.PatchTextDisplacement — patch the CALL+POP+ADD
//     prologue's text displacement
//  5. transform.InjectStubPE / InjectStubELF — write the modified
//     binary
//
// The Phase 1e-A/B host emitter and stage 2 Go EXE are removed.
// The kernel handles all binary loading; the stub only decrypts
// and JMPs.
//
// # Detection level
//
// N/A — pack-time only. The modified binary at runtime is "loud"
// (RWX section, entry point not in the original .text). Pair with
// evasion/sleepmask + evasion/preset for memory-side cover.
//
// # MITRE ATT&CK
//
// T1027.002 — Obfuscated Files or Information: Software Packing.
package stubgen
