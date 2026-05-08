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
// The pre-v0.61 host-emitter + stage 2 Go EXE architecture is
// removed; v0.61.x is the in-place transform shipped today. The
// kernel handles all binary loading; the stub only decrypts and
// JMPs. See docs/refactor-2026-doc/KNOWN-ISSUES-1e.md for the
// post-mortem of the older approach.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) —
//     pipeline driver for the parent
//     [github.com/oioio-space/maldev/pe/packer] package's UPX-style
//     transform.
//
// # Detection level
//
// noisy.
//
// Pack-time pipeline only. The modified output binary at runtime
// is heuristically suspicious (RWX section, entry point not in
// the original .text). Pair with
// [github.com/oioio-space/maldev/evasion/sleepmask] +
// [github.com/oioio-space/maldev/evasion/preset] for memory-side
// cover; chain
// [github.com/oioio-space/maldev/pe/packer.AddCoverPE] /
// [github.com/oioio-space/maldev/pe/packer.AddCoverELF] for
// static-side camouflage.
//
// # Required privileges
//
// unprivileged.
//
// # Platform
//
// Cross-platform pack-time. Output binaries run on Windows
// (FormatWindowsExe) or Linux (FormatLinuxELF).
//
// # Example
//
// See stubgen_test.go (TestGenerate_PEPasses /
// TestGenerate_ELFPasses) for the round-trip pattern.
//
// # See also
//
//   - [github.com/oioio-space/maldev/pe/packer/transform] — layout
//     planner + injector
//   - [github.com/oioio-space/maldev/pe/packer/stubgen/poly] — SGN
//     engine
//   - [github.com/oioio-space/maldev/pe/packer/stubgen/stage1] — stub
//     emitter
//   - docs/techniques/pe/packer.md — operator-facing tech md
package stubgen
