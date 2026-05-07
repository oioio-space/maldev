// Package runtime is the consumer side of [pe/packer]: takes a
// packed blob + key and reflectively loads the original PE into
// the current process's memory.
//
// Coverage so far:
//
//   - Phase 1b — Windows x64 PE EXEs: full mmap + relocations
//     + LoadLibrary/GetProcAddress imports + section protect.
//   - Phase 1f Stage A — ELF64 LE x86_64 parser + format
//     dispatch from [Prepare].
//   - Phase 1f Stage B — Linux mmap of PT_LOAD segments,
//     R_X86_64_RELATIVE relocations, per-segment mprotect.
//   - Phase 1f Stage C+D — Go static-PIE end-to-end on Linux:
//     Z-scope gate via debug/buildinfo; PT_TLS lift conditional
//     on the gate; Run() builds a kernel-style stack frame
//     (argc/argv/envp/auxv from /proc/self/auxv with AT_RANDOM
//     canary) and JMPs to the binary's entry point via Plan 9
//     asm. Symmetric with the Windows side's "JMP OEP, never
//     returns" contract.
//   - Phase 1f Stage E — broadened gate to all self-contained
//     static-PIE binaries (Go, hand-rolled asm, C/Rust built
//     with -static-pie). Structural contract: ET_DYN +
//     no DT_NEEDED + at least one PT_LOAD. The .go.buildinfo
//     check is now informational only — GoVersion is populated
//     for diagnostics when available, but does not gate
//     loading.
//
// Other ELFs (libc-using with DT_NEEDED, IFUNC, versioned
// symbols, ET_EXEC) continue to surface [ErrNotImplemented]
// with a clear rebuild hint. Stage F will eventually broaden
// to full ld.so emulation for libc-using binaries.
//
// Out of scope (rejected at parse time or surfaced as resolution
// failures): DLLs (calling DllMain), TLS callbacks, x86,
// SxS-redirected ordinal imports (e.g., COMCTL32 v6), big-endian
// ELF, ET_REL object files, ARM64.
//
// The loader's public surface splits into two:
//
//   - [Prepare] does everything except the jump to OEP. Tests
//     and inspection callers use this.
//   - [LoadPE] = [packer.Unpack] + [Prepare]. Production callers
//     pass the packed blob + key directly.
//
// The actual jump-to-OEP step ([PreparedImage.Run]) is gated
// behind the MALDEV_PACKER_RUN_E2E environment variable so
// `go test` runs against unmodified production binaries don't
// hand control to arbitrary payloads.
//
// # MITRE ATT&CK
//
//   - T1620 — Reflective Code Loading
//   - T1027.002 — Software Packing (consumer side)
//
// # Detection level
//
// noisy
//
// Reflective loading is highly observable: the new RWX/RX region
// inside the implant process triggers EDR memory scanners; the
// LoadLibrary chain is per-target-DLL visible to ETW
// `Microsoft-Windows-LoaderEvents`. Pair with
// [evasion/sleepmask] (mask the loaded payload between callbacks)
// + [evasion/preset.Stealth] (silence ETW + AMSI before load).
//
// # Required privileges
//
// unprivileged. Self-process memory only — VirtualAlloc /
// VirtualProtect / LoadLibrary / GetProcAddress on Windows;
// mmap / mprotect on Linux. No SeDebugPrivilege, no kernel
// surface.
//
// # Platform
//
// Windows x64 (PE EXEs) + Linux x86_64 (Go static-PIE ELFs).
// Other ELF types (C-built, libc-using, non-x86_64) return
// [ErrNotImplemented] — Stage E broadens to non-Go static-PIE.
//
// # Example
//
//	import (
//	    "github.com/oioio-space/maldev/pe/packer"
//	    "github.com/oioio-space/maldev/pe/packer/runtime"
//	)
//
//	blob, key, _ := packer.Pack(payloadBytes, packer.Options{})
//
//	// At the implant's startup:
//	img, err := runtime.LoadPE(blob, key)
//	if err != nil { /* … */ }
//	defer img.Free()
//
//	// Set MALDEV_PACKER_RUN_E2E=1 in the implant build's env
//	// (NOT in the operator shell — this gates production execution).
//	// _ = img.Run()
//
// # See also
//
//   - docs/techniques/pe/packer.md — operator-facing tech md
//   - docs/refactor-2026-doc/packer-design.md — full design doc
//   - [github.com/oioio-space/maldev/pe/packer] — encrypt + embed pipeline
//   - [github.com/oioio-space/maldev/evasion/sleepmask] — in-memory cover
//
// [github.com/oioio-space/maldev/pe/packer]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer
// [github.com/oioio-space/maldev/evasion/sleepmask]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask
// [evasion/sleepmask]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/sleepmask
// [evasion/preset.Stealth]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset#Stealth
package runtime
