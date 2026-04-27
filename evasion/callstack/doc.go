// Package callstack synthesises a return-address chain so a stack
// walker at a protected-API call site sees frames that originate from
// a benign thread-init sequence rather than from the attacker module.
//
// SpoofCall stitches a crafted return chain onto the stack before
// invoking the target. The target's prologue stores RSP and returns
// through our chain, so `RtlVirtualUnwind` walks
// `kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart` instead of
// the implant's own module. Helpers: FindReturnGadget locates a usable
// RET gadget in ntdll; Validate vets a hand-built Frame chain.
//
// SpoofCall accepts at most 4 args (Win64 RCX/RDX/R8/R9). Args 5+
// would require stack-arg layout — out of scope today.
//
// # MITRE ATT&CK
//
//   - T1036 (Masquerading) — synthetic call-stack frames fall under
//     the broader masquerade family; no dedicated sub-technique today.
//
// # Detection level
//
// quiet
//
// A walkable chain defeats most `CaptureStackBackTrace` consumers.
// ETW Threat Intelligence and EDRs that cross-check RIP against the
// real unwind metadata can detect synthesised frames.
//
// # Example
//
// See [ExampleSpoofCall] in callstack_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/callstack-spoof.md
//   - [SilentMoonwalk reference](https://github.com/klezVirus/SilentMoonwalk)
package callstack
