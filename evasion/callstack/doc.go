// Package callstack spoofs the return-address chain seen by a stack
// walker at a given call site, so protected-API calls appear to
// originate from the expected thread-init sequence rather than from
// the caller's own module.
//
// Technique: Synthetic unwind frames (SilentMoonwalk / HW-CallStack
// family). Before calling a target function, the caller stitches a
// crafted return chain onto the stack; the target function's prologue
// stores Rsp + returns through our chain so RtlVirtualUnwind walks
// kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart rather than
// the attacker module.
//
// MITRE ATT&CK: T1036 (Masquerading — synthetic call-stack frames fall
// under the broader masquerade family; no dedicated sub-technique today).
// Platform: Windows amd64
// Detection: Medium. A walkable chain defeats most CaptureStackBackTrace
// consumers; ETW Threat-Intelligence and some EDRs cross-check RIP
// against the real unwind metadata and can spot synthesized frames.
//
// Composition: `SpoofCall(caller *wsyscall.Caller, addr unsafe.Pointer,
// args ...uintptr)` lets existing call sites (unhook, inject, …) route
// their hot calls through a spoofed stack without plumbing.
package callstack
