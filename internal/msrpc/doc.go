// Package msrpc is maldev's adapted fork of the oiweiwei/go-msrpc
// MS-RPC + DCERPC stack. The trimmed tree underpins:
//
//   - credentials/goldenticket/ — Golden Ticket forging (chantier V).
//     Uses internal/msrpc/{ndr,msrpc/pac,msrpc/dtyp} for PAC NDR
//     marshaling.
//   - credentials/dcsync/      — DCSync over DRSUAPI (chantier VI,
//     blocked on real DCERPC transport vendoring).
//
// Provenance, license, and trim policy live in UPSTREAM.md.
//
// # First-cut state
//
// The first cut is a verbatim trim with import paths rewritten plus
// a small `dcerpc/` stub for the type signatures referenced by
// vendored client/server scaffolding. The actual DCERPC transport is
// NOT vendored. PAC NDR marshaling is the only working production
// path; calling into the vendored claims `ClaimsClient.Bind(ctx)`
// returns dcerpc.ErrStubbed.
//
// # Required privileges
//
// unprivileged in the current trim — only PAC NDR marshaling is
// active, and that is byte-level only. When chantier VI lands
// the DCERPC transport, downstream calls into DRSUAPI / SAMR
// will inherit per-RPC server gates (DCSync needs `Replicating
// Directory Changes` on the DC, SAMR needs the relevant
// account rights on the target). The fork itself remains
// agnostic.
//
// # Platform
//
// Cross-platform for PAC NDR. The vendored DCERPC stub has
// platform-neutral type signatures; the eventual real
// transport will use stdlib `net.Dial` (cross-platform) plus an
// SSPI Negotiate path that becomes Windows-only when wired up.
//
// # Caller / Opener / folder.Get integration plan
//
// PAC marshaling is purely byte-level — no syscalls, no file reads.
// The integration surface is empty for the chantier V use case.
//
// When chantier VI lands and replaces the dcerpc stub, integration
// points include:
//
//   - DCERPC transport's TCP/SMB connect — replace stdlib net.Dial
//     with a Caller-aware variant when EDR-evasion is on.
//   - SSPI Negotiate path's krb5.conf read (already routed via
//     internal/krb5/config) — confirm Opener threads through.
//   - Replay cache writes — route through Opener for stealth file I/O.
package msrpc
