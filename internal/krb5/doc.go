// Package krb5 is maldev's adapted fork of the jcmturner/gokrb5 v8
// Kerberos implementation. The trimmed tree underpins:
//
//   - credentials/sekurlsa/tickets_windows.go  — Kerberos ticket
//     export (chantier III) — consumes messages/, types/.
//   - credentials/goldenticket/                 — Golden Ticket
//     forging + injection (chantier V) — consumes pac/, messages/,
//     crypto/, types/.
//   - credentials/dcsync/                       — DCSync over
//     DRSUAPI (chantier VI) — consumes the client/ TGS path under
//     internal/msrpc's Negotiate authentication.
//
// Provenance, license, and trim policy live in UPSTREAM.md.
//
// # Caller / Opener / folder.Get integration plan
//
// This fork is a verbatim trim with import paths rewritten — the
// first cut applies no functional changes. The integration points
// listed below are the call sites we will adapt as each new
// credentials/* package starts consuming the fork. Each adaptation
// keeps a nil-tolerant default that delegates to the upstream
// behavior, so this fork stays drop-in compatible with vanilla
// gokrb5 callers.
//
// Path-based file reads — candidates for stealthopen.Opener routing:
//
//   - config.Load(filename) — reads krb5.conf via os.Open. When a
//     non-nil Opener is provided, route through it. The current
//     callers are tests; production code paths into Load() are added
//     by chantier VI.
//   - keytab.Load(filename) — reads .keytab via os.Open. Same shape
//     as above.
//
// Win32 / NT API call sites — candidates for *wsyscall.Caller
// routing:
//
//   - None today inside the trimmed tree — gokrb5 is platform-neutral
//     and uses only stdlib net/dns/file primitives.
//   - Future: when chantier VI wires DCSync, the SSPI Negotiate path
//     enters from the maldev side (internal/msrpc) — that's where
//     Caller threading lands, not inside this fork.
//
// Special-folder resolution — candidates for recon/folder.Get:
//
//   - config.Load() falls back to /etc/krb5.conf on Linux and
//     %SystemRoot%/krb5.ini on Windows. The Windows fallback is the
//     adaptation candidate (replace the env-var sniff with
//     folder.Get(folder.CSIDL_WINDOWS)).
//
// # Required privileges
//
// unprivileged. Pure-Go ASN.1 / DER + crypto over caller-
// supplied bytes. No syscall, no token surgery. Real privilege
// requirements live with the consumer (krbtgt acquisition,
// network reach to the KDC, etc.) — this internal fork is
// agnostic.
//
// # Platform
//
// Cross-platform. The trimmed tree uses only stdlib net /
// crypto / dns / file primitives — no GOOS-specific paths.
//
// # Maintenance contract
//
// 1. Behavior of the kept subpackages MUST stay observable-equivalent
//    to upstream for the test suite. Any deviation is documented
//    here and at the file header.
// 2. New maldev-specific files added inside this tree get a
//    file-top comment stating their origin and the adaptation they
//    apply.
// 3. Upstream merges are manual — see UPSTREAM.md for the policy.
package krb5
