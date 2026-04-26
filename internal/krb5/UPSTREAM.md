# internal/krb5 — adapted fork of jcmturner/gokrb5

Source: https://github.com/jcmturner/gokrb5
Upstream commit: `855dbc707a37a21467aef6c0245fcf3328dc39ed` (`v8/` root)
Upstream module path: `github.com/jcmturner/gokrb5/v8`
Upstream license: Apache License, Version 2.0 — see `UPSTREAM-LICENSE`
Upstream NOTICE: see `UPSTREAM-NOTICE`

## Why we fork instead of import

1. **Go-version control.** This subtree is anchored at the maldev
   module's `go 1.21` floor regardless of what upstream bumps to.
2. **Caller / Opener / folder.Get threading.** We adapt every call
   site that touches a Win32 / NT API or a path-based file read so it
   accepts maldev's optional `*wsyscall.Caller` and
   `stealthopen.Opener` parameters. The integration points are
   enumerated in `doc.go`.
3. **Trim scope.** Upstream ships several subpackages (server-side
   KDC, kadmin, SPNEGO HTTP middleware, GSSAPI wrapper) that are
   irrelevant to our credential-extraction stack. Carrying them
   would just increase audit surface.

## Adaptation policy (per `2026-04-26-sekurlsa-lsassdump-completion.md`)

- License-preserving: every Apache-2 source file keeps its original
  copyright header. New files added by maldev get a top-of-file
  comment stating their origin.
- Behavior-preserving for the kept subpackages: the trimmed tree
  passes the upstream test suite verbatim (with import paths
  rewritten). Any maldev modification that changes observable
  behavior must be called out in `doc.go` and in the per-file
  header.
- Upstream merges are manual. When pulling new gokrb5 changes,
  follow the steps in `UPDATING.md` (TODO: write once we do the
  first merge).

## Trim summary

**Kept** (~9.5k LOC):

- `asn1tools/` — ASN.1 helpers used by the message marshaler.
- `client/` — client-side TGT/AS/TGS dispatch loop + replay cache
  (without `passwd.go`, which depended on `kadmin/`).
- `config/` — krb5.conf parser. **Caller / Opener integration
  candidate** for the `Load(filename)` path.
- `credentials/` — credential cache + identity types.
- `crypto/` — full crypto suite (AES-CTS, AES-CBC, RC4-HMAC, DES,
  PBKDF2 derivation, key derivation per RFC 3961 / 3962 / 4757 /
  8009).
- `iana/` — IANA constants (etypes, addrtypes, error codes, etc.).
- `keytab/` — keytab parser. **Opener integration candidate**.
- `krberror/` — Kerberos error types.
- `messages/` — KRB-AS/TGS/CRED message types + ASN.1 marshalers.
  Foundation for `credentials/sekurlsa/tickets_windows.go` (chantier
  III) and `credentials/goldenticket/` (chantier V).
- `pac/` — PAC builder (LogonInfo, ClientInfo, signatures).
  Foundation for `credentials/goldenticket/` (chantier V) and the
  ticket-info display in chantier III.
- `types/` — protocol types (PrincipalName, Realm, EncryptionKey,
  Ticket, etc.).
- `test/` — small fixture data (`testtab` keytab + Go test vectors).
  Used only by the kept tests.

**Dropped**:

- `gssapi/` — GSSAPI wrapper. Out of scope for credential-extraction.
- `kadmin/` — kadmin client (kpasswd protocol). Removed along with
  the lone consumer `client/passwd.go`.
- `service/` — server-side service code (we are never a KDC).
- `spnego/` — SPNEGO HTTP middleware. Out of scope.
- `examples/` — example apps. Out of scope.

## External Go modules pulled in by the trim

| Module | Used by | License |
|---|---|---|
| `github.com/jcmturner/aescts/v2` | `crypto/rfc3962/encryption.go` | Apache-2.0 |
| `github.com/jcmturner/dnsutils/v2` | `config/hosts.go` | Apache-2.0 |
| `github.com/jcmturner/gofork` | `asn1tools/`, `crypto/rfc3962/keyDerivation.go` | Apache-2.0 |
| `github.com/jcmturner/goidentity/v6` | `credentials/credentials.go` | Apache-2.0 |
| `github.com/jcmturner/rpc/v2` (mstypes, ndr) | `pac/` | Apache-2.0 |
| `github.com/hashicorp/go-uuid` | `credentials/credentials.go` | MPL-2.0 |

All Apache-2 / MPL-2 — compatible with maldev's MIT distribution.
None require CGO. All declare go ≤ 1.21 in their go.mod.

## What this fork does NOT yet adapt

The first cut of the fork is a verbatim trim — import paths rewritten,
no functional changes. Caller / Opener / folder.Get integration points
are enumerated in `doc.go` and will be applied chantier-by-chantier as
each new credentials/* package starts consuming the fork:

- Chantier III (Kerberos ticket export) — uses `messages/` + `types/`,
  no new integration needed at this layer.
- Chantier V (Golden Ticket) — uses `pac/` + `messages/` + `crypto/`,
  same.
- Chantier VI (DCSync, blocked on `internal/msrpc/`) — when wired,
  the Kerberos-Negotiate authentication chain will call into
  `client/`'s TGS path, which reads `krb5.conf` (config/`Load`) and
  may write the replay cache. Both should route through Opener.

The integration commits will adapt the relevant call sites at that
point and update this document.
