// Package goldenticket forges Kerberos Golden Tickets — long-lived
// TGTs minted with a stolen krbtgt account hash. Produces a kirbi
// blob that is either written to disk (cross-platform) or injected
// into the calling user's TGT cache via LsaCallAuthenticationPackage
// (Windows only).
//
// Forge a KRB-CRED message containing an EncTicketPart signed with
// the krbtgt's RC4-HMAC / AES128-CTS / AES256-CTS key and embedding
// a forged PAC (KERB_VALIDATION_INFO + PAC_CLIENT_INFO + 2×
// PAC_SIGNATURE_DATA). With the krbtgt key the operator can claim
// arbitrary group memberships (Domain Admins, Enterprise Admins, …)
// and an arbitrary lifetime — the forged ticket is indistinguishable
// from a real KDC-issued one until the next krbtgt rotation.
//
// Operationally the technique is reliable until krbtgt is rotated
// (twice). It survives password changes, account disable, even
// account deletion of the impersonated principal.
//
// Build the kirbi cross-platform with [Forge]; on Windows pass it to
// [Submit] to inject directly into the calling user's ticket cache so
// the next outbound Kerberos auth uses the forged TGT.
//
// Cross-platform note: [Forge] runs on Linux/Windows (pure Go).
// [Submit] is Windows-only because LsaCallAuthenticationPackage has
// no Linux equivalent — operators on Linux must klist-import the
// kirbi out of band (or use it via gokrb5's client).
//
// References (mined for algorithm only, none vendored):
//
//   - Mimikatz `kerberos::golden` (Benjamin Delpy, CC BY-NC-SA) —
//     reference implementation.
//   - vletoux/MakeMeEnterpriseAdmin — embeds a Golden Ticket forging
//     block driven by DRSGetNCChanges.
//   - MS-PAC §2 (Microsoft Open Specifications, public): §2.5
//     KERB_VALIDATION_INFO, §2.6 PAC_CLIENT_INFO, §2.8 PAC_SIGNATURE_DATA.
//
// # MITRE ATT&CK
//
//   - T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)
//
// # Detection level
//
// noisy
//
// Defenders watch for:
//
//   - TGT lifetime > the domain's MaxTicketLifetime policy (default 10h).
//   - Logon events with mismatched user / RID combinations.
//   - PAC signature verification failures on member servers (rare —
//     servers usually trust the PAC blindly).
//   - Tickets with weak etypes (RC4) when the domain has been
//     enforced to AES-only.
//
// # Required privileges
//
// [Forge] is unprivileged — pure-Go assembly of an ASN.1 blob,
// runs in any token. The privilege gate is upstream: the krbtgt
// RC4/AES key has to come from somewhere (typically a Domain
// Controller `lsassdump` → `sekurlsa` chain, requiring DA /
// SYSTEM on a DC) or DCSync (Replicating-Directory-Changes on
// the DC). [Submit] is also unprivileged —
// `LsaCallAuthenticationPackage` injects into the calling
// user's TGT cache only, no token elevation needed.
//
// # Platform
//
// Cross-platform [Forge]; Windows-only [Submit].
// `LsaCallAuthenticationPackage` has no POSIX equivalent —
// Linux operators must klist-import the produced kirbi via
// MIT/Heimdal Kerberos or load it through gokrb5.
//
// # Example
//
// See [ExampleForge] and [ExampleSubmit] in goldenticket_example_test.go.
//
// # See also
//
//   - docs/techniques/credentials/goldenticket.md
//   - [github.com/oioio-space/maldev/credentials/sekurlsa] — extracts
//     krbtgt hashes from a domain controller LSASS dump
//   - [github.com/oioio-space/maldev/credentials/lsassdump] — produces
//     the LSASS dump consumed by sekurlsa
//
// [github.com/oioio-space/maldev/credentials/sekurlsa]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials/sekurlsa
// [github.com/oioio-space/maldev/credentials/lsassdump]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump
package goldenticket
