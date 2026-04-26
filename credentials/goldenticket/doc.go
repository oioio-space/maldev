// Package goldenticket forges Kerberos Golden Tickets — long-lived
// TGTs minted with a stolen krbtgt account hash. Produces a kirbi
// blob that is either written to disk (cross-platform) or injected
// into the calling user's TGT cache via LsaCallAuthenticationPackage
// (Windows only).
//
// Technique: Forge a KRB-CRED message containing an EncTicketPart
// signed with the krbtgt's RC4-HMAC / AES128-CTS / AES256-CTS key
// and embedding a forged PAC (KERB_VALIDATION_INFO + PAC_CLIENT_INFO
// + 2× PAC_SIGNATURE_DATA). With the krbtgt key the operator can
// claim arbitrary group memberships (Domain Admins, Enterprise
// Admins, …) and an arbitrary lifetime — the forged ticket is
// indistinguishable from a real KDC-issued one until the next
// krbtgt rotation.
//
// MITRE ATT&CK: T1558.001 (Steal or Forge Kerberos Tickets: Golden
// Ticket).
//
// Detection level: HIGH. Defenders watch for:
//   - TGT lifetime > the domain's MaxTicketLifetime policy (default 10h).
//   - Logon events with mismatched user / RID combinations.
//   - PAC signature verification failures on member servers (rare —
//     servers usually trust the PAC blindly).
//   - Tickets with weak etypes (RC4) when the domain has been
//     enforced to AES-only.
//
// Operationally the technique is reliable until krbtgt is rotated
// (twice). It survives password changes, account disable, even
// account deletion of the impersonated principal.
//
// Build the kirbi cross-platform with Forge; on Windows pass it to
// Submit to inject directly into the calling user's ticket cache so
// the next outbound Kerberos auth uses the forged TGT.
//
// References:
//
//   - Mimikatz: kerberos::golden — Benjamin Delpy. The reference
//     implementation; we mine the algorithm only (CC BY-NC-SA, not
//     vendored).
//   - MakeMeEnterpriseAdmin (vletoux) — embeds a Golden Ticket
//     forging block driven by DRSGetNCChanges. See plan
//     `docs/superpowers/plans/2026-04-26-sekurlsa-lsassdump-completion.md`
//     chantier V.
//   - MS-PAC §2 — Microsoft Open Specifications, public; not
//     copyrightable. Sections 2.5 (KERB_VALIDATION_INFO),
//     2.6 (PAC_CLIENT_INFO), 2.8 (PAC_SIGNATURE_DATA).
//
// Cross-platform note: Forge runs on Linux/Windows (pure Go). Submit
// is Windows-only because LsaCallAuthenticationPackage has no Linux
// equivalent — operators on Linux must klist-import the kirbi out of
// band (or use it via gokrb5's client).
package goldenticket
