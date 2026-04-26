# sekurlsa / lsassdump completion + adjacent credential primitives — 2026-04-26

Plan to bring `credentials/sekurlsa` and `credentials/lsassdump` to
"feature-complete" parity with mimikatz `sekurlsa::*` + `lsadump::*`,
plus adjacent credential primitives (DCSync, Golden Ticket, SAM dump)
that are the natural follow-on once the lsass extractor stack stabilises.

## Status snapshot — going in

Already shipped (host + Win10 VM coverage in last full-coverage run):

| Module | State | Notes |
|---|---|---|
| `credentials/lsassdump` | v0.31.4 | Minidump producer + PPL bypass via RTCore64 BYOVD + dynamic EPROCESS-offset discovery. 24/40 funcs covered. |
| `credentials/sekurlsa` | v0.30.4 (+ uncommitted v0.32.0) | LSA key, MSV, Wdigest, DPAPI, Kerberos AVL, TSPkg AVL, CloudAP, CredMan, LiveSSP. |

Uncommitted on `master`: the v0.32.0 lsass cleanup (Caller / Opener /
folder.Get threading through ParseFile + Discover*Offset +
FindLsassEProcess + defaultNtoskrnlPath; sentinel rename
`ErrMSV1_0NotFound` → `ErrMSVNotFound`; `Credential.wipe()` promoted to
the interface). Tracked separately by the audit doc
`2026-04-26-caller-opener-folder-audit.md`.

External references this plan mines (see memory note
`sekurlsa_lsassdump_references.md`):

- **b4rtik/SharpKatz** — BSD 3-Clause C# port of mimikatz. Frozen at
  Win10 build 19041 (May 2020), no help with Win11 cryptography
  goalpost moves but the canonical reference for everything ≤ 2004.
- **vletoux/MakeMeEnterpriseAdmin** — PowerShell DCSync + Golden
  Ticket. NOT Zerologon — assumes caller already has Replicating
  Directory Changes rights.
- **D3Ext/maldev** — investigated (per user request) for samdump
  patterns. Negative result: just a wrapper over `C-Sto/gosecretsdump`
  (GPL-3.0). Has zero hive-parsing or shadow-copy code of its own.
- **C-Sto/gosecretsdump** — pure-Go SAM/NTDS reader **but GPL-3.0**.
  Use only as a correctness oracle during clean-room reimplementation;
  do NOT vendor or import.
- **wesmar/KvcForensic + wesmar/kvc** — already in memory. PPL bypass
  + lsasrv signature reference.

## Dependency strategy — three integration models

For each external library mined here we have **three** ways to bring
it into maldev. The default in most Go projects is "import as module"
but maldev's constraints (Caller / Opener / folder.Get threading,
EDR-aware syscall routing, Win7 baseline pinned at Go 1.21) make the
"fork-and-adapt" model often the right choice.

### Model A — Import as Go module (vanilla)

`require github.com/foo/bar v1.2.3` in `go.mod`. Standard. Pros:
upstream patches arrive for free. Cons: every API call inside the dep
goes through whatever syscall convention the upstream chose — usually
direct `x/sys/windows` or `[DllImport]`-style stubs that EDRs can
hook. We can't thread our `*wsyscall.Caller` or `stealthopen.Opener`
through.

### Model B — Vendor + patch go.mod only

`go mod vendor`, then patch the vendored directory's `go.mod` to
remove the offending Go-version floor. Pros: minimal divergence;
upstream rebases stay easy. Cons: doesn't solve the Caller/Opener
threading; only solves Go-version mismatches.

### Model C — Fork into `internal/<name>` and adapt

Copy the upstream tree into `internal/krb5/` or `internal/msrpc/`,
modify call sites to accept maldev's optional `*wsyscall.Caller`,
`stealthopen.Opener`, `folder.Get`-style helpers. Trim out parts we
don't need. Treat as our code from then on; document the upstream
SHA + license in a header.

**Pros:**

- All Win32/NT calls inside the forked code route through our Caller —
  consistent EDR posture across the entire stack.
- All file reads go through stealthopen — no path-based hooks observe
  config files (krb5.conf, keytabs, hive files).
- Special-folder resolution uses our `recon/folder.Get` instead of
  PEB env-var sniffs.
- No Go-version floor leaks into our `go.mod` — we control it.
- Trim scope: we don't need gokrb5's MIT KDC server, kadmin client,
  SPNEGO HTTP middleware, etc. — drop ~60% of LOC.
- Public API can mirror our existing conventions (sentinel errors,
  `Wipe()` interface, etc.) instead of jcmturner's idioms.

**Cons:**

- Manual upstream merges (Kerberos protocol is stable — gokrb5 has
  ~8 commits/yr touching anything we'd care about; manageable).
- License obligations: must preserve copyright + state changes. Both
  Apache-2 and MIT explicitly allow this.
- Initial port cost is real (~2-4 days per fork to trim + adapt).

**Cons that don't apply:**

- Performance: irrelevant for our use case.
- "Reinventing the wheel": we're not — we're keeping the protocol
  logic verbatim, only swapping the syscall + I/O surface.

### Per-dep recommendation

| Dep | Model | Rationale |
|---|---|---|
| **`gokrb5/v8`** | **C** (fork → `internal/krb5`) | Heavily uses syscalls/file reads (krb5.conf, keytab) — every one is a stealth-routing opportunity. Trim to: messages + crypto + PAC + KDC client. Drop server, kadmin, SPNEGO HTTP, gssapi. Estimated final size ~30% of upstream. |
| **`go-msrpc`** | **C** (fork → `internal/msrpc`) | Solves the Go 1.25 floor problem cleanly (we control the floor). Trim to MS-DRSR + Kerberos auth path; drop the ~30 other RPC interfaces. Every DCERPC over SMB/TCP transport call routes through our Caller. |
| `gosecretsdump` | **N/A — clean-room only** | GPL-3.0 — fork-and-adapt would still inherit GPL. Reject. |

### Model-A fallback path

If Model-C ports are too costly to land in v1, ship Model A first
(plain import) and refactor to Model C in a follow-up release. Not
ideal because it leaks the syscall surface in the meantime, but it
unblocks chantier V (Golden Ticket) immediately.

Default for this plan: **Model C for both gokrb5 and go-msrpc**, with
Model A noted as the fallback if a port turns out larger than budgeted.

### Dep summary (Model-C path)

| Source | Lic. | Pure Go | Adapted name | Adapted scope |
|---|---|---|---|---|
| `github.com/jcmturner/gokrb5/v8` | Apache-2.0 | yes | `internal/krb5/` | messages, crypto, PAC, minimal KDC client |
| `github.com/oiweiwei/go-msrpc` | MIT | yes | `internal/msrpc/` | DCERPC core, NDR20, MS-DRSR bindings |

No CGO anywhere. No new top-level deps in `go.mod`. Win7 baseline
preserved (we control internal Go-version requirements).

### Pre-port checklist (mandatory before each fork)

1. Capture upstream SHA + license + NOTICE files in
   `internal/<name>/UPSTREAM.md`.
2. Add a single-file `internal/<name>/doc.go` that lists every Caller
   / Opener / folder.Get integration point we added.
3. Add a CI check that flags `import "C"` and any `golang.org/x/sys`
   call inside the forked tree that doesn't route through Caller.
4. Run upstream's full test suite once on the trimmed fork to catch
   transitive drops.

This adds ~1d per fork on top of the chantier estimate. Update
chantier V (Golden Ticket) and chantier VI (DCSync) effort accordingly:

| Chantier | Original | + Fork cost | New total |
|---|---|---|---|
| V — Golden Ticket | 3d | +3d (gokrb5 fork) | 6d |
| VI — DCSync | 14d | +4d (msrpc fork) | 18d |

Chantier III (Kerberos tickets) reuses the gokrb5 fork V already
shipped, no extra cost.

---

## Chantier I — `lsasrvProfile` per-build profile struct (refactor)

**Status: ✅ already shipped.** The `Template` struct in
`credentials/sekurlsa/default_templates.go` IS the `lsasrvProfile`
this chantier proposed to build. Discovery on 2026-04-26 audit:

- `Template` carries the LSA crypto sigs + offsets, MSV / Wdigest /
  DPAPI signatures + offsets, AVL layouts (NodeSize + per-field
  offsets), per-SSP list patterns (Kerberos / TSPkg / CloudAP /
  LiveSSP / DPAPI / CredMan), all keyed by `BuildMin..BuildMax`.
- Every SSP module (`kerberos.go:125`, `tspkg.go:78`, `cloudap.go:102`,
  `livessp.go:59`, `dpapi.go:114`) reads its patterns from the
  Template — no scattered per-module version tables.
- Lookup is centralized in `pattern.go:191` (the only build-conditional
  branch in the entire `credentials/sekurlsa` tree).
- Built-in coverage: Win 7 RTM (7600) → Windows-future (uint32 max),
  9 ranges including Win 11 24H2+ (26100+).

What this chantier *would* have added (per-build files, selector
skeleton) already exists under different names. **Skip.** The only
remaining tidy-up is cosmetic (consider renaming `Template` →
`lsasrvProfile` for naming consistency with SharpKatz IWinBuild — not
worth a separate commit, fold into chantier IV when those Templates
get edited).

---

## Chantier II — Pass-the-Hash write-back (`pth_windows.go`)

**Target:** `credentials/sekurlsa` v0.33.0.
**Effort:** ~3d (~300 LOC + tests).
**MITRE ATT&CK:** [T1550.002 — Use Alternate Authentication Material:
Pass the Hash](https://attack.mitre.org/techniques/T1550/002/).

### Scope

Mirror SharpKatz `Module/Pth.cs`:

1. `CreateProcessWithLogonW(NetCredentialsOnly, CREATE_SUSPENDED)`
   spawns a process under a **decoy** account (any cred works — we
   replace them in step 3).
2. Resolve the new process's LUID via `OpenProcessToken` +
   `GetTokenInformation(TokenStatistics)`.
3. Walk lsass MSV + Kerberos lists for that LUID; for each list entry,
   re-encrypt the new NTLM / AES128 / AES256 / RC4 hash with the
   already-extracted LSA key (3DES / AES-CFB selection) and
   `WriteProcessMemory` over `Password.Buffer` (MSV) and per-etype
   `KERB_HASHPASSWORD.Checksum` (Kerberos).
4. `NtResumeProcess` (or `SetThreadToken` for `--impersonate` flow).

### Prerequisites

- `BCrypt.EncryptCredentials` — currently we only ship a decrypt path.
  New helper in `credentials/sekurlsa/crypto_windows.go`.
- Write access to lsass — pairs with the existing PPL bypass
  (`lsassdump.Unprotect/Reprotect`) when targeting a PPL lsass.

### File structure

- `credentials/sekurlsa/pth_windows.go` — public entry point
  `PassTheHash(target *PTHTarget) (PTHResult, error)`.
- `credentials/sekurlsa/pth_windows_test.go` — mock-LUID-walker unit
  tests + a behind-`MALDEV_INTRUSIVE=1` real-lsass smoke test.
- Tiny `BCrypt.EncryptCredentials` extension to crypto helper.

### Risk

High operational detection — write access to lsass is one of the
loudest EDR events. Document in package doc.

### Commit train

1. `BCrypt.EncryptCredentials` helper + unit tests.
2. PTH skeleton (LUID resolve, list walker, dry-run mode that just
   prints what it WOULD write).
3. Real write path + intrusive test.
4. `--impersonate` flow with `SetThreadToken`.

---

## Chantier III — Kerberos ticket export (`tickets_windows.go`)

**Target:** `credentials/sekurlsa` v0.34.0.
**Effort:** ~4d (~400 LOC + ASN.1 KRB-CRED encoder + tests).
**MITRE ATT&CK:** [T1558.003 — Steal or Forge Kerberos Tickets:
Kerberoasting / TicketDump](https://attack.mitre.org/techniques/T1558/).

### Scope

Walk `Tickets_1` / `Tickets_2` / `Tickets_3` `LIST_ENTRY` heads in each
session's `KIWI_KERBEROS_LOGON_SESSION` and ASN.1-serialise each ticket
into a kirbi-compatible KRB-CRED blob. mimikatz output format
expected: `kirbi` files writeable to disk + in-memory blobs for
direct injection.

### Why not from SharpKatz

`Module/Kerberos.cs::Tickets_1..3` defines the offsets but does NOT
serialise — SharpKatz's Kerberos module only enumerates ekeys. Need
to mine mimikatz `kuhl_m_sekurlsa_kerberos.c` + `kerberos_data.c` for
the kirbi serialisation.

### Reuse

- `gokrb5/v8/messages` already defines KRB-CRED, EncryptedData, etc.
  with marshal helpers — use those instead of hand-rolling ASN.1.

### File structure

- `credentials/sekurlsa/tickets_windows.go` — `ExtractTickets(session)
  ([]Ticket, error)`, `Ticket.Marshal() ([]byte, error)`.
- `credentials/sekurlsa/tickets_windows_test.go` — fixture-based
  marshal tests + integration.

### Commit train

1. List walker — return raw struct dumps (no ASN.1 yet).
2. Map raw struct fields onto gokrb5 message types.
3. Marshal helper + golden-file tests.
4. Integration with `Result.Sessions` (new `Tickets []Ticket` field
   on `LogonSession`).

---

## Chantier IV — Win11 lsasrv signatures + Tier-3 cross-version coverage

**Target:** `credentials/sekurlsa` v0.34.x patch series.
**Effort:** ~3d RE + 1d unit tests per build covered.
**MITRE ATT&CK:** N/A (defensive-side: maintain compatibility).

### Scope

Last full-coverage run (2026-04-26) surfaced cross-version test
failures on win11-2 that are NOT in win10:

- `inject/TestCallerMatrix_RemoteInject` — 8 sub-fails on Win11.
- `process/tamper/{fakecmd,herpaderping}` — multiple Win11 failures.

These are not lsass-extraction failures *per se*, but the same
underlying issue (Win11 PEB / handle / mitigation tightening) bites
sekurlsa indirectly: lsasrv struct layouts and entry points have
shifted between 22H2 and 24H2 builds in ways neither SharpKatz nor
mimikatz' last-published table covers.

### Plan

1. RE current ntdll + lsasrv on Win11 22H2 + 23H2 + 24H2 (we have
   `win11-2` VM provisioned). Use IDA / Ghidra inside the VM; capture
   sigs + offsets in `lsasrv_profile_*.go`.
2. Add a fallback **triple-`lea` resolution** for the LSA key (mined
   from SharpKatz `Module/Keys.cs`): when the BCRYPT_KEY_DATA_BLOB
   structural scan misses, fall back to scanning for one anchor sig
   + three relative-offset `lea rip+disp32` instructions. Activates
   silently on Win11 builds where the structural scan returns nil.
3. Validate against the cross-version test deltas — re-run
   full-coverage; cross-version failures should drop.

### Risk

Pure RE work — no API change, no risk to existing builds.

---

## Chantier V — Golden Ticket forging (`credentials/goldenticket`)

**Target:** new package; tag `v0.1.0`.
**Effort:** ~3d (~400 LOC + gokrb5 dep + tests).
**MITRE ATT&CK:** [T1558.001 — Steal or Forge Kerberos Tickets:
Golden Ticket](https://attack.mitre.org/techniques/T1558/001/).

### Scope

Forge a TGT given a `krbtgt` hash + domain SID + target user. Mirror
mimikatz `kerberos::golden`. **Independent of DCSync** — useful as
soon as a krbtgt hash arrives via *any* channel (sekurlsa output,
operator-supplied, etc.).

### Implementation

`gokrb5/v8` already ships:

- `messages.KRB_AS_REP` / `KRB_TGT_REP`
- `crypto/{aes128cts,aes256cts,rc4hmac}`
- `pac.PACType.Marshal()` — full PAC serialiser

We add ~400 LOC of orchestration:

- Parameter struct (`User string, DomainSID string, KrbtgtHash []byte,
  PrincipalName, Lifetime time.Duration, Groups []string, …`).
- PAC builder (LogonInfo, ClientInfo, PAC_SIGNATURE_DATA × 2).
- Wrap as KRB-CRED kirbi for output to disk OR direct in-memory
  ticket cache injection (Windows-only — requires
  `LsaCallAuthenticationPackage(SubmitTicket)` — chantier VI).

### File structure

- `credentials/goldenticket/golden.go` — pure-Go ticket builder
  (cross-platform).
- `credentials/goldenticket/inject_windows.go` — LsaSubmitTicket
  helper.
- `credentials/goldenticket/golden_test.go` — golden-file tests
  validated against mimikatz-generated kirbis.

### Commit train

1. Add `gokrb5/v8` to `go.mod`. Verify host build is clean.
2. PAC + LogonInfo builder.
3. Kirbi wrapper + golden-file tests.
4. Windows ticket-cache injection.

---

## Chantier VI — DCSync (`credentials/dcsync`)

**Target:** new package; tag `v0.1.0`.
**Effort (with `go-msrpc`):** ~2 weeks (~600–1200 LOC).
**Effort (without):** ~3 months (writing impacket-in-Go for one RPC
interface).
**MITRE ATT&CK:** [T1003.006 — OS Credential Dumping: DCSync](
https://attack.mitre.org/techniques/T1003/006/).

### Gating

**BLOCKED on `go-msrpc` resolution** — see "Dependency budget"
section. Plan the dep first, then implement.

### Scope

DRSUAPI replication chain (mirror MakeMeEnterpriseAdmin):

1. `DrsBind` (op 0).
2. `DrsDomainControllerInfo` (op 600) — locate target DC.
3. `DRSCrackNames` (op 442) — resolve principal → DSNAME.
4. `DRSGetNCChanges` (op 134) — pull replication payload
   (`UNICODE_PWD`, `NT_PWD_HISTORY`, `SUPPLEMENTAL_CREDENTIALS`).
5. Decrypt with session-key-derived RC4 + per-RID DES + CRC32 check.
6. Output as impacket-style `user:rid:lm:nt:::` lines.

### File structure

- `credentials/dcsync/dcsync.go` — orchestration.
- `credentials/dcsync/decrypt.go` — RC4 / DES / CRC32 unwrap (pure
  Go, cross-platform).
- `credentials/dcsync/replication_attrs.go` — attribute-to-secret
  mapping (LM/NT/AES128/AES256/Kerberos keys).
- `credentials/dcsync/dcsync_test.go` — unit tests on decrypt path
  with golden fixtures + a behind-`MALDEV_DCSYNC_E2E=1` lab-only
  end-to-end against a test DC.

### Risk

- High operational detection — DCSync over DRSUAPI is one of the
  most-watched primitives in any AD-monitoring stack.
- The dep decision dominates effort.

---

## Chantier VII — SAM hive offline dump (`credentials/samdump`)

**Target:** new package; tag `v0.1.0`.
**Effort:** ~2 weeks (~1.5k LOC clean-room).
**MITRE ATT&CK:** [T1003.002 — OS Credential Dumping: Security Account
Manager](https://attack.mitre.org/techniques/T1003/002/).

### Scope

Offline NT-hash extraction from `SYSTEM` + `SAM` registry hives, with
no lsass involvement. Two operating modes:

1. **Live mode** — read locked hives via Volume Shadow Copy
   (`NtOpenDirectoryObject` against `\GLOBAL??\`,
   `NtQueryDirectoryObject` for `HarddiskVolumeShadowCopyN`,
   `NtCreateFile` against the shadow path). New helper
   `recon/shadowcopy/` worth carving out as a sibling package.
2. **Offline mode** — operator supplies pre-staged hives (e.g.
   exfilled separately). Pure-Go, cross-platform.

### Clean-room policy

D3Ext/maldev's only credential code is a thin wrapper over
**`C-Sto/gosecretsdump`** which is **GPL-3.0** — vendoring or
importing it would force GPL on every binary that links maldev.
Reject.

Implement clean-room from:

- impacket `secretsdump.py` algorithm description (pseudocode in the
  source comments — well-documented, not copyrightable).
- Microsoft's published hive format (Open Specifications
  MS-RegFile + reverse-engineered docs).
- SharpKatz `Module/Sam.cs` (BSD-3, mineable) for syskey scramble +
  per-RID NT hash unwrap reference.
- Use `gosecretsdump` ONLY as a correctness oracle during dev (test
  outputs against it offline, never link).

### Dependencies

Pure Go, no new external deps. Reuses `win/ntapi` for
`NtOpenDirectoryObject`/`NtQueryDirectoryObject`.

### File structure

- `recon/shadowcopy/shadowcopy_windows.go` — VSS enumeration helper.
- `recon/shadowcopy/shadowcopy_windows_test.go` — mock + intrusive.
- `credentials/samdump/hive_parser.go` — pure-Go .hiv reader.
- `credentials/samdump/syskey.go` — JD/Skew1/GBG/Data permutation.
- `credentials/samdump/samkey.go` — RC4/AES SAM-key derivation.
- `credentials/samdump/decrypt.go` — per-RID NT hash unwrap.
- `credentials/samdump/samdump.go` — orchestration + impacket output
  format.
- `credentials/samdump/*_test.go` — fixture tests.

### Commit train

1. `recon/shadowcopy/` skeleton + intrusive test.
2. Hive parser + syskey extractor (pure-Go, cross-platform).
3. SAM key derivation + per-RID unwrap.
4. End-to-end `Dump(systemHive, samHive io.ReaderAt) ([]Account, error)`.
5. Live mode wiring (Windows-only): shadow copy → hive open → parser.

---

## Aggregate

| Chantier | Tag | LOC | Days | Wave | Blocked by |
|---|---|---|---|---|---|
| ~~I — `lsasrvProfile` refactor~~ | ~~(internal)~~ | ~~200–300~~ | ✅ shipped (already done as `Template`) | — | — |
| II — PTH write-back + impersonate | sekurlsa v0.33.0 | 350 | 4 | 1 | — |
| III — Kerberos tickets | sekurlsa v0.34.0 | 400 + 3d port | 7 | 2 | gokrb5 fork |
| IV — Win11 sigs validation + lea fallback | sekurlsa v0.34.x | RE work + 150 | 4 | 2 | — |
| V — Golden Ticket (builder + injector) | goldenticket v0.1.0 | 500 + 3d port | 6 | 2 | gokrb5 fork |
| VI — DCSync | dcsync v0.1.0 | 600–1200 + 4d port | 18 | 3 | msrpc fork |
| VII — SAM dump (clean-room) | samdump v0.1.0 | 1500 | 14 | 3 | recon/shadowcopy |

**Total:** ~3,400–4,000 LOC across 7 chantiers + 4 new tags + 2 new
top-level packages (`credentials/goldenticket`, `credentials/dcsync`,
`credentials/samdump`, `recon/shadowcopy`).

### Suggested kickoff order

1. **Investigate `go-msrpc` older tags** — 1h, decides chantier VI's
   feasibility upfront.
2. **Chantier I** — 1d refactor, unlocks III + IV.
3. **Chantier II** (PTH) — biggest user-visible feature, mirrors
   SharpKatz cleanly. Independent.
4. **Chantier IV** (Win11 sigs) — addresses the cross-version test
   failures we already see this session. Pairs with I.
5. **Chantier III** (Kerberos tickets) — adds gokrb5 dep cleanly,
   completes the "pass-the-ticket" leg.
6. **Chantier V** (Golden Ticket) — light follow-up on top of III's
   gokrb5 wiring.
7. **Chantier VII** (SAM dump) — independent multi-day chantier.
8. **Chantier VI** (DCSync) — last, gated on dep decision.

### Risk register

| Risk | Mitigation |
|---|---|
| `go-msrpc` Go-version floor breaks our Win7 baseline | Pin or vendor + patch (see Dep budget). Reject only if A & B both fail. |
| Win11 22H2/24H2 sig harvest is rabbit-hole | Time-box at 3d per build; ship "best-effort table" with build tag. Out-of-table builds fall through to existing scan path. |
| GPL contamination via gosecretsdump | Hard policy: never import; clean-room only. Add a CI check that no GPL packages appear in `go.mod`. |
| PTH write to live PPL lsass detected | Document in package `doc.go` + require explicit `Confirm: true` in caller params. Never ship a `MustPth(...)`. |
| DCSync triggers AD monitoring | Out of our scope — operator's problem. Document detection level High. |

---

## Annex — License + provenance matrix

| Source | License | Integration model | Use? |
|---|---|---|---|
| `b4rtik/SharpKatz` | BSD-3 (per-file) | mine algorithms (different language) | Struct layouts + signatures + crypto helpers. |
| `vletoux/MakeMeEnterpriseAdmin` | (no license stated; PowerShell PoC) | technique reference only | DRSUAPI chain documentation. |
| `D3Ext/maldev` | MIT | not used | No relevant content (just wraps gosecretsdump). |
| `C-Sto/gosecretsdump` | **GPL-3.0** | **REJECTED** | Correctness oracle only (offline, never linked). GPL is sticky even when forked. |
| `oiweiwei/go-msrpc` | MIT | **fork → `internal/msrpc/`** | DCSync. Trim to MS-DRSR + auth + transports. |
| `jcmturner/gokrb5/v8` | Apache-2.0 | **fork → `internal/krb5/`** | Tickets, Golden Ticket. Trim to messages + crypto + PAC. |
| mimikatz (`gentilkiwi/mimikatz`) | CC BY 4.0 | reference | Win11 sigs + ticket serialisation. CC BY allows derivative work with attribution. |
| `wesmar/KvcForensic`, `wesmar/kvc` | MIT | reference | PPL bypass + lsasrv sigs (already cited). |

---

## Locked decisions (2026-04-26)

The five planning questions are resolved. Implementation proceeds
under these constraints:

1. **Integration model: Model C from the start** for both `gokrb5` and
   `go-msrpc`. No vanilla-import fallback. `internal/krb5/` and
   `internal/msrpc/` are first-class adapted forks with Caller / Opener
   / folder.Get threaded through every Win32/NT call site and every
   file read.
2. **Trim aggressiveness on `internal/krb5/`: Moderate.** Keep the
   full Kerberos client + crypto + PAC + keytab + krb5.conf parser +
   replay cache. Drop the KDC server, kadmin client, SPNEGO HTTP
   middleware, GSSAPI wrapper. Final size ~50% of upstream. Leaves
   the door open for chantier VI (DCSync needs the client) and any
   future c2/transport/kerberos.
3. **PTH `--impersonate` ships in the same chantier as write-back.**
   `credentials/sekurlsa` v0.33.0 includes both `PassTheHash` and the
   `SetThreadToken`-based impersonation flow.
4. **Golden Ticket builder + injector ship together** in
   `credentials/goldenticket` v0.1.0. The package is Windows-only at
   first release (the cross-platform builder half is unblocked once
   the v0.1.0 injector lands). Keeps the operator UX one-shot
   (`Forge → Submit`) instead of forcing a `klist` round-trip.
5. **`credentials/goldenticket` lives top-level** (sibling of
   `credentials/sekurlsa`, `credentials/dcsync`, `credentials/samdump`).
   No import-path coupling to sekurlsa even though it commonly
   consumes sekurlsa output.
