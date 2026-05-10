# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html). Pre-1.0 minor bumps may
introduce breaking API changes.

## [Unreleased]

### Packer chantier — v0.88 → v0.90 (2026-05-10)

**Note:** version-section discipline in this CHANGELOG drifted between
v0.18 and v0.87; this entry consolidates the most recent packer chantier
without backfilling the intermediate gap (a separate audit ticket).

#### v0.90.0 (2026-05-10) — polymorphism slots B & C

- `pe/packer`: V2-Negate (Linux) and V2NW (Windows) all-asm bundle
  stubs gain two new in-Builder polymorphism slots — slot B between
  CPUID prologue and scan-loop entry, slot C between matched-pointer
  computation and decrypt step. Combined with the pre-existing
  post-Encode slot A, per-pack stub diversity surface tripled
  (4-80 byte total NOP insertion vs the prior 4-32 byte single-slot).
- Builder labels auto-resolve every Jcc displacement crossing the
  new slots; the public stub functions retain their no-arg signatures
  via thin `…Rng(rng)` cores so existing callsites stay untouched.
- `cmd/packerscope`: `extract` verb round-trip tests landed (canonical
  + per-build-secret + wrong-secret negative path) — Tier 🟢 #3.2.
- Dead code retirement: V1 stubs (`bundleStubVendorAware`,
  `bundleStubVendorAwareWindows`) and V2-plain
  (`bundleStubVendorAwareV2`) deleted; −1019 LOC net. V2-Negate /
  V2NW inherit the imm32 + PIC-prefix contracts via direct pin tests.
- Internal refactor: 4 shared emitters extracted (`emitBundlePICTrampoline`,
  `emitCPUIDVendorPrologue`, `emitCPUIDFeaturesProbe`,
  `emitBundleLoopSetup`) for the cross-platform prefix.

#### v0.89.0 (2026-05-10) — Tier 🔴 close: every FingerprintPredicate bit operational

- `cmd/packer`: `-pl` bundle spec extended with optional `:negate`
  suffix — `<file>:<vendor>:<min>-<max>[:negate]`. Operators can now
  build "match EXCEPT this" rules from the CLI without a Go shim.
- `docs/techniques/pe/packer.md`: refreshed for V2-Negate / V2NW
  wire-in state. Mode 5 (all-asm) predicate-evaluator row upgraded
  from "PT_MATCH_ALL + PT_CPUID_VENDOR" to the full vocabulary
  (PT_MATCH_ALL + PT_CPUID_VENDOR + PT_WIN_BUILD + PT_CPUID_FEATURES
  + Negate). Stale "Mode 5 queued" limitations removed.

#### v0.88.0 (2026-05-10) — V2-Negate + V2NW wired into public Wrap APIs

- `pe/packer`: `WrapBundleAsExecutableLinux*` switched from the V1
  hand-encoded scan stub to `bundleStubVendorAwareV2Negate` —
  operators setting `FingerprintPredicate.Negate = true` now see
  it honoured by the all-asm path (previously only the Go-runtime
  evaluator + host-side `SelectPayload` did).
- `pe/packer`: `WrapBundleAsExecutableWindows*` switched to
  `bundleStubV2NegateWinBuildWindows` — adds `PT_WIN_BUILD`
  predicate via `EmitPEBBuildRead` (reads `PEB.OSBuildNumber`,
  Windows-only).
- `pe/packer`: `PT_CPUID_FEATURES` predicate wired into both V2-Negate
  and V2NW (CPUID leaf 1 → ECX features → per-entry mask + value
  compare). Final reserved predicate bit now operational.
- `amd64.Builder`: gained `ANDB` / `MOVZBL` / `XORB` primitives to
  let the decrypt loop emit through the Builder instead of RawBytes;
  shared `emitDecryptStep` helper unifies the 6-instruction SBox
  block across V2-Negate, V2NW, and (briefly) V2-plain.

### Added — `credentials/lsassdump` v0.31.4 — `FindLsassEProcess` walker

Closes the kvc-inspired chantier with a Windows-only high-level
helper that resolves lsass.exe's kernel EPROCESS VA from a PID,
without requiring upstream tooling.

`FindLsassEProcess(rw driver.ReadWriter, lsassPID uint32) (uintptr, error)`
ties together every v0.31.x discovery primitive:

1. Resolve ntoskrnl.exe's kernel-mode base via
   `NtQuerySystemInformation(SystemModuleInformation)` (admin
   required, same baseline as the BYOVD path).
2. Resolve the runtime-disk offsets:
   - `DiscoverInitialSystemProcessRVA` — RVA of the
     `PsInitialSystemProcess` global pointer inside ntoskrnl.
   - `DiscoverUniqueProcessIdOffset` — EPROCESS.UniqueProcessId.
   - `DiscoverActiveProcessLinksOffset` — = upid + 8.
3. Read 8 bytes at `kernel_base + InitialSystemProcessRVA` via
   `rw.ReadKernel` → System EPROCESS (PID 4, head of the
   PsActiveProcessLinks chain).
4. Walk the doubly-linked LIST_ENTRY chain via
   `walkProcessChain` (extracted into a separately-testable helper).
   Each `ActiveProcessLinks.Flink` is the address of the next
   process's embedded list-entry; subtracting `apLinksOff` recovers
   the EPROCESS containing-struct base. Bounded at 4096 iterations,
   loop-back detected against the head.

`walkProcessChain` is unexported but exposed through synthetic
mock-RW tests (4 walk scenarios: target-found, head-match,
not-found, nil-Flink-break) plus 2 guard tests on
`FindLsassEProcess` itself (nil rw, zero PID). Real-kernel
validation requires admin + a live Windows host — out of scope
for unit tests but trivially exercised once an operator runs the
high-level path against their target.

`ErrLsassEProcessNotFound` sentinel for callers needing to retry
after a lsass restart (PID changes between dump and walk).

After v0.31.4 the full PPL-bypass + dump flow looks like:

	rw := byovd.LoadRTCore64()                       // 1. BYOVD reader/writer
	defer byovd.Unload()
	pid := process.LookupByName("lsass.exe")         // 2. PID from PEB walk
	eprocess, _ := lsassdump.FindLsassEProcess(rw, pid) // 3. Auto-find EPROCESS
	tok, _ := lsassdump.Unprotect(rw, eprocess, lsassdump.PPLOffsetTable{}) // 4. Auto-discover offset
	defer lsassdump.Reprotect(tok, rw)
	h, _ := lsassdump.OpenLSASS(nil)                 // 5. NtOpenProcess(VM_READ)
	defer lsassdump.CloseLSASS(h)
	lsassdump.Dump(h, &buf, nil)                     // 6. Capture minidump

— no hand-curated PPLOffsetTable, no upstream EPROCESS lookup.
Just a PID and a kernel ReadWriter.

### Added — `credentials/lsassdump` v0.31.3 — extended kvc-style OffsetFinder

Three new discovery helpers that mirror kvc's full OffsetFinder
class. All operate on ntoskrnl.exe in user mode (pure-Go,
debug/pe), no kernel-mode read needed for the discovery itself.

- `DiscoverUniqueProcessIdOffset(path)` — extracts
  EPROCESS.UniqueProcessId from PsGetProcessId's first instruction
  (`48 8B 81 [disp32]` = `mov rax, qword ptr [rcx+disp32]`).
- `DiscoverActiveProcessLinksOffset(uniqueProcessIDOff)` — pure
  arithmetic (= upid + 8 on x64; sizeof(HANDLE)). Stable Vista →
  Win 11 25H2.
- `DiscoverInitialSystemProcessRVA(path)` — locates the
  `PsInitialSystemProcess` global pointer's RVA inside ntoskrnl.
  At runtime, reading 8 bytes at `ntoskrnl_kernel_base + RVA` via
  a kernel-mode ReadWriter yields the System EPROCESS — head of
  the `PsActiveProcessLinks` doubly-linked list. Combined with
  ActiveProcessLinks offset, this lets a future `FindLsassEProcess`
  walk every process and locate lsass by PID.

**Real-binary results on Win 10 22H2 build 19045 ntoskrnl.exe:**

	EPROCESS.Protection             = 0x87A
	EPROCESS.SignatureLevel         = 0x878
	EPROCESS.SectionSignatureLevel  = 0x879
	EPROCESS.UniqueProcessId        = 0x440
	EPROCESS.ActiveProcessLinks     = 0x448
	PsInitialSystemProcess RVA      = 0xCFC420

5 new tests (3 unit, 2 env-gated real-binary). 9/9 tests green
total in the package; the 3 env-gated tests pass against the
captured ntoskrnl.exe.

Sets up v0.31.4: high-level `FindLsassEProcess` that ties the
helpers together with a runtime kernel-base lookup
(NtQuerySystemInformation/SystemModuleInformation) so operators
no longer need to provide the eprocess argument to Unprotect.

### Changed — `credentials/lsassdump` v0.31.2 — `Unprotect` auto-discovers ProtectionOffset when zero

When `tab.ProtectionOffset == 0`, `Unprotect` now calls
`DiscoverProtectionOffset("")` (which parses
`%SystemRoot%\System32\ntoskrnl.exe`) and uses the result. If the
discovery fails (locked-down host, no SystemRoot env, ntoskrnl
unreadable, etc.), the error wraps `ErrInvalidProtectionOffset`
so `errors.Is` callers continue to work.

Operators on a covered build (Win 10 19045+, Win 11 22000+) can
now drop the `PPLOffsetTable.ProtectionOffset` argument entirely:

	tok, err := lsassdump.Unprotect(rw, eprocess, lsassdump.PPLOffsetTable{})
	// auto-discovers from ntoskrnl.exe in user mode

The explicit-offset path remains supported and recommended for
operators on locked-down hosts where ntoskrnl.exe is unreadable
or hidden behind a custom kernel image path.

`PPLToken.ProtectionOffset` now records the offset actually used
(auto-discovered OR caller-supplied), so `Reprotect` writes back
to the same byte. Bug-fix: prior to v0.31.2 the token always
captured `tab.ProtectionOffset`, which would have been 0 when
auto-discovery had succeeded — `Reprotect` would have written to
`eprocess + 0` (a stomp on the EPROCESS struct head).

`TestUnprotect_ZeroProtectionOffset` renamed to
`TestUnprotect_ZeroProtectionOffsetTriggersAutoDiscovery` — uses
`t.Setenv("SystemRoot", ...)` to force discovery failure and
verify the wrapped sentinel.

### Fixed — `credentials/lsassdump` v0.31.1 — extractor handles all 3 prologue variants

Real-binary validation against a Win 10 22H2 build 19045
ntoskrnl.exe surfaced two prologue variants v0.31.0's extractor
didn't handle:

- `PsIsProtectedProcess` → `F6 81 [disp32] [imm8]`
  (test byte ptr [rcx+disp32], imm8)
- `PsIsProtectedProcessLight` → `8A 91 [disp32]`
  (mov dl, byte ptr [rcx+disp32])

v0.31.0 only matched `0F B6 81 [disp32]` (movzx). The compiler
picks any of these three lowerings depending on the target build's
optimization profile.

Generalized the matcher: it now recognises any one-byte opcode
followed by a ModR/M byte that encodes `[rcx+disp32]` (mask
`0xC7` against `0x81` — i.e., `mod=10b, rm=001b`), and the
two-byte `0F xx [ModR/M]` form for movzx and friends. New
`isModRMRcxDisp32` helper documents the bit pattern.

**Real-binary result on Win 10 22H2 build 19045:**

	EPROCESS.Protection offset = 0x87A
	EPROCESS.SignatureLevel offset = 0x878
	EPROCESS.SectionSignatureLevel offset = 0x879

Both PsIsProtectedProcess and PsIsProtectedProcessLight extracted
the same offset (cross-validation passed).

5/5 tests green; the env-gated TestDiscoverProtectionOffset_RealNtoskrnl
now passes against a captured ntoskrnl.exe.

### Added — `credentials/lsassdump` v0.31.0 — dynamic EPROCESS offset discovery

Ports the offset-finding technique from
[wesmar/kvc](https://github.com/wesmar/kvc) (MIT) into
`credentials/lsassdump`. Eliminates the need for a hand-curated
`PPLOffsetTable` per Windows build — the EPROCESS.Protection byte
offset can now be derived at runtime by parsing ntoskrnl.exe in
user mode.

How it works: every Win 10/11 ntoskrnl.exe exports
`PsIsProtectedProcess` and `PsIsProtectedProcessLight`, both of
which compile to a trivial wrapper:

	movzx eax, byte ptr [rcx + EPROCESS.Protection_offset]
	test  eax, eax
	setnz al
	ret

The first instruction is always `0F B6 81 disp32` (5 bytes — the
movzx opcode + ModR/M for `[RAX, [RCX+disp32]]`). The disp32 IS
the EPROCESS.Protection field offset. Reading 7 bytes from the
function's RVA in the file and decoding the disp32 gives the
offset; cross-validating against PsIsProtectedProcessLight catches
malformed extracts.

**v0.31.0 surface:**

- `DiscoverProtectionOffset(path string) (uint32, error)` — the
  main entry point. Pass an empty path to default to
  `%SystemRoot%\System32\ntoskrnl.exe`; pass an explicit path on
  Linux/CI to point at a captured ntoskrnl.
- `SignatureLevelOffset(protection uint32) uint32` — derives
  EPROCESS.SignatureLevel offset (= protection - 2) per kvc.
- `SectionSignatureLevelOffset(protection uint32) uint32` —
  EPROCESS.SectionSignatureLevel offset (= protection - 1).
- `ErrProtectionOffsetNotFound` sentinel for `errors.Is` dispatch.

**Why we didn't port kvc's full PPL bypass.** kvc's bypass uses
a CUSTOM signed driver and requires defeating Driver Signature
Enforcement (DSE) first. Our existing
`credentials/lsassdump.Unprotect` uses RTCore64 BYOVD — already
signed by Microsoft (vulnerable but signed), no DSE bypass needed.
kvc is operationally heavier; we keep RTCore64 as the primary
path and port only the offset-discovery technique.

5 new tests: arithmetic identities for the two Signature*Level
helpers, error paths for non-existent / non-PE inputs, plus an
env-gated end-to-end test (`MALDEV_NTOSKRNL=<path>`) that pulls a
real ntoskrnl.exe through the discovery and asserts a plausible
offset range.

### Fixed — `credentials/sekurlsa` v0.30.4 — TSPkg AVL refactor + signature/layout fix

Continued real-binary refinement, this time TSPkg. Three problems
surfaced and fixed against the Win 10 22H2 build 19045 dump:

1. **Wrong signature byte.** KvcForensic JSON ships
   `48 83 EC 20 48 8B 0D` (MOV via pointer); pypykatz ships
   `48 83 EC 20 48 8D 0D` (LEA of address). The dump confirms only
   the LEA variant matches in tspkg.dll on this build. We now
   ship pypykatz's value as the default.

2. **Linked-list walker → AVL walker.** Same fix pattern as
   v0.30.3 Kerberos. extractTSPkg now derefs once
   (LEA_target → table_ptr), reads the RTL_AVL_TABLE, walks the
   tree, and at each AVL node dereferences the user_data at +0x20
   to reach the actual KIWI_TS_CREDENTIAL.

3. **Wrong outer-node offsets + UserName/Domain swap.** The
   KIWI_TS_CREDENTIAL_1607 layout per pypykatz has
   LUID at +0x70 (not +0x10), pTsPrimary at +0x88 (not +0x18). The
   inner KIWI_TS_PRIMARY_CREDENTIAL stores UserName and Domain at
   SWAPPED slots — a Microsoft quirk pypykatz documents. Our
   decoder now swaps them back so callers see the canonical pair.

Real-binary status on Win 10 22H2 build 19045: TSPkg walker runs
clean (no warning, no junk credentials) — the dump's tspkg.dll
session AVL is empty because no RDP / Terminal Services session
was active when the snapshot was taken. The walker correctly
produces zero credentials in that case rather than hanging or
emitting bogus data.

The synthetic-fixture HappyPath test was rewritten as
`TestDecodeTSPkgNode_SwapsUserNameAndDomain` — a focused unit test
on `decodeTSPkgNode` that exercises the swap quirk + new layout.
The full extractTSPkg pipeline is now validated end-to-end via
real-binary parser runs (pre-existing avl_test.go covers the AVL
machinery; tspkg_test.go covers the inner-struct decode).

112/112 tests green.

### Fixed — `credentials/sekurlsa` v0.30.3 — Kerberos AVL user_data deref (real-binary validated)

**Real-binary validation: 4 Kerberos credentials extracted from a
Win 10 22H2 dump, including `DESKTOP-41TGTR3\test` with both an
MSV NT hash and 2 Kerberos tickets.**

The remaining bug after v0.30.2: AVL nodes are NOT the
KIWI_KERBEROS_LOGON_SESSION structs themselves — each AVL node is
laid out as `[RTL_BALANCED_LINKS (0x20 bytes)][user_data]`, and
the user_data at +0x20 is a *pointer* to the actual session
struct. My v0.30.1 walker called `decodeKerberosSession` directly
on the AVL node's address, which is the BalancedLinks (Parent /
Left / Right pointers). Result: every "session" had garbled
fields because we were reading session-struct offsets out of the
balanced-links bytes.

Diagnosed by writing `kerb_probe_test.go` — env-gated dump
introspection that prints the bytes at globalVA + at *globalVA
and applies an AVL-shape sniffer (Parent self-ref + Right pointing
into userland). The dump confirmed: globalVA IS the table (Parent
self-ref + Right at lsass-heap VA), and the fix is at the
*per-node* level via the user_data offset.

Fix: `walkAVL` callback now reads `*(node + 0x20)` to get the
session pointer, then reads the session struct at THAT address.
New constant `avlNodeUserDataOffset = 0x20` documents the layout.

Result on the Win 10 22H2 dump:

  Session  LUID         Cred types
  -------  -----------  ----------------------------
  test                  MSV1_0 + Kerberos (2 tickets)
  machine$ (3E4/3E7)    MSV1_0 + Kerberos (2 tickets each)
  test (orphan AVL LUID 3D49D) → new session, 2 tickets

Same approach should fix TSPkg once the build-19045 signature
lands. Queued for v0.30.4.

`kerb_probe_test.go` ships as a gated diagnostic
(`MALDEV_REALDUMP=<path>`) for anyone needing to triage future
build variations. 112/112 tests green at default, +1 gated probe.

### Fixed — `credentials/sekurlsa` v0.30.2 — Kerberos pointer chain + field offsets per pypykatz Win 10 1607+

Continued real-binary refinement of the Kerberos walker. Two fixes:

1. **Extra pointer indirection.** Pypykatz's `find_first_entry`
   does `ptr_entry_loc = get_ptr_with_offset(...)` (= our derefRel32)
   THEN `ptr_entry = get_ptr(ptr_entry_loc)` — i.e., the LEA target
   is the address of a *pointer* to the RTL_AVL_TABLE, not the
   table itself. The v0.30.1 walker skipped that second deref and
   walked the wrong tree root. Fixed by adding `readPointer` between
   `derefRel32` and `readAVLTreeRoot`.

2. **KIWI_KERBEROS_LOGON_SESSION_10_1607 field offsets.** Manually
   walked the pypykatz Python struct definitions for Win 10 1607+
   (the same layout family our build 19045 dump targets). Updated:
   - LUIDOffset 0x48 (was 0x48 — already correct)
   - UserNameOffset 0x78 → **0x88** (credentials sub-struct moved)
   - DomainOffset 0x88 → **0x98**
   - PasswordOffset 0xA8 → **0xB8**
   - TicketEncTypeOffset 0x134 → **0x124**
   - TicketKvnoOffset 0x138 → **0x128**
   - TicketBufferLenOffset 0x140 → **0x130**
   - TicketBufferPtrOffset 0x148 → **0x138**

   KvcForensic JSON values were 16 bytes higher (0x134/0x138/0x140/
   0x148) — they appear to target a later build with one extra
   16-byte field inserted in the back half. We ship pypykatz's
   Win 10 1607+ values as primary defaults; KvcForensic-style
   builds need an operator override.

3. NodeSize bumped from 0x180 → 0x200 to cover the longer session
   struct (credentials sub-struct + ticket-list pointers + extras).

**Real-binary status on Win 10 22H2 build 19045:** the AVL walker
fires through the corrected indirection chain, but session-struct
offsets on this specific build still produce non-aligned LUIDs and
empty UserName/Domain UNICODE_STRING reads — suggests our LEA's
target on this binary lands somewhere other than `g_kerb_table_ptr`,
or the build has a layout variant pypykatz doesn't yet document.
Disassembly walk on a real kerberos.dll image is the next step;
queued for v0.30.3.

### Added — `credentials/sekurlsa` v0.30.1 — RTL_AVL_TABLE walker for Kerberos

Vista+ Kerberos uses an `RTL_AVL_TABLE` (balanced binary tree) for
session enumeration, NOT a flat doubly-linked LIST_ENTRY chain. The
v0.26.1 walker assumed Flink-at-offset-0 semantics — on AVL nodes,
that position holds the Parent pointer, so the walker walked UP to
the root sentinel and stopped without surfacing any sessions. The
real-binary diagnostic in v0.30.0 confirmed this on a Win 10 22H2
dump (signature matched in kerberos.dll, walker returned zero).

What ships:

- New `credentials/sekurlsa/avl.go` with a generic `walkAVL` helper
  that traverses an `RTL_AVL_TABLE`-rooted tree in-order, with a
  visited-set guard against corrupted-dump cycles and an explicit
  maxNodes cap.
- New `readAVLTreeRoot` helper that dereferences
  `RTL_AVL_TABLE.BalancedRoot.RightChild` (offset +0x10 of the
  table) — the actual tree root that callers pass to walkAVL.
- `extractKerberos` refactored to call `readAVLTreeRoot` +
  `walkAVL` instead of the Flink-chain walker. The session layout
  + ticket-cache walks remain unchanged (Kerberos tickets are
  still flat lists per cache).
- LUID-fallback heuristic improved: triggers when the primary
  read is zero OR when the upper-32 bits are non-zero (real LUIDs
  allocated by NT stay well under 2^32; an upper-bits-set value
  is almost always a stray pointer).
- `KerberosLayout` defaults updated: LUIDOffset shifts from
  0x40 (KvcForensic Vista-generic) to 0x48 (pypykatz Win 10
  1607+ struct), with the fallback list reordered. Real-binary
  validation surfaces 2 Kerberos sessions where v0.26.1 surfaced
  zero — but field offsets (UserName, Domain, ticket layout) on
  Win 10 22H2 still produce junk; per-build refinement queued.
- maxTickets cap reduced from 256 → 32 to limit junk-ticket
  runaway when offsets misalign (real caches rarely exceed
  ~20 tickets per session).
- 5 new unit tests for walkAVL + readAVLTreeRoot covering in-order
  traversal, empty root, maxNodes cap, cycle detection, and
  table-root deref. 112/112 tests green (was 108).

Real-binary status on Win 10 22H2 build 19045:
- AVL walker fires + visits Kerberos session nodes ✅
- LUID extraction lands on stray pointers (per-build offsets need
  to land on the actual Win 10 1607+ session struct LUID at +0x48
  inside the BalancedLinks-prefixed node) — refinement queued.

TSPkg also uses an AVL on Vista+ but the v0.30.0 diagnostic shows
its KvcForensic signature `48 83 EC 20 48 8B 0D` doesn't match in
tspkg.dll on this build — separate refinement before the AVL
refactor lands there.

### Added/Fixed — `credentials/sekurlsa` v0.30.0 — DPAPI fallback to dpapisrv.dll + diagnostic infrastructure

Real-binary validation continued. Findings documented in package
doc + diagnostic test infrastructure shipped.

- **DPAPI fallback**: `Parse()` now scans `lsasrv.dll` for the
  master-key cache list head, then falls back to `dpapisrv.dll`
  when the lsasrv scan yields no keys. Mirrors pypykatz's `for
  modulename in ['lsasrv.dll','dpapisrv.dll']:` loop.
- **TestRealDumpDiagnostics**: env-gated diagnostic
  (MALDEV_REALDUMP=<path>) that scans every default template's
  signature in its candidate module(s) and reports per-module
  match counts + first-match VAs. Used to triage which templates
  match and which need refinement against a real binary.
- **Documented v0.30.0 findings** in package doc:
  - MSV1_0: validated end-to-end on Win 10 22H2 build 19045 dump.
  - Wdigest: signature matches, cache empty (UseLogonCredential=0
    default — expected).
  - DPAPI: lives in dpapisrv.dll on this build; fallback validated.
  - Kerberos: signature matches in kerberos.dll BUT Vista+ uses an
    RTL_AVL_TABLE instead of a flat doubly-linked list — current
    walker returns zero silently. AVL refactor queued.
  - TSPkg: signature mismatched on build 19045; same AVL-tree
    caveat as Kerberos.
- 108/108 tests green (was 107; +1 diagnostic test).

### Fixed — `credentials/sekurlsa` v0.29.2 — real-binary validation surfaced two critical bugs

**First end-to-end run against a real Win 10 22H2 lsass dump (build
19045) surfaced two bugs the synthetic-fixture suite couldn't see.
Both are fixed; MSV1_0 NT-hash extraction now round-trips on real
binaries.**

1. **`ModuleByName` matched full paths verbatim.** Real Win 10/11
   dumps store full paths in MODULE_LIST (`C:\Windows\system32\
   lsasrv.dll`); the synthetic tests passed bare basenames. The
   matcher now reduces both sides to the basename via a new
   `basename` helper before case-insensitive comparison. Callers
   may pass either form.
2. **The LSA crypto chain skipped one indirection.** The previous
   parser expected a flat BCRYPT_KEY_DATA_BLOB at the rel32 target;
   real lsass uses a 3-level pointer chain instead:
   `LEA → BCRYPT_KEY_HANDLE → KIWI_BCRYPT_HANDLE_KEY (+0x10) →
   KIWI_BCRYPT_KEY (cbSecret @+0x38, data @+0x3C)`. The synthetic
   test passed because it built a fake KDBM blob at the handle's
   first indirection — a tautology. v0.29.2 walks the real chain
   via the new `readKiwiKey` helper and `instantiateCipher` (which
   wraps raw key bytes 8/16/24/32 → DES/AES-128/3DES/AES-256).
   Constants `kiwiHandleKeyKeyPtrOffset = 0x10` /
   `kiwiKeyCbSecretOffset = 0x38` / `kiwiKeyDataOffset = 0x3C` are
   stable Vista → Win 11 25H2 per pypykatz + KvcForensic JSON.

The synthetic test helper `buildKDBM` + the now-unused
`parseBCryptKeyDataBlob` are removed; tests across the package use
`instantiateCipher(rawKey)` directly which is the actual production
path.

**Real-binary validation result** on a Win 10 22H2 dump (build 19045):
- 10 logon sessions surfaced
- 1 real NT/LM hash extracted (interactive `test` user)
- 9 SYSTEM / service accounts with empty hashes (placeholder)
- DPAPI + TSPkg signatures don't match this build's lsasrv.dll —
  follow-up in v0.30.0 to derive the per-build offsets.

Also includes the path-based ModuleByName regression test +
TestBasename. 107/107 tests green.

### Added — `credentials/sekurlsa` v0.29.0 — x86 dump detection + rejection

WoW64 / legacy x86 lsass dumps are now detected at Parse() entry and
rejected with a new sentinel `ErrUnsupportedArchitecture`. The
partial Result still populates `BuildNumber` + `Architecture` +
`Modules` so callers can report the rejection cleanly with full
context.

Rationale: implementing the x86 walker would require a parallel set
of layouts with 4-byte pointers + 8-byte UNICODE_STRINGs (vs x64's
8-byte pointers + 16-byte UNICODE_STRINGs) — roughly 400 LOC of
near-duplicated code that operationally yields little because modern
Win 10/11 lsass is x64 by default. Operators on x86-only targets
should use pypykatz which has dedicated x86 layout support.

What ships:

- `ErrUnsupportedArchitecture` sentinel + Parse() short-circuit
  (returns the partial Result with the sentinel wrapped via fmt.Errorf
  so callers can `errors.Is` to dispatch).
- 2 new unit tests covering x86 (`ProcessorArchitecture=0`) and
  ARM64 (`ProcessorArchitecture=12`) rejection. Both produce the
  same sentinel — the parser is x64-only regardless of the specific
  non-x64 architecture.

105/105 tests green (was 103; +2 from arch rejection).

This closes the v0.2x.x credential-extraction roadmap. After v0.29.0
the sekurlsa package supports:

| Provider | Status |
|---|---|
| MSV1_0 | inline default templates Win 7 → Win 11 25H2 |
| Wdigest | inline default templates Win 7 → Win 11 25H2 |
| DPAPI master keys | inline default templates Win 10+ |
| TSPkg (RDP) | inline default templates Win 7 → Win 11 25H2 |
| Kerberos (password + tickets) | inline default templates Win 7 → Win 11 25H2 |
| CredMan / Vault | framework; per-build layouts opt-in |
| CloudAP (Azure AD PRT) | framework; per-build layouts opt-in |
| LiveSSP (legacy MSA) | framework; per-build layouts opt-in |
| x86 / WoW64 | detected + rejected with sentinel |

### Added — `credentials/sekurlsa` v0.28.0 — CloudAP + LiveSSP providers (framework)

Seventh and eighth credential providers — covering modern (Azure AD)
and legacy (Microsoft Account) cloud-auth flows.

**CloudAP** (`cloudap.dll`, Win 10+) is the modern cloud-auth
provider. Azure AD-joined accounts, Microsoft Account SSO, hybrid
AD-joined sessions all route through it. The big prize is the
**Primary Refresh Token (PRT)** — feed it to a downstream tool like
AADInternals to derive a session token and pivot to any Azure AD
application the account can reach.

**LiveSSP** (`livessp.dll`, Win 8+) is the legacy Microsoft Account
SSP, mostly superseded by CloudAP from Win 10 forward. Same
walker shape as Wdigest — single doubly-linked list with
plaintext password (encrypted, decrypt with LSA keys).

What ships:

- `CloudAPCredential` (UserName + AccountID + PRT bytes) +
  `CloudAPLayout` with both pointer-and-inline PRT-read modes —
  Win 10 LCUs vary on this.
- `LiveSSPCredential` (UserName + LogonDomain + Password) +
  `LiveSSPLayout`. Same shape as TSPkg.
- Both walkers add `*ListPattern` / `*ListWildcards` / `*ListOffset`
  + `*Layout` fields to `Template`. Eight credential types now
  coexist in `Session.Credentials`.
- Parse() scans `cloudap.dll` and `livessp.dll` after Kerberos.
  Same merge-by-LUID + orphan-surface semantics as the other
  per-DLL walkers.
- 15 new unit tests including merge graft/orphan/empty + bounds
  guards.

**v0.28.0 ships framework-only.** Default templates leave both
providers disabled (NodeSize=0). KvcForensic's JSON has no entries
for CloudAP / LiveSSP — their layouts shift between Win 10 LCUs
more aggressively than older providers, so default auto-enable
awaits per-build verification against real binaries.

103/103 tests green (was 88; +15 from CloudAP+LiveSSP).

### Added — `credentials/sekurlsa` v0.27.0 — CredMan / Vault provider (framework)

Sixth credential provider — Windows Credential Manager (Vault).
CredMan stores RDP saved sessions, IE/Edge form passwords,
network-share credentials, git/HTTP token entries, and any
`CredentialAdd` (advapi32) entry whose persistence type is
`CRED_PERSIST_LOGON_SESSION`.

Structurally different from the other providers: CredMan entries
are attached to an MSV LogonSession via a per-session pointer, not
a separate dll-global list. The walker is invoked from inside the
MSV walk via the new `MSVLayout.CredManListPtrOffset` field — when
non-zero, the session node carries a list-head pointer that the
CredMan walker follows.

What ships:

- `CredManCredential` implementing the `Credential` interface with
  `UserName` + `LogonDomain` + `Password` + `ResourceName`.
  `String()` renders `Resource | Domain\User:Password` so log lines
  show *what* the credential unlocks.
- `CredManLayout` struct + new fields on `MSVLayout`:
  `CredManListPtrOffset` (pointer to list head, 0 = disabled) +
  `CredManLayout` (per-node layout when the walker runs).
- The walker hooks into `decodeLogonSession` so CredMan credentials
  appear directly in `Session.Credentials` alongside the matching
  `MSV1_0Credential` — no separate merge-by-LUID step.
- `readUnicodeStringIfFits` bounds-check helper guards against a
  layout whose offset would extend past `NodeSize`.
- 7 new unit tests including a synthetic-fixture round-trip
  exercising pattern → list walk → AES-CBC decrypt → UTF-16LE decode
  for a `TERMSRV/dc01` resource.

**v0.27.0 ships framework-only.** Default templates leave
`CredManListPtrOffset = 0` (disabled). KvcForensic's JSON ships the
pointer offset for Win 11 24H2+ (`session_credman_ptr_offset = 0x168`)
but no per-node layout values; operators with verified offsets
register an extended `MSVLayout` that fills both fields. Default
auto-enable for Win 11 24H2 will ship in v0.27.1 once the per-node
offsets are validated against a real binary.

88/88 tests green (was 81; +7 from CredMan).

### Added — `credentials/sekurlsa` v0.26.1 — Kerberos provider

Fifth credential provider — the most complex of the post-MSV
providers. Kerberos sessions in `kerberos.dll` carry a plaintext
password (when present) plus three ticket caches (TGT, TGS, MIT-style
imports). Each ticket carries service / target / client names, flags,
key + enc type, KVNO, and the raw ASN.1 ticket buffer.

What ships:

- `KerberosCredential` implementing the `Credential` interface with
  `UserName` + `LogonDomain` + `Password` + `[]KerberosTicket`. Five
  credential types now coexist in the same `Session.Credentials`
  slice: MSV1_0 / Wdigest / DPAPI / TSPkg / Kerberos.
- `KerberosTicket` carries `ServiceName` + `TargetName` + `ClientName`
  + `Flags` + `KeyType` + `EncType` + `KVNO` + `Buffer`. The buffer
  is the raw ASN.1 ticket bytes — feed to a downstream Kerberos
  parser (impacket / Rubeus / pypykatz `kerberos ccache`) for
  protocol-level inspection.
- `KerberosLayout` struct + `KerberosList{Pattern,Wildcards,Offset}`
  fields on `Template`. NodeSize=0 skips the walker.
- The walker handles three structural quirks:
  1. **LUID fallback offsets**: tries each in order if the primary
     LUID reads as zero — Microsoft has shifted the LUID's position
     across LCUs.
  2. **Multiple ticket caches per session**: walks each pointer in
     `KerberosLayout.TicketListOffsets` (default 3: TGT, TGS, …).
  3. **External-name decoding**: service / target / client are
     pointers to KIWI_KERBEROS_EXTERNAL_NAME structs with a
     NameCount field + N UNICODE_STRING components — joined with "/"
     so `krbtgt/CORP.LOCAL` round-trips correctly.
- Every default template (all 9 build ranges, Win 7 → Win 11 25H2 /
  Server 2025) now carries the Kerberos signature + layout per
  KvcForensic `Kerberos_x64_vista_plus`. One signature suffices
  because the kerberos.dll bootstrap prologue is unusually stable.
- 9 new unit tests including a `readExternalName` round-trip
  exercising the multi-component name decoder. **No full session
  fixture** — the layout is complex enough that a synthetic test
  would tautologically validate itself; real-binary validation is
  queued for VM dumps.
- 81/81 tests green (was 72; +9 from Kerberos).

### Added — `credentials/sekurlsa` v0.26.0 — TSPkg provider

Fourth credential provider on top of the v0.23.x crypto + walker
layers. Terminal Services Package (`tspkg.dll`) caches plaintext
RDP / Terminal Services credentials — the classic "domain admin
RDP'd to a server, we dump LSASS" scenario.

What ships:

- `TSPkgCredential` implementing the `Credential` interface alongside
  `MSV1_0Credential` + `WdigestCredential` + `DPAPIMasterKey`. Fields:
  `UserName` + `LogonDomain` + `Password` (plaintext after LSA decrypt).
- `TSPkgLayout` struct + `TSPkgList{Pattern,Wildcards,Offset}` fields
  on `Template`. `NodeSize=0` skips the walker at no cost.
- The outer `KIWI_TS_CREDENTIAL` carries a pointer to an inner
  `KIWI_TS_PRIMARY_CREDENTIAL` whose UserName / Domain / Password
  UNICODE_STRINGs sit at stable offsets (0x00 / 0x10 / 0x20 across
  every Win 7+ build). The walker dereferences the inner pointer and
  decrypts the Password buffer with the same lsaKey chain.
- `Parse()` now scans `tspkg.dll` (when present) after DPAPI. TSPkg
  credentials merge onto matching MSV/Wdigest/DPAPI sessions by LUID;
  orphan LUIDs surface as new sessions.
- 8 new unit tests including a synthetic-fixture round-trip
  exercising pattern → rel32 deref → outer-list walk → inner-pointer
  deref → AES-CBC decrypt → UTF-16LE decode → LUID-merge.
- Default templates include TSPkg signature + layout for every
  Win 7+ build per KvcForensic's `Tspkg_x64_vista_to_win10` /
  `Tspkg_x64_win11_24h2_plus` (same 7-byte signature, same
  first_entry_offset = 7).
- 72/72 tests green (was 64; +8 from TSPkg).

### Fixed/Added — `credentials/sekurlsa` v0.25.2 — KvcForensic-validated templates

Major rewrite of `default_templates.go` integrating the validated
per-build offsets from [KvcForensic](https://github.com/wesmar/KvcForensic)
(MIT, Marek Wesołowski). Compatible licensing means we can cite the
JSON values directly; maldev stays MIT.

Corrections applied:

- **MSV signatures** — replaced 2 hand-rolled signatures with
  KvcForensic's 9 validated ranges. Several v0.25.1 entries used the
  wrong byte sequence for their build window (e.g., Win 11 21H2 was
  paired with the Win 10 22H2 signature, missing the `45 89 34 24`
  prefix introduced at build 20348).
- **MSV first_entry_offset** — corrected per range. Win 8.1 / Server
  2012 R2 (9600-10239) uses offset 36 (not 23); Win 11 24H2+ uses 25
  (not 24); Win 11 22H2/23H2 (22100-26099) uses 27 (not 24).
- **LSA IV offset for Win 11 24H2+** — shifted from 0x43 to 0x47 per
  KvcForensic `LSA_24H2_plus`. Older builds keep 0x43 from pypykatz.
- **KIWI_MSV1_0_LIST_65 layout (Win 11 24H2+)** — corrected
  UserName=0xA0 (was 0x90), Domain=0xB0 (was 0xA0), SID=0xE0 (was
  0xD0). These match KvcForensic's `parser_support: true` data,
  exercised by their parser on real binaries.
- **Wdigest defaults** — added inline templates for both KvcForensic
  ranges: `WDigest_x64_pre11` (builds 6000-21999, sig `48 3B D9 74`)
  and `WDigest_x64_11plus` (builds 22000+, longer sig).
- **DPAPI defaults** — added inline `Dpapi_x64_win10_plus` for
  builds 14393+ (sig `48 89 4F 08 48 89 78 08`).

After v0.25.2, every default template in the registry includes
LSA + MSV1_0 + Wdigest + DPAPI signatures, with per-field session
offsets transcribed from KvcForensic (★/◎ where validated by their
parser; ▲ where pypykatz remains the only source).

Build coverage remains 9 ranges (KvcForensic boundaries):
7600-9199 / 9200-9599 / 9600-10239 / 10240-15062 / 15063-17133 /
17134-20347 / 20348-22099 / 22100-26099 / 26100-uint32max.

Test matrix: 23 build-coverage assertions (was 24 in v0.25.1) — added
Win 11 25H2 + far-future + Win 7 RTM coverage; removed obsolete
exclusions. 64/64 tests green.

### Added — `credentials/sekurlsa` v0.25.1 — Win7→Win11 24H2 / Server 2025 templates

- Built-in coverage now spans every NT6+ x64 Windows build pypykatz +
  mimikatz publicly document — Win 7 SP1 / Server 2008 R2 (build 7601)
  through Win 11 24H2 / Server 2025 (build 26100). Nine
  Template entries replace the previous two:
  | Build range | OS / Server family | MSV layout |
  |---|---|---|
  | 7601 | Win 7 SP1 / Server 2008 R2 | KIWI_MSV1_0_LIST_52 |
  | 7602–9200 | Win 8 / Server 2012 | KIWI_MSV1_0_LIST_60 |
  | 9600–14393 | Win 8.1 / Server 2012 R2 / Win 10 1507–1607 / Server 2016 | KIWI_MSV1_0_LIST_61 |
  | 15063–17763 | Win 10 1703–1809 / Server 2019 | KIWI_MSV1_0_LIST_62 |
  | 18362–19045 | Win 10 19H1–22H2 | KIWI_MSV1_0_LIST_63 |
  | 20348 | Server 2022 | KIWI_MSV1_0_LIST_63 |
  | 22000–22621 | Win 11 21H2–22H2 pre-22622 | KIWI_MSV1_0_LIST_63 |
  | 22622–22631 | Win 11 22622+ / 23H2 | KIWI_MSV1_0_LIST_64 |
  | 26100–26999 | Win 11 24H2 / Server 2025 | KIWI_MSV1_0_LIST_65 |
- Each Template carries a validation marker in source comments —
  ★ VM-validated, ◎ research-cited (most), ▲ best-effort. None are
  ★ yet: LSASS dump corpora aren't publicly available on GitHub
  (pypykatz's test set is local to Skelsec's NAS), so real-binary
  validation is queued for when we generate dumps from local VMs.
- Three new LSA crypto signature variants (`lsaSignatureWin7Sp1`,
  `lsaSignatureWin8`, `lsaSignatureCommon`) and three new MSV
  signatures (`msvSignatureWin7Sp1`, `msvSignatureWin8`,
  `msvSignatureWin11Late`) cover the bootstrap-prologue drift
  Microsoft introduced across builds.
- Test matrix grew from 10 to 24 build-coverage assertions in
  `TestDefaultTemplates_RegisteredAtInit`. 64/64 tests green.
- Framework degrades gracefully on a bad offset — `derefRel32` ⊕
  `findPattern` return ErrKeyExtractFailed cleanly, the parser
  surfaces the warning, MSV/Wdigest/DPAPI walkers continue with
  whatever did succeed. So speculative ▲ entries don't break Parse
  for unrelated builds.

### Added — `credentials/sekurlsa` v0.25.0 — DPAPI master-key cache

- New `DPAPIMasterKey` type implementing the `Credential` interface
  alongside `MSV1_0Credential` + `WdigestCredential`. Carries the
  LUID + 16-byte GUID + inline key bytes from a single
  KIWI_MASTERKEY_CACHE_ENTRY in lsasrv.dll's `g_MasterKeyCacheList`.
- `DPAPIMasterKey.GUIDString()` returns the canonical 8-4-4-4-12
  Microsoft hyphenated GUID format (LE on the first three
  components, BE on the last two — the same convention every
  Windows-targeting tool uses).
- `DPAPIMasterKey.String()` returns `{guid}:hex-bytes` for
  downstream consumption by blob decryptors.
- `DPAPIMasterKey.wipe()` zeros key bytes, GUID, and resets Found —
  pre-decrypted master keys are the highest-value extracted secret
  (they unlock everything DPAPI-protected for that LUID).
- New `DPAPILayout` struct + `DPAPIList{Pattern,Wildcards,Offset}`
  fields on `Template`. Set `DPAPILayout.NodeSize=0` and the walker
  is skipped at no runtime cost — DPAPI support is opt-in per
  template (defaults stay disabled until a real-binary verification
  pass).
- `Parse()` now walks `g_MasterKeyCacheList` after Wdigest, merging
  master keys onto matching MSV/Wdigest LogonSessions by LUID;
  orphan LUIDs surface as new sessions.
- 12 new unit tests including a synthetic-fixture round-trip
  exercising pattern → rel32 deref → list walk → GUID/key extract →
  LUID-merge, plus oversized-key-size + node-overrun guards. 64/64
  tests green.

DPAPI cache entries are stored **already decrypted** in lsasrv.dll
on every Win10/Win11 path observed today, so no LSA crypto chain is
walked for this provider. Downstream callers feed `KeyBytes` to
`BCryptDecrypt` to unwrap Chrome/Edge/Firefox cookies, Windows
Vault credentials, WinRM saved sessions, RDP saved credentials,
Outlook PSTs, and any other DPAPI-protected blob bound to that
LUID.

### Added — `credentials/sekurlsa` v0.24.0 — Wdigest provider

- New `WdigestCredential` type implementing the `Credential` interface
  (alongside `MSV1_0Credential`). Carries the plaintext password
  decrypted from `wdigest.dll` when `UseLogonCredential=1`.
- New `WdigestLayout` struct + `WdigestList{Pattern,Wildcards,Offset}`
  fields on `Template`. Set `WdigestLayout.NodeSize=0` and the
  Wdigest walker is skipped at no runtime cost — the v0.23.x default
  templates default to disabled until offsets are verified against a
  real binary.
- `Parse()` now scans `wdigest.dll` (when present in MODULE_LIST)
  after the MSV1_0 walk. Wdigest credentials are merged onto matching
  MSV `LogonSession` entries by LUID; orphan Wdigest LUIDs surface as
  new sessions so callers don't lose any extracted credential.
- `WdigestCredential.String()` renders as `Domain\User:Password`;
  `wipe()` zeros the plaintext field for `Result.Wipe()` callers.
- 9 new unit tests including a synthetic-fixture round-trip covering
  pattern → rel32 deref → list walk → AES-CBC decrypt → UTF-16LE
  decode → LUID-merge.

### Added — `credentials/sekurlsa` v0.23.2 — inline default Templates

- Win10 19H1 → 22H2 (builds 18362–19045) and Win11 21H2 → 22H2
  pre-22622 (builds 22000–22621) Templates now register at package
  load via `init()`. A dump from one of those builds parses without
  any operator `RegisterTemplate(...)` boilerplate — out-of-the-box
  NTLM-hash extraction.
- Patterns + offsets are facts about Microsoft's compiled lsasrv.dll;
  the framework remains MIT (no GPL-3 / CC-NC code reuse). pypykatz
  and mimikatz are cited as research source in `default_templates.go`
  per Feist v. Rural — facts are not copyrightable.
- `resetTemplates()` continues to clear the registry for tests that
  need a clean slate; new helper `registerDefaultTemplates()` lets
  tests re-prime the registry after a reset without re-importing.
- 4 new unit tests covering: init-time registration coverage,
  validate() pass for every shipping template, NodeSize ≥ max-offset
  invariant, no-overlap between BuildMin/BuildMax windows.

### Fixed — `credentials/sekurlsa` v0.23.1

- `extractMSV1_0` now scans the LogonSessionList head pattern in
  `lsasrv.dll` (correct host) instead of `msv1_0.dll`. The list head
  is an lsasrv global; msv1_0 only defines the per-session struct
  layout. v0.23.0 wouldn't have found a real-Windows session list
  even with a registered template — the synthetic Phase-4 test
  passed because it pretended msv1_0 was a single-module dump and
  fed the pattern there.
- `Parse` still presence-checks msv1_0.dll in the dump's MODULE_LIST
  (returns `ErrMSV1_0NotFound` if missing) but no longer reads its
  bytes. Future provider extensions (NetLogon, …) may branch on
  which auth-package DLLs are loaded.

### Added — `docs/credentials.md` template-reference table

Public Win10/Win11 baseline byte patterns + offsets from pypykatz +
mimikatz, with explicit licensing note: byte patterns extracted from
public Microsoft binaries are factual observations, not redistributed
GPL/CC-NC code. Operators paste the values into a `Template` literal
at `init()` and call `RegisterTemplate(t)` — framework + values stay
separately licensed.

### Added — `credentials/sekurlsa` v0.23.0: pure-Go LSASS minidump parser

Consumer counterpart to `credentials/lsassdump`. Parses a MINIDUMP
blob (the format `MiniDumpWriteDump(MiniDumpWithFullMemory)` and our
own `lsassdump.Build` produce), walks the LSA crypto globals in
lsasrv.dll, decrypts the MSV1_0 logon-session list, and surfaces NTLM
hashes ready for pass-the-hash workflows. Pure Go — an analyst Linux
box can parse a Windows dump without Python or pypykatz/mimikatz.

Public surface:

- `Parse(reader io.ReaderAt, size int64) (*Result, error)` — primary entry; consumes any seekable byte source.
- `ParseFile(path string) (*Result, error)` — convenience wrapper.
- `Result` carries `BuildNumber`, `Architecture`, `Modules`, `Sessions`, `Warnings`. `Result.ModuleByName` for case-insensitive module lookup; `Result.Wipe()` zeroizes every hash buffer post-extract.
- `Credential` interface with v1 implementation `MSV1_0Credential` (UserName, LogonDomain, NTHash[16], LMHash[16], SHA1Hash[20], DPAPIKey[16], Found bool). `String()` emits pwdump format `Domain\User:0:LM:NT:::` directly consumable by pth tools, with standard placeholders when LM/NT are empty.
- `Architecture` (x86/x64/Unknown) + `LogonType` (Interactive/Network/Service/...) enums with friendly `String()` matching Windows event-log conventions.
- `Template` per-build offset table with wildcard-mask pattern scanner support; `RegisterTemplate(t *Template) error` for runtime opt-in. Templates ship as community contributions verified against real dumps.
- `MSVLayout` per-build _MSV1_0_LOGON_SESSION node offsets (NodeSize, LUIDOffset, UserNameOffset, LogonDomainOffset, LogonServerOffset, LogonTypeOffset, CredentialsOffset, SIDOffset, LogonTimeOffset).
- 5 sentinel errors: `ErrNotMinidump`, `ErrUnsupportedBuild`, `ErrLSASRVNotFound`, `ErrMSV1_0NotFound`, `ErrKeyExtractFailed`.

Implementation:

- MINIDUMP reader handles SystemInfo, ModuleList, Memory64List streams; `ReadVA(va, n)` translates lsass virtual addresses to dump bytes via the Memory64 descriptors with descriptor-spanning support.
- LSA crypto: BCRYPT_KEY_DATA_BLOB header parser (magic 0x4D42444B + version 1 + cbKeyData), AES (16-byte payload) / 3DES (24-byte payload) import via Go stdlib, CBC decrypt with cipher-by-alignment heuristic (16 → AES, 8-but-not-16 → 3DES).
- Pattern scanner: linear-scan with sorted-wildcard-mask, RIP-relative rel32 dereference for x64 globals.
- MSV walker: bucket × Flink-chain traversal bounded at 1024 nodes/bucket, UNICODE_STRING decode, PrimaryCredentials decryption, MSV1_0_PRIMARY_CREDENTIAL projection (Win10 0x40-byte and Win11 0x54-byte layouts both supported).

39 unit tests cover every public path: `Parse_NotMinidump`, `Parse_TruncatedHeader`, `Parse_RoundTripBuildAndArch` (no-template path), `ParseFile_NotFound`, `Reader_ParsesModuleNames`, `Reader_ReadVA_RoundTrip`, `Reader_ReadVA_AcrossRegions`, `Reader_ReadVA_NotInDump`, `Architecture_String`, `LogonType_String`, `Result_Wipe`, `Module_ByName_FoundCaseInsensitive`, `Module_ByName_NotFound`, `Parse_PopulatesModulesField`, `RegisterTemplate_AcceptsValid` + RejectsNil + RejectsInvalid (×5 sub-cases) + `OrderedByBuildMin`, `TemplateFor_ReturnsNilForUnknownBuild`, `FindPattern_ExactMatch` + `WildcardMatch` + `NoMatch` + `PatternLongerThanHaystack`, `ParseBCryptKeyDataBlob_AES` + `_3DES` + `_InvalidMagic` + `_ShortBlob` + `_UnsupportedKeyLength`, `DecryptLSA_AESRoundTrip` + `_3DESRoundTrip` + `_NilKey` + `_BadAlignment`, `MSV1_0Credential_AuthPackage` + `_String_Pwdump` + `_Wipe`, `ParseMSV1_0Primary_FullStruct` + `_Win10Layout` + `_AllZero`, `ExtractMSV1_0_HappyPath` (full synthetic-dump end-to-end). Cross-platform: every test runs on Linux without VM dependency thanks to lsassdump.Build-generated synthetic fixtures.

What does not ship in v0.23.0: per-build `Template` values
(IV/3DES/AES key globals + LogonSessionList head pattern + offset).
These require lsasrv.dll/msv1_0.dll disassembly — they're facts about
Microsoft's compiled binaries and ship as community contributions
verified against real dumps. Operators on a build without coverage
get `ErrUnsupportedBuild` + a partial Result, register their own
Template via `RegisterTemplate` at init, and retry. Same workflow
as pypykatz's sigfile contributions.

Out-of-scope follow-ups (each is its own ~300-500 LOC chantier on
top of v1's crypto layer): WDigest plaintext, Kerberos tickets,
DPAPI master keys, LiveSSP / TSPkg / CloudAP, x86 / WoW64 dumps,
live-process attach.

Docs: `docs/credentials.md` (new area-doc covering producer +
consumer as a matched pair), `docs/techniques/credentials/sekurlsa.md`
(technique page with primer + simple/advanced/composed examples),
README capability-table extension, `docs/mitre.md` T1003.001 row
extension. Plan + 5-phase roadmap captured at
`docs/superpowers/plans/2026-04-25-lsasparse-minimum-viable.md`.

### Reorganization — Pass 3 (v0.22.0): `privesc/` + `credentials/` + `process/tamper/` + `persistence/account`

Final pass of the 2026-04-25 reorganization. Closes the privilege-
escalation fragmentation, separates credential access from collection,
groups process-state-mutation techniques together, and moves local-
account management out of the `win/*` Layer-1 primitives where it never
belonged.

**Privilege escalation consolidated under `privesc/`:**

- `uacbypass/` → `privesc/uac` (FODHelper, SLUI, SilentCleanup, EventVwr — T1548.002)
- `exploit/cve202430088/` → `privesc/cve202430088` (Windows kernel TOCTOU LPE to SYSTEM)
- `exploit/` directory **retired entirely**.

**Credential access carved out of collection:**

- `collection/lsassdump` → `credentials/lsassdump` (T1003.001 — distinct ATT&CK tactic from collection)

**Process state mutation grouped under `process/tamper/`:**

- `evasion/hideprocess` → `process/tamper/hideprocess` (NtQSI patch in victim process)
- `evasion/herpaderping` → `process/tamper/herpaderping` (process creation deception)
- `evasion/fakecmd` → `process/tamper/fakecmd` (PEB CommandLine spoof, self + remote)
- `evasion/phant0m` → `process/tamper/phant0m` (kill EventLog svchost threads)

These 4 packages don't fit "make-myself-invisible" evasion — they
modify a target process's state. Grouping them under `process/tamper/`
makes the operator-mental-model clearer: `evasion/` is now strictly
about defending the implant's own process.

**Local account management is persistence:**

- `win/user` → `persistence/account` (NetUserAdd / NetLocalGroupAddMembers — T1136.001)

`win/user` was the only `win/*` package that wasn't a low-level
syscall/COM wrapper. T1136.001 (Local Account creation) is persistence
by definition.

**Breaking change for external consumers:** every import path that
referenced `uacbypass`, `exploit/cve202430088`, `collection/lsassdump`,
`evasion/{hideprocess,herpaderping,fakecmd,phant0m}`, or `win/user`
must be rewritten. No type aliases ship.

**Tests on Win10 VM:** all moved packages green (privesc/uac,
privesc/cve202430088, credentials/lsassdump, process/tamper/{fakecmd,
herpaderping,hideprocess,phant0m}, persistence/account, plus regression
on inject/, process/{enum,session}).

**Docs updated:** README capability table (split Collection /
Credentials, added Process Tampering row, renamed "Privilege & Exploits"
to "Privilege Escalation", trimmed Evasion + Windows Primitives rows),
`docs/architecture.md` Layer-2 subgraph rewritten with all the new
groups + dependency edges, CLAUDE.md package-structure block updated to
reflect the post-Pass-3 layering.

**Final post-reorganization tree (top-level dirs, alphabetical):**

```
c2/  cleanup/  cmd/  collection/  credentials/  crypto/
docs/  encode/  evasion/  hash/  inject/  internal/
kernel/  pe/  persistence/  privesc/  process/  random/
recon/  runtime/  testutil/  ui/  useragent/  win/
```

23 top-level dirs (was 18 pre-Pass-1, with `system/` 7-deep + `exploit/`
+ `uacbypass/` flat). Each parent has a clear 1-line purpose.

### Reorganization — Pass 2 (v0.21.0): `runtime/` carve-out + `inject/` file split

Top-level package restructure separating **in-process code loaders**
(execute managed/COFF code) from **PE binary manipulation** (parse /
transform / convert without executing). Plus an internal
`inject/injector_windows.go` file split by audience (self vs remote
process), no API change. See
`docs/superpowers/plans/2026-04-25-package-reorganization.md` for the
full audit.

**Moved into new `runtime/`:**

- `pe/clr` → `runtime/clr` (in-process .NET CLR hosting via ICLRMetaHost / ICorRuntimeHost — T1620)
- `pe/bof` → `runtime/bof` (Beacon Object File / COFF loader for in-memory x64 object-file execution)

**`inject/` internal file split (no API change):**

- `inject/injector_windows.go` (736 lines) split into 4 files:
  - `inject/injector_windows.go` (63 lines) — package types + `Inject` dispatch only
  - `inject/injector_self_windows.go` — Methods 2/7/8/9 (self-process: CreateThread, Fiber, Etwp, deprecated DirectSyscall stub)
  - `inject/injector_remote_windows.go` — Methods 1/3/4/5/6/10 (remote-process: CreateRemoteThread, QueueUserAPC, EarlyBird, ThreadHijack, RtlCreateUserThread, NtQueueApcThreadEx)
  - `inject/memory_helpers_windows.go` — shared `findAllThreads`, `allocateAndWriteMemoryRemoteWithCaller`, `allocateAndWriteMemoryLocalWithCaller`

Per-method files for the larger methods (`callback_windows.go`,
`kcallback_windows.go`, `phantomdll_windows.go`,
`sectionmap_windows.go`, `spoofargs_windows.go`,
`threadpool_windows.go`, `modulestomp_windows.go`,
`remoteexec_windows.go`) were already separated and stay put.

**Breaking change for external consumers:** every import path that
referenced `pe/clr` or `pe/bof` must be rewritten to `runtime/clr` /
`runtime/bof`. The `inject/` API is unchanged — `Injector` interface,
`Pipeline`, all `Method*` constants stay.

**Docs updated:** README capability table (split "PE Operations" +
new "In-process Runtimes" rows), `docs/architecture.md` Layer-2
subgraph, `docs/pe.md` trimmed (CLR + BOF sections moved to new
`docs/runtime.md`), `docs/techniques/pe/{clr.md,bof-loader.md}` moved
to `docs/techniques/runtime/`, `docs/mitre.md` paths updated, technique
landing page links updated.

### Reorganization — Pass 1 (v0.20.0): `recon/` carve-out + `system/` retirement

Top-level package restructure separating **passive recon** (read-only
environment discovery) from **active evasion** (system-state mutation).
The pre-Pass-1 `evasion/` mixed both, and `system/` was a junk drawer
containing recon, persistence, anti-forensic, destructive, and UI
packages. See `docs/superpowers/plans/2026-04-25-package-reorganization.md`
for the full audit and the 3-pass migration plan.

**Moved into new `recon/` (read-only environment discovery):**

- `evasion/antidebug` → `recon/antidebug` (debugger detection)
- `evasion/antivm` → `recon/antivm` (VM/hypervisor detection)
- `evasion/sandbox` → `recon/sandbox` (multi-factor sandbox orchestrator)
- `evasion/timing` → `recon/timing` (time-acceleration detection)
- `evasion/hwbp` → `recon/hwbp` (DR0-DR7 hardware-breakpoint inspection)
- `evasion/dllhijack` → `recon/dllhijack` (DLL search-order hijack opportunity discovery — never modifies state, returns `Opportunity` records)
- `system/drive` → `recon/drive`
- `system/folder` → `recon/folder`
- `system/network` → `recon/network`

**Moved into other trees:**

- `system/lnk` → `persistence/lnk` (LNK creation, used by `persistence/startup`)
- `system/ads` → `cleanup/ads` (NTFS Alternate Data Streams data-hiding)
- `system/bsod` → `cleanup/bsod` (destructive system disruption)
- `system/ui` → `ui/` (top-level — interactive MessageBox + sounds)

**`system/` retired entirely.**

Package names are unchanged — only import paths move. `antidebug` and
`antivm` keep the well-known `anti-` prefix (terms of art). The
`evasion.Technique` interface, `inject.Injector` + `Pipeline`, and all
other contracts are unchanged.

**Breaking change for external consumers:** every import path that
referenced one of the 13 moved packages must be rewritten. No type
aliases ship — clean break, version bump.

**Docs updated:** README capability table, `docs/architecture.md`
Layer-2 subgraph, `docs/system.md` renamed to `docs/recon.md`,
`docs/mitre.md` package paths, technique pages
(`docs/techniques/evasion/{anti-analysis,sandbox,timing,hw-breakpoints,dll-hijack}.md`,
`docs/techniques/collection/alternate-data-streams.md`).

### Added

- `kernel/driver`: new Layer-1 package defining `Reader` /
  `ReadWriter` / `Lifecycle` interfaces consumed by EDR-bypass
  packages that need arbitrary kernel reads or writes (kcallback,
  lsassdump PPL-bypass, …). Sentinel errors `ErrNotImplemented`,
  `ErrNotLoaded`, `ErrPrivilegeRequired`. **Chantier A.1.**
- `kernel/driver/rtcore64`: BYOVD primitive scaffold for MSI Afterburner
  RTCore64.sys (CVE-2019-16098). Ships SCM service install / start /
  stop / uninstall, `\\.\RTCore64` device handle management, and
  IOCTL `0x80002048` read / `0x8000204C` write wrappers (cap
  `MaxPrimitiveBytes = 4096` per IOCTL). Driver binary intentionally
  NOT embedded by default — callers opt-in via the `byovd_rtcore64`
  build tag and ship a sibling embed file. Default builds surface
  `ErrDriverBytesMissing`. Technique page
  `docs/techniques/evasion/byovd-rtcore64.md`. **Chantier A.1.**
- `evasion/kcallback`: `Remove` + `Restore` + `RemoveToken` (v0.17.1).
  Captures the slot's tagged-pointer value before zeroing 8 bytes;
  `Reprotect` writes the original back. `Callback.SlotAddr` is now
  populated by `Enumerate` so `Remove` can key on the per-slot
  kernel VA. 12 mock-reader unit tests cover happy path, race
  windows, nil-writer guards, deferred-cleanup zero-token idiom.
  **Chantier B (v0.17.1).**
- `credentials/lsassdump`: `Unprotect` + `Reprotect` + `PPLToken` +
  `PPLOffsetTable` (v0.15.1). EPROCESS-unprotect path mirroring
  mimikatz's mimidrv strategy: caller plugs in a
  `kernel/driver.ReadWriter`, passes lsass's EPROCESS kernel VA +
  build-specific `PS_PROTECTION` byte offset, and Unprotect zeros
  the byte so a userland `OpenLSASS` succeeds even when
  `RunAsPPL=1`. 8 mock-reader unit tests. **Chantier C (v0.15.1).**

### Changed

- `runtime/clr`: `corBindToRuntimeEx` now wraps `REGDB_E_CLASSNOTREG`
  (HRESULT `0x80040154`) with `%w` + the raw HRESULT, so SKIP
  messages on the win10 TOOLS snapshot now read
  `"CorBindToRuntimeEx(v2.0.50727): HRESULT 0x80040154 (REGDB_E_CLASSNOTREG): clr: ICorRuntimeHost unavailable …"`
  — the next investigator sees the actual code without rebuilding.
  **Chantier F (pt 1/2).**
- `scripts/vm-provision.sh`: TOOLS v2 — registers the
  `{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}` (CorRuntimeHost) CLSID
  every provisioning pass. Confirmed 2026-04-25 that this alone is
  insufficient to unblock `runtime/clr` tests — mscoree's binding chain
  needs more than the CLSID (interface, typelib, Fusion entries),
  which only the full .NET 3.5 Redistributable / Win10-ISO
  `sources/sxs` payload runs. The CLSID baseline stays so future
  ISO-based reprovisioning starts from a stable point. **Chantier F
  (pt 1/2).**

- `evasion/callstack`: `SpoofCall(target, chain, args...)` + plan9 asm
  pivot (`spoof_windows_amd64.s`). Allocates a 64 KiB side stack via
  VirtualAlloc, plants the chain, and JMPs to target with RSP swapped
  to the chain top; `spoofTrampoline` lands on the chain bottom and
  restores Go's RSP/R14 before returning the target's RAX. **Scaffold
  only** — 6 caller-side unit tests are green but the end-to-end
  pivot crashes Go's runtime (`lastcontinuehandler`) under
  `MALDEV_SPOOFCALL_E2E=1`. Promotion to a tagged release waits on
  the e2e crash being root-caused. **Chantier D.**
- `evasion/sleepmask`: `MultiRegionRotation` wrapper — applies any
  single-region strategy (notably `EkkoStrategy`) sequentially across
  N regions, sleeping `d/N` per region. Total wall-clock matches `d`;
  trade-off is staggered protection. 7 unit tests cover the dispatch
  contract, error propagation, context-cancel, and short-duration
  fallback. **Chantier H.**

### Documented

- `inject/realsc`: `MethodCreateFiber + Go runtime` incompatibility.
  `ConvertThreadToFiber` permanently transforms the calling OS thread
  into a fiber-control thread; Go's M:N scheduler does not understand
  fibers. Real shellcode ending in `ExitThread`/`ret` kills the host
  runtime mid-execution; goroutines + `runtime.LockOSThread` are NOT
  enough. Documented integration pattern: spawn a true
  `kernel32!CreateThread` OS thread (not a goroutine) and let the
  fiber die there. `TestFiber_RealShellcode` SKIP message + header
  comment + `docs/techniques/injection/README.md` warning. **Chantier
  E.**
- `recon/dllhijack`: KindProcess Validate sandboxed-spawn design
  sketch in `docs/techniques/evasion/dll-hijack.md`. Pattern: spawn a
  fresh copy of the same binary in a sandboxed working directory
  reproducing the production DLL search path, drop canary, wait
  for marker / bounded timeout, terminate child. Implementation
  pending — needs sandboxed-spawn helper, signed-canary support,
  `opts.AllowSpawn` operator opt-in. **Chantier G.**

- `recon/dllhijack`: `stealthopen.Opener` composition — every scanner
  (`ScanServices` / `ScanProcesses` / `ScanScheduledTasks` /
  `ScanAutoElevate` / `ScanAll`) now accepts a trailing `...ScanOpts`
  variadic whose `Opener` field routes every PE file read through the
  given stealth open strategy (e.g. NTFS Object ID, bypassing
  path-keyed EDR file hooks). Backward-compatible: zero args preserves
  the historical `os.Open` path. `ScanProcesses` accepts the opts for
  symmetry but has no file-read surface (loaded-module Toolhelp32
  reads only).

### Changed

- `recon/dllhijack`: major `/simplify` pass against the v0.14.0 series
  (aggregated 4 review agents: reuse, quality, efficiency, skill-
  conformity + test relevance). Single shared `emitOppsForDLLs` helper
  replaces the near-identical loop body of all 4 scanners (dedup →
  `HijackPath` → emit Opportunity with consistent field fill). ~120 LOC
  removed from scan_services / scan_processes / scan_autoelevate. Each
  scanner now passes scanner-specific reason + extras via closures.
- `recon/dllhijack`: `isKnownDLL` caches the KnownDLLs registry list
  behind a `sync.Once` — a full service+process+task scan previously
  re-enumerated the registry ~3,000× (O(N×M)); now it's loaded once
  and backed by a `map[string]struct{}` for O(1) lookups.
- `recon/dllhijack`: `HijackPath` adds a per-call `map[string]bool`
  stat cache so the resolver's two directory walks share `os.Stat`
  results, halving syscalls per call.

### Added

- `recon/dllhijack`: `ScanAutoElevate` + `Rank` + `IsAutoElevate`
  (**Phase D**). Walks System32 .exes whose embedded manifest sets
  `autoElevate=true` (fodhelper, sdclt, WSReset, …) — the UAC-bypass
  vector class — parses PE imports + search order, and emits
  Opportunities flagged `AutoElevate=true` + `IntegrityGain=true`
  (MITRE T1548.002). `Rank` scores all Opportunities with a coarse
  weighting (AutoElevate +200, IntegrityGain +100, Kind base score)
  and returns a sorted slice. `IsAutoElevate([]byte)` is a
  cross-platform byte-level check for the manifest flag. New
  `KindAutoElevate` Kind value. `ScanAll` now aggregates
  services + processes + tasks + auto-elevate.
- `recon/dllhijack`: `Validate` + canary-drop/trigger/poll orchestration
  (**Phase C**). Given an Opportunity and a user-supplied canary DLL,
  Validate drops the DLL at HijackedPath, triggers the victim (service
  restart via SCM for KindService, scheduler.Run for KindScheduledTask),
  polls a configurable glob for a marker file created by the canary's
  DllMain, and always cleans up (retries removal to tolerate writers
  still holding the handle). `ValidateOpts` exposes MarkerGlob /
  MarkerDir / Timeout / PollInterval / KeepCanary. KindProcess is
  rejected (can't cleanly relaunch a running process). Sample
  `canary.c` (30 lines, MinGW-buildable) shipped in
  `recon/dllhijack/canary/` with build instructions — deliberately
  not pre-built to avoid committing a hash-fingerprinted artifact.
- `persistence/scheduler`: `Actions(name)` returns the IAction Path
  entries for a registered task (used by dllhijack). `Run` and
  `Actions` routed through ITaskFolder.GetTask rather than
  ITaskService.GetTask (which is not an actual method on that
  interface; the old call path would always fail).
- `recon/dllhijack`: two new scanners (**Phase B**):
  - `ScanProcesses` — enumerates every accessible running process and
    reads the live loaded-module list via Toolhelp32, covering DLLs
    loaded at runtime via LoadLibrary (the blind spot of static PE
    import analysis).
  - `ScanScheduledTasks` — walks every registered scheduled task via
    COM ITaskService, extracts each exec action's binary path, applies
    the same PE-imports filter as `ScanServices`.
  - `ScanAll` aggregates services + processes + tasks. Partial failures
    are surfaced but don't abort the remaining scanners.
- `process/enum`: `ImagePath(pid)` via `QueryFullProcessImageNameW`,
  `Modules(pid)` via `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`,
  and the `Module` struct (Name/Path/Base/Size).
- `persistence/scheduler`: `Actions(name)` returns exec-action binary
  paths for a registered task. Only `TASK_ACTION_EXEC` entries are
  reported; COM/email/message actions are skipped.
- `recon/dllhijack`: `ScanServices` rewritten to use PE imports + DLL
  search-order resolution (**Phase A**). Each Opportunity now names the
  exact `HijackedDLL` and the `HijackedPath` where a payload DLL
  should be dropped, instead of just flagging writable service
  directories. KnownDLLs (HKLM\...\Session Manager\KnownDLLs) are
  correctly excluded. New exported primitives `SearchOrder(exeDir)`
  and `HijackPath(exeDir, dllName)` for callers that read service
  config from non-SCM sources.
- `evasion/sleepmask`: `FoliageStrategy` (L3) — Ekko + a stack-scrub
  `memset` gadget inserted between the encrypt and wait steps. Before
  the pool thread blocks in `WaitForSingleObjectEx`, it zeros the used
  gadget shadow frames so a stack-walker mid-sleep sees clean zeros
  above Rsp instead of VP/SF032 residue. Lighter than Austin Hudson's
  full Foliage (no fake-RA chain), but self-contained. Clamp on
  `ScrubBytes` prevents over-requesting from clobbering the memset's
  own return path. Added to the 4-strategy e2e sub-test loop
  (inline / timerqueue / ekko / foliage) — all pass the concurrent
  scanner invariant. Layout bumped to accommodate 7 gadgets
  (trampolines at +0x10000, slots at +0x10160, contexts at +0x11000)
  in the shared `ekkoLayout`. `ntdll!memset` added to `win/api` (used
  via `.Addr()` as gadget target — the exported `RtlFillMemory` is a
  memset alias, so calling it with RtlFillMemory's documented arg
  order crashes).
- `recon/dllhijack` — new package for DLL search order hijack discovery
  (MITRE T1574.001). MVP: `ScanServices()` enumerates every installed
  Windows service and returns `Opportunity` rows for those whose binary
  directory is writable by the current user — the classic "drop DLL →
  service loads it next start" vector. `ParseBinaryPath` exported as a
  pure-string helper that handles quoted + unquoted SCM BinaryPathNames.
  Cross-platform stub returns an error on non-Windows. Process /
  scheduled-task scanning, PE-imports resolution, and canary-DLL
  validation deferred to Phase 2.1. Added to docs/mitre.md, README
  tables, and docs/techniques/evasion/dll-hijack.md.

### Fixed

- `evasion/sleepmask`: `EkkoStrategy` full ROP chain round-trip now works
  end-to-end on Win10 amd64. Root cause of the previous crashes was that
  `SystemFunction032`'s stack frame grew downward from each gadget's Rsp
  into our own slot-table / trampoline bytes, corrupting them mid-chain;
  subsequent trampolines then loaded garbage CONTEXT pointers and
  NtContinue faulted at `0xffffffffffffffff`. Scratch layout restructured
  so all metadata (trampolines, slots, USTRs, key, contexts) lives at the
  top of the buffer, above every gadget's Rsp; each gadget gets 8 KB of
  pure padding below its Rsp for the API's own stack growth.
  `TestEkkoStrategy_CycleRoundTrip` un-skipped; Ekko added to the
  `TestSleepMaskE2E_DefeatsExecutablePageScanner/{inline,timerqueue,ekko}`
  sub-test loop. Also fixed: single-timer kickoff (removed multi-timer
  pool-thread race), `resumeStub` spins-forever instead of ExitThread
  (avoids corrupting thread-pool callback bookkeeping),
  `DeleteTimerQueueEx(NULL)` for non-blocking cleanup, USTRING layout
  (`ULONG Length` not `USHORT`), `ContextFlags` narrowed to
  CONTROL|INTEGER so FPU state isn't restored cross-thread.

### Added

- `scripts/vm-provision.sh`: Windows VM now gets WER LocalDumps
  configured (HKLM\...\LocalDumps → `C:\Dumps`, DumpType=2/full,
  DumpCount=10, DontShowUI=1). Used to diagnose the Ekko SF032
  stack-clobbering bug; stays for future pool-thread crash
  investigation. `vm_running` locale fix (`LC_ALL=C virsh domstate`) so
  the script no longer trips on French `en cours d'exécution`.
- `docs/vm-test-setup.md`: new "Debugging native crashes" section
  documenting the Go crash-reporter + WER LocalDumps workflow for
  investigating non-Go-thread access violations (e.g. thread-pool
  callbacks, ROP chains) on the VM.


## [v0.17.0] — 2026-04-25

### Added

- `evasion/kcallback`: kernel callback-array enumeration (MITRE
  T1562.001). User-mode symbol & driver resolution via
  `NtQuerySystemInformation(SystemModuleInformation = 11)` —
  `NtoskrnlBase()` returns the kernel image base, `DriverAt(addr)`
  reverse-maps a kernel VA to its owning driver module name. Both
  are cached once per process and require no elevation.
- `Enumerate(reader KernelReader, tab OffsetTable)` reads the three
  callback arrays (PspCreateProcessNotifyRoutine / ThreadNotifyRoutine
  / LoadImageNotifyRoutine) via a caller-supplied KernelReader,
  masks the `PEX_CALLBACK` flags, dereferences each ROUTINE_BLOCK+8
  to get the callback function VA, and resolves the owning driver.
  `NullKernelReader` (default) always returns `ErrNoKernelReader` —
  callers plug in a BYOVD-backed reader (RTCore64, GDRV, custom
  driver). Offsets are caller-supplied (no built-in database;
  PDB-derivation workflow documented in
  `docs/techniques/evasion/kernel-callback-removal.md`).
- Removal is deliberately **out of scope** for v0.17.0; the write
  primitive lands in v0.17.1 alongside a dedicated BYOVD chantier.
  The `KernelReadWriter` interface + `ErrReadOnly` are shipped so
  the removal API can slot in without a breaking change.


## [v0.16.0] — 2026-04-25

### Added

- `evasion/callstack`: call-stack spoofing metadata primitives (MITRE
  T1036). Ships `LookupFunctionEntry` (ntdll!RtlLookupFunctionEntry
  wrapper, returns a Frame carrying ReturnAddress + ImageBase +
  RUNTIME_FUNCTION by value), `StandardChain` (cached 2-frame chain:
  kernel32!BaseThreadInitThunk inner → ntdll!RtlUserThreadStart
  outer, each frame pre-populated with unwind metadata),
  `FindReturnGadget` (byte-scans ntdll's .text for a lone RET
  0xC3 + int3/nop padding, cached once per process, guaranteed to
  have its own RUNTIME_FUNCTION), and `Validate` (structural chain
  consistency check).
- The asm pivot that actually executes a call through a synthesized
  chain is deferred to **v0.16.1** — v0.16.0 provides the building
  blocks so higher-level packages (`inject`, `evasion/unhook`,
  future sleepmask L4) can compose their own pivots.


## [v0.15.0] — 2026-04-24

### Added

- `credentials/lsassdump`: LSASS credential dump package (MITRE
  T1003.001). `OpenLSASS` walks the process list via
  `NtGetNextProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` (cheap
  access even protected processes grant), identifies `lsass.exe` via
  `NtQueryInformationProcess(ProcessImageFileName)`, reads the PID
  via `ProcessBasicInformation`, and reopens the target via
  `NtOpenProcess(pid, QUERY_LIMITED | VM_READ)` — keeping the
  `VM_READ` audit surface to a single targeted event. `Dump` streams
  a MINIDUMP blob (MDMP, SystemInfo + ThreadList + ModuleList +
  Memory64List) to the caller's `io.Writer`; memory contents are
  `NtQueryVirtualMemory`-walked and `NtReadVirtualMemory`-read one
  region at a time, never via `MiniDumpWriteDump` (heavily
  EDR-hooked). Every `Nt*` call accepts an optional
  `*wsyscall.Caller` for direct/indirect syscall routing.
- `credentials/lsassdump.Build` is exported so callers can assemble a
  MINIDUMP from arbitrary memory regions (test fixtures, replayed
  snapshots). Pure-Go byte-packing; no dbghelp.
- VM e2e (admin + MALDEV_INTRUSIVE, Win10 TOOLS snapshot): dumps
  lsass in ~0.6s, produces a 56MB MINIDUMP parseable by pypykatz /
  mimikatz — extracts MSV NT hashes, WDigest, Kerberos session
  material, and DPAPI master keys. PPL-protected lsass returns
  `ErrPPL`; bypass is a separate chantier.


## [v0.14.1] — 2026-04-24

### Fixed

- `persistence/scheduler`: `CoInitializeEx` now accepts `S_FALSE`
  (0x00000001) as a success code. COM refcounts per thread — when a
  prior caller on the same goroutine's underlying thread already
  initialised COM, CoInitializeEx returns `S_FALSE`, which go-ole
  wraps as an OleError. The handler only whitelisted
  `RPC_E_CHANGED_MODE`, so any scheduler call after another
  COM-initialising path failed with "Fonction incorrecte." Surfaced
  by the dllhijack VM sweep (ScanScheduledTasks + Validate running
  in the same test binary).

### Changed

- `recon/dllhijack`: drop `readAll` / `readImports` nil-opener
  branches in favour of `stealthopen.Use`/`stealthopen.OpenRead`;
  `ScanAutoElevate` now reads each candidate PE once (not twice) and
  parses imports from the in-memory bytes via `importsFromBytes`.
- `testutil`: new `SpyOpener` consolidates the `stealthopen.Opener`
  spy pattern previously duplicated across four test files
  (`recon/dllhijack`, `process/tamper/herpaderping`, `evasion/unhook`,
  `inject/phantomdll`). Single source, mutex-guarded `Paths()` /
  `Last()` snapshots, and a defaulted `Inner` so tests can stay
  focused on call-count / last-path assertions.
- `recon/dllhijack`: `TestValidate_OrchestrationEndToEnd` timeout
  bumped 10s → 30s to tolerate PowerShell cold-start on a
  freshly-reverted VM (observed up to 10.4s from first run).


## [v0.12.0] — 2026-04-24

3-strategy sleep-mask architecture, pluggable Cipher (XOR/RC4/AES-CTR),
cross-process RemoteMask, EkkoStrategy scaffold, and a runnable
`cmd/sleepmask-demo` that demonstrates both self-process and
host-injection scenarios with a concurrent scanner.

### Breaking (pre-1.0 minor bump)

- `(*Mask).Sleep(d time.Duration)` → `Sleep(ctx context.Context, d time.Duration) error`.
  Callers must pass a context and may inspect the returned error
  (`ctx.Err()` on cancel, nil on success). Decrypt still always runs, even
  on cancellation.
- `SleepMethod`, `MethodNtDelay`, `MethodBusyTrig`, `(*Mask).WithMethod`
  removed. Use `WithStrategy(&InlineStrategy{UseBusyTrig: true})` for the
  old busy-wait path, or one of the new `TimerQueueStrategy` /
  `EkkoStrategy` for a different thread model.

### Added

- `sleepmask.Cipher` interface + three implementations:
  `NewXORCipher()`, `NewRC4Cipher()`, `NewAESCTRCipher()`. Self-inverse
  `Apply(buf, key)` so encrypt and decrypt are the same call. Selected
  via `Mask.WithCipher(...)`. Fresh random key per cycle is still drawn
  from `crypto/rand` sized to `cipher.KeySize()` and scrubbed via
  `cleanup/memory.SecureZero`.
- `sleepmask.Strategy` interface + three implementations:
  - `InlineStrategy{UseBusyTrig bool}` — historical L1 behavior; caller
    goroutine runs the encrypt/wait/decrypt.
  - `TimerQueueStrategy{}` — L2-light: cycle runs on a Windows
    thread-pool worker via `CreateTimerQueueTimer`; caller blocks on an
    auto-reset completion event.
  - `EkkoStrategy{}` — L2-full scaffold: 6 CONTEXT ROP chain
    (`VirtualProtect` → `SystemFunction032` → `WaitForSingleObjectEx` →
    `SystemFunction032` → `VirtualProtect` → resumeStub) with a plan9
    asm resume stub. Input validation (RC4 only, single region) ships;
    chain execution itself is WIP (CONTEXT alignment, Rsp alignment,
    shadow-space separation). `TestEkkoStrategy_CycleRoundTrip` is
    skipped with a diagnostic message.
- `sleepmask.RemoteMask` + `RemoteRegion` + `RemoteInlineStrategy` for
  masking memory in another process via `VirtualProtectEx` +
  `ReadProcessMemory` + `WriteProcessMemory`. Requires
  `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`. Verified
  against a spawned notepad in `TestRemoteInlineStrategy_RoundTrip`.
- `cmd/sleepmask-demo` — flag-driven demo (`-scenario self|host`,
  `-cipher xor|rc4|aes`, `-strategy inline|timerqueue|ekko`,
  `-cycles`, `-sleep`, `-scanner`). Runs a concurrent scanner printing
  HIT/MISS transitions as the mask cycles.
- `win/api` procs added: (kernel32) `CreateTimerQueue`,
  `DeleteTimerQueueTimer`, `DeleteTimerQueueEx`, `SetEvent`,
  `ExitThread`, `VirtualProtect`, `WaitForSingleObjectEx`; (ntdll)
  `NtContinue`, `RtlCaptureContext`; (advapi32) `SystemFunction032`.
- `docs/techniques/evasion/sleep-mask.md` rewritten around the 4-level
  taxonomy with strategy/cipher comparison tables and a demo walkthrough.

### Deferred

- EkkoStrategy ROP chain execution (scaffold ships, chain debug is future
  work — see strategy_ekko_windows.go doc comment).
- L3 (Foliage-style stack scrubbing), L4 (BOF-style in-memory loader
  isolation).
- Remote L2 and remote L2-full variants.

## [v0.11.0] — 2026-04-23

Go 1.21 baseline (Windows 7 binary support), Opener composition analog to
wsyscall.Caller, SelfInjector interface, DoSecret runtime/secret
integration, sleepmask bug fix + e2e tests, reproducible cross-platform
coverage workflow.

### Breaking (pre-1.0 minor bump)

- `evasion/unhook.ClassicUnhook(funcName, caller)` →
  `ClassicUnhook(funcName, caller, opener stealthopen.Opener)`. Pass `nil`
  for opener to keep the historic path-based ntdll.dll read. (e674462)
- `evasion/unhook.FullUnhook(caller)` →
  `FullUnhook(caller, opener stealthopen.Opener)`. Same nil fallback. (e674462)
- `inject.PhantomDLLInject(pid, dll, shellcode)` →
  `PhantomDLLInject(pid, dll, shellcode, opener stealthopen.Opener)`. The
  opener is consulted twice: PE-parse read + NtCreateSection HANDLE.
  (e674462)
- `go.mod` directive: `go 1.25.0` → `go 1.21`. Requires downgrade of
  `github.com/refraction-networking/utls` to v1.6.7,
  `golang.org/x/{arch,crypto,sync,sys,text}` to their last Go-1.21-compatible
  versions. No regression in used APIs (audited call-site by call-site).
  Unlocks Go 1.21 compilation, which is the last Go release producing
  binaries compatible with Windows 7 / Server 2008 R2. (5b0689e)

### Added

- `evasion/stealthopen.Opener` interface + `Standard`, `Stealth`,
  `NewStealth`, `VolumeFromPath`, `Use` helpers. Mirrors how
  `*wsyscall.Caller` is threaded through the library: optional, nil-safe,
  swaps a path-based `os.Open` for `OpenFileById` via NTFS Object ID so
  path-keyed EDR file hooks never observe the open. Wired into
  `evasion/unhook`, `inject.PhantomDLLInject`, and
  `process/tamper/herpaderping.Config.Opener` (new field). (e674462)
- `cleanup/memory.DoSecret(func())` and `SecretEnabled()` — opt-in wrapper
  around Go 1.26's experimental `runtime/secret.Do` for erasing registers,
  stack locals, and heap temporaries of a sensitive computation. Selected
  via build tags `go1.26 && goexperiment.runtimesecret`; stub fallback
  everywhere else keeps the same API so callers can wrap unconditionally.
  (5b0689e)
- `cleanup/memory.SecureZero` is now cross-platform (moved out of
  `memory_windows.go` into `memory.go`). `WipeAndFree` remains Windows-only.
  (5b0689e)
- `inject.Region` + `inject.SelfInjector` optional interface. Self-process
  injectors (`MethodCreateThread`, `MethodCreateFiber`,
  `MethodEtwpCreateEtwThread` on Windows, `MethodProcMem` on Linux) publish
  the local allocation via `InjectedRegion() (Region, bool)` after a
  successful Inject, so callers can feed it straight into `sleepmask.Mask`
  or `cleanup/memory.WipeAndFree` without re-deriving addr/size.
  Decorators (`WithValidation`, `WithCPUDelay`, `WithXOR`) and `Pipeline`
  forward the region transparently. Cross-process methods return
  `(Region{}, false)`. (5b0689e)
- 6 e2e tests for `evasion/sleepmask` (`sleepmask_e2e_windows_test.go`):
  concurrent `testutil.ScanProcessMemory` loop during `Mask.Sleep()`,
  protection round-trip checks, multi-region, 10-cycle beacon stability,
  `MethodBusyTrig` variant. Run via `./scripts/vm-run-tests.sh windows`.
  (5b0689e, 82a9ab7)
- Opener-wiring tests: `evasion/stealthopen/opener{_,_windows_}test.go`,
  `evasion/unhook/opener_windows_test.go`,
  `inject/phantomdll_opener_test.go`,
  `process/tamper/herpaderping/opener_windows_test.go`. Cover both the
  `Standard`/`Use(nil)` fallback and the real `NewStealth` round-trip
  through `OpenFileById`, plus spy-opener assertions that each consumer
  consults the Opener the expected number of times. (e674462)
- `cmd/vmtest`: new `-report-dir` flag with `Fetch()` method (scp for
  libvirt, `VBoxManage copyfrom` for VBox). Auto-injects
  `-coverprofile=<guest-path>` into forwarded `go test` invocations, tees
  `test.log`, and repatriates `cover.out` plus `clrhost-cover.out` when
  the guest produced one. (8aac278)
- `scripts/coverage-merge.go`: merges N Go cover profiles (union with
  per-block max hit count) and renders a Markdown gap report sorted by
  ascending coverage. (8aac278)
- `scripts/full-coverage.sh`: orchestrates host + Linux VM + Windows VM +
  Kali end-to-end, exports every `MALDEV_*` gate, restores to
  `--snapshot=NAME` (default `INIT`). Tolerant of test-level non-zero
  exits so gated failures don't abort subsequent phases. (8aac278)
- `scripts/vm-provision.sh`: idempotent per-VM tool install (NetFx3 via
  DISM SYSTEM scheduled task, postgresql + msfdb init on Kali). Takes a
  `TOOLS` snapshot when it's done. (8aac278)
- `docs/coverage-workflow.md`: canonical reference for the coverage
  workflow — snapshots, gates, layout, known blockers (QEMU pause race,
  CLR v2 COM activation on TOOLS snapshot), reproduction recipe. (8aac278)
- 16 gap-filling tests covering non-Windows stubs (c2/transport/namedpipe,
  evasion/{fakecmd,hideprocess,preset,stealthopen,hook,hook/probe,
  hook/remote,hook/bridge/controller}, cleanup/ads, process/session,
  runtime/clr, cet) plus Windows-only factory tests (evasion/unhook,
  recon/hwbp) and `internal/compat/{cmp,slices}` polyfill smoke tests.
  (914aab4)
- `testutil/kali_test.go`: env-var resolvers (`kaliSSHHost/Port/Key/User`)
  with both override and fallback paths. (914aab4)
- `runtime/clr` subprocess coverage: `testutil/clrhost` now builds with
  `go build -cover -covermode=atomic`, `GOCOVERDIR` points at a stable
  temp dir, `go tool covdata textfmt` converts to `clrhost-cover.out`
  which `cmd/vmtest` fetches and `coverage-merge` unions with the main
  profile. Ships with `testutil/clrhost/maldev_clr_test.dll` (3 KB .NET
  2.0 assembly) for `TestExecuteDLLReal`. (d0b9e0f)
- 8 deeper tests for `evasion/hook/bridge` Controller (`CallOriginal`,
  `ArgsDefault`, `SetReturnNoPanic`, `LogViaTransport`,
  `LogStandaloneNoop`, `ExfilStandaloneNoop`, `AskStandaloneAlwaysAllows`)
  and 2 hook lifecycle tests (`TestReinstallAfterRemove`,
  `TestInstallOnPristineTargetAfterGroupRollback`). (94a57cf)

### Fixed

- `evasion/sleepmask.Mask.Sleep`: crash (`STATUS_ACCESS_VIOLATION`) on the
  standard post-inject `PAGE_EXECUTE_READ` region. The encrypt phase did
  XOR *before* the `VirtualProtect(PAGE_READWRITE)` downgrade, so the
  first XOR byte faulted on a read-only executable page. Reordered to
  VirtualProtect-then-XOR. Existing tests allocated `PAGE_EXECUTE_READWRITE`
  so never hit the bug; the new e2e test suite pins the correct order.
  (5b0689e)
- `evasion/sleepmask_e2e_test.TestSleepMaskE2E_DefeatsExecutablePageScanner`:
  timing race under coverage instrumentation — the scanner goroutine could
  fire its first pass before `mask.Sleep` completed the encrypt phase,
  triggering a legitimate hit against still-unmasked memory. Gated behind
  a busy-wait barrier on `VirtualQuery(addr).Protect == PAGE_READWRITE`
  so the scanner only starts counting once the mask is provably engaged.
  (82a9ab7)
- `evasion/hook.TestReinstallAfterRemove`: overspecified assertion
  `require.NotEqual(h1.Trampoline(), h2.Trampoline())`. Windows's
  `VirtualFree(MEM_RELEASE)` + `VirtualAlloc(0)` of the same size may
  reuse the address (and does so reliably under coverage). Replaced with
  a byte-equality check against the captured pristine prologue — the
  actual correctness property the test's docstring claims ("no residual
  bytes"). (9bdf43f)
- `evasion/sleepmask/doc.go`: corrected description — `MethodNtDelay`
  uses Go's `time.Sleep` (which goes through `NtWaitForSingleObject` on a
  timer), not an explicit `NtDelayExecution` via Caller. The docstring
  now also tells the reader that the XOR key lives on the Go stack during
  sleep. (5b0689e)
- `recon/timing.TestBusyWaitPrimality`: upper bound 10s → 60s. VM CPU
  is shared and non-deterministic; the fixed-workload check still guards
  against infinite loops. (914aab4)
- `inject/linux_test.TestProcMemSelfInject`: now retries 3× and matches
  `PROCMEM_OK` in stdout instead of requiring exit 0. The child's Go
  runtime can SIGSEGV during exit cleanup after injection succeeded — the
  marker is the real success signal. (914aab4)

### Docs

- `docs/techniques/cleanup/memory-wipe.md`: honest implementation section
  (`SecureZero` delegates to Go's `clear` builtin — Go 1.21+ intrinsic;
  legacy `unsafe.Pointer` fallback is dead code at the module's `go 1.21`
  baseline). New section on `DoSecret` and the build-tag matrix.
- `docs/techniques/evasion/sleep-mask.md`: rewritten. Mermaid diagram
  fixed for the order-of-operations. New "Verifying It Works" section
  with extracts from the e2e tests. "Common Pitfalls" section covering
  the RX-page crash, XOR key on stack, short-sleep overhead, and
  `MethodNtDelay` still going through the kernel scheduler. New
  "Integrating with inject.SelfInjector" section showing the canonical
  beacon-loop pattern.
- `docs/techniques/evasion/stealthopen.md`: new "Composing with Other
  Packages — the Opener Pattern" section with wiring table pointing at
  every consumer and their test files.
- `docs/techniques/injection/README.md`: new "SelfInjector — Getting the
  Region Back" section with contract details and sample code.
- `docs/techniques/evasion/ntdll-unhooking.md`,
  `docs/techniques/injection/phantom-dll.md`: signatures + examples
  updated for the new opener parameter.
- `docs/testing.md`: new Opener coverage table pointing at every new
  test file and the commands to run each VM-side suite.

### Coverage

Baseline 39.4% (Linux host only, no gates) → **52.40% merged** across
the host + ubuntu20.04 VM + Windows VM + Kali (full gates open). Full
report at `ignore/coverage/report-full.md`.



### Added

- `cmd/vmtest`: new `-report-dir` flag with `Fetch()` method (scp for
  libvirt, `VBoxManage copyfrom` for VBox). Auto-injects
  `-coverprofile=<guest-path>` into forwarded `go test` invocations, tees
  `test.log`, and repatriates `cover.out` plus `clrhost-cover.out` when
  the guest produced one. (8aac278)
- `scripts/coverage-merge.go`: merges N Go cover profiles (union with
  per-block max hit count) and renders a Markdown gap report sorted by
  ascending coverage. (8aac278)
- `scripts/full-coverage.sh`: orchestrates host + Linux VM + Windows VM +
  Kali end-to-end, exports every `MALDEV_*` gate, restores to
  `--snapshot=NAME` (default `INIT`). Tolerant of test-level non-zero
  exits so gated failures don't abort subsequent phases. (8aac278)
- `scripts/vm-provision.sh`: idempotent per-VM tool install (NetFx3 via
  DISM SYSTEM scheduled task, postgresql + msfdb init on Kali). Takes a
  `TOOLS` snapshot when it's done. (8aac278)
- `docs/coverage-workflow.md`: canonical reference for the coverage
  workflow — snapshots, gates, layout, known blockers (QEMU pause race,
  CLR v2 COM activation on TOOLS snapshot), reproduction recipe. (8aac278)
- 16 gap-filling tests covering non-Windows stubs (c2/transport/namedpipe,
  evasion/{fakecmd,hideprocess,preset,stealthopen,hook,hook/probe,
  hook/remote,hook/bridge/controller}, cleanup/ads, process/session,
  runtime/clr, cet) plus Windows-only factory tests (evasion/unhook,
  recon/hwbp) and `internal/compat/{cmp,slices}` polyfill smoke tests.
  (914aab4)
- `testutil/kali_test.go`: env-var resolvers (`kaliSSHHost/Port/Key/User`)
  with both override and fallback paths. (914aab4)
- `runtime/clr` subprocess coverage: `testutil/clrhost` now builds with
  `go build -cover -covermode=atomic`, `GOCOVERDIR` points at a stable
  temp dir, `go tool covdata textfmt` converts to `clrhost-cover.out`
  which `cmd/vmtest` fetches and `coverage-merge` unions with the main
  profile. Ships with `testutil/clrhost/maldev_clr_test.dll` (3 KB .NET
  2.0 assembly) for `TestExecuteDLLReal`. (d0b9e0f)
- 8 deeper tests for `evasion/hook/bridge` Controller (`CallOriginal`,
  `ArgsDefault`, `SetReturnNoPanic`, `LogViaTransport`,
  `LogStandaloneNoop`, `ExfilStandaloneNoop`, `AskStandaloneAlwaysAllows`)
  and 2 hook lifecycle tests (`TestReinstallAfterRemove`,
  `TestInstallOnPristineTargetAfterGroupRollback`). (94a57cf)

### Fixed

- `recon/timing`: `TestBusyWaitPrimality` upper bound 10s → 60s. VM
  CPU is shared and non-deterministic; the fixed-workload check still
  guards against infinite loops. (914aab4)
- `inject/linux_test.go`: `TestProcMemSelfInject` now retries 3× and
  matches `PROCMEM_OK` in stdout instead of requiring exit 0. The
  child's Go runtime can SIGSEGV during exit cleanup after injection
  succeeded — the marker is the real success signal. (914aab4)

### Coverage

Baseline 39.4% (Linux host only, no gates) → **51.9% merged** across 6
run contexts. See `docs/coverage-workflow.md` for the full breakdown.

## [v0.10.1] — 2026-04-18

Patch release: unlocks 116 previously-skipped tests + post-review fixes.

### Added

- `scripts/test-all.sh` auto-provisions per-layer MSF handler on Kali
  (`exploit/multi/handler` with sleep-3600 trick) and pushes the host-side
  Kali SSH key into each guest with strict ACLs. `MALDEV_KALI_SSH_KEY` is
  overridden per-layer so `testutil.KaliSSH` reaches Kali from inside the
  guest. `resolve_vm_ip` (arp/lease/agent fallback), `restore_init_silent`
  helpers. `set -Euo pipefail`.

### Fixed

- `cmd/memscan-mcp` `get_export` MCP tool: resolves `module` by name via
  `/module` first, then forwards the hex base to `/export`. Was always
  erroring because the server expects hex, not a DLL name.
- `scripts/vm-test/install-keys.sh`: now uses `qemu:///session` URI
  consistently (was defaulting to `qemu:///system` and silently skipping
  every domain on developer machines).
- `pe/morph TestUPXMorphRealBinary`: skip cleanly on non-Windows
  (UPXMorph is PE-only, the test execs the morphed binary); on Windows,
  skip under UPX 4.x because UPXMorph was written for 3.x signatures.

### Changed

- `cmd/vmtest/driver_libvirt.go`: collapsed three virsh helpers into a
  single `virshCmd` factory.
- `cmd/memscan-server/server_windows.go`: extracted `enumModules` +
  `moduleBasename` (deduped between `findModule` and `moduleNameAt`);
  `bytes.Index` instead of hand-rolled scan loop; `strconv.ParseUint`
  for hex parsing.
- `cmd/memscan-harness/harness_windows.go`: stdlib `sort.Strings`,
  `pickCaller` delegates to `pickWSyscallMethod`.
- `cmd/memscan-mcp/main.go`: extracted `toolText`/`toolError` helpers,
  `strings.Builder` in `formatJSON`.
- `cmd/test-report/main.go`: `countStatus` consolidated, dead
  `findTest` removed.

### Final test matrix (from INIT snapshots)

```text
memscan  77 / 77
linux   302 / 302   (40 legitimate skips)
windows 754 / 754   (21 legitimate skips)
TOTAL   1133 passed / 0 failed / 61 skipped
```

+116 tests now running vs v0.10.0; 0 failures maintained.

## [v0.10.0] — 2026-04-17

139 commits since [v0.9.0]. Highlights:

### Added — inline hooking + bridge

- **`evasion/hook/`** — x64 inline function hooking with trampoline and RIP-relative fixup, `InstallProbe` for unknown-signature targets, `HookGroup` (atomic multi-hook with rollback), `WithCaller`/`WithCleanFirst` options, `RemoteInstall` helpers.
- **`evasion/hook/bridge/`** — bidirectional controller/listener protocol over TCP/named-pipe/io.Pipe: wire-format with `ArgBlock`, `Decision`, multiplexed RPC (`Register`/`Call`), gob serialization layer, typed RPC via reflection (`func(T) (R, error)`).
- **`evasion/hook/shellcode/`** — Block/Nop/Replace/Redirect templates for drop-in decisions.

### Added — PE operations

- **`pe/masquerade/`** — compile-time PE resource embedding (manifest, VERSIONINFO, icons), blank-import `pe/masquerade/preset/` for one-liner impersonation, `IconFromFile`/`IconFromImage`/`WithSourcePE` programmatic API.
- **`pe/imports/`** — PE import table parser (IAT enumeration by DLL).

### Added — cross-host test infrastructure

- **`cmd/vmtest/`** — driver-based runner (auto-detects VBox vs libvirt), forwards `MALDEV_*` env into guests, ssh key-auth + rsync/scp push + snapshot restore.
- **`cmd/memscan-server/`** — Windows HTTP API on port 50300 wrapping `ReadProcessMemory` / `EnumProcessModulesEx` / `VirtualQueryEx`. Replaces the gitignored x64dbg MCP with pure-Go byte-pattern inspection.
- **`cmd/memscan-harness/`** — target-side tool with 5 groups (`ssn`, `amsi`, `etw`, `unhook`, `inject`) covering every caller × resolver combination in `docs/testing.md`.
- **`cmd/memscan-mcp/`** — stdio JSON-RPC 2.0 MCP adapter for Claude Code (tools: `read_memory`, `find_pattern`, `get_module`, `get_export`, `run_tests`).
- **`cmd/test-report/`** — parses `go test -json` streams, emits per-test / per-package / cross-platform matrix + failure detail + tally.
- **`scripts/test-all.sh`** — unified three-layer runner (memscan + linux + windows) with INIT snapshot revert between layers.
- **`scripts/vm-test-memscan.go`** — 32-row matrix → 77 static byte-pattern sub-checks (SSN 4×4, AMSI 4×3, ETW 4×6, Unhook 4×2, Inject 17).
- **`scripts/vm-test/`** — reproducible provisioning (`bootstrap-linux-guest.sh`, `bootstrap-windows-guest.ps1`, `install-keys.sh`), committed `config.yaml` + `config.local.example.yaml` + `kali-env.sh.example` templates.
- **`docs/vm-test-setup.md`** — end-to-end reproducibility guide (host install, guest provisioning, INIT snapshot, troubleshooting, Phase-5 punch-list).
- **`.mcp.json.example`** — Claude Code MCP wiring template.

### Fixed — test matrix (0 FAIL on libvirt Fedora against Windows 10 + Ubuntu 20)

- `win/impersonate`: `ThreadEffectiveTokenSID` + `ThreadEffectiveTokenHasGroup` helpers (locale-independent); dropped `Système` vs `SYSTEM` string assertions.
- `win/token`: `EnableAll`/`DisableAll` now no-op when every eligible privilege already matches (was `ErrNoPrivilegesSpecified`).
- `process/enum`: `TestSessionIDPopulated` compares against `ProcessIdToSessionId`, no longer assumes interactive session.
- `cleanup/service`: SCM DACL tests gated behind `MALDEV_SCM=1` + elevation probe (crashed silently under OpenSSH).
- `process/tamper/herpaderping`: manual temp dir + `taskkill` cleanup (image-lock race on spawned cmd.exe).
- `evasion/hook/bridge`: `skipIfNonWindowsController` on 11 tests needing the real Windows Controller.
- `pe/masquerade`: fall back to `explorer.exe` when `notepad.exe` UWP-shim ships without icon resources.
- `persistence/scheduler`: skip `TestList` in session 0 (OpenSSH).
- `c2/meterpreter` (linux e2e): `net.DialTimeout` probe + skip if no MSF handler.
- `evasion/hook/bridge`: moved `rpcResponse` to an untagged file (Linux cross-compile was broken).

### Changed

- **`testutil/kali.go`** — parameterised via `MALDEV_KALI_SSH_{HOST,PORT,KEY,USER}` envs; same test binaries now run on both libvirt and VBox hosts.
- **`scripts/vm-run-tests.sh`** — collapsed into a shim delegating to `cmd/vmtest`.
- **`cmd/vmtest/driver_{vbox,libvirt}.go`** — `collectMaldevEnv()` forwards `MALDEV_*` into the guest `go test` command.

### Final test run (from INIT snapshots, 2026-04-17)

```text
memscan  PASS  77 / 77
linux    PASS  282 / 282  (41 skip)
windows  PASS  735 / 735  (21 skip)
TOTAL    1017 passed / 0 failed / 62 skipped
```

### Deferred to Phase 5 (documented in `docs/vm-test-setup.md`)

Remote-inject harness (CRT/RTL/EarlyBird/QueueUserAPC/ThreadHijack/KernelCallback/PhantomDLL/ModuleStomp/ExecuteCallback — needs notepad-target spawn), BSOD test runner port, Meterpreter matrix runner, MCP SSE streamable HTTP transport.

---

[Unreleased]: https://github.com/oioio-space/maldev/compare/v0.10.1...HEAD
[v0.10.1]: https://github.com/oioio-space/maldev/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/oioio-space/maldev/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/oioio-space/maldev/releases/tag/v0.9.0
