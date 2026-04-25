# Plan — `credentials/lsasparse`: Minimum-Viable LSASS Credential Extraction

> **Status:** Draft for review. **Author:** session 2026-04-25.
> **Inputs:** existing `credentials/lsassdump` (minidump *writer*),
> public pypykatz source (`pypykatz/pypykatz/`),
> Mimikatz `mimikatz/sekurlsa/`, `volatility3/plugins/windows/cachedump.py`.

---

## Goal

Ship a Go package that **reads** a minidump produced by
`credentials/lsassdump` (or by `MiniDumpWriteDump` / DFIR tooling) and
extracts at minimum the **MSV1_0 NTLM hashes** for every active logon
session — equivalent to the `lsa_secrets` + `msv` portions of
`pypykatz lsa minidump <file>` output.

Out-of-scope for v1 (deliberate, can be follow-ups):

- WDigest plaintext credentials
- Kerberos tickets (TGT / TGS extraction)
- DPAPI master keys
- LiveSSP / SSP / TSPkg / CloudAP secrets
- Mimikatz-style live-process attach
- LSAISO trustlet (Credential Guard) bypass

The minimum-viable cut is shaped by what gives operators the most
value per LOC: NTLM hashes are the dominant pivot for lateral
movement, every dump format and every Windows build supports them,
and the crypto layer is the same one every other provider needs —
so MSV first builds the foundation for adding WDigest/Kerberos later.

---

## Why we need this

`credentials/lsassdump` shipped in v0.15.x as a *producer* — it
generates a MINIDUMP blob and hands it to the operator (or a C2
exfil channel). To use the blob the operator currently needs an
external tool (mimikatz on a different host, pypykatz on a Linux
analyst box). For pure-Go red-team workflows the dependency is
awkward:

- pypykatz needs Python + 50 MB of dependencies on the analyst box
- mimikatz is the loudest binary an EDR will ever see on a Windows host
- exfiltrating the dump introduces a network artefact + a >50 MB blob
- offline credential extraction means the dump persists on disk
  somewhere — every minute it sits is more forensic surface

A native Go parser lets the implant **dump → extract → wipe** in the
same process, never touching disk and never leaving LSASS bytes
unencrypted in memory longer than the parse takes.

---

## Architecture

### Layer placement

`credentials/lsasparse/` — Layer 2 alongside `credentials/lsassdump`.
Pure Go (no Win32 calls). Cross-platform: a Linux analyst box can run
the parser against a dump exfiltrated from Windows, exactly like
pypykatz today. `_windows.go` files only when we add live-process
read (Mimikatz path) — out of v1 scope.

### Directory layout

```
credentials/
├── lsassdump/              (existing — producer)
└── lsasparse/              (new — consumer)
    ├── doc.go              package doc + MITRE T1003.001
    ├── lsasparse.go        public API (Parse, Result, Error sentinels)
    ├── minidump_reader.go  MINIDUMP reader (mirror of lsassdump/minidump.go writer)
    ├── module.go           ModuleListStream walker — locate lsasrv.dll/msv1_0.dll/kerberos.dll
    ├── memory.go           Memory64ListStream — RVA→bytes lookups
    ├── pattern.go          version-keyed signature scanner
    ├── crypto.go           LSA crypto: BCrypt 3DES + AES key import, NL$KM derivation
    ├── crypto_test.go      AES-CBC + 3DES round-trip with known-good keys
    ├── msv.go              MSV1_0 logon-session walker + NTLM hash extraction
    ├── msv_test.go         table-test against committed minidump fixtures
    ├── session.go          LogonSession struct + LUID / SID parsing
    ├── lsasparse_test.go   end-to-end against committed fixtures
    └── testdata/
        ├── win10-22h2-19045.dmp.gz       known-good dump (SHA pinned)
        ├── win10-22h2-19045.expected.json expected MSV output
        └── README.md                      how to regenerate fixtures
```

Single Go module — no internal sub-packages, no embed.FS gymnastics.
Fixtures gzip'd to keep repo lean (a 50 MB lsass dump compresses to
~12 MB; we ship ONE fixture per supported build).

### Public API (locked v1 surface)

```go
// Parse extracts credentials from a minidump blob produced by
// MiniDumpWriteDump or credentials/lsassdump.Dump.
//
// reader can be a *bytes.Reader, *os.File, or any io.ReaderAt — the
// parser does random-access reads via Memory64List RVAs.
//
// On success returns a Result containing every successfully decrypted
// MSV1_0 logon session. Partial success is normal: a dump from an
// unsupported build will yield 0 sessions but no error; a corrupted
// dump returns the underlying parse error. Per-session decryption
// failures are collected into Result.Warnings without aborting.
func Parse(reader io.ReaderAt, size int64) (*Result, error)

// ParseFile is a convenience wrapper.
func ParseFile(path string) (*Result, error)

// Result aggregates everything Parse extracts.
type Result struct {
    BuildNumber uint32         // detected ntoskrnl build (e.g. 19045)
    Architecture Architecture  // x64 only in v1; Architecture enum kept for x86 future
    Sessions    []LogonSession // every session with at least one successful decrypt
    Warnings    []string       // non-fatal: a session whose key decrypt failed, an unknown package
}

// LogonSession mirrors the shape of pypykatz's LogonSession with
// only MSV1_0 populated in v1.
type LogonSession struct {
    LUID          uint64    // locally-unique session ID from EPROCESS
    LogonType     LogonType // Interactive, Network, Service, etc.
    AuthPackage   string    // "NTLM", "Kerberos", … (v1 always "NTLM")
    UserName      string
    LogonDomain   string
    LogonServer   string
    LogonTime     time.Time
    SID           string    // S-1-5-21-…
    Credentials   []Credential
}

// Credential is the typed payload. v1 ships exactly one variant:
// MSV1_0 NTLM hash pair.
type Credential interface {
    AuthPackage() string // "MSV1_0", future: "Wdigest", "Kerberos", "TSPkg", "CloudAP"
}

// MSV1_0Credential is the NT/LM hash pair extracted from MSV's logon
// list. NT hash is MD4(unicode(password)); LM is empty on Win10/11
// (Microsoft killed LM caching by default).
type MSV1_0Credential struct {
    UserName    string
    LogonDomain string
    NTHash      [16]byte // empty if !Found
    LMHash      [16]byte // typically empty on Win10/11
    SHA1Hash    [20]byte // present from Win11 onwards
    DPAPIKey    [16]byte // optional companion key sometimes co-located with the hashes
    Found       bool     // false on a session whose decrypt produced all-zero — warn, don't fail
}

func (MSV1_0Credential) AuthPackage() string { return "MSV1_0" }

// LogonType mirrors the standard Windows LogonType enum.
type LogonType uint32
const (
    Interactive       LogonType = 2
    Network           LogonType = 3
    Batch             LogonType = 4
    Service           LogonType = 5
    Unlock            LogonType = 7
    NetworkClearText  LogonType = 8
    NewCredentials    LogonType = 9
    RemoteInteractive LogonType = 10
    CachedInteractive LogonType = 11
)

// Architecture is x64 only in v1.
type Architecture int
const (
    ArchUnknown Architecture = iota
    ArchX64
)

// Sentinel errors for callers that need errors.Is dispatch.
var (
    ErrNotMinidump        = errors.New("lsasparse: input is not a MINIDUMP")
    ErrUnsupportedBuild   = errors.New("lsasparse: no signature template for this build")
    ErrLSASRVNotFound     = errors.New("lsasparse: lsasrv.dll module not in MODULE_LIST")
    ErrMSV1_0NotFound     = errors.New("lsasparse: msv1_0.dll module not in MODULE_LIST")
    ErrKeyExtractFailed   = errors.New("lsasparse: LSA crypto keys could not be extracted")
)
```

The single-public-function shape (`Parse(reader, size) (*Result, error)`)
keeps the door open for streaming variants and live-process variants
without breaking v1 callers.

---

## Implementation phases

Each phase ends with a tag + commit. None depend on a Windows VM —
the test fixtures are committed dumps, so CI runs on Linux.

### Phase 1 — MINIDUMP reader (~250 LOC, 1 commit)

**Deliverable:** parse a minidump blob, expose the four streams we
care about (`SystemInfoStream`, `ThreadListStream`, `ModuleListStream`,
`Memory64ListStream`). Implement `io.ReaderAt`-backed RVA→bytes
lookups against the Memory64List.

**Files:**
- `minidump_reader.go` — header + directory + per-stream parsing
- `memory.go` — `MemoryRegion` walker + `(r *Reader) ReadAt(addr uint64, n int) ([]byte, error)` for kernel-VA random access

**Tests:**
- `minidump_reader_test.go` — round-trip a known-good dump produced by
  `credentials/lsassdump.Dump` against a live test fixture; assert
  every region the writer emitted is recoverable byte-for-byte.

**Why first:** the reader is shared infrastructure. The crypto and
provider phases all read kernel VA bytes through this reader; zero
provider code can be written before this lands.

### Phase 2 — Module + version detection (~150 LOC, 1 commit)

**Deliverable:** walk `ModuleListStream`, locate
`lsasrv.dll` / `msv1_0.dll` / `kerberos.dll` by basename match; pull
each module's `(Base, Size, TimeDateStamp, CheckSum)` out of the
ModuleEntry. Detect the dump's source build via `SystemInfoStream`'s
`ProcessorArchitecture` + `MajorVersion` + `MinorVersion` +
`BuildNumber`.

**Files:**
- `module.go` — Module struct + `ModuleByName(name string) (*Module, bool)`
- Extend `lsasparse.go` with `BuildNumber` detection.

**Tests:**
- `module_test.go` — given the committed fixture, assert `ModuleByName("lsasrv.dll")` returns a non-nil module with a plausible base address.

**Why second:** all signature scans key on a (build, module) pair.
Without build detection we don't know which template to apply; without
module-by-name we don't know where to scan.

### Phase 3 — Pattern scanner + LSA key extraction (~350 LOC, 1 commit)

This is the hardest phase. Three sub-deliverables in one commit because
they're tightly coupled:

**3a. Pattern scanner.** Each Windows build has a per-module byte
pattern that locates the IV / 3DES key / AES key globals inside
`lsasrv.dll`. Templates from pypykatz. We embed them as Go consts:

```go
type lsaTemplate struct {
    BuildMin, BuildMax  uint32       // inclusive build range
    InitializationVectorPattern []byte
    InitializationVectorOffset  int  // signed offset from match start to the IV uint64
    Key3DESPattern    []byte
    Key3DESOffset     int
    KeyAESPattern     []byte
    KeyAESOffset      int
    // Bytes after Pattern that we mask via 0x00 in the wildcard search
    Wildcards         []int
}

var lsaTemplates_x64 = []lsaTemplate{
    // Win10 1909 (18363) through 22H2 (19045)
    {BuildMin: 18362, BuildMax: 19045, …},
    // Win11 21H2 (22000) through 22H2 (22621)
    {BuildMin: 22000, BuildMax: 22621, …},
    // Win11 23H2 (22631) onward
    {BuildMin: 22631, BuildMax: 99999, …},
}
```

The wildcard mask (`0x00`-as-don't-care) handles the small per-CU
variations within a build range — pypykatz uses the same trick.

**3b. Pointer chase.** A pattern hit gives us an RVA *near* the global;
the `Offset` field tells us how many bytes forward/back the actual
`uint64*` lives. We dereference: `keyPtr := readPtr(matchAddr+Offset)`.

**3c. Key import via Win-style BCrypt blob.** What we recover from
`lsasrv.dll` is a `BCRYPT_KEY_DATA_BLOB_HEADER` followed by the
session-key bytes. Decode the header, validate the `dwMagic` against
`BCRYPT_KEY_DATA_BLOB_MAGIC` (`KDBM`, 0x4d42444b), import the key into
Go's `crypto/cipher.Block` via `crypto/aes.NewCipher` for the AES
variant or `crypto/des.NewTripleDESCipher` for the 3DES variant.

**Files:**
- `pattern.go` — pattern scanner with wildcard mask + version-keyed template registry
- `crypto.go` — BCrypt blob parser, AES-CBC + 3DES-CBC decrypt wrappers, helper `decrypt(ct, iv, key) ([]byte, error)` that picks the cipher based on ciphertext length (3DES if `len%8==0 && len%16!=0`, AES otherwise — same heuristic as pypykatz)

**Tests:**
- `pattern_test.go` — feed the scanner a 4 KiB prefix of lsasrv.dll
  bytes from the fixture; assert the matcher returns the expected
  offset.
- `crypto_test.go` — encrypt-decrypt round-trip with both cipher
  variants using vectors generated offline once and committed.

**Why third:** every provider after this point is "find the per-package
struct, decrypt its fields with the LSA key" — all of which depend
on the key.

### Phase 4 — MSV1_0 logon session extraction (~300 LOC, 1 commit)

The actual credential extraction. MSV stores a doubly-linked list
whose head pointer lives in `msv1_0.dll`'s `.data` section. Each node
is a `LogonSessionListEntry` with an embedded `MSV1_0_PRIMARY_CREDENTIAL`
that's encrypted with the LSA key from phase 3.

**Sub-deliverables:**

- `msv.go::findLogonSessionListHead(reader, msv1_0Module, template) (uint64, error)`
  — pattern-match the `_LogonSessionList` global and dereference.
- `msv.go::walkLogonSessions(reader, head, template) ([]rawSession, error)`
  — follow `Flink` pointers until we loop back to head; bound the walk
  at 1024 nodes to defeat malformed dumps.
- `msv.go::decryptPrimary(rawSession, lsaKey) (MSV1_0Credential, error)`
  — pull the `Credentials.PrimaryCredentials_data` blob, decrypt
  with the LSA key, parse the `MSV1_0_PRIMARY_CREDENTIAL_*` struct
  for the build, copy NT/LM/SHA1 hashes out.

The struct layout has changed several times between Win10 1909 and
Win11 23H2. Each layout becomes a constant in the same template
struct from phase 3:

```go
type lsaTemplate struct {
    // … crypto fields from phase 3 …
    LogonSessionListPattern []byte
    LogonSessionListOffset  int
    LogonSessionListCount   int    // Win10/11 differ — Win10 has 32 buckets, Win11 has 64
    LogonSessionStruct      msvLogonSessionLayout
}

type msvLogonSessionLayout struct {
    LUIDOffset      int
    UsernameOffset  int  // UNICODE_STRING field
    DomainOffset    int  // UNICODE_STRING
    PrimaryDataOffset int // pointer to encrypted PrimaryCredentials_data
}
```

**Tests:**
- `msv_test.go` — committed fixture + expected JSON. Run Parse,
  serialize Sessions to JSON, diff against expected. Single
  golden-file test per supported build.

**Why fourth:** this is the payoff. After phase 4 lands the package is
materially useful — `Parse(dumpBytes)` returns a list of
`MSV1_0Credential` ready for `pth` / `pass-the-hash` workflows.

### Phase 5 — Polish + docs (~100 LOC, 1 commit, **tag v0.23.0**)

- Public docs: `docs/techniques/credentials/lsasparse.md` with primer,
  simple example (`Parse(file) → for _, s := range result.Sessions`),
  advanced example (in-process pipeline: `lsassdump.Dump → bytes.NewReader → lsasparse.Parse → wipe`),
  composed example (BYOVD `Unprotect → Dump → Parse → Reprotect → wipe`),
  API reference, MITRE T1003.001, detection level (Low — the parse is
  pure Go on the operator side; the loud part is the dump itself,
  already covered in lsass-dump.md).
- README capability table: extend the `Credentials` row.
- `docs/mitre.md`: add `credentials/lsasparse` under T1003.001 alongside
  `lsassdump`.
- `docs/credentials.md`: new area-doc covering `lsassdump` (producer)
  + `lsasparse` (consumer) as a matched pair.
- CHANGELOG `[Unreleased]` entry.
- Tag `v0.23.0` after Phase 5 lands.

---

## Risks + open questions

### Brittleness on new Windows builds

Microsoft ships `lsasrv.dll` updates inside cumulative updates that
sometimes shift global offsets without bumping the build number — same
build, different LCU, different addresses. Pypykatz handles this via
"sigfile" updates published as the community discovers them. Our
strategy:

- Ship templates for Win10 22H2 (19045) + Win11 22H2 (22621) + Win11 23H2 (22631) at v1.
- Document the `lsaTemplates_x64` extension path in the package's
  `doc.go` so operators can register their own template at runtime if
  needed.
- Surface `ErrUnsupportedBuild` cleanly so callers know to either
  contribute a template or fall back to external pypykatz.

### x86 dumps

WoW64-induced 32-bit `lsass.exe` dumps exist but are vanishingly rare
on modern Windows. Skip in v1; `Architecture` enum reserves the slot.

### Credential Guard / LSAISO

When Credential Guard is enabled, NT hashes for non-cached domain
sessions are isolated in the LSAISO trustlet. The dump still contains
the wrappers but the secrets read as ciphertext we can't decrypt
without a kernel exploit. v1 detects this case (the `IsoCreds` flag
in the LogonSession entry is set) and surfaces it as a per-session
warning rather than a parse error.

### Go runtime + sensitive-bytes hygiene

The package decrypts NT hashes into `[]byte` slices that live on Go's
heap. Standard slice resize / GC could leave fragments after the
caller wipes the visible reference. Mitigations:

- Allocate the decrypted buffers from a pool we wipe on package
  release (`SecureZero` from `cleanup/memory`).
- Document that callers MUST call `result.Wipe()` after consumption.
- Consider `runtimesecret` GOEXPERIMENT for the NT-hash field
  specifically (Go 1.26+) — same pattern already used in
  `cleanup/memory.DoSecret`.

### Test fixture acquisition

Committing a real LSASS dump to git is fine (it's de-facto-public
information for a default-config Win10 + a throwaway local account)
but the SHA must be pinned and the dump must NOT contain real
credentials. Procedure documented in `testdata/README.md`:

1. Fresh Win10 22H2 VM (TOOLS snapshot).
2. Create local account `pypykatz-test` with password `test123`.
3. Log on interactively as that account once (so MSV caches it).
4. From an admin shell, run our `cmd/lsasdump-fixture` helper that
   chains `lsassdump.Dump → gzip → write`.
5. Run `pypykatz` against the same dump as ground truth, save the
   `--json` output to `*.expected.json`.
6. Pin SHAs in `testdata/SHA256SUMS`.

Same procedure per build we add a template for.

---

## Aggregate estimate

| Phase | LOC | Commits | Tag |
|---|---|---|---|
| 1 — MINIDUMP reader | 250 | 1 | — |
| 2 — Module + version | 150 | 1 | — |
| 3 — Pattern + crypto | 350 | 1 | — |
| 4 — MSV1_0 walker | 300 | 1 | — |
| 5 — Docs + polish | 100 | 1 | **v0.23.0** |
| **Total** | **~1,150** | **5** | |

Compared to pypykatz (Python, ~3,000 LOC for `lsa.py` alone) we're
intentionally narrower: one provider, one architecture, three
template ranges. Expansion to Wdigest / Kerberos / DPAPI is each its
own ~300-500 LOC chantier on top of phase 4's foundation, all
gated by phase 3's crypto layer.

---

## Suggested kickoff order

1. **Phase 1 first** — committed minidump fixture from the existing
   `credentials/lsassdump` Windows VM tests is the gating dependency.
   No fixture, no parser tests, no confidence anything works.
2. **Phase 2 second** — small, builds operator confidence the pattern
   scanner has a stable target to scan.
3. **Phase 3 third** — biggest single effort. Allocate budget for a
   debug spike if AES-CBC round-trip drifts from pypykatz's output (the
   `BCRYPT_KEY_DATA_BLOB` parsing has historical traps around endianness
   that bit several maldev-style projects).
4. **Phase 4 fourth** — when this passes the golden-file test, the
   package is shippable. Do not gate v0.23.0 on extras.
5. **Phase 5 fifth** — docs + tag. Keep the docs honest about which
   builds we cover; don't claim "Win10/11 support" if we only tested
   on 19045 + 22621 + 22631.

---

## What this plan does NOT cover

Same exclusions as the goal section, plus:

- A live `mimikatz!sekurlsa` clone that attaches to lsass via OpenProcess.
  That's a separate `credentials/lsalive` chantier — interesting, much
  noisier, requires PPL bypass (which we already have via
  `credentials/lsassdump.Unprotect`).
- A web UI / CLI binary. The point is the **library**; operators wrap
  it in whatever pipeline they need. A `cmd/lsasparse` binary may be
  added later as a convenience but is out of scope for v1.
- Any cryptographic novelty. Every primitive we use is in
  `crypto/aes`, `crypto/des`, `crypto/cipher` from Go stdlib.

---

## Open questions for the user

1. **Template scope at v1** — are Win10 22H2 + Win11 22H2 + Win11 23H2
   enough? Adding 21H2 + 1909 + 2004 is straightforward but each
   means one more committed fixture (~12 MB compressed each).

2. **Test fixture provenance** — am I OK to spin up the Win10 VM,
   create a `pypykatz-test` local account with a known throwaway
   password, dump LSASS, and commit the resulting `.dmp.gz`? The
   committed dump would contain a real (but disposable) NTLM hash for
   `pypykatz-test:test123` — that's fine for fixture purposes but I
   want explicit OK before pushing.

3. **Phase 5 area-doc structure** — do you want `docs/credentials.md`
   as a new top-level area doc (mirroring `docs/persistence.md` etc.)
   or fold lsasparse coverage into the existing
   `docs/techniques/collection/lsass-dump.md`? Pass 3 already moved
   `lsassdump` to `credentials/`; consistency argues for the new
   area-doc.

4. **Hash output format** — pypykatz emits NT hashes as 32-char hex.
   Our `MSV1_0Credential.NTHash` is `[16]byte`. Should we add a
   `String()` method that returns `Username::Domain::LMHash:NTHash:::`
   (the pwdump format pth tools expect) so callers don't need to roll
   their own formatter?

5. **Go this week / next week / shelved** — three commits-worth of work
   (phases 1-3) is doable in one session if there are no surprises;
   phases 4-5 are a follow-up. Want me to start phase 1 immediately
   after this plan settles?
