---
package: github.com/oioio-space/maldev/pe/cert
last_reviewed: 2026-04-27
reflects_commit: 23c9331
---

# PE Certificate Theft

[← pe index](README.md) · [docs/index](../../index.md)

## TL;DR

Lift the Authenticode certificate blob from a legitimately signed
PE (Microsoft binary, vendor driver, etc.) and append it to an
unsigned implant — patching the security directory in place. The
signature won't verify cryptographically but many naive scanners
only check for certificate *presence*, not *validity*.

## Primer

Windows uses Authenticode signatures to verify executable
provenance. The cryptographic check is two-part: presence of a
certificate blob in the PE security directory, and validation of
that blob against a trusted root CA. A surprising number of
defensive tools — naive AV, file-property dialogs, allowlists
keyed on "is signed?" — only check the first part. Cloning a
known-good cert blob onto an unsigned implant clears those naive
checks while still failing `signtool verify`.

The package is **cross-platform**: cert blobs are pure-byte PE
manipulation, no Win32 APIs involved. Use it on a Linux build
host to prepare implants without round-tripping through
`signtool.exe`.

## How It Works

```mermaid
sequenceDiagram
    participant Signed as Signed PE<br/>e.g. notepad.exe
    participant Tool as pe/cert
    participant Unsigned as Unsigned implant

    Tool->>Signed: Read() — locate security directory
    Note over Tool: PE Data Directory[4]<br/>VirtualAddress = file offset<br/>(unique among directories)
    Tool->>Signed: read WIN_CERTIFICATE blob
    Tool->>Unsigned: Write() — pad to 8-byte alignment
    Tool->>Unsigned: append cert blob
    Tool->>Unsigned: patch security directory entry
    Note over Unsigned: Now carries Authenticode cert<br/>(signature fails verify; presence checks pass)
```

The PE security directory (data directory index 4) is unique:
its `VirtualAddress` field is a **file offset**, not an RVA.
WIN_CERTIFICATE structures are appended after the last section,
8-byte aligned. `Read` parses the directory entry and returns
the raw blob; `Write` truncates / appends + patches.

## API Reference

### `type Certificate`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Certificate)

| Field | Type | Description |
|---|---|---|
| `Raw` | `[]byte` | Raw `WIN_CERTIFICATE` bytes including header(s) and the embedded PKCS#7 signature blob |

### `Has(pePath string) (bool, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Has)

Cheapest probe — true when the security directory entry is
non-zero. Does not parse the certificate.

### `Read(pePath string) (*Certificate, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Read)

Parse the security directory and return the embedded cert.
Returns `ErrNoCertificate` when the PE is unsigned.

### `Write(pePath string, c *Certificate) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Write)

Append `c.Raw` to the PE, 8-byte align, patch the security
directory header in place.

### `Copy(srcPE, dstPE string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Copy)

`Read(srcPE)` + `Write(dstPE, …)` in a single call.

### `Strip(pePath, dst string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Strip)

Zero the security directory entry. When `dst` is non-empty, the
removed cert bytes are written there for later restoration.

### `Import(path string) (*Certificate, error)` / `(c *Certificate) Export(path string) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert#Import)

Persist / re-load raw cert blobs to and from disk so they can
travel between operations.

## Examples

### Simple — copy a Microsoft cert onto an implant

```go
import "github.com/oioio-space/maldev/pe/cert"

if err := cert.Copy(
    `C:\Windows\System32\notepad.exe`,
    `C:\Users\Public\implant.exe`,
); err != nil {
    panic(err)
}
```

### Composed — morph + cert + presence check

Layer with `pe/morph` so the static fingerprint is altered before
the cert is grafted on.

```go
import (
    "os"

    "github.com/oioio-space/maldev/pe/cert"
    "github.com/oioio-space/maldev/pe/morph"
)

raw, _ := os.ReadFile(`C:\loader.exe`)
raw, _ = morph.UPXMorph(raw)
_ = os.WriteFile(`C:\loader.exe`, raw, 0o644)

_ = cert.Copy(`C:\Windows\System32\notepad.exe`, `C:\loader.exe`)
ok, _ := cert.Has(`C:\loader.exe`) // true
```

### Advanced — round-trip donor selection

Cache the existing cert, try multiple donors, restore on burn.

```go
import (
    "os"

    "github.com/oioio-space/maldev/pe/cert"
)

target := `C:\loader.exe`
_ = cert.Strip(target, `C:\old.cert`)

candidates := []string{
    `C:\Windows\System32\notepad.exe`,
    `C:\Program Files\Google\Chrome\Application\chrome.exe`,
    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
}
for _, donor := range candidates {
    _ = cert.Copy(donor, target)
    // run target through the AV under test, observe verdict, decide
}

// Restore original if every candidate burned.
saved, _ := os.ReadFile(`C:\old.cert`)
_ = cert.Write(target, &cert.Certificate{Raw: saved})
```

See [`ExampleRead`](../../../pe/cert/cert_example_test.go) and
[`ExampleCopy`](../../../pe/cert/cert_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `signtool verify /pa <implant.exe>` failure | Any defender that actually validates signatures sees a chain failure |
| Modified file size + 8-byte alignment padding | EDR file-write telemetry; unusual delta-from-known-good if the signed donor was hashed earlier |
| Cert subject / issuer mismatched against the implant's metadata (CompanyName, OriginalFilename) | Mature allowlists cross-check signer identity vs `VERSIONINFO` |
| Naive `Get-AuthenticodeSignature` checking only `.Status -eq 'Valid'` | False-negative on the modified cert; common in homebrew scripts |

**D3FEND counters:**

- [D3-EAL](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/)
  — strict allowlisting validates the chain.
- [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/)
  — cert-blob inspection on submission.

**Hardening for the operator:**

- Pair with [`pe/masquerade`](masquerade.md) so the
  VERSIONINFO / manifest matches the donor cert's identity.
- Use a donor whose subject matches the *implant's apparent
  purpose* (PowerShell signer for a `pwsh.exe` lookalike, etc.).
- Recompute the PE checksum if downstream tooling validates it.
- Don't deploy where signature chain validation is enforced
  (Defender ATP, SmartScreen, AppLocker with publisher rules).

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Subvert Trust Controls: Code Signing | full — clone a third-party signature blob | D3-EAL, D3-SEA |

## Limitations

- **Signature won't verify.** Cryptographic chain validation
  (`signtool verify`, SmartScreen, AppLocker publisher rules)
  catches the substitution.
- **No checksum recomputation.** PE optional header `CheckSum`
  field stays as the source-PE value; downstream verifiers that
  check it (rare but real) will flag.
- **No certificate-chain emulation.** This is blob copy, not
  cert forging — for that, look at separate signing pipelines.
- **Validity-window mismatch.** Donor certs have NotBefore /
  NotAfter; an implant deployed outside that window flags as
  expired even before the chain is checked.

## See also

- [PE masquerade](masquerade.md) — clone the donor's manifest +
  VERSIONINFO + icon to match the cert subject.
- [PE strip / sanitize](strip-sanitize.md) — pair to scrub
  Go-toolchain markers before/after the cert graft.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
