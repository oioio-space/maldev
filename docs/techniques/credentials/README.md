---
last_reviewed: 2026-04-27
reflects_commit: e171423
---

# Credential access

[← maldev README](../../../README.md) · [docs/index](../../index.md)

Pure-Go credential-extraction primitives: live LSASS process dumping,
offline SAM hive parsing, and Kerberos ticket forging. Composes with
[`kernel/driver/rtcore64`](../evasion/byovd-rtcore64.md) for the PPL
unprotect path that LSASS dumping needs on modern Windows.

## Packages

| Package | Tech page | Detection | One-liner |
|---|---|---|---|
| [`credentials/lsassdump`](../../../credentials/lsassdump) | [sekurlsa.md](sekurlsa.md) (covers dump+parse chain) | very-noisy | NtGetNextProcess + in-process MINIDUMP + EPROCESS PPL unprotect |
| [`credentials/sekurlsa`](../../../credentials/sekurlsa) | [sekurlsa.md](sekurlsa.md) | quiet (parser only) | Pure-Go MSV1_0 / Wdigest / Kerberos / DPAPI / TSPkg / CloudAP / LiveSSP / CredMan walkers + LSA-crypto unwrap + NTLM/AES extraction + PTH write-back + Kerberos kirbi export |
| [`credentials/samdump`](../../../credentials/samdump) | (technique page TBD) | noisy | Offline SAM hive dump — REGF parser + boot-key permutation + AES/RC4 hashed-bootkey + per-RID DES de-permutation |
| [`credentials/goldenticket`](../../../credentials/goldenticket) | (technique page TBD) | quiet (forge) / noisy (submit) | PAC marshaling + KRB5 `Forge` + LSA `Submit` for Golden Ticket attacks |

## Quick decision tree

| You want to… | Use |
|---|---|
| …get NTLM hashes / Kerberos tickets from a live host | [`lsassdump`](../../../credentials/lsassdump) → [`sekurlsa.Parse`](../../../credentials/sekurlsa) chain |
| …parse a `.dmp` you obtained out-of-band | [`sekurlsa.Parse`](../../../credentials/sekurlsa) |
| …dump SAM offline (no LSASS access) | [`samdump`](../../../credentials/samdump) |
| …forge a Golden/Silver Ticket | [`goldenticket.Forge`](../../../credentials/goldenticket) → [`Submit`](../../../credentials/goldenticket) |
| …pass-the-hash into a live LSASS | [`sekurlsa.Pass`](sekurlsa.md) / `PassImpersonate` |
| …pass-the-ticket | [`sekurlsa.KerberosTicket.ToKirbi`](sekurlsa.md) → [`goldenticket.Submit`](../../../credentials/goldenticket) |

## MITRE ATT&CK

| T-ID | Name | Packages | D3FEND counter |
|---|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | `credentials/lsassdump`, `credentials/sekurlsa` | D3-PSA, D3-SICA |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | OS Credential Dumping: SAM | `credentials/samdump` | D3-PSA, D3-FCA |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material: Pass the Hash | `credentials/sekurlsa` | D3-PSA, D3-SICA |
| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Use Alternate Authentication Material: Pass the Ticket | `credentials/sekurlsa`, `credentials/goldenticket` | D3-NTA |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Steal or Forge Kerberos Tickets: Golden Ticket | `credentials/goldenticket` | D3-NTA |

## See also

- [Operator path: credential harvest scenario](../../by-role/operator.md#credential-harvest)
- [Detection eng path: credential-access artifacts](../../by-role/detection-eng.md#credential-access--credentials)
- [`kernel/driver/rtcore64`](../evasion/byovd-rtcore64.md) — BYOVD primitive for PPL unprotect
- [`docs/credentials.md`](../../credentials.md) — flat API reference (legacy)
