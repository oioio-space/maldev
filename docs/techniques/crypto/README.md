# Cryptography & Encoding

[<- Back to README](../../../README.md)

The `crypto/` and `encode/` packages provide payload encryption and encoding: AES-256-GCM, XChaCha20-Poly1305, XOR, RC4, Base64, ROT13, and UTF-16LE encoding for PowerShell.

---

## Architecture Overview

```mermaid
graph TD
    subgraph "crypto/"
        AES["AES-256-GCM\nEncryptAESGCM / DecryptAESGCM"]
        CHACHA["XChaCha20-Poly1305\nEncryptChaCha20 / DecryptChaCha20"]
        XOR["XOR\nXORWithRepeatingKey"]
        RC4["RC4\nEncryptRC4"]
        AESKEY["NewAESKey()"]
        CCKEY["NewChaCha20Key()"]
    end

    subgraph "encode/"
        B64["Base64Encode / Base64Decode"]
        B64URL["Base64URLEncode / Base64URLDecode"]
        ROT["ROT13"]
        UTF["ToUTF16LE"]
        PS["EncodePowerShell"]
    end

    PAYLOAD["Raw Payload"] --> AES
    PAYLOAD --> CHACHA
    PAYLOAD --> XOR
    PAYLOAD --> RC4

    AES --> INJECT["inject/"]
    CHACHA --> INJECT

    style AES fill:#4a9,color:#fff
    style CHACHA fill:#49a,color:#fff
    style XOR fill:#a94,color:#fff
    style RC4 fill:#f96,color:#fff
```

## Documentation

| Document | Description |
|----------|-------------|
| [Payload Encryption](payload-encryption.md) | AES-GCM, ChaCha20, XOR, RC4, Base64, ROT13 |

## MITRE ATT&CK

| Technique | ID | Description |
|-----------|-----|-------------|
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Payload encryption and encoding |

## D3FEND Countermeasures

| Countermeasure | ID | Description |
|----------------|-----|-------------|
| Static Executable Analysis | [D3-SEA](https://d3fend.mitre.org/technique/d3f:StaticExecutableAnalysis/) | Detect encrypted/encoded payloads |

## Security Levels

| Algorithm | Security | Use Case |
|-----------|----------|----------|
| AES-256-GCM | Cryptographic | Primary payload encryption |
| XChaCha20-Poly1305 | Cryptographic | Alternative to AES (no AES-NI needed) |
| XOR | Obfuscation only | Quick payload obfuscation, not security |
| RC4 | Broken | Compatibility with legacy tools only |
| Base64 | Encoding (no security) | Transport encoding |
| ROT13 | Trivial | String obfuscation |
