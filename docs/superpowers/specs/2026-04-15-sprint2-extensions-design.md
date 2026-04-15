# Sprint 2 Extensions — Design Spec

**Date:** 2026-04-15  
**Status:** Approved  
**Adds to:** `docs/superpowers/plans/2026-04-14-sprint2-evasion.md`

---

## Overview

Five additions to the Sprint 2 plan:

| # | Area | What |
|---|------|------|
| A | `c2/multicat` | Multi-session reverse shell listener |
| B | `crypto` | TEA, XTEA, arithmetic shift, byte substitution, Agent Smith matrix transform |
| C | `evasion/fakecmd` | Remote PID spoofing (`SpoofPID`) |
| D | `ADS ↔ selfdelete` | Analysis + documentation of relationship |
| E | `docs` | Dedicated markdown page for `encode` package |

---

## A. `c2/multicat` — Multi-Session Listener

### Problem

`c2/shell` is an **agent-side** component: it dials out. There is no server-side component to accept and manage multiple incoming reverse shell connections simultaneously. Operators need session multiplexing comparable to Metasploit's session subsystem.

### Architecture

Two new types:

**`Listener`** — server-side symmetric to `transport.Transport`:
```go
// transport/listener.go
type Listener interface {
    Accept(ctx context.Context) (net.Conn, error)
    Close() error
    Addr() net.Addr
}
```

**`c2/multicat.Manager`** — manages sessions, emits events:
```go
type SessionMetadata struct {
    ID          string    // "1", "2", ...
    RemoteAddr  net.Addr
    ConnectedAt time.Time
    Hostname    string    // from optional BANNER line (see Wire Protocol)
}

type Session struct {
    Meta   SessionMetadata
    conn   net.Conn       // underlying connection (unexported)
}

// Session is io.ReadWriteCloser for operator ↔ agent I/O
func (s *Session) Read(p []byte) (int, error)
func (s *Session) Write(p []byte) (int, error)
func (s *Session) Close() error

type EventType int
const (
    EventOpened EventType = iota
    EventClosed
)

type Event struct {
    Type    EventType
    Session *Session
}

type Manager struct {
    mu       sync.RWMutex
    sessions map[string]*Session
    counter  atomic.Int32
    events   chan Event   // buffered (64)
}

func New() *Manager

// Listen accepts connections from a Listener until ctx is cancelled.
// Each new connection spawns a goroutine, populates metadata, emits EventOpened.
func (m *Manager) Listen(ctx context.Context, l transport.Listener) error

// Events returns the read-only event channel.
func (m *Manager) Events() <-chan Event

// Sessions returns a snapshot copy of all active sessions.
func (m *Manager) Sessions() []*Session

// Get returns a session by ID ("1", "2", ...).
func (m *Manager) Get(id string) (*Session, bool)

// Remove closes and removes a session. Emits EventClosed.
func (m *Manager) Remove(id string) error
```

### Wire Protocol (BANNER)

When an agent connects, the multicat listener reads the first line with a short deadline (500 ms):

```
BANNER:<hostname>\n
```

If the line is absent or times out, `Hostname` is left empty. This is **opt-in** on the agent side — `c2/shell` does not send it today; a future option `WithBanner(hostname)` can be added to `c2/shell.Config` without breaking existing agents.

### Listener Implementations (in `c2/transport`)

```go
// transport/listener.go
func NewTCPListener(addr string) (Listener, error)
func NewTLSListener(addr string, cfg *tls.Config) (Listener, error)
```

Both return a `Listener`. Internally they call `net.Listen` / `tls.Listen`.

### Usage Example

```go
l, _ := transport.NewTCPListener(":4444")
mgr := multicat.New()

go mgr.Listen(ctx, l)

for ev := range mgr.Events() {
    switch ev.Type {
    case multicat.EventOpened:
        fmt.Printf("[+] session %s from %s\n", ev.Session.Meta.ID, ev.Session.Meta.RemoteAddr)
    case multicat.EventClosed:
        fmt.Printf("[-] session %s closed\n", ev.Session.Meta.ID)
    }
}

// Interact with a specific session
sess, _ := mgr.Get("1")
sess.Write([]byte("whoami\n"))
io.Copy(os.Stdout, sess)
```

### Files

```
c2/transport/listener.go          Listener interface + NewTCPListener + NewTLSListener
c2/multicat/doc.go                MITRE T1571 (non-standard port), detection note
c2/multicat/multicat.go           Manager, Session, Event types + all methods
c2/multicat/multicat_test.go      TestListenAccept, TestSessions, TestRemove (net.Pipe)
```

### MITRE / Detection

- **T1571** — Non-Standard Port (listening on arbitrary port)
- Detection: **Low** — package is operator-side only, never embedded in implant

---

## B. `crypto` — Lightweight Obfuscation Additions

### Rationale

Currently `crypto` offers strong AEAD ciphers (AES, ChaCha20) and trivial XOR. For shellcode obfuscation there is a gap: algorithms that are **lightweight, reversible, and produce low-entropy output change** — useful when high entropy is itself a detection signal, or when a simple layered scheme (e.g., matrix → XOR) is needed.

### New Functions

All follow the existing function-pair pattern. All are symmetric or have explicit Reverse counterpart.

#### TEA (Tiny Encryption Algorithm)

```go
// 16-byte key, operates on 8-byte blocks (PKCS7 padded internally).
func EncryptTEA(key [16]byte, data []byte) ([]byte, error)
func DecryptTEA(key [16]byte, data []byte) ([]byte, error)
```

64 Feistel rounds, 32-bit words. Very fast on any architecture.

#### XTEA (eXtended TEA)

```go
// 16-byte key, same block size. Fixes TEA's equivalent-key weakness.
func EncryptXTEA(key [16]byte, data []byte) ([]byte, error)
func DecryptXTEA(key [16]byte, data []byte) ([]byte, error)
```

#### Arithmetic Shift Obfuscation

```go
// Each byte: out[i] = (in[i] + key[i%len(key)] + i) & 0xFF
// Not cryptographic — trivially reversible but breaks static signatures.
func ArithShift(data, key []byte) ([]byte, error)
func ReverseArithShift(data, key []byte) ([]byte, error)
```

The position-dependent `+i` term means identical input bytes produce different output, unlike pure XOR.

#### Byte Substitution (S-Box)

```go
// NewSBox generates a random 256-byte permutation and its inverse.
func NewSBox() (sbox [256]byte, inverse [256]byte, err error)

// SubstituteBytes applies a substitution table (any 256-byte permutation).
func SubstituteBytes(data []byte, sbox [256]byte) []byte

// ReverseSubstituteBytes applies the inverse table.
func ReverseSubstituteBytes(data []byte, inverse [256]byte) []byte
```

#### Agent Smith — Matrix Transform

```go
// MatrixTransform pads data to a multiple of n*n bytes, reshapes into n×n matrices,
// multiplies each by the key matrix (mod 256), serialises back to bytes.
// n must be 2, 3, or 4 (preset sizes). For arbitrary n use MatrixTransformN.
func MatrixTransform(data []byte, key [][]byte) ([]byte, error)
func ReverseMatrixTransform(data []byte, key [][]byte) ([]byte, error)

// NewMatrixKey generates a random n×n matrix that is invertible mod 256
// (i.e., det(key) is odd, guaranteeing a mod-256 inverse exists).
func NewMatrixKey(n int) (key [][]byte, inverse [][]byte, err error)
```

The matrix must be invertible mod 256: `gcd(det(key), 256) == 1`, which requires `det(key)` to be odd.

**Layering example** (Agent Smith + XOR):
```go
key, inv, _ := crypto.NewMatrixKey(3)
obf, _ := crypto.MatrixTransform(shellcode, key)
obf, _ = crypto.XORWithRepeatingKey(obf, xorKey)
// decrypt: XOR then ReverseMatrixTransform
```

### Doc Updates

- Update `docs/techniques/crypto/payload-encryption.md`: add section "Lightweight Obfuscation" covering TEA/XTEA, ArithShift, SubstituteBytes, MatrixTransform.
- Update comparison table to include new algorithms.

---

## C. `evasion/fakecmd` — Remote PID Spoofing

### Problem

Current `Spoof()` operates on the calling process only (`windows.CurrentProcess()`). Operators may want to patch the command line of a **target process** (e.g., a sacrificial process spawned for injection) so it appears innocuous in process listings before the payload runs.

### New Function

```go
// SpoofPID overwrites the PEB CommandLine UNICODE_STRING of the process
// identified by pid. Requires PROCESS_VM_READ | PROCESS_VM_WRITE |
// PROCESS_QUERY_INFORMATION on the target.
//
// Unlike Spoof(), there is no corresponding RestorePID — the caller must
// track the original string if restoration is needed.
func SpoofPID(pid uint32, fakeCmd string, caller *wsyscall.Caller) error
```

### Implementation Notes

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PebBaseAddress`
2. `ReadProcessMemory` at `PebBaseAddress + offset(ProcessParameters)` → `ProcessParameters` pointer
3. `ReadProcessMemory` at `ProcessParameters + offset(CommandLine)` → current `UNICODE_STRING`
4. Allocate UTF-16 buffer in **target** process: `NtAllocateVirtualMemory` with target handle
5. `WriteProcessMemory` → copy fake string into that allocation
6. `WriteProcessMemory` → patch `CommandLine.Buffer`, `Length`, `MaximumLength` in target PEB

Step 4 (remote allocation) uses `api.ProcNtAllocateVirtualMemory` or caller if non-nil.

### Files Modified

- `evasion/fakecmd/fakecmd_windows.go` — add `SpoofPID`
- `evasion/fakecmd/fakecmd_windows_test.go` — `TestSpoofPID` (spawn notepad, spoof, verify via `NtQueryInformationProcess` from test, kill notepad)
- `docs/techniques/evasion/fakecmd.md` — add Remote section

---

## D. `system/ads` ↔ `cleanup/selfdelete` — Relationship Analysis

### Conclusion: No Dependency Appropriate

| | `system/ads` | `cleanup/selfdelete` |
|---|---|---|
| ADS operation | Named streams via `CreateFile(path:name)` | Default stream (`:$DATA`) via `SetFileInformationByHandle + FILE_RENAME_INFO` |
| Abstraction level | High (CRUD on named streams) | Low (rename default stream by handle, delete-on-close) |
| Goal | Data storage/retrieval in streams | Self-deletion of running executable |

`selfdelete.Run()` renames `:$DATA → :x` using `SetFileInformationByHandle`. This is a **different WinAPI path** than what `ads` uses (`CreateFile` with stream suffix). Refactoring selfdelete to call `ads.Write/Delete` would require a roundtrip through a higher-level API that cannot express the "rename default stream" semantic.

**Action:** Add a comment block in `selfdelete_windows.go` explaining why it does not use `system/ads`, to prevent future confusion.

---

## E. `encode` Package Documentation

### Problem

`encode/doc.go` exists but there is no markdown technique page. The encode API is only mentioned inside `docs/techniques/crypto/payload-encryption.md` as a subsection, not as a first-class package page.

### Solution

Create `docs/techniques/encode/README.md` covering:
- Base64 / Base64-URL
- ROT13 string obfuscation
- UTF-16LE conversion
- PowerShell `-EncodedCommand` format
- Full API reference
- When to use encode vs crypto

---

## Self-Review

- ✅ No placeholder TBDs
- ✅ `Listener` interface does not break existing `Transport` interface
- ✅ BANNER handshake is opt-in — zero breaking change to c2/shell
- ✅ `MatrixKey` invertibility constraint (det odd mod 256) is explicit
- ✅ `SpoofPID` does not attempt `Restore` — correct, remote restoration requires tracking original bytes which is caller's responsibility
- ✅ ADS/selfdelete analysis is conclusive (no forced refactor)
- ✅ TEA/XTEA block size padding is noted (PKCS7 internally)
- ✅ All new packages need `doc.go` with MITRE ATT&CK

---

## File Impact Summary

```
NEW:
  c2/transport/listener.go
  c2/multicat/doc.go
  c2/multicat/multicat.go
  c2/multicat/multicat_test.go
  docs/techniques/encode/README.md

MODIFIED:
  evasion/fakecmd/fakecmd_windows.go       (+ SpoofPID)
  evasion/fakecmd/fakecmd_windows_test.go  (+ TestSpoofPID)
  docs/techniques/evasion/fakecmd.md       (+ Remote section)
  cleanup/selfdelete/selfdelete_windows.go (+ explanatory comment)
  crypto/tea.go                            (new file in crypto/)
  crypto/xtea.go
  crypto/arith.go
  crypto/sbox.go
  crypto/matrix.go
  crypto/crypto_test.go                    (+ new test cases)
  docs/techniques/crypto/payload-encryption.md  (+ Lightweight Obfuscation section)
  docs/techniques/crypto/README.md         (+ new entries)
```
