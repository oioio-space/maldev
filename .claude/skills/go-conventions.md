---
name: go-conventions
description: Use when writing, modifying, reviewing, or creating any Go code — enforces naming conventions, anti-stutter rules, package structure, build tags, error handling, unsafe.Pointer safety, and MITRE documentation requirements. Reference for all Go style rules in this project.
---

# Go Conventions Skill

Apply these rules to ALL Go code written or modified in this project. Check compliance before every commit.

## Naming Rules (MUST)

### Identifiers
- `camelCase` for unexported, `PascalCase` for exported
- Acronyms/initialisms: consistent case within identifier. `APIKey` or `apiKey`, never `ApiKey`
- `ID` always fully capitalized: `userID` not `userId`, `GetSessionID` not `GetSessionId`
- Never include the type in the name: `count` not `intCount`, `results` not `resultSlice`
- Exception: type conversion disambiguation is OK: `userIDStr := strconv.Itoa(userID)`
- Never clash with builtins: no `int`, `bool`, `any`, `len`, `max`, `min`, `clear` as var names
- Avoid clashing with imported stdlib package names in the same file

### Packages
- Lowercase ASCII letters and numbers only. No `_`, no `camelCase`
- Short, ideally one-word nouns: `orders`, `customer`, `slug`
- Multi-word: concatenate all lowercase, no separator: `ordermanager` not `order_manager`
- Abbreviations OK: `strconv`, `expvar`
- NEVER use: `common`, `util`, `helpers`, `types`, `interfaces` — these are catch-all anti-patterns
- NEVER use: `vendor`, `testdata`, `internal` as package names (reserved by Go tooling)
- NEVER start with `.` or `_`

### Files
- Lowercase, ideally one word: `cookie.go`, `server.go`
- Multi-word: concatenate (`routingindex.go`) or underscore (`routing_index.go`) — pick one, be consistent
- In this project: **use underscore for OS/arch suffixes only** (`_windows.go`, `_linux.go`, `_amd64.go`)
- Multi-word filenames: concatenate without separator (`selfdelete.go`, `antivm.go`)

### Anti-Chatter (Stuttering)
- Don't repeat package name in exported identifiers
- `customer.New()` not `customer.NewCustomer()`
- `customer.Address` not `customer.CustomerAddress`
- `transport.NewTCP()` not `transport.NewTCPTransport()`
- `token.New()` not `token.NewToken()`
- `etw.Patch()` not `etw.PatchETW()`
- `inject.Stats` not `inject.InjectionStats`
- Exception: type sharing package name is acceptable: `time.Time`, `context.Context`
- Methods: `token.Privileges()` not `token.GetTokenPrivileges()`
- **Types**: the main type of a package should NOT repeat the package name.
  `drive.Info` not `drive.Drive`, `process.Entry` not `process.Process`,
  `token.Token` is acceptable (same as `time.Time` exception)
- **Collections/managers**: name by purpose, not by content.
  `drive.Watcher` not `drive.Drives`, `inject.Pipeline` not `inject.Injections`

### Windows SDK Constants
- Windows SDK mirror constants (MB_OK, LOGON32_LOGON_INTERACTIVE, PROCESS_ALL_ACCESS, etc.)
  keep their original ALL_CAPS naming — developers search by SDK name
- Project-invented constants use MixedCaps: `Native` not `NATIF`, `DriveType` not `DRIVETYPE`
- Rule of thumb: if the constant exists in MSDN docs, keep its name; if you invented it, use Go style
- **String() on Windows enum types**: return the MSDN constant name (`DRIVE_FIXED`, `DRIVE_REMOVABLE`)
  not lowered Go names (`fixed`, `removable`). Developers search by MSDN name.
  For out-of-range values: `fmt.Sprintf("TYPE_NAME(%d)", val)` not empty string

### Channels
- Never use `chan any` for typed data — define a typed event struct:
  `type Event struct { Kind EventKind; Data *Info; Err error }`
- Channel direction: always specify `<-chan` (receive) or `chan<-` (send) in function signatures
- Close channels via `defer close(ch)` in the producing goroutine

### Identifiers (OS-Native vs Custom)
- Prefer OS-native identifiers over custom hashes for uniqueness:
  Volume GUID (`\\?\Volume{...}\`) over MD5(serial+fs), Process PID over custom hash
- Use stable identifiers as map keys: GUID > drive letter, PID > process name

### Method Receivers
- Short: 1-3 chars, abbreviation of type: `c` for `Customer`, `hs` for `HighScore`
- Never `this`, `self`, `me`
- Consistent: same receiver name for ALL methods on same type

### Getters/Setters
- Getter: `Address()` not `GetAddress()`
- Setter: `SetAddress()` — prefix with `Set`

### Interfaces
- Single-method: method name + `-er`: `Speaker`, `Authorizer`, `Authenticator`
- Never `UserInterface` or `OrderInterface`

## Project Structure Rules (MUST)

### Use x/sys/windows Instead of Custom Wrappers
Before declaring a new `LazyProc`, check if `golang.org/x/sys/windows` already provides a typed wrapper:
- `windows.CreateToolhelp32Snapshot()` instead of `ProcCreateToolhelp32Snapshot.Call()`
- `windows.VirtualAlloc()` instead of `ProcVirtualAlloc.Call()`
- `windows.ProcessEntry32` instead of custom `PROCESSENTRY32W`
- `windows.OpenProcess()` instead of `ProcOpenProcess.Call()`

Only use `LazyProc` for APIs **not wrapped** by x/sys/windows (NT*, ETW*, Fiber*, etc.)

### Keep Related Things Close
- Constants, types, helpers near the code that uses them
- Methods directly below struct declaration
- Don't create packages just to organize files — only when there's a reuse/isolation need

### Build Tags
- Windows-only: `//go:build windows` as FIRST line (before package comment)
- Linux-only: `//go:build linux`
- Cross-platform: no build tag
- Arch-specific: `//go:build linux && amd64`

### Error Handling
- Always check return values from Windows API calls
- `proc.Call()` third return is `error` only if first return indicates failure
- Close handles with `defer` immediately after successful open
- Add max buffer size limits on growing allocations

### Secure Error Handling (OPSEC-critical)
Based on JetBrains Go secure error handling best practices.

**Error messages are OPSEC artifacts** — every `fmt.Errorf("failed to allocate memory at %p", addr)`
puts a format string and potentially sensitive data in the binary.

Rules:
- **Never expose internal details in errors that cross trust boundaries**
  `fmt.Errorf("db error: %w", err)` → BAD (leaks db driver info)
  `domain.ErrNotFound` → GOOD (opaque sentinel)
- **Sanitize at subsystem boundaries** — convert low-level errors to domain errors
  when crossing package boundaries. Database errors, OS errors, and network errors
  should not propagate to callers as-is.
- **Use `%w` for internal wrapping, sentinel errors for public APIs**
  Internal: `fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", r, err)` (OK within package)
  Public: return `ErrAllocationFailed` (opaque to consumers)
- **Never log structs directly** — `fmt.Errorf("request %v", req)` leaks all fields
  including passwords, tokens, keys. Always select fields explicitly.
- **Error strings are in the binary** — in release builds (garble -literals helps),
  but prefer generic messages: `"operation failed"` over `"NtCreateThreadEx in PID 1234 failed"`
- **Structured logging only** — use `internal/log` (slog-based), never `fmt.Printf` or
  `fmt.Fprintf(os.Stderr)` for error reporting
- **Redact sensitive data** — if an error must include context, use explicit allowlists:
  ```go
  // BAD
  return fmt.Errorf("inject into %s failed: %w", processPath, err)
  // GOOD
  return fmt.Errorf("inject failed: %w", err)  // processPath is OPSEC-sensitive
  ```

### unsafe.Pointer
- Never convert `uintptr` to `unsafe.Pointer` except via `unsafe.Add(nil, int(addr))`
- Add compile-time size assertions: `var _ [N]byte = [unsafe.Sizeof(T{})]byte{}`
- Validate bounds before pointer arithmetic

### Documentation
- Every exported package: package-level doc comment explaining purpose and usage
- Every exported function: one-line description, parameters, return values
- Security-sensitive code: document technique name, Windows API used, detection risk

### Technique Documentation (MANDATORY for every security technique)
Every package implementing a security technique MUST have in its `doc.go`:
1. **Technique name** — human-readable name (e.g., "Process Herpaderping")
2. **MITRE ATT&CK ID** — e.g., T1055, T1562.001 (use N/A for utility packages)
3. **Detection level** — Low, Medium, or High
4. **Platform** — Windows, Linux, or Cross-platform
5. **How it works** — 3-5 sentences in plain language explaining the technique
6. **Usage example** — at least one compilable Go code example
7. **Advantages and limitations** — what it does well, what it doesn't cover

When creating a NEW technique package, also:
- Add it to the evasion/inject/cleanup package table in README.md
- Add it to the MITRE ATT&CK coverage table in README.md
- Create tests (safe tests ungated, intrusive gated with MALDEV_INTRUSIVE=1, manual with MALDEV_MANUAL=1)
- Add it to `testutil/manual-tests.ps1` if it requires manual testing
- If it implements `evasion.Technique`, verify it composes with presets

### MITRE ATT&CK Reference
See [docs/mitre.md](../../docs/mitre.md) for the full mapping. Key technique IDs:
- T1055 — Process Injection (inject, herpaderping)
- T1106 — Native API (win/api PEB walk, win/syscall, win/ntapi)
- T1562.001 — Impair Defenses (amsi, etw, acg, blockdlls, unhook)
- T1562.002 — Disable Logging (phant0m, etw)
- T1497 — Sandbox Evasion (antivm, sandbox, timing)
- T1622 — Debugger Evasion (antidebug)
- T1070 — Indicator Removal (selfdelete, timestomp, wipe, service)
- T1134 — Token Manipulation (win/token, win/privilege, win/impersonate)
- T1548.002 — Abuse Elevation (uacbypass)
- T1082 — System Info Discovery (win/domain, win/version)
- T1120 — Peripheral Device Discovery (system/drive)
- T1083 — File Discovery (system/folder)

## Checklist (Run Before Every Commit)

```
[ ] No snake_case or SCREAMING_CASE identifiers (except Windows SDK constants)
[ ] All acronyms consistently cased (ID, API, HTTP, URL, DNS, TLS)
[ ] No type names in identifiers
[ ] No stuttering (package name not repeated in symbol name)
[ ] No Get-prefix on getters
[ ] No catch-all package names (utils, helpers, common)
[ ] No chatter (package name repeated in exported identifiers OR types)
[ ] Main type of package does not repeat package name (drive.Info not drive.Drive)
[ ] Receivers are short and consistent
[ ] x/sys/windows used where available instead of LazyProc
[ ] String() on Windows enums returns MSDN names
[ ] No chan any — use typed event structs
[ ] OS-native IDs preferred over custom hashes (GUID > MD5)
[ ] All handles closed with defer
[ ] All unsafe.Pointer arithmetic bounds-checked
[ ] Build tags present on all platform-specific files
[ ] Package doc comment present
```
