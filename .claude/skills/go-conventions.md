---
name: go-conventions
description: Enforce Go naming conventions and project structure rules from alexedwards.net when writing or reviewing Go code
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

### Anti-Chatter
- Don't repeat package name in exported identifiers
- `customer.New()` not `customer.NewCustomer()`
- `customer.Address` not `customer.CustomerAddress`
- Exception: type sharing package name is acceptable: `time.Time`, `context.Context`
- Methods: `token.Validate()` not `token.ValidateToken()`

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

### unsafe.Pointer
- Never convert `uintptr` to `unsafe.Pointer` except via `unsafe.Add(nil, int(addr))`
- Add compile-time size assertions: `var _ [N]byte = [unsafe.Sizeof(T{})]byte{}`
- Validate bounds before pointer arithmetic

### Documentation
- Every exported package: package-level doc comment explaining purpose and usage
- Every exported function: one-line description, parameters, return values
- Security-sensitive code: document technique name, Windows API used, detection risk

## Checklist (Run Before Every Commit)

```
[ ] No snake_case or SCREAMING_CASE identifiers
[ ] All acronyms consistently cased (ID, API, HTTP, URL, DNS, TLS)
[ ] No type names in identifiers
[ ] No catch-all package names (utils, helpers, common)
[ ] No chatter (package name repeated in exported identifiers)
[ ] Receivers are short and consistent
[ ] x/sys/windows used where available instead of LazyProc
[ ] All handles closed with defer
[ ] All unsafe.Pointer arithmetic bounds-checked
[ ] Build tags present on all platform-specific files
[ ] Package doc comment present
```
