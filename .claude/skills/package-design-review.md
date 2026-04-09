---
name: package-design-review
description: >
  Trigger: when creating a new Go package, reviewing a package in depth,
  refactoring a package API, or when asked to "look at" / "check" a package.
  Purpose: check architecture, API surface, type naming (anti-stutter), String()
  on enums, OS-native IDs, state encapsulation, channel typing, polling
  optimization, reusability audit, Observer pattern for monitoring.
  Keywords: package, new package, doc.go, API design, refactor package, review.
---

# Package Design Review

When creating or reviewing a full package, check these design principles beyond naming and conventions. This is a deeper review than post-write-review — it evaluates the package as a cohesive unit.

## When to Trigger

- Creating a new package
- Reviewing an existing package "in depth"
- Refactoring a package's public API
- When the user asks to "look at" or "check" a package

## 1. Type Naming & Anti-Stutter

The main type should NOT repeat the package name:

| Bad | Good | Why |
|-----|------|-----|
| `drive.Drive` | `drive.Info` | Package name is the context |
| `process.Process` | `process.Entry` | Redundant |
| `token.TokenInfo` | `token.Info` | Double stutter |
| `drive.Drives` | `drive.Watcher` | Name by purpose, not content |
| `drive.DriveType` | `drive.Type` | Package prefix is enough |

Exception: `time.Time`, `context.Context` — when the type IS the concept.

## 2. String() on OS Enum Types

Types that mirror Windows/Linux constants MUST return the official name:

```go
// BAD: invented lowercase names
func (t Type) String() string { return "fixed" }

// GOOD: MSDN constant names — developers search by these
func (t Type) String() string { return "DRIVE_FIXED" }
```

Default case: `fmt.Sprintf("TYPE_NAME(%d)", val)` — never empty string.

## 3. Unique Identifiers

Prefer OS-native identifiers over custom hashes:

| Bad | Good | Why |
|-----|------|-----|
| `MD5(serial+fs)` | Volume GUID (`\\?\Volume{...}\`) | OS-assigned, stable across reboots |
| `hash(PID+name)` | PID (uint32) | Already unique per-process |
| `md5(hostname)` | SID string | OS-assigned, unique |

If the OS provides a unique ID, use it. Don't invent your own.

## 4. State Encapsulation

Internal state must be private. No exported mutable maps.

```go
// BAD: caller can mutate internal state
type Manager struct {
    List map[string]*Item  // exported, mutable
}

// GOOD: state is private, accessed via methods
type Manager struct {
    known map[string]*Item  // unexported
}
func (m *Manager) Snapshot() []*Item { ... }
```

Side-effect rule: query methods (`All`, `List`, `Get`) should NOT mutate state.
If they must populate a cache, document it explicitly.

## 5. Channel Design

Typed events, never `chan any`:

```go
// BAD
func Watch() <-chan any { ... }  // consumer needs type switch

// GOOD
type Event struct {
    Kind  EventKind  // Added, Removed, Error
    Item  *Info
    Err   error
}
func Watch() <-chan Event { ... }
```

Watchers should detect **both additions AND removals**, not just additions.

## 6. Polling Optimization

For poll-based watchers on Windows:

```go
// BAD: expensive enumeration every tick
for range ticker.C {
    items := enumerateAll()  // N API calls every 200ms
    diff(items, known)
}

// GOOD: fast-path bitmask check, expensive path only on change
for range ticker.C {
    mask := cheapSnapshot()  // 1 API call (GetLogicalDrives, etc.)
    if mask == prevMask {
        continue  // zero additional API calls
    }
    items := enumerateChanged(mask ^ prevMask)  // only changed items
}
```

## 7. Reusability Audit (CRITICAL)

**Any function that could be useful to another package MUST live in a shared package — not in the consumer that happens to need it first.**

When reviewing a package, check:

- **Inward**: Does this package duplicate functionality from another package?
  (e.g., defining LazyProcs that exist in `win/api`, reimplementing handle enumeration)
- **Outward**: Does this package contain reusable primitives that belong in a shared package?
  (e.g., handle enumeration → `win/ntapi`, token theft → `win/token`, remote exec → `inject/`)
- **Dead code**: Are there unused exports or proc declarations?
  (e.g., LazyProcs in `win/api` that no consumer calls)

**Shared package placement guide:**

| Primitive | Belongs in |
|-----------|-----------|
| NT syscall wrappers (NtXxx) | `win/ntapi/` |
| Handle enumeration, kernel pointer leak | `win/ntapi/` |
| Token operations (steal, impersonate, privilege) | `win/token/` |
| Shellcode injection, remote exec | `inject/` |
| Memory patching (function prologue overwrite) | `win/api/` (PatchMemory) |
| Process enumeration, finding by name | `process/enum/` |
| Evasion techniques (timing, patching) | `evasion/` sub-packages |
| Crypto operations | `crypto/` |
| PE parsing | `pe/parse/` |
| Version checking, CVE lookups | `win/version/` |
| DLL handles and proc pointers | `win/api/` (single source of truth) |

**Red flag**: A function in `exploit/cveXXX/` or `cmd/` that does something generic (enumerate handles, steal token, inject shellcode). Extract it immediately.

## 8. Observer Pattern for Monitoring

Packages that monitor system changes should follow Observer:

```go
// Watcher is the Observable
type Watcher struct {
    ctx    context.Context
    filter FilterFunc      // Strategy pattern for filtering
    known  map[string]*Info // private state
}

// Watch returns a channel (Observer subscription)
func (w *Watcher) Watch(interval time.Duration) (<-chan Event, error)

// Event is the notification
type Event struct {
    Kind  EventKind  // what changed
    Item  *Info      // the affected item
    Err   error      // if enumeration failed
}
```

## 9. Context Placement

- Context belongs on the **manager/watcher**, not on each data struct
- Data structs (`Info`, `Entry`) are snapshots — no context needed
- Operations that block or poll take `context.Context` as parameter or store it at construction

## Checklist

```
[ ] Main type does not repeat package name
[ ] Collection/manager type named by purpose
[ ] String() returns OS constant names for enum types
[ ] OS-native IDs used instead of custom hashes
[ ] Internal state is private (unexported maps/slices)
[ ] Query methods don't mutate state
[ ] Channels are typed (no chan any)
[ ] Watchers detect additions AND removals
[ ] Polling uses fast-path before expensive enumeration
[ ] No duplicated functionality from other packages
[ ] No reusable primitives trapped in a specific package
[ ] Observer pattern for monitoring (Watcher + Event + channel)
[ ] Context on manager/watcher, not on data structs
```
