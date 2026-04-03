---
name: post-write-review
description: Use AUTOMATICALLY after writing, modifying, or creating any Go code in this project — performs two mandatory checks (naming/conventions compliance and design pattern opportunities) on the code just written. Triggers on ANY code change including edits, new files, refactors, and bug fixes. This is not optional.
---

# Post-Write Automatic Review

**This skill runs AUTOMATICALLY after every code modification.** Do not skip it. Do not wait to be asked.

## When to Trigger

After ANY of these actions:
- Writing a new function, method, type, or file
- Editing existing code
- Creating a new package
- Refactoring code
- Implementing a feature or fix

## Process

After writing code, perform BOTH checks below. Report findings inline as brief observations — do NOT block the workflow.

---

## Check 1: Naming & Convention Compliance

Scan the code you just wrote/modified against these rules. Report violations immediately.

### Quick Scan (< 5 seconds mental check)

```
NAMING:
  [ ] camelCase unexported, PascalCase exported
  [ ] Acronyms: ID not Id, HTTP not Http, API not Api, URL not Url
  [ ] No type in name: count not intCount
  [ ] No stuttering: pkg.New() not pkg.NewPkg()
  [ ] No Get prefix on getters
  [ ] Receiver: 1-3 chars, never this/self

STRUCTURE:
  [ ] windows.X() preferred over api.ProcX.Call() where available
  [ ] Build tag present on platform-specific files
  [ ] Handles closed with defer
  [ ] Errors wrapped with %w, context in message
  [ ] No OPSEC-sensitive data in error strings (paths, PIDs, addresses, DLL names)
  [ ] Errors crossing package boundaries use sentinel/domain errors, not raw wraps
  [ ] No fmt.Errorf with %v on structs (leaks all fields incl. passwords/tokens)
  [ ] Structured logging only (internal/log), never fmt.Printf/Fprintf for errors

DOCUMENTATION:
  [ ] Exported functions have doc comments
  [ ] New packages have doc.go with MITRE ID + detection level

PARAMETRIZATION:
  [ ] No hardcoded timeouts that users might want to change
  [ ] No hardcoded paths/strings that vary per operation
  [ ] Config structs have sensible zero-value defaults

CALLER SYSCALL:
  [ ] Any NT function call (NtXxx, ZwXxx) should accept optional *wsyscall.Caller
  [ ] If Caller is nil, fall back to standard api.Proc*.Call() or windows.Xxx()
  [ ] Pattern: if caller != nil { caller.Call("NtXxx", ...) } else { api.ProcNtXxx.Call(...) }
  [ ] Kernel32-only APIs (GetLogicalDrives, SetProcessMitigationPolicy, Fiber*) CANNOT use Caller — skip
  [ ] Functions called in tight loops (race conditions, polling) benefit most from Caller
  [ ] Security-sensitive calls (OpenProcess, CreateThread, VirtualAlloc) should route through Caller

REUSABILITY:
  [ ] Any function useful beyond this package belongs in a shared package
  [ ] Handle enumeration → win/ntapi, token ops → win/token, injection → inject/
  [ ] Check: could another package need this? If yes, extract now — not later
  [ ] No duplicated logic across packages (DRY across the module)
  [ ] Dead code in win/api or other shared packages? Remove it

PACKAGE DESIGN:
  [ ] Main type does not repeat package name (drive.Info not drive.Drive)
  [ ] Manager/collection types named by purpose (Watcher not Drives)
  [ ] String() on Windows enums returns MSDN names (DRIVE_FIXED not "fixed")
  [ ] No chan any — use typed Event structs
  [ ] OS-native IDs as keys (Volume GUID not MD5 hash)
  [ ] Watchers detect both additions AND removals
  [ ] Poll-based watchers use fast-path check before expensive enumeration
  [ ] Internal state is private (not exported maps)
```

### Report Format

Only report actual violations found. If the code is clean, say nothing.

```
Convention: [identifier] should be [correction] — [rule]
```

Example:
```
Convention: GetVersion() should be Version() — no Get prefix on getters
Convention: token.NewToken() should be token.New() — anti-stutter
Convention: userId should be userID — acronym casing
```

---

## Check 2: Design Pattern Opportunities

Scan the code you just wrote for these signals. Only suggest patterns with **concrete, quantifiable benefit**.

### Signal → Pattern Map

| If you see... | Consider... |
|---------------|-------------|
| Struct with 5+ fields, invalid combos | **Builder** |
| `switch` on type/method for algorithm selection | **Strategy** |
| Same interface wrapped with pre/post behavior | **Decorator** |
| Fixed algo skeleton with pluggable steps | **Template Method** |
| Object behavior varies by internal state, many `if state ==` | **State** |
| Multiple handlers tried until one succeeds | **Chain of Responsibility** |
| Complex subsystem with many entry points | **Facade** |
| Many objects sharing identical read-only state | **Flyweight** |
| Duplicate code across variants (WinAPI vs Caller) | **Strategy** or **Template Method** |

### Rules

- **Only suggest if benefit > cost** — quantify: "saves ~X LOC" or "eliminates Y duplication"
- **Check existing patterns first** — maldev already uses Strategy (syscall methods), Chain (SSN resolvers), Decorator (inject middleware), Builder (inject builder), State (shell lifecycle), Template Method (inject pipeline)
- **Never suggest patterns that add complexity without reducing it elsewhere**
- **Go idioms first** — interfaces over abstract classes, functions over Command objects, channels over Observer

### Report Format

Only report genuine opportunities. If none found, say nothing.

```
Pattern opportunity: [Name] in [file:function]
Signal: [what you noticed]
Benefit: [concrete improvement]
```

---

## Important

- These checks take < 10 seconds of review — never skip them
- Do NOT produce a full report if everything is clean — silence means compliance
- Do NOT block the user's workflow — report inline as brief notes
- Fix obvious violations immediately without asking (rename, add doc comment)
- For pattern suggestions, mention but don't implement unless asked
