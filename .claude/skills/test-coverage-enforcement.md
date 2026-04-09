---
name: test-coverage-enforcement
description: >
  Trigger: after Edit/Write on any .go file, after creating a new Go package,
  before marking a task as complete, before git commit.
  Purpose: enforce that every new/changed exported function, type, method, and
  pattern has corresponding _test.go coverage. Block completion until tests exist.
  Keywords: test, _test.go, coverage, assert, require, TestXxx, go test, testutil.
---

# Test Coverage Enforcement

**Every line of code you write MUST have tests before the work is considered done.** This is not optional. Do not wait to be asked.

## When to Trigger

- After writing ANY new function, method, type, or file
- After modifying existing function signatures or behavior
- After creating a new package
- Before claiming any task is complete

## Test Classification

This project uses three test tiers:

| Tier | Gate | When to Use | Example |
|------|------|-------------|---------|
| **Unit** | None | Pure logic, no OS calls | XOR encode/decode, validation, config defaults |
| **Intrusive** | `MALDEV_INTRUSIVE=1` | Modifies process state, executes shellcode, patches memory | Injection, AMSI patch, ETW patch |
| **Manual** | `MALDEV_MANUAL=1` | Requires admin, modifies system, or needs VM | Service hide, herpaderping |

### Gating Rules

```go
// Unit test — no gate needed
func TestValidateShellcode(t *testing.T) { ... }

// Intrusive test — gate with testutil
func TestCreateThreadSelfInject(t *testing.T) {
    testutil.RequireWindows(t)
    testutil.RequireIntrusive(t)
    // ...
}

// Manual test — gate with env check
func TestHideService(t *testing.T) {
    if os.Getenv("MALDEV_MANUAL") != "1" {
        t.Skip("manual test: set MALDEV_MANUAL=1")
    }
    // ...
}
```

## What to Test (Checklist)

After writing code, verify ALL of these have tests:

### For every new/modified exported function:
```
[ ] Happy path — correct input produces correct output
[ ] Error path — invalid input returns expected error
[ ] Edge cases — nil, empty, zero-value, boundary values
[ ] Return type correctness — verify exact return type matches doc
```

### For every new interface:
```
[ ] Contract test — mock implementation satisfies interface
[ ] Nil handling — nil concrete type passed as interface
```

### For every new pattern (Builder, Decorator, State, etc.):
```
[ ] Builder: Create() with missing required fields → error
[ ] Builder: Full valid chain → success
[ ] Builder: Invalid combinations → specific error
[ ] Decorator: Each decorator wraps correctly (verify side effects)
[ ] Decorator: Chain() applies in correct order
[ ] State: All valid transitions work
[ ] State: Invalid transitions return errors
[ ] Pipeline: Steps execute in order
[ ] Pipeline: Error in step N prevents step N+1
```

### For every new config struct:
```
[ ] Zero value / default behavior
[ ] Every field has at least one test
[ ] Invalid field combinations detected
```

### For platform-specific code:
```
[ ] Build tag present: //go:build windows (or linux, etc.)
[ ] testutil.RequireWindows(t) / RequireLinux(t) at test start
[ ] Cross-compilation builds: GOOS=linux go build ./...
```

## Test Patterns for This Project

### Mock Injector for Decorator Tests
```go
type mockInjector struct {
    called    bool
    shellcode []byte
    err       error
}

func (m *mockInjector) Inject(sc []byte) error {
    m.called = true
    m.shellcode = make([]byte, len(sc))
    copy(m.shellcode, sc)
    return m.err
}
```

### Child Process Pattern for Intrusive Tests
```go
func TestIntrusive(t *testing.T) {
    testutil.RequireIntrusive(t)
    if os.Getenv("MALDEV_CHILD_TEST") == "mytest" {
        // Dangerous code runs here in child
        os.Exit(0)
    }
    // Parent: re-exec self as child
    cmd := exec.Command(os.Args[0], "-test.run=TestIntrusive")
    cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=mytest")
    assert.NoError(t, cmd.Run())
}
```

### Table-Driven Tests
```go
func TestBuilder(t *testing.T) {
    tests := []struct {
        name    string
        build   func() *InjectorBuilder
        wantErr string
    }{
        {"missing method", func() *InjectorBuilder { return Build() }, "method is required"},
        {"remote without PID", func() *InjectorBuilder {
            return Build().Method(MethodCreateRemoteThread)
        }, "requires a target PID"},
        {"valid self-inject", func() *InjectorBuilder {
            return Build().Method(MethodCreateThread)
        }, ""},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := tt.build().Create()
            if tt.wantErr != "" {
                assert.ErrorContains(t, err, tt.wantErr)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

## Test File Naming

```
package_test.go        — main test file (unit tests)
package_windows_test.go — Windows-specific tests (//go:build windows)
package_linux_test.go   — Linux-specific tests (//go:build linux)
```

## Assertion Library

Use `github.com/stretchr/testify` consistently:
- `assert` for non-fatal checks
- `require` for fatal preconditions

## Pre-Completion Check

Before marking any task as done, verify:

```
[ ] LIST every new/modified exported symbol explicitly (function, type, method, const)
[ ] For EACH symbol on that list, name the test that covers it
[ ] If no test exists for a symbol, write one NOW — do not defer
[ ] Every new unexported helper used by exported code is tested indirectly
[ ] go test ./affected/package... passes
[ ] GOOS=linux go build ./affected/package... compiles (if cross-platform)
```

**The test gap that always slips through**: you write a new method (e.g., `Detach()`, `FindHandleByType()`), it compiles, existing tests pass, so you move on. But NO test actually calls the new method. The fix: explicitly enumerate every new symbol and match it to a test name. If you can't name the test, it doesn't exist.

If any check fails, write the missing tests before reporting completion.
