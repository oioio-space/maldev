---
name: go-styleguide
description: >
  Trigger: when writing, reviewing, or refactoring any .go file.
  Purpose: Google Go Style Guide best practices — error handling (%w/%v),
  interfaces (accept interfaces return concrete), documentation, variable
  declarations, shadowing avoidance. Supplements go-conventions.
  Keywords: error handling, interface, documentation, variable, shadowing,
  Go style, Google style guide, fmt.Errorf, %w, sentinel error.
---

# Google Go Style Guide

Apply these rules to ALL Go code in this project. This supplements `go-conventions.md` with deeper guidance from https://google.github.io/styleguide/go/best-practices.html and https://google.github.io/styleguide/go/guide.html.

## Core Principles (by priority)

1. **Clarity** > Simplicity > Concision > Maintainability > Consistency
2. Code should be clear to the READER, not just the AUTHOR
3. Comments explain WHY, not WHAT — let the code speak for itself
4. **Least Mechanism**: prefer core language → stdlib → external dependency

---

## Naming

### Functions — No Repetition
```go
// BAD:
package yamlconfig
func ParseYAMLConfig(input string) (*Config, error)

// GOOD:
package yamlconfig
func Parse(input string) (*Config, error)
```

```go
// BAD: method repeats type name
func (c *Config) WriteConfigTo(w io.Writer) error

// GOOD:
func (c *Config) WriteTo(w io.Writer) error
```

### Functions — Verb vs Noun
- Returns something → noun-like: `func (c *Config) JobName() string`
- Does something → verb-like: `func (c *Config) WriteDetail(w io.Writer) error`
- Never prefix getters with `Get`: `JobName()` not `GetJobName()`

### Functions — Type Disambiguation
```go
// GOOD: primary version omits type, variants include it
func ParseInt(input string) (int, error)
func ParseInt64(input string) (int64, error)
func (c *Config) Marshal() ([]byte, error)
func (c *Config) MarshalText() (string, error)
```

### Constants — MixedCaps Always
```go
// GOOD:
const MaxLength = 256
const maxRetries = 3

// BAD:
const MAX_LENGTH = 256
const MAX_RETRIES = 3
```

---

## Error Handling

### Structure Over Strings
```go
// GOOD: sentinel errors + errors.Is
var ErrDuplicate = errors.New("duplicate entry")
if errors.Is(err, ErrDuplicate) { ... }

// BAD: string matching
if regexp.MatchString(`duplicate`, err.Error()) { ... }
```

### Don't Repeat Info
```go
// GOOD: adds context the error doesn't have
return fmt.Errorf("launch codes unavailable: %v", err)

// BAD: duplicates info already in err
if err := os.Open("settings.txt"); err != nil {
    return fmt.Errorf("could not open settings.txt: %v", err) // path already in err
}

// BAD: adds nothing
return fmt.Errorf("failed: %v", err) // just return err
```

### %v vs %w
- **%v** at system boundaries (RPC, IPC, storage) — don't leak internal errors
- **%w** for internal error chaining — preserves errors.Is/As
- **%w at END**: `fmt.Errorf("context: %w", err)`
- Exception: sentinel at beginning: `var ErrBad = fmt.Errorf("%w: bad thing", ErrParent)`

### Don't Log AND Return
```go
// BAD: logs and returns — caller may log again
log.Error(err)
return err

// GOOD: return only, let caller decide
return fmt.Errorf("operation failed: %w", err)
```

### Panics
- Libraries: prefer returning errors, NEVER panic across package boundaries
- Use `log.Fatal` for invariant violations (not panic)
- Don't recover panics to avoid crashes (corrupted state)
- Panics OK only for: API misuse + internal recover, unreachable code

---

## Variable Declarations

### Short Declarations Preferred
```go
// GOOD:
i := 42
buf := new(bytes.Buffer)

// BAD:
var i = 42
var buf = new(bytes.Buffer)
```

### Zero Values — Don't State the Obvious
```go
// GOOD: zero values are implicit
var (
    coords Point
    primes []int
)

// BAD: explicit zero is noise
var (
    coords = Point{X: 0, Y: 0}
    primes = []int(nil)
)
```

### Size Hints — Only When Proven
```go
// GOOD: known sizes
buf := make([]byte, 131072)
q := make([]Node, 0, 16)
seen := make(map[string]bool, shardSize)
```

### Channel Direction — Always Specify
```go
// GOOD:
func sum(values <-chan int) int

// BAD: allows accidental close
func sum(values chan int) int
```

---

## Function Arguments

### Option Struct for Complex Config
```go
// GOOD:
type Options struct {
    Regions   []string
    Workers   int
    Interval  time.Duration
    Overwrite bool
}
func Enable(ctx context.Context, opts Options) error

// BAD: too many params
func Enable(ctx context.Context, regions []string, workers int, interval time.Duration, overwrite bool) error
```

- **Context is NEVER in option structs** — always first explicit parameter

### Variadic Options for Extensible APIs
```go
type Option func(*options)

func WithWorkers(n int) Option {
    return func(o *options) { o.workers = n }
}

func New(ctx context.Context, opts ...Option) *Client
```

---

## Interfaces

### Don't Create Prematurely
- No interface before a real need (multiple implementations, decoupling, testing)
- Consumer defines the interface, not the producer
- Keep interfaces small

### Accept Interfaces, Return Concrete Types
```go
// GOOD: accept interface
func Process(r io.Reader) error

// GOOD: return concrete
func New() *Client

// Exception: return interface for encapsulation or factory patterns
func NewWriter(format string) io.Writer {
    switch format {
    case "json": return &jsonWriter{}
    default:     return &textWriter{}
    }
}
```

---

## Documentation

### What to Document
- Non-obvious behavior, cleanup requirements, significant error types
- Don't restate the obvious (parameter names = self-documenting)
- Context cancellation behavior is implied — don't restate unless different

```go
// BAD: restates the obvious
// format is the format string. data is the interpolation data.
func Sprintf(format string, data ...any) string

// GOOD: says something useful
// Sprintf formats according to a format specifier and returns the resulting string.
// If the data does not match the expected format verbs or the number of arguments
// doesn't match, the output will contain error tokens.
func Sprintf(format string, data ...any) string
```

### Document Cleanup
```go
// GOOD:
// NewTicker returns a new Ticker containing a channel that will send
// the current time on the channel after each tick.
// Call Stop to release the Ticker's associated resources when done.
func NewTicker(d Duration) *Ticker
```

### Document Errors
```go
// GOOD:
// Read reads up to len(b) bytes from the File.
// At end of file, Read returns 0, io.EOF.
func (*File) Read(b []byte) (n int, err error)
```

---

## Global State

### Libraries Must NOT Force Global State
```go
// BAD: global registry
package sidecar
var registry = make(map[string]*Plugin)
func Register(name string, p *Plugin) error { ... }

// GOOD: instance-based
package sidecar
type Registry struct { plugins map[string]*Plugin }
func New() *Registry { return &Registry{plugins: make(map[string]*Plugin)} }
func (r *Registry) Register(name string, p *Plugin) error { ... }
```

### Safe Global State Only When:
- Logically constant (compile-time fixed)
- Observably stateless (private cache)
- Doesn't bleed into external systems
- No ordering expectations

---

## Strings

### Prefer fmt.Sprintf for Complex Strings
```go
// GOOD:
str := fmt.Sprintf("%s [%s:%d]-> %s", src, qos, mtu, dst)

// BAD: obscures result
bad := src.String() + " [" + qos.String() + ":" + strconv.Itoa(mtu) + "]-> " + dst.String()
```

### Write Directly to io.Writer
```go
// GOOD:
fmt.Fprintf(w, "Header: %s\n", val)

// BAD: allocates intermediate string
w.Write([]byte(fmt.Sprintf("Header: %s\n", val)))
```

### Use Raw Strings for Multi-line
```go
// GOOD:
usage := `Usage:

custom_tool [args]`

// BAD:
usage := "Usage:\n\ncustom_tool [args]"
```

---

## Shadowing

### Stomping is OK When Original is Dead
```go
// GOOD: ctx is replaced, original not needed after
ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
defer cancel()
```

### Shadowing in Blocks is DANGEROUS
```go
// BAD: ctx inside if shadows outer ctx
if condition {
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second) // shadows!
    defer cancel()
}
// BUG: ctx here is still the outer one

// GOOD: use = not :=
if condition {
    var cancel func()
    ctx, cancel = context.WithTimeout(ctx, 3*time.Second) // assigns
    defer cancel()
}
```

---

## Testing

- **No assertion libraries** — use standard `if got != want` patterns
- Test helpers call `t.Helper()`
- `t.Fatal` in subtests, `t.Error` + continue in table-driven loops without subtests
- Never call `t.Fatal` from goroutines — use `t.Error` instead
- Use field names in table-driven test struct literals
- Use real transports (httptest.Server) over mocks when possible

---

## Checklist (Supplement to go-conventions.md)

```
[ ] Errors structured (sentinel values, not string matching)
[ ] %w at end of fmt.Errorf, %v at system boundaries
[ ] No log-and-return (pick one)
[ ] No premature interfaces
[ ] Accept interfaces, return concrete types
[ ] No global mutable state in library packages
[ ] Option structs for >3 parameters (context always separate)
[ ] Channel directions specified
[ ] Zero values implicit (no explicit zeroing)
[ ] Shadowing checked in conditional blocks
[ ] Documentation explains WHY, not WHAT
[ ] Cleanup requirements documented
```
