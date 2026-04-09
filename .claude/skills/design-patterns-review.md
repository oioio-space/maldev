---
name: design-patterns-review
description: >
  Trigger: after Edit/Write on .go files, when creating new packages, refactoring,
  or reviewing code architecture.
  Purpose: evaluate whether design patterns (Builder, Strategy, Decorator, Template
  Method, State, Chain, Facade, Flyweight) would improve the implementation.
  Keywords: pattern, refactor, architecture, duplication, switch, strategy, builder.
---

# Design Patterns Review

After writing or modifying Go code, evaluate whether any of these design patterns would improve the implementation. This check is automatic — do it after every significant code change without being asked.

## When to Trigger

- After creating a new package or file
- After adding a new feature or method
- After refactoring existing code
- After reviewing a PR or code diff
- When you notice code duplication, rigid coupling, or complex conditionals

## Pattern Catalog (refactoring.guru)

Evaluate each pattern against the code you just wrote. Only suggest patterns with **concrete, immediate benefit** — never suggest a pattern just because it could theoretically apply.

### Creational

| Pattern | Trigger Signal | Go Idiom |
|---------|---------------|----------|
| **Builder** | Struct with 5+ fields, invalid combinations possible, complex construction | Fluent methods returning `*Builder`, terminal `Build() (T, error)` |
| **Factory Method** | Multiple concrete types behind one interface, choice depends on config | Constructor function `NewXxx(cfg) Interface` |
| **Abstract Factory** | Families of related objects that must be created together | Rare in Go — prefer explicit factory funcs |
| **Prototype** | Deep copying complex structs | `Clone() T` method |
| **Singleton** | Single shared resource (DLL handle pool, connection pool) | `sync.Once` + package-level var |

### Structural

| Pattern | Trigger Signal | Go Idiom |
|---------|---------------|----------|
| **Decorator** | Adding behavior to an interface without modifying implementations | Wrapper struct embedding the interface, `Middleware func(I) I` |
| **Proxy** | Controlling access, adding lazy init, logging, or caching | Same interface, wrapper struct with internal delegate |
| **Adapter** | Incompatible interfaces that need to work together | Wrapper struct implementing target interface |
| **Facade** | Complex subsystem with many entry points | Single function/struct exposing simplified API |
| **Composite** | Tree structure where leaf and branch are treated uniformly | Interface with `Children()` or recursive methods |
| **Flyweight** | Many objects sharing identical state (DLL handles, proc pointers) | Package-level shared pool, `sync.Pool` |
| **Bridge** | Abstraction and implementation that vary independently | Two interfaces composed together |

### Behavioral

| Pattern | Trigger Signal | Go Idiom |
|---------|---------------|----------|
| **Strategy** | Algorithm that varies by config, `switch` on method/type | Interface for the algorithm, pass as parameter |
| **Chain of Responsibility** | Multiple handlers tried in sequence, first match wins | Slice of handlers, `for _, h := range handlers` |
| **Template Method** | Fixed algorithm skeleton with pluggable steps | Struct with interface fields for each step |
| **State** | Object behavior changes based on internal state, many `if state ==` checks | State interface with method per action |
| **Observer** | Need to notify multiple listeners of changes | Callback slice or channel |
| **Command** | Queuing, undoing, or logging operations | Struct with `Execute()` method |
| **Iterator** | Sequential access to collection elements | `func(yield func(T) bool)` (Go 1.23 range-over-func) or channel |
| **Visitor** | Adding operations to a type hierarchy without modifying it | `Accept(Visitor)` pattern or type switch |
| **Mediator** | Many-to-many communication between components | Central coordinator struct |
| **Memento** | Undo/restore to previous state | `Snapshot() State` + `Restore(State)` |

## Review Checklist

After writing code, scan for these signals:

```
1. DUPLICATION      -> Decorator, Template Method, Strategy
2. BIG SWITCH/IF    -> Strategy, State, Chain of Responsibility
3. COMPLEX CONFIG   -> Builder
4. INTERFACE WRAP   -> Decorator, Proxy
5. SHARED RESOURCE  -> Flyweight, Singleton
6. RIGID COUPLING   -> Facade, Adapter, Bridge
7. LIFECYCLE STATES -> State
8. PLUGGABLE ALGO   -> Strategy, Template Method
```

## Rules

- **Only suggest patterns with immediate, concrete benefit** — "this would save X lines" or "this eliminates the Y switch statement"
- **Never suggest a pattern that adds complexity without reducing it elsewhere**
- **Prefer Go idioms** — channels over Observer, interfaces over abstract classes, functions over Command objects
- **Check if the pattern already exists** in the codebase before suggesting a new one (e.g., maldev already uses Strategy for syscall methods, Chain for SSN resolvers)
- **Quantify the benefit**: "Decorator would eliminate the XOR/delay duplication across 3 methods (~45 LOC)"

## Output Format

When you identify an applicable pattern, mention it briefly:

```
Pattern opportunity: [Pattern Name]
Where: [file/function]
Signal: [what triggered the suggestion]
Benefit: [concrete improvement]
```

Do NOT block work for pattern suggestions. Mention them as post-implementation observations.
