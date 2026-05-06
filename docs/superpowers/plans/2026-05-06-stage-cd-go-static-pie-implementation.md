# Phase 1f Stage C+D — Go static-PIE reflective loader on Linux

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `pe/packer/runtime` reflectively load Go static-PIE binaries on Linux end-to-end — Prepare maps + relocates, Run() jumps to entry via a kernel-style stack frame and never returns.

**Architecture:** Detect Go static-PIE via `debug/buildinfo` (stdlib). Gate non-Go inputs in the Linux backend with `ErrNotImplemented`. Run() builds a fake stack with `/proc/self/auxv` passthrough + fresh `AT_RANDOM` canary, then a Plan 9 asm helper swaps RSP and JMPs to the entry point.

**Tech Stack:** Go 1.21, `golang.org/x/sys/unix` (already a dep), Plan 9 amd64 assembly, `debug/buildinfo` (stdlib). No cgo. No purego (not needed at scope Z).

**Source spec:** `docs/superpowers/specs/2026-05-06-stage-cd-go-static-pie-runtime-design.md` (commit `6f80cb0`).

**Scope check:** Single subsystem (Linux ELF runtime). Does not need decomposition.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `pe/packer/runtime/elf.go` | modify | Add `isGoStaticPIE bool`, `goVersion string` to `elfHeaders`. Add `detectGoStaticPIE` (uses `debug/buildinfo`). Add `gateRejectionReason` method. |
| `pe/packer/runtime/runtime.go` | modify | Add `CheckELFLoadable(input []byte) error` cross-platform export. |
| `pe/packer/runtime/runtime_linux.go` | modify | Extend `mapAndRelocateELF` to enforce gate + lift PT_TLS reject for Go static-PIE. Replace `Run()` stub body with full kernel-frame setup. Add `fakeStackSize` const, `readSelfAuxv`, `writeKernelFrame` helpers. |
| `pe/packer/runtime/runtime_linux_amd64.s` | **create** | Plan 9 asm: `enterEntry(entry, stackTop uintptr)` — RSP swap + JMP. NOSPLIT \| NOFRAME. |
| `pe/packer/runtime/testdata/hello_static_pie.go` | **create** | Fixture source — `package main; func main() { print("hello from packer\n") }`. |
| `pe/packer/runtime/testdata/hello_static_pie` | **create** | Pre-compiled fixture binary, `~1.5 MB` stripped. |
| `pe/packer/runtime/testdata/Makefile` | **create** | `make hello_static_pie` rebuilds reproducibly. |
| `pe/packer/runtime/runtime_test.go` | modify | Tests for detection / gate / fixture happy path. |
| `pe/packer/runtime/runtime_e2e_linux_test.go` | **create** | Gated E2E test: subprocess re-spawn pattern, captures stdout. Build tag `maldev_packer_run_e2e`. |
| `pe/packer/runtime/main_test.go` | **create** | `TestMain` that routes to inner harness when `MALDEV_PACKER_E2E_INNER=1` env is set. |
| `pe/packer/packer.go` | modify | Add `ValidateELF(elf []byte) error` wrapper around `runtime.CheckELFLoadable`. |
| `pe/packer/runtime/doc.go` | modify | Bump phase coverage to mention Stage C+D shipped. |
| `docs/refactor-2026-doc/packer-design.md` | modify | Mark phase 1f row ✅. |
| `docs/refactor-2026-doc/HANDOFF-2026-05-06.md` | modify | Add Stage C+D shipped section. |

---

## Task 1: Go static-PIE detection on `elfHeaders`

**Why first:** All later tasks depend on the detection signal. No behavior change yet — pure parser extension.

**Files:**
- Modify: `pe/packer/runtime/elf.go`
- Modify: `pe/packer/runtime/runtime_test.go`

- [ ] **Step 1.1: Write failing test for `detectGoStaticPIE` on a non-Go ELF**

Append to `runtime_test.go`:

```go
func TestParseELFHeaders_NonGoIsNotStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("internal-state assertion needs the buildMinimalELF helper")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithDynamic: true})
	// buildMinimalELF emits no .go.buildinfo section → must NOT be Go.
	// We need access to the unexported isGoStaticPIE field; since the
	// test is in package runtime_test, do an indirect assertion via
	// runtime.CheckELFLoadable expecting a "not a Go binary" rejection.
	if err := runtime.CheckELFLoadable(elf); err == nil {
		t.Fatal("CheckELFLoadable on non-Go ELF: got nil, want non-nil error")
	} else if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("got %v, want ErrNotImplemented", err)
	}
}
```

- [ ] **Step 1.2: Verify the test fails**

Run: `go test -count=1 -run TestParseELFHeaders_NonGoIsNotStaticPIE ./pe/packer/runtime/`

Expected: FAIL with `runtime.CheckELFLoadable undefined` (Task 1 hasn't shipped CheckELFLoadable yet — that lands in Task 2).

⚠ If failure shape differs, stop and re-read spec. Do not continue.

- [ ] **Step 1.3: Add the new fields to `elfHeaders`**

In `pe/packer/runtime/elf.go`, in the `elfHeaders` struct definition (currently has `elfType`, `entry`, `phoff`, `phnum`, `phentsize`, `programs`), append:

```go
	// isGoStaticPIE is true when the ELF satisfies the Z-scope
	// contract: ET_DYN + .go.buildinfo present + no DT_NEEDED +
	// no PT_INTERP. Computed once in parseELFHeaders.
	isGoStaticPIE bool

	// goVersion is the Go toolchain version string (e.g. "go1.21.5")
	// when isGoStaticPIE is true; empty otherwise. Surfaced in
	// Run() error messages so operators can correlate runtime
	// crashes to toolchain skew.
	goVersion string
```

- [ ] **Step 1.4: Add `detectGoStaticPIE` helper**

Below the existing `parseELFHeaders` function in `elf.go`, add:

```go
// detectGoStaticPIE runs the four-condition Z-scope gate after
// the program-header walk completes. Uses debug/buildinfo from
// stdlib (stable since Go 1.18) to find the .go.buildinfo
// section without re-implementing ELF section parsing.
//
// Returns (isGo, goVersion). When isGo is false, goVersion is
// always empty.
func detectGoStaticPIE(input []byte, h *elfHeaders) (bool, string) {
	// Condition 1: no PT_INTERP.
	for _, p := range h.programs {
		if p.Type == ptInterp {
			return false, ""
		}
	}
	// Condition 2: no DT_NEEDED. Walk PT_DYNAMIC if present.
	if !dynamicHasNoNeeded(input, h) {
		return false, ""
	}
	// Condition 3: .go.buildinfo present (delegated to stdlib).
	bi, err := buildinfo.Read(bytes.NewReader(input))
	if err != nil {
		return false, ""
	}
	return true, bi.GoVersion
}

// dynamicHasNoNeeded returns true when the PT_DYNAMIC segment
// (if any) carries zero DT_NEEDED entries, OR when there's no
// PT_DYNAMIC at all (truly static binary).
func dynamicHasNoNeeded(input []byte, h *elfHeaders) bool {
	const dtNeeded int64 = 1
	for _, p := range h.programs {
		if p.Type != ptDynamic {
			continue
		}
		end := p.Offset + p.FileSz
		if end > uint64(len(input)) || end < p.Offset {
			return false // malformed; conservative reject
		}
		dyn := input[p.Offset:end]
		for off := 0; off+16 <= len(dyn); off += 16 {
			tag := int64(binary.LittleEndian.Uint64(dyn[off : off+8]))
			if tag == 0 { // DT_NULL
				break
			}
			if tag == dtNeeded {
				return false
			}
		}
	}
	return true
}
```

Add the imports at the top of `elf.go`:

```go
import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"errors"
	"fmt"
)
```

(`bytes` and `debug/buildinfo` are new; the other three already present.)

- [ ] **Step 1.5: Wire `detectGoStaticPIE` into `parseELFHeaders`**

In `elf.go`, at the end of `parseELFHeaders` (right before the final `return h, nil`), insert:

```go
	h.isGoStaticPIE, h.goVersion = detectGoStaticPIE(in, h)
```

- [ ] **Step 1.6: Add `gateRejectionReason` method on `elfHeaders`**

Below the helpers, add:

```go
// gateRejectionReason returns the specific Z-scope condition
// that failed, suitable for embedding in an ErrNotImplemented
// error message. Returns "" when isGoStaticPIE is true.
func (h *elfHeaders) gateRejectionReason() string {
	for _, p := range h.programs {
		if p.Type == ptInterp {
			return "has PT_INTERP (binary requires ld.so resolution)"
		}
	}
	for _, p := range h.programs {
		if p.Type == ptDynamic {
			end := p.Offset + p.FileSz
			if end <= uint64(0) {
				continue
			}
		}
	}
	// At this point either DT_NEEDED present or .go.buildinfo missing.
	// Distinguish for diagnostics.
	if h.elfType != etDyn {
		return "not ET_DYN (need PIE)"
	}
	return "not a Go binary (no .go.buildinfo section)"
}
```

- [ ] **Step 1.7: Run /simplify on this commit's diff**

Per CLAUDE.md mandate: run `simplify` skill on the modified `pe/packer/runtime/elf.go`. Apply any reuse / quality / efficiency findings inline. Skip false positives.

Run: `go build ./pe/packer/runtime/`
Expected: clean (no errors).

Run: `GOOS=windows go build ./pe/packer/runtime/`
Expected: clean.

Run: `GOOS=darwin go build ./pe/packer/runtime/`
Expected: clean.

- [ ] **Step 1.8: Commit Task 1**

Note: the test we wrote in Step 1.1 still fails because `CheckELFLoadable` lives in Task 2. That's expected — the test is "in motion" across two commits. Don't include the test file edit in this commit; revert the test edit before committing, then re-add it in Task 2 where the assertion can pass.

Run:
```bash
git checkout pe/packer/runtime/runtime_test.go  # discard Step 1.1 test edit
git add pe/packer/runtime/elf.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/runtime): detect Go static-PIE binaries via debug/buildinfo

Adds isGoStaticPIE + goVersion to elfHeaders. detectGoStaticPIE
runs the four-condition Z-scope gate (no PT_INTERP, no DT_NEEDED,
.go.buildinfo present, ET_DYN). Stdlib debug/buildinfo (Go 1.18+)
is the primary signal — robust against internal layout changes.

Pure detection: no behavior change yet. Linux backend gate
enforcement + cross-platform CheckELFLoadable export land in the
next two commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- `go build ./pe/packer/runtime/` passes on linux/windows/darwin
- `go test ./pe/packer/runtime/` passes (existing tests still green)
- /simplify findings applied or rejected with note

---

## Task 2: `runtime.CheckELFLoadable` cross-platform export

**Why second:** ValidateELF and the gate enforcement both need this surface; landing it here lets the next two tasks be small.

**Files:**
- Modify: `pe/packer/runtime/runtime.go`
- Modify: `pe/packer/runtime/runtime_test.go`

- [ ] **Step 2.1: Write the failing test**

Append to `pe/packer/runtime/runtime_test.go`:

```go
// TestCheckELFLoadable_NonGo confirms a synthetic non-Go ET_DYN
// binary is rejected with ErrNotImplemented + a clear reason.
func TestCheckELFLoadable_NonGo(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithDynamic: true})
	err := runtime.CheckELFLoadable(elf)
	if err == nil {
		t.Fatal("got nil, want non-nil error")
	}
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("got %v, want ErrNotImplemented", err)
	}
}

// TestCheckELFLoadable_NotELF confirms PE / garbage inputs return
// the right sentinel.
func TestCheckELFLoadable_NotELF(t *testing.T) {
	err := runtime.CheckELFLoadable([]byte{'M', 'Z', 0, 0})
	if err == nil {
		t.Fatal("got nil, want non-nil error")
	}
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("got %v, want ErrBadELF", err)
	}
	err = runtime.CheckELFLoadable(nil)
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("nil input: got %v, want ErrBadELF", err)
	}
}
```

- [ ] **Step 2.2: Verify the test fails**

Run: `go test -count=1 -run TestCheckELFLoadable -v ./pe/packer/runtime/`
Expected: FAIL with `undefined: runtime.CheckELFLoadable`.

- [ ] **Step 2.3: Implement `CheckELFLoadable`**

Append to `pe/packer/runtime/runtime.go` (cross-platform — no build tag):

```go
// CheckELFLoadable returns nil when `input` is an ELF that the
// Linux runtime would accept (ET_DYN + Go static-PIE marker +
// no DT_NEEDED + no PT_INTERP), or an error wrapping the same
// sentinels Prepare would emit on Linux.
//
// Cross-platform — runs the same gate regardless of host GOOS.
// Operators packing on macOS get the same answer the target
// Linux loader would. Pure parse + boolean checks; no syscalls,
// no allocations beyond a single bytes.Reader.
func CheckELFLoadable(input []byte) error {
	if len(input) < 4 {
		return fmt.Errorf("%w: input shorter than ELF magic", ErrBadELF)
	}
	if input[0] != elfMagic0 || input[1] != elfMagic1 ||
		input[2] != elfMagic2 || input[3] != elfMagic3 {
		return fmt.Errorf("%w: not an ELF (magic % x)", ErrBadELF, input[:4])
	}
	h, err := parseELFHeaders(input)
	if err != nil {
		return err
	}
	if h.elfType != etDyn {
		return fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
	}
	if !h.isGoStaticPIE {
		return fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
	}
	return nil
}
```

- [ ] **Step 2.4: Verify the tests pass**

Run: `go test -count=1 -run TestCheckELFLoadable -v ./pe/packer/runtime/`
Expected: both subtests PASS.

Run: `go test -count=1 ./pe/packer/runtime/`
Expected: ALL tests pass (existing + new).

- [ ] **Step 2.5: Run cross-OS build sanity**

Run:
```bash
GOOS=windows go build ./pe/packer/runtime/
GOOS=darwin go build ./pe/packer/runtime/
go build ./pe/packer/runtime/
```
Expected: all three exit 0 with no output.

- [ ] **Step 2.6: Run /simplify on this commit's diff**

Apply findings inline.

- [ ] **Step 2.7: Commit Task 2**

```bash
git add pe/packer/runtime/runtime.go pe/packer/runtime/runtime_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/runtime): CheckELFLoadable cross-platform gate export

CheckELFLoadable lets pack-time validators ask 'is this binary
loadable by the Linux runtime?' from any host GOOS. Pure parse +
gate, no syscalls, no allocations. Wraps ErrNotImplemented with
the specific Z-scope rejection reason via gateRejectionReason.

Two tests cover the non-Go ET_DYN reject + not-ELF / nil input
guards.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- New tests green; existing tests still green
- Cross-OS build clean
- /simplify findings applied

---

## Task 3: Linux backend gate enforcement + PT_TLS lift

**Why third:** With detection (Task 1) and CheckELFLoadable (Task 2) in place, the Linux backend can enforce the gate consistently. This task changes runtime behavior on Linux but doesn't yet wire Run() — that's Task 4.

**Files:**
- Modify: `pe/packer/runtime/runtime_linux.go`
- Modify: `pe/packer/runtime/runtime_test.go`

- [ ] **Step 3.1: Write a failing test for Linux backend gate**

Append to `runtime_test.go`:

```go
// TestPrepare_ELF_LinuxRejectsNonGoStaticPIE confirms the Linux
// backend rejects non-Go ET_DYN inputs at Stage B with
// ErrNotImplemented (same surface as CheckELFLoadable).
func TestPrepare_ELF_LinuxRejectsNonGoStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B gate is Linux-only; CheckELFLoadable covers cross-platform")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithDynamic: true})
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("got %v, want ErrNotImplemented", err)
	}
}
```

- [ ] **Step 3.2: Verify the test fails**

Run: `go test -count=1 -run TestPrepare_ELF_LinuxRejectsNonGoStaticPIE -v ./pe/packer/runtime/`
Expected: FAIL — currently `mapAndRelocateELF` accepts the synthetic ET_DYN with PT_DYNAMIC and proceeds to mmap (returns success), or fails on a different reason than expected.

- [ ] **Step 3.3: Add the gate at the top of `mapAndRelocateELF`**

In `pe/packer/runtime/runtime_linux.go`, in `mapAndRelocateELF`, before the existing ET_DYN check (`if h.elfType != etDyn { ... }`), insert:

```go
	// Z-scope gate: only Go static-PIE is loadable today. Surfaces
	// the same sentinel + reason CheckELFLoadable would.
	if !h.isGoStaticPIE {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
	}
```

Then, in the same function, find the existing `if hasTLS { return nil, fmt.Errorf("%w: PT_TLS requires TLS init (Stage D)", ErrNotImplemented) }` and replace it with: simply REMOVE that block. Go static-PIE binaries handle their own TLS; we trust the Z-scope gate above to ensure only Go static-PIE got this far.

After the change, the function header section should look like:

```go
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	if !h.isGoStaticPIE {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
	}
	if h.elfType != etDyn {
		return nil, fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
	}

	var (
		hasInterp  bool
		dynVAddr   uint64
		dynFileSz  uint64
		dynPresent bool
		spanEnd    uint64
	)
	for _, p := range h.programs {
		switch p.Type {
		case ptLoad:
			end := p.VAddr + p.MemSz
			if end > spanEnd {
				spanEnd = end
			}
		case ptDynamic:
			dynVAddr = p.VAddr
			dynFileSz = p.FileSz
			dynPresent = true
		case ptInterp:
			hasInterp = true
		}
	}
	if hasInterp {
		// Reachable only if isGoStaticPIE detection has a bug; defensive.
		return nil, fmt.Errorf("%w: PT_INTERP requires ld.so resolution (Stage C)", ErrNotImplemented)
	}
	if !dynPresent {
		return nil, fmt.Errorf("%w: ET_DYN missing PT_DYNAMIC", ErrBadELF)
	}
	// ... rest unchanged ...
```

Note: the `hasTLS` variable and its check disappear. Grep for `hasTLS` in `runtime_linux.go` and remove every reference.

- [ ] **Step 3.4: Verify the new test passes**

Run: `go test -count=1 -run TestPrepare_ELF_LinuxRejectsNonGoStaticPIE -v ./pe/packer/runtime/`
Expected: PASS.

- [ ] **Step 3.5: Update existing PT_TLS-related test**

The Stage B test `TestPrepare_ELF_RejectsTLSOnLinux` asserts that ANY ELF with PT_TLS gets rejected. After this commit, only non-Go-static-PIE ELFs with PT_TLS get rejected (because the Z-scope gate catches them first). The test still passes (synthetic ELF has no `.go.buildinfo` so the gate fires) but the rejection reason changes.

Verify the existing test still passes:

Run: `go test -count=1 -run TestPrepare_ELF_RejectsTLSOnLinux -v ./pe/packer/runtime/`
Expected: PASS (the gate now fires before the TLS check, but `errors.Is(err, ErrNotImplemented)` still matches).

- [ ] **Step 3.6: Verify the full suite still passes**

Run: `go test -count=1 ./pe/packer/runtime/`
Expected: PASS.

Run: `GOOS=windows go build ./pe/packer/runtime/`
Expected: clean.

- [ ] **Step 3.7: Run /simplify on this commit's diff**

Apply findings inline.

- [ ] **Step 3.8: Commit Task 3**

```bash
git add pe/packer/runtime/runtime_linux.go pe/packer/runtime/runtime_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/runtime): enforce Go static-PIE Z-scope gate on Linux

mapAndRelocateELF now bails with ErrNotImplemented + reason when
isGoStaticPIE is false. The PT_TLS reject is removed because Go
static-PIE binaries self-amorce TLS via arch_prctl in their own
_rt0; the gate ensures only those reach the mapper.

Stage B's existing TestPrepare_ELF_RejectsTLSOnLinux still
passes — the synthetic non-Go fixture is now rejected by the
gate (errors.Is(err, ErrNotImplemented) unchanged).

Run() body still stub; full kernel-frame + asm jump lands next.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- All existing tests + new gate test green
- Cross-OS build clean
- /simplify findings applied
- No `hasTLS` references remain in runtime_linux.go

---

## Task 4: Test fixture (hello_static_pie binary + Makefile + source)

**Why fourth:** Task 5 (Run() implementation) needs a real Go static-PIE fixture to exercise the happy path. Land the fixture before the code that uses it so each task is a clean commit.

**Files:**
- Create: `pe/packer/runtime/testdata/hello_static_pie.go`
- Create: `pe/packer/runtime/testdata/Makefile`
- Create: `pe/packer/runtime/testdata/hello_static_pie` (binary, ~1.5 MB)
- Modify: `pe/packer/runtime/runtime_test.go`

- [ ] **Step 4.1: Create the fixture source**

Create `pe/packer/runtime/testdata/hello_static_pie.go`:

```go
// Build (see Makefile):
//   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
//     go build -buildmode=pie \
//     -ldflags='-s -w -extldflags=-static' \
//     -o hello_static_pie ./hello_static_pie.go
//
// The resulting binary is the runtime test fixture: a Go
// static-PIE that prints "hello from packer\n" and exits.
// Stripped (-s -w) to keep the checked-in size near 1.5 MB
// AND to better resemble a real operator payload (which
// typically also strips symbols).
package main

func main() { print("hello from packer\n") }
```

- [ ] **Step 4.2: Create the Makefile**

Create `pe/packer/runtime/testdata/Makefile`:

```makefile
# Reproducible rebuild of the Stage C+D test fixture.
# Run from this directory: `make` or `make hello_static_pie`.

GO ?= go

hello_static_pie: hello_static_pie.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -buildmode=pie \
		-ldflags='-s -w -extldflags=-static' \
		-o $@ ./$<

clean:
	rm -f hello_static_pie

.PHONY: clean
```

- [ ] **Step 4.3: Build the fixture**

Run from repo root:

```bash
cd pe/packer/runtime/testdata && make hello_static_pie && cd -
```

Expected: `pe/packer/runtime/testdata/hello_static_pie` exists, file size in the 1.4-1.7 MB range.

Verify the binary shape:

```bash
file pe/packer/runtime/testdata/hello_static_pie
```

Expected output (substring): `ELF 64-bit LSB pie executable, x86-64, ..., statically linked, Go BuildID=...`.

If the output says `dynamically linked` or includes `interpreter`, the build flags are wrong — re-check `-extldflags=-static`. Stop and fix before continuing.

- [ ] **Step 4.4: Verify the fixture passes Z-scope gate**

Run a quick assertion via `go run` script (one-off, don't commit):

```bash
cat > /tmp/check_fixture.go << 'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

func main() {
	b, err := os.ReadFile("pe/packer/runtime/testdata/hello_static_pie")
	if err != nil { panic(err) }
	if err := runtime.CheckELFLoadable(b); err != nil {
		fmt.Println("REJECTED:", err)
		os.Exit(1)
	}
	fmt.Println("OK: fixture is loadable")
}
EOF
go run /tmp/check_fixture.go
rm /tmp/check_fixture.go
```

Expected: `OK: fixture is loadable`. If REJECTED, the fixture's build flags don't produce a Go static-PIE we recognize — re-check Step 4.3 output and fix.

- [ ] **Step 4.5: Add a test that loads the fixture via Prepare**

Append to `pe/packer/runtime/runtime_test.go`:

```go
// TestPrepare_ELF_AcceptsRealGoStaticPIE loads the fixture binary
// from testdata, runs Prepare, and confirms the mapper succeeds
// without errors. Does NOT call Run() — that's gated behind the
// E2E test in runtime_e2e_linux_test.go.
func TestPrepare_ELF_AcceptsRealGoStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B mapper is Linux-only")
	}
	elf, err := os.ReadFile("testdata/hello_static_pie")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare(hello_static_pie): %v", err)
	}
	defer func() {
		if err := img.Free(); err != nil {
			t.Errorf("Free: %v", err)
		}
	}()
	if img.Base == 0 {
		t.Error("Base = 0 — mapper did not allocate")
	}
	if img.SizeOfImage == 0 {
		t.Error("SizeOfImage = 0")
	}
	if img.EntryPoint <= img.Base {
		t.Errorf("EntryPoint %#x not within mapped region (base %#x, size %d)",
			img.EntryPoint, img.Base, img.SizeOfImage)
	}
}
```

Add the `"os"` import if not already present in the file.

- [ ] **Step 4.6: Verify the test passes**

Run: `go test -count=1 -run TestPrepare_ELF_AcceptsRealGoStaticPIE -v ./pe/packer/runtime/`
Expected: PASS.

If the test fails with "fixture is rejected by gate", recheck Step 4.4. If it fails inside the mapper (mmap / mprotect / RELATIVE reloc errors), the fixture has more relocs than RELATIVE — Stage B can't handle them. Verify `readelf -r pe/packer/runtime/testdata/hello_static_pie | head -20` shows ONLY `R_X86_64_RELATIVE` relocations.

- [ ] **Step 4.7: Run /simplify on this commit's diff**

Apply findings inline.

- [ ] **Step 4.8: Commit Task 4**

```bash
git add pe/packer/runtime/testdata/ pe/packer/runtime/runtime_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "test(pe/packer/runtime): hello_static_pie fixture + Stage B real-binary load

Adds testdata/hello_static_pie.go (source), Makefile (reproducible
rebuild), and the pre-compiled binary checked in for test
ergonomics. ~1.5 MB stripped (-s -w), shape: ELF 64-bit static
PIE x86-64 with Go BuildID — passes the Z-scope gate.

TestPrepare_ELF_AcceptsRealGoStaticPIE confirms Stage B's mapper
handles a real Go static-PIE end-to-end (mmap + relocate +
mprotect + Free idempotent) without invoking Run(). E2E execution
test lands in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- `make hello_static_pie` produces a working static-PIE
- `runtime.CheckELFLoadable` accepts the fixture
- New test green; existing tests green
- Binary size between 1.0 and 2.0 MB

---

## Task 5: Run() body — auxv passthrough + frame writer + Plan 9 asm

**Why fifth:** All scaffolding is in place; this task ships the actual jump-to-entry capability. Largest task; broken into the most steps.

**Files:**
- Modify: `pe/packer/runtime/runtime_linux.go`
- Create: `pe/packer/runtime/runtime_linux_amd64.s`
- Create: `pe/packer/runtime/main_test.go`
- Create: `pe/packer/runtime/runtime_e2e_linux_test.go`
- Modify: `pe/packer/runtime/runtime_test.go`

### Sub-task 5a: Plan 9 asm enterEntry

- [ ] **Step 5a.1: Create the asm file**

Create `pe/packer/runtime/runtime_linux_amd64.s` (filename `_linux_amd64.s` enforces GOOS+GOARCH constraints implicitly):

```
// Plan 9 amd64 assembly for the Stage C+D Linux loader.
//
// enterEntry swaps RSP to a caller-supplied stack and JMPs to a
// caller-supplied entry point. Used by PreparedImage.Run() after
// the Go-side code has built a kernel-style stack frame
// (argc/argv/envp/auxv) at stackTop.
//
// NOSPLIT|NOFRAME because the Go runtime's stack-growth machinery
// would corrupt our hand-built frame; we never grow the stack
// here, and we never return.

#include "textflag.h"

// func enterEntry(entry, stackTop uintptr)
TEXT ·enterEntry(SB), NOSPLIT|NOFRAME, $0-16
	// Order matters: FP is computed relative to SP, so we must
	// read both args before swapping SP. Once SP is overwritten,
	// FP no longer references our caller's frame.
	MOVQ entry+0(FP), AX
	MOVQ stackTop+8(FP), SP
	JMP  AX
```

- [ ] **Step 5a.2: Add the Go-side declaration**

In `pe/packer/runtime/runtime_linux.go`, somewhere above `Run()`, add:

```go
// enterEntry swaps RSP to stackTop and JMPs to entry. Implemented
// in runtime_linux_amd64.s. Never returns.
//
//go:noescape
func enterEntry(entry, stackTop uintptr)
```

- [ ] **Step 5a.3: Verify build**

Run: `go build ./pe/packer/runtime/`
Expected: clean. If failure mentions `relocation target enterEntry not defined`, the .s file isn't being picked up — verify filename is exactly `runtime_linux_amd64.s`.

### Sub-task 5b: fakeStackSize const + readSelfAuxv helper

- [ ] **Step 5b.1: Add the constant**

In `pe/packer/runtime/runtime_linux.go`, near the top of the file (after the `const ()` block for relocations):

```go
const (
	// fakeStackSize is the byte size of the kernel-style stack
	// mmap'd by Run() before transferring control. 256 KiB is
	// ample: Go's _rt0_amd64_linux + rt0_go switch to the g0
	// stack within hundreds of bytes of stack use; the rest is
	// headroom for auxv parsing and arch_prctl.
	fakeStackSize = 256 * 1024
)
```

- [ ] **Step 5b.2: Add `readSelfAuxv` helper**

Append (still in `runtime_linux.go`):

```go
// auxvEntry mirrors one Elf64_auxv_t (i64 a_type, u64 a_val).
type auxvEntry struct {
	Type uint64
	Val  uint64
}

// auxv constants we override or special-case at frame build time.
const (
	atNull   = 0
	atRandom = 25
)

// readSelfAuxv reads /proc/self/auxv, parses the entries, and
// returns them with AT_RANDOM rewritten to canaryPtr (so the
// loaded binary reads our fresh canary instead of the parent's).
// The trailing AT_NULL terminator is preserved.
//
// Returning a slice keeps the caller free to compute the exact
// frame size before mmap'ing the fake stack.
func readSelfAuxv(canaryPtr uintptr) ([]auxvEntry, error) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil, err
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("auxv length %d not a multiple of 16", len(data))
	}
	out := make([]auxvEntry, 0, len(data)/16)
	for off := 0; off+16 <= len(data); off += 16 {
		e := auxvEntry{
			Type: binary.LittleEndian.Uint64(data[off : off+8]),
			Val:  binary.LittleEndian.Uint64(data[off+8 : off+16]),
		}
		if e.Type == atRandom {
			e.Val = uint64(canaryPtr)
		}
		out = append(out, e)
		if e.Type == atNull {
			return out, nil
		}
	}
	return nil, fmt.Errorf("auxv missing AT_NULL terminator")
}
```

Add `"os"` to the import block if not present. `binary` already imported.

- [ ] **Step 5b.3: Write a unit test for readSelfAuxv**

Append to `runtime_test.go`:

```go
// TestReadSelfAuxv_ContainsCanaryOverride confirms the helper
// returns at least an AT_RANDOM entry whose Val matches the
// override pointer the caller passed in.
func TestReadSelfAuxv_ContainsCanaryOverride(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("/proc/self/auxv is Linux-only")
	}
	// Use the unexported helper via the package-private test bridge;
	// since it's unexported and the test is in package runtime_test,
	// add a tiny linux-only export shim in runtime_linux.go for
	// testing — see Step 5b.4.
	canary := uintptr(0xCAFEBABE)
	auxv := runtime.ReadSelfAuxvForTest(canary)
	var found bool
	for _, e := range auxv {
		if e.Type == 25 { // AT_RANDOM
			if e.Val != uint64(canary) {
				t.Errorf("AT_RANDOM not overridden: got %#x, want %#x", e.Val, canary)
			}
			found = true
		}
	}
	if !found {
		t.Skip("/proc/self/auxv on this kernel doesn't carry AT_RANDOM (uncommon, no fault of ours)")
	}
}
```

- [ ] **Step 5b.4: Add the test bridge**

In `runtime_linux.go`, at the bottom:

```go
// ReadSelfAuxvForTest exposes the auxv parser to runtime_test
// without leaking the auxvEntry type into the public API. Linux-
// only mirror of readSelfAuxv that returns a typed pair slice
// the test package can iterate.
func ReadSelfAuxvForTest(canaryPtr uintptr) []struct {
	Type, Val uint64
} {
	entries, err := readSelfAuxv(canaryPtr)
	if err != nil {
		return nil
	}
	out := make([]struct{ Type, Val uint64 }, len(entries))
	for i, e := range entries {
		out[i] = struct{ Type, Val uint64 }{e.Type, e.Val}
	}
	return out
}
```

- [ ] **Step 5b.5: Verify**

Run: `go test -count=1 -run TestReadSelfAuxv_ContainsCanaryOverride -v ./pe/packer/runtime/`
Expected: PASS (or SKIP if AT_RANDOM absent, which is rare).

### Sub-task 5c: writeKernelFrame helper

- [ ] **Step 5c.1: Add writeKernelFrame**

Append to `runtime_linux.go`:

```go
// writeKernelFrame writes the Linux SysV-ABI process startup
// frame at the top of `stack`, mimicking what the kernel sets
// up for a freshly-execve'd binary. Returns the resulting RSP
// (16-byte aligned per x86_64 ABI; rsp -= padding when needed).
//
// Frame layout, low to high addresses (RSP at frame[0]):
//
//	argc                          (i64)
//	argv[0..argc-1]               (i64 each — pointers to argv strings)
//	NULL                          (argv terminator)
//	envp[0..]                     (i64 each — pointers to envp strings)
//	NULL                          (envp terminator)
//	auxv[0..]                     (16 bytes each: type + val)
//	AT_NULL                       (auxv terminator, 16 bytes of zero)
//	[argv strings]                (NUL-terminated)
//	[envp strings]                (NUL-terminated)
//	[16-byte canary buf]          (target of AT_RANDOM)
//
// We emit argc=0 and no argv/envp strings; the loaded Go binary
// has no use for argv beyond os.Args (which becomes empty).
func writeKernelFrame(stack []byte, auxv []auxvEntry, canary [16]byte) uintptr {
	frameSize := 8 // argc
	frameSize += 8 // argv NULL
	frameSize += 8 // envp NULL
	frameSize += len(auxv) * 16
	frameSize += 16 // canary buffer
	// 16-byte align frame size BEFORE the canary so the canary
	// itself doesn't break alignment of the SP.
	if pad := frameSize % 16; pad != 0 {
		frameSize += 16 - pad
	}

	// Layout: write canary at the highest address; everything
	// else grows downward.
	top := len(stack)
	canaryOff := top - 16
	copy(stack[canaryOff:top], canary[:])

	// Walk auxv backward so AT_NULL is at the highest address
	// before the canary.
	off := canaryOff
	for i := len(auxv) - 1; i >= 0; i-- {
		off -= 16
		binary.LittleEndian.PutUint64(stack[off:off+8], auxv[i].Type)
		binary.LittleEndian.PutUint64(stack[off+8:off+16], auxv[i].Val)
	}
	// envp NULL
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0)
	// argv NULL
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0)
	// argc = 0
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0)

	// 16-byte align RSP.
	off &^= 0xF

	return uintptr(unsafe.Pointer(&stack[off]))
}
```

Add `"unsafe"` to imports if not present.

- [ ] **Step 5c.2: Verify build**

Run: `go build ./pe/packer/runtime/`
Expected: clean.

### Sub-task 5d: Wire Run() body

- [ ] **Step 5d.1: Replace Run() body**

In `runtime_linux.go`, find the existing `func (p *PreparedImage) Run() error { ... }` and REPLACE its body so the function reads:

```go
func (p *PreparedImage) Run() error {
	if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
		return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
	}

	stack, err := unix.Mmap(-1, 0, fakeStackSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("packer/runtime: fake stack mmap: %w", err)
	}

	var canary [16]byte
	if _, err := rand.Read(canary[:]); err != nil {
		_ = unix.Munmap(stack)
		return fmt.Errorf("packer/runtime: AT_RANDOM canary: %w", err)
	}

	canaryPtr := uintptr(unsafe.Pointer(&stack[len(stack)-16]))
	auxv, err := readSelfAuxv(canaryPtr)
	if err != nil {
		_ = unix.Munmap(stack)
		return fmt.Errorf("packer/runtime: read /proc/self/auxv: %w", err)
	}

	stackTop := writeKernelFrame(stack, auxv, canary)
	enterEntry(p.EntryPoint, stackTop)
	return nil // unreachable — JMP never returns
}
```

Add `"crypto/rand"` (renamed `rand`) to imports — be careful not to clash with `math/rand` (don't import that here).

- [ ] **Step 5d.2: Verify build**

Run: `go build ./pe/packer/runtime/`
Expected: clean.

### Sub-task 5e: TestMain + E2E test

- [ ] **Step 5e.1: Create main_test.go**

Create `pe/packer/runtime/main_test.go`:

```go
package runtime_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// TestMain routes to the inner E2E harness when MALDEV_PACKER_E2E_INNER=1.
// The outer E2E test re-spawns this binary with that env var so the
// loaded fixture binary can call exit_group without killing the
// developer's go-test process.
func TestMain(m *testing.M) {
	if os.Getenv("MALDEV_PACKER_E2E_INNER") == "1" {
		runE2EFixtureAndExit()
	}
	os.Exit(m.Run())
}

// runE2EFixtureAndExit loads testdata/hello_static_pie via
// runtime.Prepare, calls Run(). Must be invoked from the test
// binary working directory (which go test sets to the package
// dir). Never returns — the loaded binary calls exit_group.
func runE2EFixtureAndExit() {
	elf, err := os.ReadFile("testdata/hello_static_pie")
	if err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: read fixture:", err)
		os.Exit(2)
	}
	img, err := runtime.Prepare(elf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: Prepare:", err)
		os.Exit(2)
	}
	if err := img.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "E2E inner: Run:", err)
		os.Exit(2)
	}
	// Unreachable — Run() must not return.
	fmt.Fprintln(os.Stderr, "E2E inner: Run returned (should be unreachable)")
	os.Exit(3)
}
```

- [ ] **Step 5e.2: Create the gated E2E test**

Create `pe/packer/runtime/runtime_e2e_linux_test.go`:

```go
//go:build linux && maldev_packer_run_e2e

package runtime_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRun_GoStaticPIE_E2E exercises the full Stage C+D path:
// load the fixture binary, JMP to entry, capture its stdout,
// assert the expected greeting.
//
// Re-spawns the test binary with MALDEV_PACKER_E2E_INNER=1 so
// TestMain routes to the inner harness. The subprocess inherits
// MALDEV_PACKER_RUN_E2E=1 so Run() un-gates.
//
// Build-tagged behind maldev_packer_run_e2e to keep CI runs
// safe; opt in via:
//
//	go test -tags=maldev_packer_run_e2e ./pe/packer/runtime/...
func TestRun_GoStaticPIE_E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"MALDEV_PACKER_E2E_INNER=1",
		"MALDEV_PACKER_RUN_E2E=1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		// Subprocess returned cleanly. The loaded fixture's
		// "exit_group(0)" yields exit status 0 — that's a clean
		// run from the parent's POV.
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 0 {
			t.Fatalf("subprocess exit code %d (stderr: %q)",
				exitErr.ExitCode(), stderr.String())
		}
	} else {
		t.Fatalf("subprocess: %v (stderr: %q)", err, stderr.String())
	}

	const want = "hello from packer"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout %q does not contain %q (stderr: %q)",
			stdout.String(), want, stderr.String())
	}
}
```

- [ ] **Step 5e.3: Verify the gated test compiles**

Run: `go test -tags=maldev_packer_run_e2e -count=1 -run TestRun_GoStaticPIE_E2E_DOES_NOT_EXIST ./pe/packer/runtime/`
Expected: PASS (with `0 of 0 tests run` or similar — just confirms the build tag compiles).

Run: `go vet -tags=maldev_packer_run_e2e ./pe/packer/runtime/`
Expected: clean.

- [ ] **Step 5e.4: Run the gated E2E test**

Run: `go test -tags=maldev_packer_run_e2e -count=1 -run TestRun_GoStaticPIE_E2E -v ./pe/packer/runtime/`
Expected: PASS, with `--- PASS: TestRun_GoStaticPIE_E2E`.

If it fails:
- Output `subprocess exit code N`: read stderr from the test log; the subprocess wrote what went wrong (`E2E inner: ...`).
- Output `does not contain "hello from packer"`: the JMP succeeded but the binary's stdout didn't reach us. Check that `cmd.Stdout = &stdout` is wired and that the fixture was rebuilt with the latest source.
- Hang past 10s: the asm JMP didn't transfer control and the subprocess is stuck. Examine `runtime_linux_amd64.s` for an off-by-one in arg offsets.

### Sub-task 5f: Verify, /simplify, commit

- [ ] **Step 5f.1: Run the full unit suite without the gated tag**

Run: `go test -count=1 ./pe/packer/runtime/`
Expected: PASS for all tests; the gated E2E test is excluded.

- [ ] **Step 5f.2: Run cross-OS build sanity**

Run:
```bash
GOOS=windows go build ./pe/packer/runtime/
GOOS=darwin go build ./pe/packer/runtime/
```
Expected: both clean. The asm file's `_linux_amd64.s` suffix excludes it on other GOOS.

- [ ] **Step 5f.3: Run /simplify on this commit's diff**

Apply findings inline. The asm file is small (~10 LOC); simplify focuses on `runtime_linux.go` Go-side helpers and the test files.

- [ ] **Step 5f.4: Commit Task 5**

```bash
git add pe/packer/runtime/runtime_linux.go pe/packer/runtime/runtime_linux_amd64.s \
        pe/packer/runtime/main_test.go pe/packer/runtime/runtime_e2e_linux_test.go \
        pe/packer/runtime/runtime_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/runtime): Stage C+D Run() — jump to Go static-PIE entry

Wires the Linux loader end-to-end:

- enterEntry (Plan 9 amd64 asm, NOSPLIT|NOFRAME): two-instruction
  RSP swap + JMP to entry. No register zeroing — Go's
  _rt0_amd64_linux re-initializes everything from scratch.
- readSelfAuxv: parses /proc/self/auxv into typed entries,
  overrides AT_RANDOM with a caller-supplied canary pointer.
  Pass-through for AT_PAGESZ / AT_HWCAP / AT_PLATFORM /
  AT_SYSINFO_EHDR so the loaded Go runtime sees the host's vDSO
  and CPU features.
- writeKernelFrame: writes argc=0 / argv NULL / envp NULL / auxv
  / AT_NULL / canary buffer at the top of the fake stack, with
  16-byte SP alignment before the JMP.
- Run() body: 256 KiB MAP_PRIVATE|MAP_ANONYMOUS fake stack +
  fresh crypto/rand canary + auxv passthrough + frame write +
  enterEntry. Never returns on the happy path.

Gated E2E test (maldev_packer_run_e2e build tag): re-spawns the
test binary with MALDEV_PACKER_E2E_INNER=1 so TestMain routes to
runE2EFixtureAndExit. Outer test captures stdout, asserts on
'hello from packer' substring.

Run with: go test -tags=maldev_packer_run_e2e ./pe/packer/runtime/

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- `go test ./pe/packer/runtime/` green (no tag)
- `go test -tags=maldev_packer_run_e2e ./pe/packer/runtime/` green (E2E PASS)
- `GOOS=windows go build ./pe/packer/runtime/` clean
- /simplify findings applied
- Plan 9 asm syntax validated by `go vet`

---

## Task 6: `pe/packer.ValidateELF` operator helper

**Why sixth:** Now that the gate exists at runtime layer, expose it at packer layer + wire into `cmd/packer pack` to refuse misuse.

**Files:**
- Modify: `pe/packer/packer.go`
- Modify: `pe/packer/packer_test.go`
- Modify: `cmd/packer/main.go`

- [ ] **Step 6.1: Inspect current cmd/packer to plan the wire-in**

Run: `head -50 cmd/packer/main.go` and `grep -n "Pack\|ParseFlags" cmd/packer/main.go`
Expected: locate the `pack` subcommand handler. Note the function name and the line where `packer.Pack` is called.

- [ ] **Step 6.2: Write the failing test**

Append to `pe/packer/packer_test.go` (or create if absent):

```go
func TestValidateELF_AcceptsRealFixture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture is built for linux/amd64")
	}
	elf, err := os.ReadFile("../../pe/packer/runtime/testdata/hello_static_pie")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := packer.ValidateELF(elf); err != nil {
		t.Errorf("ValidateELF(fixture): got %v, want nil", err)
	}
}

func TestValidateELF_RejectsGarbage(t *testing.T) {
	if err := packer.ValidateELF([]byte{0x00, 0x00, 0x00, 0x00}); err == nil {
		t.Error("ValidateELF(zeros): got nil, want error")
	}
}
```

(Test-package paths: `packer_test` lives in `pe/packer/`, so the testdata file is `runtime/testdata/hello_static_pie` from there. Adjust the relative path if needed — verify with `ls pe/packer/runtime/testdata/`.)

Add `"runtime"` and `"os"` imports if missing.

- [ ] **Step 6.3: Verify the test fails**

Run: `go test -count=1 -run TestValidateELF -v ./pe/packer/`
Expected: FAIL with `undefined: packer.ValidateELF`.

- [ ] **Step 6.4: Add ValidateELF**

Append to `pe/packer/packer.go`:

```go
// ValidateELF returns nil when `elf` is a Go static-PIE binary
// the Linux runtime can load, or an error explaining the
// rejection reason. Operators should call this at pack time to
// catch unsupported inputs before deploy.
//
// Thin wrapper around runtime.CheckELFLoadable; lives on the
// packer package so the CLI / SDK callers don't need to import
// the runtime sub-package.
func ValidateELF(elf []byte) error {
	return runtime.CheckELFLoadable(elf)
}
```

Add the import if missing:

```go
import (
	// ... existing imports ...
	"github.com/oioio-space/maldev/pe/packer/runtime"
)
```

- [ ] **Step 6.5: Run the tests**

Run: `go test -count=1 -run TestValidateELF -v ./pe/packer/`
Expected: PASS.

- [ ] **Step 6.6: Wire ValidateELF into cmd/packer pack**

Open `cmd/packer/main.go`. Find the `pack` subcommand handler — the function that calls `packer.Pack(input, opts)` after reading the input file.

Just BEFORE the call to `packer.Pack`, insert:

```go
	if err := packer.ValidateELF(input); err != nil {
		fmt.Fprintf(os.Stderr, "packer: input is not a loadable Go static-PIE: %v\n", err)
		fmt.Fprintln(os.Stderr, "rebuild with: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w -extldflags=-static' -o <out> <pkg>")
		os.Exit(1)
	}
```

Note: only do this validation when the input *might* be ELF. If the CLI also packs PE files, gate the call:

```go
	if len(input) >= 4 && input[0] == 0x7F && input[1] == 'E' && input[2] == 'L' && input[3] == 'F' {
		if err := packer.ValidateELF(input); err != nil {
			// ... as above ...
		}
	}
```

- [ ] **Step 6.7: Verify cmd/packer still builds**

Run: `go build ./cmd/packer`
Expected: clean.

Run a smoke test:

```bash
go run ./cmd/packer pack --help
```

Expected: usage text emitted; no panics.

- [ ] **Step 6.8: Run /simplify on this commit's diff**

Apply findings inline.

- [ ] **Step 6.9: Commit Task 6**

```bash
git add pe/packer/packer.go pe/packer/packer_test.go cmd/packer/main.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer): ValidateELF + cmd/packer pre-flight gate

ValidateELF wraps runtime.CheckELFLoadable so SDK callers don't
need to import the runtime sub-package. Same Z-scope contract:
nil when input is Go static-PIE loadable on Linux; wrapped
ErrNotImplemented + rejection reason otherwise.

cmd/packer pack now calls ValidateELF on ELF inputs before
encrypting and refuses with a clear rebuild hint when the binary
fails the gate. Saves a deploy-and-fail cycle.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

**Ready to ship as commit when:**
- `go test ./pe/packer/...` green
- `go build ./cmd/packer` clean
- `cmd/packer pack` emits the rejection message on a non-Go ELF (manual smoke test)
- /simplify findings applied

---

## Task 7: Docs + handoff bump + SEMVER tag

**Why last:** Phase 1f Stage C+D is a major milestone. Update doc-of-truth, mark phase ✅, ship a version tag for changelog.

**Files:**
- Modify: `pe/packer/runtime/doc.go`
- Modify: `docs/refactor-2026-doc/packer-design.md`
- Modify: `docs/refactor-2026-doc/HANDOFF-2026-05-06.md`

- [ ] **Step 7.1: Update runtime/doc.go**

In `pe/packer/runtime/doc.go`, in the `Coverage so far:` block, replace the Phase 1f Stage A + Stage B paragraphs with:

```go
//   - Phase 1f Stage A — ELF64 LE x86_64 parser + format
//     dispatch from [Prepare].
//   - Phase 1f Stage B — Linux mmap of PT_LOAD segments,
//     R_X86_64_RELATIVE relocations, per-segment mprotect.
//   - Phase 1f Stage C+D — Go static-PIE end-to-end on Linux:
//     four-condition Z-scope gate via debug/buildinfo;
//     PT_TLS lift conditional on the gate; Run() builds a
//     kernel-style stack frame (argc/argv/envp/auxv from
//     /proc/self/auxv with AT_RANDOM canary) and JMPs to the
//     binary's entry point via Plan 9 asm. Symmetric with the
//     Windows side's "JMP OEP, never returns" contract.
//
// Other ELFs (C-built, libc-using, IFUNC, versioned symbols,
// ET_EXEC) continue to surface [ErrNotImplemented] with a clear
// rebuild hint. Stage E will broaden to non-Go static-PIE; Stage
// F to full ld.so emulation.
```

- [ ] **Step 7.2: Update packer-design.md**

In `docs/refactor-2026-doc/packer-design.md`, find the row in the phase table that starts `| 1f |` and replace it with:

```markdown
| 1f | Linux ELF reflective loader for Go static-PIE binaries (Stage A: parser + dispatch; Stage B: mmap + RELATIVE; Stage C+D: gate + Run() jump-to-entry). Other ELFs out of scope (Stage E for non-Go, Stage F for full ld.so). | ✅ Stages A+B+C+D |
```

- [ ] **Step 7.3: Update HANDOFF-2026-05-06.md**

In `docs/refactor-2026-doc/HANDOFF-2026-05-06.md`, near the top of the "What landed today" section, insert a new sub-section:

```markdown
### Phase 1f Stage C+D shipped — Go static-PIE end-to-end on Linux ✅

`pe/packer/runtime/elf.go` (+detection), `runtime.go` (+CheckELFLoadable),
`runtime_linux.go` (gate + Run() body), `runtime_linux_amd64.s` (NEW —
enterEntry asm), `testdata/hello_static_pie` (fixture). Plus
`pe/packer.ValidateELF` operator helper + cmd/packer pre-flight gate.

Z-scope contract:

- Accepts: ELF64 LE x86_64, ET_DYN, .go.buildinfo present, no
  DT_NEEDED, no PT_INTERP. Built with
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w -extldflags=-static'`.
- Rejects everything else with ErrNotImplemented + rebuild hint.

Run() flow: 256 KiB MAP_PRIVATE|MAP_ANONYMOUS fake stack +
`/proc/self/auxv` passthrough with fresh AT_RANDOM canary + Plan 9
asm RSP swap + JMP to entry. Never returns on the happy path
(loaded binary calls exit_group, kills loader process). Mirrors
the Windows side's contract.

E2E test gated behind `go test -tags=maldev_packer_run_e2e`;
re-spawns the test binary with MALDEV_PACKER_E2E_INNER=1 so the
loaded fixture's exit_group doesn't kill the developer's go-test.

Validated: linux green (gated + ungated), Windows + Darwin builds
clean.
```

In the "Recommended next moves" section near the bottom, replace any "Phase 1f Stage C / Stage D" entries with:

```markdown
1. **Phase 1e — polymorphism + multi-format** (Task #6 in the
   live TaskList). Compile-time templating per pack; multi-format
   output (exe / dll / reflective-dll / service-exe / dotnet / bof).
   Breaks pure-library mode (operator's build host needs Go
   toolchain).
2. **Phase 1f Stage E** (optional) — non-Go static-PIE
   (C / Rust). Reuses enterEntry asm; needs different gate
   detection (no .go.buildinfo).
3. **Phase 1f Stage F** (optional) — full ld.so emulation for
   libc-using ELFs. Operationally heavy; defer until demand
   evidence.
```

Bump the front-matter to point at the new tip:

```markdown
---
last_reviewed: 2026-05-06
reflects_commit: <will be replaced post-commit>
---
```

(Leave `reflects_commit` at the existing value `c89b877` — it'll bump on the next handoff edit, and the design spec already pinned `6f80cb0` for this milestone.)

- [ ] **Step 7.4: Run /simplify on this commit's diff**

Doc-only commit. /simplify focuses on consistency: any contradictions between doc.go, packer-design.md, and HANDOFF? If yes, fix.

- [ ] **Step 7.5: Build sanity**

Run: `go build $(go list ./... | grep -v scripts/x64dbg-harness)`
Expected: clean (the pre-existing `pe/masquerade/preset` warning is acceptable).

- [ ] **Step 7.6: Commit + push + tag**

```bash
git add pe/packer/runtime/doc.go docs/refactor-2026-doc/packer-design.md docs/refactor-2026-doc/HANDOFF-2026-05-06.md
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "docs(packer): Phase 1f Stage C+D shipped — handoff + design + doc.go bump

Mark phase 1f row in packer-design.md as ✅ for Stages A+B+C+D.
Bump runtime/doc.go to advertise the Stage C+D capability and
reaffirm scope (Go static-PIE only; Stage E broadens to non-Go).
Add 'What landed today' section in HANDOFF-2026-05-06.md
documenting the runtime + cmd/packer surface, the E2E test
opt-in flag, and the next-moves order (Phase 1e polymorphism is
next big milestone).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push origin master

git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com tag -a v0.57.0 -m "Phase 1f Stage C+D — Go static-PIE reflective loader on Linux"
git push origin v0.57.0
```

**Ready to ship as commit when:**
- All previous tasks committed and on master
- Whole-module build clean
- /simplify pass complete
- Tag pushed

---

## Self-Review Checklist (run after writing this plan)

**1. Spec coverage:**

- [x] `isGoStaticPIE` + `goVersion` fields on `elfHeaders` → Task 1
- [x] `detectGoStaticPIE` via `debug/buildinfo` → Task 1
- [x] `gateRejectionReason` method → Task 1
- [x] `runtime.CheckELFLoadable` cross-platform export → Task 2
- [x] Linux gate enforcement in `mapAndRelocateELF` → Task 3
- [x] PT_TLS lift for Go static-PIE → Task 3
- [x] `fakeStackSize` const → Task 5b
- [x] `readSelfAuxv` helper with AT_RANDOM override → Task 5b
- [x] `writeKernelFrame` with 16-byte alignment → Task 5c
- [x] `enterEntry` Plan 9 asm → Task 5a
- [x] `Run()` body wired → Task 5d
- [x] `pe/packer.ValidateELF` → Task 6
- [x] cmd/packer pack pre-flight gate → Task 6
- [x] `testdata/hello_static_pie.go` + Makefile + binary → Task 4
- [x] E2E test with subprocess re-spawn → Task 5e
- [x] Build-tagged behind `maldev_packer_run_e2e` → Task 5e
- [x] Doc bumps + tag → Task 7

No gaps.

**2. Placeholder scan:** No "TBD", "TODO", "fill in details", "similar to Task N" left. Every step has actual code or concrete commands. Self-review passes.

**3. Type consistency:** `elfHeaders` field names (`isGoStaticPIE`, `goVersion`, `programs`, `elfType`, `entry`) are consistent across all tasks. `auxvEntry` struct used in Task 5b/5c is defined once. `enterEntry(entry, stackTop uintptr)` signature is identical in Go declaration (Task 5a.2) and asm header comment (Task 5a.1).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-06-stage-cd-go-static-pie-implementation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for plans with multiple independent phases (this plan: 7 tasks).

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Slower but lets you watch each step in real time.

Which approach?
