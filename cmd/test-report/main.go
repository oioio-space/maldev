// Command test-report ingests one or more `go test -json` output streams
// and emits a per-test / per-package / per-platform matrix report.
//
// Usage:
//
//	test-report -in linux=/tmp/linux.json -in windows=/tmp/windows.json
//	test-report -in host=/tmp/host.json -out /tmp/report.md -format md
//
// Flags:
//
//	-in LABEL=PATH   (repeat) attach a label (linux/windows/host) to a JSON stream
//	-format text|md  output format (default text)
//	-out PATH        write report to file (default stdout)
//	-fail-only       list only failing tests in per-test section
//
// Exit: non-zero if any test failed.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// goTestEvent matches the line-delimited JSON emitted by `go test -json`.
// See `go doc test2json`.
type goTestEvent struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"` // run, pass, fail, skip, output, pause, cont, bench, start
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Elapsed float64   `json:"Elapsed"`
	Output  string    `json:"Output"`
}

type testResult struct {
	Pkg    string
	Name   string
	Status string  // PASS | FAIL | SKIP
	Dur    float64 // seconds
	Output string  // captured output for FAIL tests
}

type pkgResult struct {
	Pkg    string
	Status string // ok | FAIL | skip | no-tests | build-error
	Dur    float64
	Tests  []*testResult
}

type platform struct {
	Label string
	Pkgs  map[string]*pkgResult // key: package import path
}

func newPlatform(label string) *platform {
	return &platform{Label: label, Pkgs: make(map[string]*pkgResult)}
}

// ingest parses a go test -json stream and populates p.
func (p *platform) ingest(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<24)
	// Temporarily hold captured output per (pkg, test) so FAIL entries
	// carry context.
	outs := map[string]*strings.Builder{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var ev goTestEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // tolerate stray non-JSON lines
		}
		if ev.Package == "" {
			continue
		}
		pr, ok := p.Pkgs[ev.Package]
		if !ok {
			pr = &pkgResult{Pkg: ev.Package}
			p.Pkgs[ev.Package] = pr
		}
		key := ev.Package + "\x00" + ev.Test
		switch ev.Action {
		case "output":
			if ev.Test != "" {
				b := outs[key]
				if b == nil {
					b = &strings.Builder{}
					outs[key] = b
				}
				b.WriteString(ev.Output)
			}
		case "run":
			// Test starts: reserve a slot.
			if ev.Test != "" && !findTest(pr.Tests, ev.Test) {
				pr.Tests = append(pr.Tests, &testResult{Pkg: ev.Package, Name: ev.Test})
			}
		case "pass", "fail", "skip":
			status := strings.ToUpper(ev.Action)
			if ev.Test == "" {
				// Package-level event.
				pr.Status = map[string]string{"pass": "ok", "fail": "FAIL", "skip": "skip"}[ev.Action]
				pr.Dur = ev.Elapsed
			} else {
				tr := findOrAppendTest(pr, ev.Test)
				tr.Status = status
				tr.Dur = ev.Elapsed
				if status == "FAIL" {
					if b, ok := outs[key]; ok {
						tr.Output = b.String()
					}
				}
				delete(outs, key)
			}
		}
	}
	// Packages with no explicit package-level pass/fail event fall through
	// to here. If at least one test ran and none failed, treat as ok
	// (common when go test -json is consumed alongside other output and
	// the trailing package event is swallowed). Only mark as build-error
	// when no tests ran at all AND there are still no test slots — that
	// indicates compilation or linker failure.
	for _, pr := range p.Pkgs {
		if pr.Status != "" {
			continue
		}
		if len(pr.Tests) == 0 {
			pr.Status = "no-tests"
			continue
		}
		anyFail := false
		anyPass := false
		for _, tr := range pr.Tests {
			switch tr.Status {
			case "FAIL":
				anyFail = true
			case "PASS":
				anyPass = true
			}
		}
		switch {
		case anyFail:
			pr.Status = "FAIL"
		case anyPass:
			pr.Status = "ok"
		default:
			pr.Status = "build-error"
		}
	}
	return sc.Err()
}

func findTest(ts []*testResult, name string) bool {
	for _, t := range ts {
		if t.Name == name {
			return true
		}
	}
	return false
}

func findOrAppendTest(pr *pkgResult, name string) *testResult {
	for _, t := range pr.Tests {
		if t.Name == name {
			return t
		}
	}
	t := &testResult{Pkg: pr.Pkg, Name: name}
	pr.Tests = append(pr.Tests, t)
	return t
}

// -------------------------------------------------------------------
// Report rendering

type tally struct {
	pkgs, tests, passed, failed, skipped, buildErr int
}

func (p *platform) tally() tally {
	t := tally{}
	for _, pr := range p.Pkgs {
		t.pkgs++
		if pr.Status == "build-error" {
			t.buildErr++
		}
		for _, tr := range pr.Tests {
			t.tests++
			switch tr.Status {
			case "PASS":
				t.passed++
			case "FAIL":
				t.failed++
			case "SKIP":
				t.skipped++
			}
		}
	}
	return t
}

func sortedPkgs(p *platform) []*pkgResult {
	out := make([]*pkgResult, 0, len(p.Pkgs))
	for _, pr := range p.Pkgs {
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pkg < out[j].Pkg })
	return out
}

func renderText(w io.Writer, plats []*platform, failOnly bool) {
	fmt.Fprintln(w, strings.Repeat("=", 78))
	fmt.Fprintln(w, "  maldev — test-report")
	fmt.Fprintln(w, strings.Repeat("=", 78))

	// Per-platform sections.
	for _, p := range plats {
		t := p.tally()
		fmt.Fprintf(w, "\n[%s]  packages=%d  tests=%d  passed=%d  failed=%d  skipped=%d  build-err=%d\n",
			p.Label, t.pkgs, t.tests, t.passed, t.failed, t.skipped, t.buildErr)
		fmt.Fprintln(w, strings.Repeat("-", 78))
		for _, pr := range sortedPkgs(p) {
			pass, fail, skip := 0, 0, 0
			for _, tr := range pr.Tests {
				switch tr.Status {
				case "PASS":
					pass++
				case "FAIL":
					fail++
				case "SKIP":
					skip++
				}
			}
			mark := "✓"
			if pr.Status == "FAIL" || fail > 0 {
				mark = "✗"
			} else if pr.Status == "build-error" {
				mark = "⚠"
			} else if pr.Status == "no-tests" {
				mark = "·"
			} else if pr.Status == "skip" {
				mark = "-"
			}
			fmt.Fprintf(w, "  %s %-60s  %3dP %2dF %2dS  (%s)\n",
				mark, shorten(pr.Pkg, 60), pass, fail, skip, pr.Status)
		}
	}

	// Failing-tests detail.
	fmt.Fprintln(w, "\n"+strings.Repeat("=", 78))
	fmt.Fprintln(w, "  Failures (per test)")
	fmt.Fprintln(w, strings.Repeat("=", 78))
	anyFail := false
	for _, p := range plats {
		for _, pr := range sortedPkgs(p) {
			for _, tr := range pr.Tests {
				if tr.Status != "FAIL" {
					continue
				}
				anyFail = true
				fmt.Fprintf(w, "\n[%s] %s.%s  (%.2fs)\n", p.Label, pr.Pkg, tr.Name, tr.Dur)
				out := strings.TrimRight(tr.Output, "\n")
				if out != "" {
					for _, line := range strings.Split(out, "\n") {
						fmt.Fprintf(w, "    | %s\n", line)
					}
				}
			}
		}
	}
	if !anyFail {
		fmt.Fprintln(w, "\n  (none)")
	}

	// Cross-platform matrix for packages present in multiple platforms.
	if len(plats) > 1 {
		fmt.Fprintln(w, "\n"+strings.Repeat("=", 78))
		fmt.Fprintln(w, "  Cross-platform matrix (per package)")
		fmt.Fprintln(w, strings.Repeat("=", 78))
		// Union of package paths.
		set := map[string]bool{}
		for _, p := range plats {
			for k := range p.Pkgs {
				set[k] = true
			}
		}
		var keys []string
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		header := fmt.Sprintf("  %-62s", "package")
		for _, p := range plats {
			header += fmt.Sprintf("  %-10s", p.Label)
		}
		fmt.Fprintln(w, header)
		fmt.Fprintln(w, "  "+strings.Repeat("-", 60+12*len(plats)))
		for _, k := range keys {
			row := fmt.Sprintf("  %-62s", shorten(k, 62))
			for _, p := range plats {
				pr, ok := p.Pkgs[k]
				if !ok {
					row += fmt.Sprintf("  %-10s", "—")
					continue
				}
				pass, fail, _ := countStatus(pr)
				if pr.Status == "build-error" {
					row += fmt.Sprintf("  %-10s", "buildErr")
				} else if fail > 0 {
					row += fmt.Sprintf("  %-10s", fmt.Sprintf("%dF/%dP", fail, pass))
				} else if pass > 0 {
					row += fmt.Sprintf("  %-10s", fmt.Sprintf("%dP", pass))
				} else {
					row += fmt.Sprintf("  %-10s", "—")
				}
			}
			fmt.Fprintln(w, row)
		}
	}

	// Grand summary.
	fmt.Fprintln(w, "\n"+strings.Repeat("=", 78))
	fmt.Fprintln(w, "  Grand summary")
	fmt.Fprintln(w, strings.Repeat("=", 78))
	var tot tally
	for _, p := range plats {
		t := p.tally()
		fmt.Fprintf(w, "  %-10s  packages=%-3d tests=%-4d  %3dP  %3dF  %3dS  (%d buildErr)\n",
			p.Label, t.pkgs, t.tests, t.passed, t.failed, t.skipped, t.buildErr)
		tot.pkgs += t.pkgs
		tot.tests += t.tests
		tot.passed += t.passed
		tot.failed += t.failed
		tot.skipped += t.skipped
		tot.buildErr += t.buildErr
	}
	fmt.Fprintln(w, "  "+strings.Repeat("-", 76))
	fmt.Fprintf(w, "  %-10s  packages=%-3d tests=%-4d  %3dP  %3dF  %3dS  (%d buildErr)\n",
		"TOTAL", tot.pkgs, tot.tests, tot.passed, tot.failed, tot.skipped, tot.buildErr)
	if tot.failed == 0 && tot.buildErr == 0 {
		fmt.Fprintln(w, "\n  OVERALL: PASS")
	} else {
		fmt.Fprintln(w, "\n  OVERALL: FAIL")
	}
}

func countStatus(pr *pkgResult) (pass, fail, skip int) {
	for _, tr := range pr.Tests {
		switch tr.Status {
		case "PASS":
			pass++
		case "FAIL":
			fail++
		case "SKIP":
			skip++
		}
	}
	return
}

func shorten(s string, max int) string {
	const prefix = "github.com/oioio-space/maldev/"
	s = strings.TrimPrefix(s, prefix)
	if len(s) > max {
		s = "..." + s[len(s)-max+3:]
	}
	return s
}

// -------------------------------------------------------------------
// CLI

func main() {
	var inputs stringFlag
	flag.Var(&inputs, "in", "LABEL=PATH (repeatable)")
	outPath := flag.String("out", "", "write report to file (default stdout)")
	format := flag.String("format", "text", "text (only format supported for now)")
	failOnly := flag.Bool("fail-only", false, "list only failing tests in details")
	flag.Parse()

	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "test-report: need at least one -in LABEL=PATH")
		os.Exit(2)
	}
	var plats []*platform
	for _, s := range inputs {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "test-report: bad -in value %q (want LABEL=PATH)\n", s)
			os.Exit(2)
		}
		f, err := os.Open(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "test-report: open %s: %v\n", parts[1], err)
			os.Exit(2)
		}
		p := newPlatform(parts[0])
		if err := p.ingest(f); err != nil {
			fmt.Fprintf(os.Stderr, "test-report: ingest %s: %v\n", parts[1], err)
		}
		_ = f.Close()
		plats = append(plats, p)
	}
	var out io.Writer = os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test-report: create %s: %v\n", *outPath, err)
			os.Exit(2)
		}
		defer f.Close()
		out = f
	}
	_ = *format
	renderText(out, plats, *failOnly)

	anyFail := false
	for _, p := range plats {
		t := p.tally()
		if t.failed > 0 || t.buildErr > 0 {
			anyFail = true
		}
	}
	if anyFail {
		os.Exit(1)
	}
}

// stringFlag is a repeatable string flag.
type stringFlag []string

func (s *stringFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringFlag) Set(v string) error { *s = append(*s, v); return nil }
