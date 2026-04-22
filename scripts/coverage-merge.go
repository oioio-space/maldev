//go:build ignore

// coverage-merge ingests multiple `go test -coverprofile` outputs and emits:
//   - a merged profile on stdout (or -out), with per-block hit counts as the
//     max across inputs (so "covered on any platform" wins),
//   - a Markdown summary on -report: per-package %, function-level gaps, and
//     a priority list of packages with the most uncovered code.
//
// Usage:
//
//	go run scripts/coverage-merge.go -report ignore/coverage/report.md \
//	    ignore/coverage/cover-linux-host.out \
//	    ignore/coverage/win10/cover.out \
//	    ignore/coverage/ubuntu20.04-/cover.out
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// block is one `filename:startLine.startCol,endLine.endCol numStmts count` row.
type block struct {
	key   string // "file:start.col,end.col" — identifies the region
	stmts int
	count int
}

type profile struct {
	mode   string
	blocks map[string]*block
}

func main() {
	var (
		outPath    = flag.String("out", "ignore/coverage/cover-merged.out", "output path for merged profile")
		reportPath = flag.String("report", "ignore/coverage/report.md", "output path for Markdown report")
	)
	flag.Parse()
	inputs := flag.Args()
	if len(inputs) == 0 {
		die("at least one input profile is required")
	}

	merged := &profile{blocks: map[string]*block{}}
	for _, p := range inputs {
		if err := merged.ingest(p); err != nil {
			die("ingest %s: %v", p, err)
		}
	}
	if merged.mode == "" {
		merged.mode = "atomic"
	}

	if err := merged.writeProfile(*outPath); err != nil {
		die("write merged: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote merged profile: %s (%d blocks)\n", *outPath, len(merged.blocks))

	if err := writeReport(*reportPath, *outPath, inputs); err != nil {
		die("write report: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote report: %s\n", *reportPath)
}

func (m *profile) ingest(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<24)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				mode := strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
				if m.mode == "" {
					m.mode = mode
				}
				continue
			}
		}
		if line == "" {
			continue
		}
		// "file:start.col,end.col numStmts count"
		lastSpace := strings.LastIndexByte(line, ' ')
		if lastSpace < 0 {
			continue
		}
		countStr := line[lastSpace+1:]
		rest := line[:lastSpace]
		penulSpace := strings.LastIndexByte(rest, ' ')
		if penulSpace < 0 {
			continue
		}
		stmtsStr := rest[penulSpace+1:]
		key := rest[:penulSpace]
		count := atoi(countStr)
		stmts := atoi(stmtsStr)
		if b, ok := m.blocks[key]; ok {
			if count > b.count {
				b.count = count
			}
		} else {
			m.blocks[key] = &block{key: key, stmts: stmts, count: count}
		}
	}
	return sc.Err()
}

func (m *profile) writeProfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "mode: %s\n", m.mode)
	keys := make([]string, 0, len(m.blocks))
	for k := range m.blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := m.blocks[k]
		fmt.Fprintf(w, "%s %d %d\n", b.key, b.stmts, b.count)
	}
	return w.Flush()
}

// writeReport runs `go tool cover -func=<merged>` and formats a Markdown
// summary. The tool gives us file:line:func:pct per function, which we bucket
// by package.
func writeReport(reportPath, mergedPath string, sources []string) error {
	out, err := exec.Command("go", "tool", "cover", "-func="+mergedPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("go tool cover: %v\n%s", err, out)
	}

	type funcCov struct {
		file, fn string
		pct      float64
	}
	pkgFuncs := map[string][]funcCov{}
	var totalPct float64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Two formats:
		//   "file.go:line:\tfunction\tpct%"
		//   "total:\t(statements)\tpct%"
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pctStr := fields[len(fields)-1]
		pctStr = strings.TrimSuffix(pctStr, "%")
		pct := atoFloat(pctStr)
		if strings.HasPrefix(fields[0], "total:") {
			totalPct = pct
			continue
		}
		fileLoc := fields[0]          // e.g. github.com/.../pkg/file.go:12:
		fn := strings.Join(fields[1:len(fields)-1], " ")
		pkg := packageFromFileLoc(fileLoc)
		pkgFuncs[pkg] = append(pkgFuncs[pkg], funcCov{file: fileLoc, fn: fn, pct: pct})
	}

	type pkgStat struct {
		name       string
		funcs      int
		avg        float64
		uncovered  []funcCov
	}
	var stats []pkgStat
	for pkg, fs := range pkgFuncs {
		sum := 0.0
		var unc []funcCov
		for _, f := range fs {
			sum += f.pct
			if f.pct == 0 {
				unc = append(unc, f)
			}
		}
		stats = append(stats, pkgStat{
			name:      pkg,
			funcs:     len(fs),
			avg:       sum / float64(len(fs)),
			uncovered: unc,
		})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].avg < stats[j].avg })

	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# maldev — consolidated coverage report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Overall statement coverage:** %.2f%%\n\n", totalPct)
	fmt.Fprintln(w, "Sources merged:")
	for _, s := range sources {
		fmt.Fprintf(w, "- `%s`\n", s)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Per-package coverage (ascending)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Package | Funcs | Avg % | Uncovered funcs |")
	fmt.Fprintln(w, "| --- | ---: | ---: | ---: |")
	for _, s := range stats {
		fmt.Fprintf(w, "| %s | %d | %.1f | %d |\n", s.name, s.funcs, s.avg, len(s.uncovered))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Gap list (0%-covered functions)")
	fmt.Fprintln(w)
	for _, s := range stats {
		if len(s.uncovered) == 0 {
			continue
		}
		fmt.Fprintf(w, "### %s (%d uncovered)\n", s.name, len(s.uncovered))
		for _, fc := range s.uncovered {
			fmt.Fprintf(w, "- `%s` — %s\n", fc.fn, fc.file)
		}
		fmt.Fprintln(w)
	}
	return w.Flush()
}

func packageFromFileLoc(s string) string {
	// s looks like "github.com/.../pkg/file.go:12:"
	s = strings.TrimSuffix(s, ":")
	// Strip trailing ":line" if present.
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i > 0 {
		return s[:i]
	}
	return s
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func atoFloat(s string) float64 {
	// Minimal fixed-point parser; avoids strconv dep just for symmetry.
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	dot := strings.IndexByte(s, '.')
	var whole, frac int
	var fracDigits int
	if dot < 0 {
		whole = atoi(s)
	} else {
		whole = atoi(s[:dot])
		frac = atoi(s[dot+1:])
		fracDigits = len(s[dot+1:])
	}
	f := float64(whole)
	if fracDigits > 0 {
		scale := 1.0
		for i := 0; i < fracDigits; i++ {
			scale *= 10
		}
		f += float64(frac) / scale
	}
	if neg {
		f = -f
	}
	return f
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "coverage-merge: "+format+"\n", args...)
	os.Exit(1)
}
