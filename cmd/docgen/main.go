// Command docgen regenerates the package-table sections of README.md,
// docs/index.md, and docs/mitre.md from each public package's doc.go.
//
// It walks `go list ./...`, parses every package's package-level comment
// for the structured fields the doc-conventions skill mandates (`# MITRE
// ATT&CK` and `# Detection level` headers), and renders three tables
// inside the canonical `<!-- BEGIN AUTOGEN: <name> --> ... <!-- END AUTOGEN:
// <name> -->` markers. Narrative content outside the markers is
// preserved.
//
// Usage:
//
//	go run ./cmd/docgen           # rewrite the autogen blocks
//	go run ./cmd/docgen --check   # exit non-zero when the autogen blocks
//	                              # would change (CI / pre-commit guard)
//
// See docs/conventions/documentation.md § Auto-generation.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	moduleRoot   = "github.com/oioio-space/maldev"
	indexPath    = "docs/index.md"
	mitrePath    = "docs/mitre.md"
	readmePath   = "README.md"
	beginByPkg   = "<!-- BEGIN AUTOGEN: package-index -->"
	endByPkg     = "<!-- END AUTOGEN: package-index -->"
	beginByMitre = "<!-- BEGIN AUTOGEN: mitre-index -->"
	endByMitre   = "<!-- END AUTOGEN: mitre-index -->"
	beginMitre   = "<!-- BEGIN AUTOGEN: mitre-table -->"
	endMitre     = "<!-- END AUTOGEN: mitre-table -->"
)

// PackageDoc is the structured view of a package's doc.go we care about.
type PackageDoc struct {
	ImportPath     string
	RelativePath   string // path under module root, e.g. "cleanup/ads"
	OneLiner       string // first sentence of package doc
	MITREIDs       []string
	DetectionLevel string
}

func main() {
	check := flag.Bool("check", false, "exit non-zero on drift instead of writing")
	flag.Parse()

	pkgs, err := loadPackages()
	if err != nil {
		die("load packages: %v", err)
	}

	pkgs = filterPublic(pkgs)
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ImportPath < pkgs[j].ImportPath })

	// README package map stays hand-curated until Phase 4; only index +
	// mitre have autogen markers today.
	targets := []string{indexPath, mitrePath}

	drift := false
	for _, path := range targets {
		changed, err := applyAutogenBlocks(path, pkgs, *check)
		if err != nil {
			die("apply %s: %v", path, err)
		}
		if changed {
			drift = true
			if *check {
				fmt.Printf("drift: %s would change\n", path)
			} else {
				fmt.Printf("updated: %s\n", path)
			}
		}
	}

	if *check && drift {
		os.Exit(1)
	}
}

// loadPackages runs `go list ./...` under both GOOS=linux and GOOS=windows
// and parses each importable package's doc.go (or first file with a package
// comment) for the structured fields. Running under both GOOSes is required
// because OS-only packages (`//go:build windows` or `//go:build linux`)
// would otherwise be invisible to whichever listing matches the host —
// dropping their MITRE / detection-level rows from the regenerated indices.
func loadPackages() ([]PackageDoc, error) {
	// `-e` so packages with stale imports (e.g. some scripts/x64dbg-harness
	// entries) don't abort the whole listing.
	listFor := func(goos string) ([]string, error) {
		cmd := exec.Command("go", "list", "-e", "-f", "{{.ImportPath}}\t{{.Dir}}", "./...")
		cmd.Env = append(os.Environ(), "GOOS="+goos)
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (GOOS=%s): %w", goos, err)
		}
		return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
	}
	// Run the two listings in parallel — independent invocations of `go list`
	// share no state and roughly halve the cold-start latency of docgen.
	type result struct {
		lines []string
		err   error
	}
	results := make(map[string]result, 2)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, goos := range []string{"linux", "windows"} {
		wg.Add(1)
		go func(goos string) {
			defer wg.Done()
			lines, err := listFor(goos)
			mu.Lock()
			results[goos] = result{lines, err}
			mu.Unlock()
		}(goos)
	}
	wg.Wait()
	// Tolerate partial failure — an EDR / sandboxed CI may refuse one GOOS
	// while the other works. Only abort if both branches failed.
	if results["linux"].err != nil && results["windows"].err != nil {
		return nil, fmt.Errorf("both go list runs failed: linux=%v, windows=%v",
			results["linux"].err, results["windows"].err)
	}
	for _, goos := range []string{"linux", "windows"} {
		if results[goos].err != nil {
			fmt.Fprintf(os.Stderr, "warn: go list GOOS=%s: %v (continuing with the other listing)\n", goos, results[goos].err)
		}
	}
	seen := map[string]bool{}
	var lines []string
	for _, goos := range []string{"linux", "windows"} {
		for _, l := range results[goos].lines {
			if !seen[l] {
				seen[l] = true
				lines = append(lines, l)
			}
		}
	}
	var pkgs []PackageDoc
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			continue
		}
		pd, err := parsePackage(fields[0], fields[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: parse %s: %v\n", fields[0], err)
			continue
		}
		pkgs = append(pkgs, pd)
	}
	return pkgs, nil
}

func parsePackage(importPath, dir string) (PackageDoc, error) {
	pd := PackageDoc{
		ImportPath:   importPath,
		RelativePath: strings.TrimPrefix(importPath, moduleRoot+"/"),
	}
	if pd.RelativePath == importPath {
		// root package
		pd.RelativePath = "."
	}

	fset := token.NewFileSet()
	// Scan files for the package-level comment. ParseDir trips on
	// build-tagged sources, so iterate manually. Prefer doc.go; skip
	// any *_test.go file (their package-level comments belong to test
	// helpers, not the documented package).
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	sort.SliceStable(files, func(i, j int) bool {
		return filepath.Base(files[i]) == "doc.go" && filepath.Base(files[j]) != "doc.go"
	})
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasSuffix(base, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ParseComments|parser.PackageClauseOnly)
		if err != nil {
			continue
		}
		if af.Doc == nil || af.Doc.Text() == "" {
			continue
		}
		text := af.Doc.Text()
		pd.OneLiner = firstSentence(text)
		pd.MITREIDs = parseMITRE(text)
		pd.DetectionLevel = parseDetectionLevel(text)
		break
	}
	return pd, nil
}

// firstSentence returns the first sentence of pkg-doc, stripping the
// "Package <name> " prefix and collapsing internal whitespace runs
// (newlines from the comment word-wrap, tabs, multi-space) to single
// spaces. The split is on `. ` or `.\n` (period followed by whitespace)
// so abbreviations like "X.509" don't truncate. If the first paragraph
// ends without a period (e.g., a lead-in colon followed by a bullet
// list), the whole paragraph is returned — that prevents bullet-list
// fragments from leaking into the index summary.
func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	// Cap the search to the first paragraph (delimited by a blank line).
	if pb := strings.Index(text, "\n\n"); pb > 0 {
		text = text[:pb]
	}
	// Find the first period followed by whitespace (or end of string).
	cut := -1
	for i := 0; i < len(text); i++ {
		if text[i] != '.' {
			continue
		}
		if i == len(text)-1 || text[i+1] == ' ' || text[i+1] == '\n' || text[i+1] == '\t' {
			cut = i
			break
		}
	}
	var s string
	if cut > 0 {
		s = text[:cut]
	} else {
		// No sentence-ending period in the first paragraph — take the
		// whole paragraph and trim a trailing colon (lead-in style).
		s = strings.TrimRight(text, " \t\n:")
	}
	if strings.HasPrefix(s, "Package ") {
		if sp := strings.Index(s[len("Package "):], " "); sp > 0 {
			s = strings.TrimSpace(s[len("Package ")+sp+1:])
		}
	}
	return collapseWhitespace(s)
}

// collapseWhitespace replaces every run of whitespace (space, tab,
// newline) with a single space — so a multi-line comment summary
// renders correctly inside a single markdown table cell.
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// canonicalDetectionLevels is the closed set declared in
// docs/conventions/documentation.md. Anything else is normalised to
// "—" so the table column stays scannable.
var canonicalDetectionLevels = map[string]bool{
	"very-quiet": true,
	"quiet":      true,
	"moderate":   true,
	"noisy":      true,
	"very-noisy": true,
}

// normalizeDetectionLevel returns one of the five canonical levels
// or "—" for umbrella packages, varies-per-subpackage docs, and
// anything that doesn't match.
func normalizeDetectionLevel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, ".,;:")
	if canonicalDetectionLevels[s] {
		return s
	}
	return "—"
}

var (
	mitreRE = regexp.MustCompile(`T\d{4}(\.\d{3})?`)
	detRE   = regexp.MustCompile(`(?im)^# Detection level\s*\n\s*\n\s*(\S+)`)
)

func parseMITRE(text string) []string {
	// Look only inside the "# MITRE ATT&CK" section if present.
	idx := strings.Index(text, "# MITRE ATT&CK")
	if idx < 0 {
		return nil
	}
	rest := text[idx:]
	end := strings.Index(rest[len("# MITRE ATT&CK"):], "\n# ")
	var section string
	if end < 0 {
		section = rest
	} else {
		section = rest[:len("# MITRE ATT&CK")+end]
	}
	hits := mitreRE.FindAllString(section, -1)
	uniq := map[string]bool{}
	var out []string
	for _, h := range hits {
		if !uniq[h] {
			uniq[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func parseDetectionLevel(text string) string {
	m := detRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// filterPublic removes packages a documentation reader doesn't browse:
// - internal/* (Go-tooling-reserved)
// - scripts/* (test harnesses)
// - cmd/* (binaries — irrelevant for a library import map)
// - pe/masquerade/preset/* and pe/masquerade/internal/* (preset blank-imports)
// - testutil/clrhost (test helper)
// - the root "." module entry (no useful one-liner, dilutes the index)
func filterPublic(pkgs []PackageDoc) []PackageDoc {
	var out []PackageDoc
	for _, p := range pkgs {
		rel := p.RelativePath
		if rel == "." ||
			strings.HasPrefix(rel, "internal/") ||
			strings.HasPrefix(rel, "scripts/") ||
			strings.HasPrefix(rel, "cmd/") ||
			strings.HasPrefix(rel, "pe/masquerade/preset/") ||
			strings.HasPrefix(rel, "pe/masquerade/internal/") ||
			rel == "testutil" ||
			rel == "testutil/clrhost" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// areaOf returns the top-level area name a package belongs to —
// the first path segment, with stand-alone Layer-0 / utility
// packages collapsed into a synthetic "_layer-0" group.
func areaOf(rel string) string {
	switch rel {
	case "crypto", "encode", "hash", "random", "useragent":
		return "_layer-0"
	case "ui":
		return "_utility"
	case "inject":
		return "inject"
	}
	if i := strings.Index(rel, "/"); i > 0 {
		return rel[:i]
	}
	return rel
}

// areaTitle is the human-facing label for an area key from areaOf.
func areaTitle(area string) string {
	switch area {
	case "_layer-0":
		return "Layer 0 — pure-Go primitives (`crypto`, `encode`, `hash`, `random`, `useragent`)"
	case "_utility":
		return "UI utilities"
	case "c2":
		return "C2 — `c2/*`"
	case "cleanup":
		return "Cleanup — `cleanup/*`"
	case "collection":
		return "Collection — `collection/*`"
	case "credentials":
		return "Credentials — `credentials/*`"
	case "evasion":
		return "Evasion — `evasion/*`"
	case "inject":
		return "Injection — `inject`"
	case "kernel":
		return "Kernel BYOVD — `kernel/driver/*`"
	case "pe":
		return "PE manipulation — `pe/*`"
	case "persistence":
		return "Persistence — `persistence/*`"
	case "privesc":
		return "Privilege escalation — `privesc/*`"
	case "process":
		return "Process — `process/*` + `process/tamper/*`"
	case "recon":
		return "Recon — `recon/*`"
	case "runtime":
		return "Runtime loaders — `runtime/*`"
	case "win":
		return "Windows primitives — `win/*`"
	default:
		return area
	}
}

// areaOrder is the canonical display order for the grouped package
// index. Areas not listed fall through to alphabetical at the end.
var areaOrder = []string{
	"_layer-0",
	"win", "kernel",
	"evasion", "inject", "pe", "runtime",
	"recon", "process", "credentials", "collection",
	"cleanup", "persistence", "privesc",
	"c2",
	"_utility",
}

// applyAutogenBlocks reads path, replaces every `<!-- BEGIN AUTOGEN: name
// -->...<!-- END AUTOGEN: name -->` block with freshly rendered content,
// and writes back if anything changed (or only reports drift in --check
// mode). Returns true when content would change.
func applyAutogenBlocks(path string, pkgs []PackageDoc, checkOnly bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	original := string(data)
	current := original

	blocks := []struct{ begin, end, body string }{
		{beginByPkg, endByPkg, renderPackageIndex(pkgs)},
		{beginByMitre, endByMitre, renderMITREIndex(pkgs)},
		{beginMitre, endMitre, renderMITRETable(pkgs)},
	}
	for _, b := range blocks {
		current = replaceBlock(current, b.begin, b.end, b.body)
	}

	if current == original {
		return false, nil
	}
	if checkOnly {
		return true, nil
	}
	return true, os.WriteFile(path, []byte(current), 0o644)
}

// replaceBlock swaps the content between begin and end markers (markers
// preserved). If markers aren't present in src, it returns src unchanged.
func replaceBlock(src, begin, end, body string) string {
	bi := strings.Index(src, begin)
	ei := strings.Index(src, end)
	if bi < 0 || ei < 0 || ei < bi {
		return src
	}
	prefix := src[:bi+len(begin)]
	suffix := src[ei:]
	return prefix + "\n" + body + "\n" + suffix
}

// --- Renderers --------------------------------------------------------------

func renderPackageIndex(pkgs []PackageDoc) string {
	// Bucket packages by area, preserving alphabetical order inside.
	byArea := map[string][]PackageDoc{}
	for _, p := range pkgs {
		a := areaOf(p.RelativePath)
		byArea[a] = append(byArea[a], p)
	}
	for a := range byArea {
		sort.Slice(byArea[a], func(i, j int) bool {
			return byArea[a][i].RelativePath < byArea[a][j].RelativePath
		})
	}
	// Drive the loop from areaOrder; trailing unknown areas alphabetised.
	rendered := map[string]bool{}
	var areas []string
	for _, a := range areaOrder {
		if _, ok := byArea[a]; ok {
			areas = append(areas, a)
			rendered[a] = true
		}
	}
	var leftover []string
	for a := range byArea {
		if !rendered[a] {
			leftover = append(leftover, a)
		}
	}
	sort.Strings(leftover)
	areas = append(areas, leftover...)

	var b bytes.Buffer
	b.WriteString("\n_Each area is collapsed by default — click to expand. Detection level is the canonical 5-level scale (`very-quiet` → `very-noisy`); umbrella / variable packages show as `—`._\n")
	for _, area := range areas {
		group := byArea[area]
		fmt.Fprintf(&b, "\n<details><summary><strong>%s</strong> — %d package%s</summary>\n\n",
			areaTitle(area), len(group), pluralS(len(group)))
		b.WriteString("| Package | Detection | Summary |\n|---|---|---|\n")
		for _, p := range group {
			det := normalizeDetectionLevel(p.DetectionLevel)
			summary := p.OneLiner
			if summary == "" {
				summary = "_(no doc.go summary)_"
			}
			fmt.Fprintf(&b, "| [`%s`](https://pkg.go.dev/%s) | %s | %s |\n",
				p.RelativePath, p.ImportPath, det, summary)
		}
		b.WriteString("\n</details>\n")
	}
	return b.String()
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func renderMITREIndex(pkgs []PackageDoc) string {
	idx := map[string][]string{} // T-ID -> rel paths
	for _, p := range pkgs {
		for _, t := range p.MITREIDs {
			idx[t] = append(idx[t], p.RelativePath)
		}
	}
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("\n| T-ID | Packages |\n|---|---|\n")
	for _, k := range keys {
		paths := idx[k]
		sort.Strings(paths)
		var links []string
		for _, p := range paths {
			links = append(links, fmt.Sprintf("[`%s`](https://pkg.go.dev/%s/%s)", p, moduleRoot, p))
		}
		fmt.Fprintf(&b, "| [%s](https://attack.mitre.org/techniques/%s/) | %s |\n",
			k, strings.ReplaceAll(k, ".", "/"), strings.Join(links, " · "))
	}
	return b.String()
}

func renderMITRETable(pkgs []PackageDoc) string {
	// Same idea but rendered for docs/mitre.md (paths relative to /docs/).
	idx := map[string][]string{}
	for _, p := range pkgs {
		for _, t := range p.MITREIDs {
			idx[t] = append(idx[t], p.RelativePath)
		}
	}
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("\n| T-ID | Packages |\n|---|---|\n")
	for _, k := range keys {
		paths := idx[k]
		sort.Strings(paths)
		var links []string
		for _, p := range paths {
			links = append(links, fmt.Sprintf("[`%s`](https://pkg.go.dev/%s/%s)", p, moduleRoot, p))
		}
		fmt.Fprintf(&b, "| [%s](https://attack.mitre.org/techniques/%s/) | %s |\n",
			k, strings.ReplaceAll(k, ".", "/"), strings.Join(links, " · "))
	}
	return b.String()
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "docgen: "+format+"\n", args...)
	os.Exit(1)
}
