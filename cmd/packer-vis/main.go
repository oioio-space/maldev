// Command packer-vis is a small introspection tool that renders
// human-readable views of packer artefacts:
//
//	packer-vis entropy <file>     # Shannon-entropy heatmap (Unicode shading + ANSI color)
//	packer-vis bundle  <bundle>   # bundle wire-format ASCII art (header + entries + data)
//
// No TUI framework, no external assets — pure stdlib + ANSI 256-color
// codes. The output is paste-friendly into terminals, READMEs, demo
// recordings.
//
// Pedagogical intent: anyone who wants to *see* what the packer does
// to a binary can run `packer-vis entropy notepad.exe` before and
// after `packer pack` and watch the .text section flip from low-
// entropy code to high-entropy ciphertext. The bundle view exposes
// the wire format byte-by-byte so the spec at
// docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md
// stops being an abstract document and becomes a thing on screen.
package main

import (
	"fmt"
	"math"
	"os"

	"github.com/oioio-space/maldev/pe/packer"
)

const usage = `packer-vis — packer artefact introspection

Usage:
  packer-vis entropy <file>                       Shannon entropy heatmap
  packer-vis compare <before> <after>             Two heatmaps stacked, with delta
  packer-vis bundle  <bundle.bin>                 Bundle wire-format viz
  packer-vis round-diff <file> [-rounds N] [-seed S]
                                                  SGN per-round byte-evolution table
  packer-vis sections <file>                      PE section table + COFF pointers
                                                  (debugging companion for the
                                                  Phase 2-F transforms — shows
                                                  Name/VA/VirtSize/RawOff/RawSize/
                                                  Char per section + COFF
                                                  PointerToSymbolTable)

Entropy heatmap reads each file in 256-byte windows, computes Shannon
entropy in bits/byte (0 = perfectly redundant, 8 = perfectly random),
and renders one row of 64 cells per 16 KiB. Each cell is a Unicode
shading character (▁▂▃▄▅▆▇█) plus an ANSI 256-color code: cool blue
= low entropy (machine code, ASCII), hot red = high entropy
(compressed / encrypted / random).

Compare stacks two heatmaps and prints their average-entropy delta —
the canonical "see what the packer did" view. Run before+after a
PackBinary call to watch the .text region flip from blue to red.

Bundle viz dumps a packer.BundleInfo as boxed ASCII art, one row
per entry, with offset / size annotations.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "entropy":
		if len(os.Args) != 3 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(runEntropy(os.Args[2]))
	case "compare":
		if len(os.Args) != 4 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(runCompare(os.Args[2], os.Args[3]))
	case "bundle":
		if len(os.Args) != 3 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(runBundleViz(os.Args[2]))
	case "round-diff":
		os.Exit(runRoundDiff(os.Args[2:]))
	case "sections":
		if len(os.Args) != 3 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(runSections(os.Args[2]))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// shadeChars are the 8 Unicode shading levels used to render entropy
// magnitude. ▁ is the lightest, █ the densest. Index = bucket of
// (entropy / 8) bits-per-byte, clamped to [0, 7].
var shadeChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// entropy256 returns the Shannon entropy in bits/byte of the given
// byte window. Range [0.0, 8.0]; 0 when all bytes equal, 8 when each
// of the 256 values appears equally often.
func entropy256(window []byte) float64 {
	if len(window) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range window {
		counts[b]++
	}
	var h float64
	n := float64(len(window))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// shadeFor maps an entropy value to a (Unicode shade, 256-color
// ANSI code) pair. The color ramp goes from cool blue (low entropy
// = code) through cyan/green/yellow to hot red (high entropy =
// random/compressed/encrypted). 256-color codes 17–196 are used as a
// path through the cube.
//
// Returns the shade rune, the foreground ANSI 256-color code, and
// the background code (chosen one step darker for legibility).
func shadeFor(h float64) (rune, int, int) {
	bucket := int(h)
	if bucket < 0 {
		bucket = 0
	}
	if bucket > 7 {
		bucket = 7
	}
	colors := []int{27, 33, 51, 46, 226, 208, 202, 196}
	bgColors := []int{17, 18, 23, 22, 100, 130, 124, 88}
	return shadeChars[bucket], colors[bucket], bgColors[bucket]
}

func runEntropy(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packer-vis entropy:", err)
		return 1
	}
	fmt.Printf("\nfile: %s (%d bytes, avg entropy %.2f bits/byte)\n",
		path, len(data), averageEntropy(data))
	fmt.Println("entropy bits/byte — ▁ low (code/ASCII)   █ high (compressed/encrypted)")
	fmt.Println()
	renderHeatmap(data)
	fmt.Println()
	return 0
}

// runCompare renders two entropy heatmaps stacked, with file sizes
// and average-entropy figures printed in the gutter. Pedagogical
// payload: drop two paths in (e.g. an unpacked binary and its
// `packer pack` output), see the .text region flip from cool to hot
// while the file size grows by the stub overhead.
func runCompare(pathA, pathB string) int {
	a, err := os.ReadFile(pathA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packer-vis compare:", err)
		return 1
	}
	b, err := os.ReadFile(pathB)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packer-vis compare:", err)
		return 1
	}

	avgA := averageEntropy(a)
	avgB := averageEntropy(b)
	delta := avgB - avgA

	fmt.Println()
	fmt.Printf("  \033[1m%s\033[0m  %d bytes  avg entropy %.2f bits/byte\n", pathA, len(a), avgA)
	renderHeatmap(a)
	fmt.Println()
	fmt.Printf("  \033[1m%s\033[0m  %d bytes  avg entropy %.2f bits/byte\n", pathB, len(b), avgB)
	renderHeatmap(b)
	fmt.Println()

	sizeDelta := len(b) - len(a)
	fmt.Printf("  delta:  size %+d bytes  entropy %+.2f bits/byte", sizeDelta, delta)
	switch {
	case delta > 1.5:
		fmt.Print("   \033[31m← strong randomness gain (encryption/compression)\033[0m")
	case delta > 0.5:
		fmt.Print("   \033[33m← moderate gain\033[0m")
	case delta < -0.5:
		fmt.Print("   \033[36m← gain (after path is more redundant — odd)\033[0m")
	}
	fmt.Println()
	fmt.Println()
	return 0
}

// averageEntropy returns the mean Shannon entropy across non-empty
// 256-byte windows of the input — a single-number proxy for "how
// random does this file look".
func averageEntropy(data []byte) float64 {
	const window = 256
	if len(data) == 0 {
		return 0
	}
	var sum float64
	var n int
	for off := 0; off < len(data); off += window {
		end := off + window
		if end > len(data) {
			end = len(data)
		}
		sum += entropy256(data[off:end])
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// renderHeatmap is the entropy-heatmap rendering loop reused by both
// `entropy` and `compare`. Outputs one row of 64 cells per 16 KiB of
// input, prefixed with the file offset.
func renderHeatmap(data []byte) {
	const window = 256
	const cellsPerRow = 64
	bytesPerRow := window * cellsPerRow
	for off := 0; off < len(data); off += bytesPerRow {
		end := off + bytesPerRow
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("\033[38;5;245m%08x\033[0m  ", off)
		for c := off; c < end; c += window {
			cellEnd := c + window
			if cellEnd > end {
				cellEnd = end
			}
			h := entropy256(data[c:cellEnd])
			shade, fg, bg := shadeFor(h)
			fmt.Printf("\033[38;5;%dm\033[48;5;%dm%c\033[0m", fg, bg, shade)
		}
		fmt.Println()
	}
}

func runBundleViz(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packer-vis bundle:", err)
		return 1
	}
	info, err := packer.InspectBundle(blob)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packer-vis bundle:", err)
		return 1
	}

	const dim = "\033[2m"
	const cyan = "\033[36m"
	const yellow = "\033[33m"
	const reset = "\033[0m"

	fmt.Printf("\n  %s%s\n", cyan, path)
	fmt.Printf("  %d bytes | magic=%#x version=%#x count=%d fallback=%d%s\n\n",
		len(blob), info.Magic, info.Version, info.Count, info.FallbackBehaviour, reset)

	// Header box
	fmt.Printf("  ┌─ %sBundleHeader%s ─────────────────────────────────────┐\n", yellow, reset)
	fmt.Printf("  │ %s0x00..0x20%s  magic + version + count + offsets    │\n", dim, reset)
	fmt.Printf("  │            fpTable=%#-6x plTable=%#-6x data=%#-6x │\n",
		info.FpTableOffset, info.PayloadTableOffset, info.DataOffset)
	fmt.Println("  └────────────────────────────────────────────────────┘")

	// Per-entry rows
	for i, e := range info.Entries {
		fpOff := info.FpTableOffset + uint32(i*packer.BundleFingerprintEntrySize)
		plOff := info.PayloadTableOffset + uint32(i*packer.BundlePayloadEntrySize)
		fmt.Printf("\n  ┌─ %s[%d]%s FingerprintEntry @ %s%#x%s ────────────────────┐\n",
			yellow, i, reset, dim, fpOff, reset)
		fmt.Printf("  │ predType=%#02x  vendor=%-12q  build=[%d, %d] │\n",
			e.PredicateType, vendorOrWildcard(e), e.BuildMin, e.BuildMax)
		fmt.Println("  └────────────────────────────────────────────────────┘")
		fmt.Printf("  ┌─ %s[%d]%s PayloadEntry     @ %s%#x%s ────────────────────┐\n",
			yellow, i, reset, dim, plOff, reset)
		fmt.Printf("  │ data=%#-6x..+%-6d  plain=%-6d  cipher=XOR(16) │\n",
			e.DataRVA, e.DataSize, e.PlaintextSize)
		fmt.Println("  └────────────────────────────────────────────────────┘")
	}
	fmt.Println()
	return 0
}

func vendorOrWildcard(e packer.BundleEntryInfo) string {
	if e.PredicateType&packer.PTCPUIDVendor == 0 {
		return "*"
	}
	return string(e.VendorString[:])
}
