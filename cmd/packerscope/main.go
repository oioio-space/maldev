// Command packerscope is the defender-side companion to the maldev
// packer: it identifies, parses, and unpacks maldev bundle artefacts
// without requiring a running target.
//
// Three verbs:
//
//	packerscope detect  <file>                    What kind of maldev artefact is this?
//	packerscope dump    <file> [-secret S]        Print the full wire-format structure.
//	packerscope extract <file> [-secret S] -out D Write decrypted payloads under D/.
//
// Per Kerckhoffs: when an operator wraps with `-secret S`, packerscope
// must be invoked with the same `-secret S` to find the
// deterministically-derived BundleMagic + footer. Without the secret,
// canonical detection still works (catches operator builds that
// shipped without `-secret`), and structural heuristics flag suspicious
// shapes (single-PT_LOAD RWX ELF under 4 KiB) so a defender knows
// "this looks like a maldev all-asm bundle of unknown deployment".
//
// Pedagogical pair: every algorithm `cmd/packer` ships forward,
// `cmd/packerscope` undoes (or at least describes) backward. Operator
// or defender — the wire format is genuinely public.
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oioio-space/maldev/pe/packer"
)

const usage = `packerscope — maldev bundle artefact analyser

Usage:
  packerscope detect  <file>
  packerscope dump    <file> [-secret <s>]
  packerscope extract <file> [-secret <s>] -out <dir>

Detects whether a file is:
  - a raw bundle blob (BundleMagic at offset 0)
  - a Go-launcher wrapped bundle (footer magic at end)
  - an all-asm wrapped bundle (single-PT_LOAD-RWX ELF carrying the magic)
  - none of the above (opaque)

When -secret is supplied the per-build profile derived from that
secret replaces the canonical magics — same path operators take when
shipping with 'packer bundle -secret'.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "detect":
		os.Exit(runDetect(os.Args[2:]))
	case "dump":
		os.Exit(runDump(os.Args[2:]))
	case "extract":
		os.Exit(runExtract(os.Args[2:]))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// artefactKind enumerates the high-level shapes packerscope recognises.
type artefactKind int

const (
	kindUnknown artefactKind = iota
	kindRawBundle
	kindLauncherWrapped
	kindAllAsmWrapped
)

func (k artefactKind) String() string {
	switch k {
	case kindRawBundle:
		return "raw-bundle"
	case kindLauncherWrapped:
		return "launcher-wrapped"
	case kindAllAsmWrapped:
		return "allasm-wrapped"
	default:
		return "unknown"
	}
}

// detectionResult describes a detection outcome plus the bundle slice
// (when extractable) so dump/extract can reuse the work.
type detectionResult struct {
	Kind    artefactKind
	Bundle  []byte             // bytes that parse as a bundle (when applicable)
	Profile packer.BundleProfile
	Notes   []string           // human-readable observations
}

// detectArtefact walks the file in priority order: raw bundle (cheap),
// launcher footer (8-byte sentinel), all-asm ELF heuristic (parse PT_LOADs
// and look for the magic in the loaded segment).
func detectArtefact(blob []byte, profile packer.BundleProfile) detectionResult {
	res := detectionResult{Profile: profile}

	// 1. Raw bundle blob — magic at offset 0.
	if len(blob) >= packer.BundleHeaderSize {
		expected := profile.Magic
		if expected == 0 {
			expected = packer.BundleMagic
		}
		if got := binary.LittleEndian.Uint32(blob[0:4]); got == expected {
			res.Kind = kindRawBundle
			res.Bundle = blob
			res.Notes = append(res.Notes, fmt.Sprintf("bundle magic %#x at offset 0", got))
			return res
		}
	}

	// 2. Launcher-wrapped — read trailing 16-byte footer.
	if extracted, err := extractLauncherBundle(blob, profile); err == nil {
		res.Kind = kindLauncherWrapped
		res.Bundle = extracted
		res.Notes = append(res.Notes, "MLDV-END-style footer at end of file")
		return res
	}

	// 3. All-asm wrap — ELF shape heuristic + magic search.
	if note, bundle, ok := detectAllAsm(blob, profile); ok {
		res.Kind = kindAllAsmWrapped
		res.Bundle = bundle
		res.Notes = append(res.Notes, note)
		return res
	}

	// Structural hints when nothing matches — defender-friendly notes.
	if isTinyRWXELF(blob) {
		res.Notes = append(res.Notes, "looks like a tiny single-PT_LOAD-RWX ELF (suggestive); -secret may be needed")
	}
	return res
}

func extractLauncherBundle(blob []byte, profile packer.BundleProfile) ([]byte, error) {
	if profile.FooterMagic == ([8]byte{}) {
		return packer.ExtractBundle(blob)
	}
	return packer.ExtractBundleWith(blob, profile)
}

func detectAllAsm(blob []byte, profile packer.BundleProfile) (string, []byte, bool) {
	if !isTinyRWXELF(blob) {
		return "", nil, false
	}
	expected := profile.Magic
	if expected == 0 {
		expected = packer.BundleMagic
	}
	var magicBytes [4]byte
	binary.LittleEndian.PutUint32(magicBytes[:], expected)

	// Scan the file body for the magic — the all-asm wrap concatenates
	// stub + bundle inside a single PT_LOAD, so the magic lands at a
	// known position once we know the stub length, but we don't.
	// Cheap forward scan with strict alignment to 1 byte (the magic
	// is at the start of BundleHeader which has no alignment
	// constraint within the segment).
	idx := bytes.Index(blob, magicBytes[:])
	if idx < 0 {
		return "", nil, false
	}
	if idx+packer.BundleHeaderSize > len(blob) {
		return "", nil, false
	}
	return fmt.Sprintf("bundle magic %#x at file offset %#x", expected, idx), blob[idx:], true
}

// isTinyRWXELF returns true for ELFs that look like all-asm bundle wraps:
// 1 PT_LOAD with PF_R | PF_W | PF_X and total file size under 4 KiB.
func isTinyRWXELF(blob []byte) bool {
	if len(blob) < 4 || string(blob[0:4]) != "\x7fELF" {
		return false
	}
	if len(blob) > 4096 {
		return false
	}
	f, err := elf.NewFile(bytes.NewReader(blob))
	if err != nil {
		return false
	}
	defer f.Close()
	if len(f.Progs) != 1 {
		return false
	}
	p := f.Progs[0]
	return p.Type == elf.PT_LOAD && p.Flags == elf.PF_R|elf.PF_W|elf.PF_X
}

func runDetect(args []string) int {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	secret := fs.String("secret", "", "operator secret (optional — derives per-build profile)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	blob, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "packerscope detect:", err)
		return 1
	}
	profile := packer.BundleProfile{}
	if *secret != "" {
		profile = packer.DeriveBundleProfile([]byte(*secret))
	}
	res := detectArtefact(blob, profile)
	fmt.Printf("kind: %s\n", res.Kind)
	for _, n := range res.Notes {
		fmt.Printf("  - %s\n", n)
	}
	if res.Kind == kindUnknown {
		return 1
	}
	return 0
}

func runDump(args []string) int {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	secret := fs.String("secret", "", "operator secret")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	blob, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "packerscope dump:", err)
		return 1
	}
	profile := packer.BundleProfile{}
	if *secret != "" {
		profile = packer.DeriveBundleProfile([]byte(*secret))
	}
	res := detectArtefact(blob, profile)
	if res.Kind == kindUnknown {
		fmt.Fprintln(os.Stderr, "packerscope dump: no maldev artefact detected (try -secret if operator built with one)")
		return 1
	}

	info, err := packer.InspectBundleWith(res.Bundle, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packerscope dump: inspect failed:", err)
		return 1
	}
	fmt.Printf("artefact: %s (%d bytes)\n", res.Kind, len(blob))
	fmt.Printf("bundle:   magic=%#x version=%#x count=%d fallback=%d\n",
		info.Magic, info.Version, info.Count, info.FallbackBehaviour)
	for i, e := range info.Entries {
		vendor := "*"
		if e.PredicateType&packer.PTCPUIDVendor != 0 {
			vendor = strings.TrimRight(string(e.VendorString[:]), "\x00")
		}
		fmt.Printf("  [%d] pred=%#02x vendor=%-12q build=[%d, %d] data=%#x..+%d\n",
			i, e.PredicateType, vendor, e.BuildMin, e.BuildMax,
			e.DataRVA, e.DataSize)
	}
	return 0
}

func runExtract(args []string) int {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	secret := fs.String("secret", "", "operator secret")
	out := fs.String("out", "", "output directory (one file per payload)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "packerscope extract: -out <dir> is required")
		return 2
	}
	blob, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "packerscope extract:", err)
		return 1
	}
	profile := packer.BundleProfile{}
	if *secret != "" {
		profile = packer.DeriveBundleProfile([]byte(*secret))
	}
	res := detectArtefact(blob, profile)
	if res.Kind == kindUnknown {
		fmt.Fprintln(os.Stderr, "packerscope extract: no maldev artefact detected")
		return 1
	}
	info, err := packer.InspectBundleWith(res.Bundle, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "packerscope extract: inspect failed:", err)
		return 1
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "packerscope extract: mkdir:", err)
		return 1
	}
	for i := range info.Entries {
		plain, err := packer.UnpackBundleWith(res.Bundle, i, profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extract payload %d: %v\n", i, err)
			return 1
		}
		path := filepath.Join(*out, fmt.Sprintf("payload-%02d.bin", i))
		if err := os.WriteFile(path, plain, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			return 1
		}
		fmt.Printf("payload %02d: %d bytes → %s\n", i, len(plain), path)
	}
	return 0
}

// Sentinel for tests.
var errNoArtefact = errors.New("packerscope: no artefact")
