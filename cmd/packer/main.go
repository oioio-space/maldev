// Command packer is a thin CLI wrapper around
// [github.com/oioio-space/maldev/pe/packer].
//
// Usage:
//
//	packer pack   -in <file> -out <file> [-key <hex32>] [-keyout <file>]
//	              [-format blob|windows-exe|linux-elf] [-rounds N] [-seed S]
//	              [-cover]
//	packer unpack -in <file> -out <file>  -key <hex32>
//	packer bundle -out <file> -pl <spec> [-pl <spec> ...] [-fallback exit|crash|first]
//
// pack:
//   - reads `-in`,
//   - when -format=blob (default): runs Pack with default options
//     (AES-GCM, no compression) and writes the encrypted blob to
//     `-out`, printing the AEAD key to stdout as hex (or to
//     `-keyout` when set).
//   - when -format=windows-exe (Phase 1e-A): runs PackBinary, writes
//     a runnable PE32+ to `-out`, and prints the AEAD key to stdout.
//     Use -rounds (default 3) and -seed (default 0 = crypto-random)
//     to tune the polymorphic stage-1 decoder.
//   - when -format=linux-elf (Phase 1e-B): runs PackBinary, writes
//     a runnable ELF64 static-PIE to `-out`, and prints the AEAD key
//     to stdout. Same -rounds/-seed knobs as windows-exe.
//
// unpack:
//   - reads `-in`,
//   - runs Unpack with the `-key` hex string,
//   - writes the recovered bytes to `-out`.
//
// bundle (C6 multi-target wire format):
//   - takes one or more `-pl <file>:<vendor>:<min>-<max>` specs and
//     packs them into a single bundle blob. <vendor> is one of
//     "intel", "amd", or "*" (wildcard); <min>-<max> is the inclusive
//     Windows build-number range (use "*" on either side for "no
//     bound"). E.g. -pl payload-w11.exe:intel:22000-99999.
//   - -fallback selects the no-match behaviour: "exit" (default),
//     "crash", or "first".
//   - The output is the bundle blob — the runtime stub-side evaluator
//     is C6-P3/P4 work; until then operators inspect the bundle on
//     the build host via `packer bundle -inspect`.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "pack":
		os.Exit(runPack(os.Args[2:]))
	case "unpack":
		os.Exit(runUnpack(os.Args[2:]))
	case "bundle":
		os.Exit(runBundle(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `packer — maldev pe/packer CLI

Usage:
  packer pack   -in <file> -out <file> [-format blob|windows-exe|linux-elf]
                [-key <hex32>] [-keyout <file>]
                [-rounds N] [-seed S] [-cover]
  packer unpack -in <file> -out <file>  -key <hex32>
  packer bundle -out <file> -pl <spec> [-pl <spec> ...]
                [-fallback exit|crash|first]
  packer bundle -inspect <bundle>

Formats:
  blob         (default) AES-GCM encrypted bytes; key printed as 64-char hex
  windows-exe  Phase 1e-A runnable PE32+; AEAD key printed as hex.
               -rounds (default 3) and -seed (default 0 = crypto-random)
               tune the polymorphic SGN-style stage-1 decoder.
  linux-elf    Phase 1e-B runnable ELF64 static-PIE; AEAD key printed as hex.
               Same -rounds/-seed knobs as windows-exe.

Bundle spec syntax (-pl):
  <file>:<vendor>:<min>-<max>
    vendor ∈ {intel | amd | *}        (* = any vendor)
    min/max = Windows build number    (use * for "no bound")
  e.g. -pl payload-w11.exe:intel:22000-99999
       -pl payload-w10.exe:amd:10000-19999
       -pl fallback.exe:*:*-*
  Fallback behaviour: exit (silent), crash (loud), first (always payload 0).
  Note: the runtime stub-side fingerprint evaluator is C6-P3/P4 work;
  until it ships, the bundle is a build-host artefact you can inspect
  with: packer bundle -inspect <bundle>
`)
}

func runPack(args []string) int {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	in := fs.String("in", "", "input file (PE EXE or arbitrary bytes)")
	out := fs.String("out", "", "output file path")
	keyHex := fs.String("key", "", "AEAD key as 64-char hex (default: generate fresh)")
	keyOut := fs.String("keyout", "", "write the AEAD key to this file (hex); default: stdout")
	format := fs.String("format", "blob", `output format: "blob" (legacy: encrypted bytes), "windows-exe" (Phase 1e-A: runnable PE32+), "linux-elf" (Phase 1e-B: runnable ELF static-PIE)`)
	rounds := fs.Int("rounds", 3, "SGN polymorphism rounds (1-10); windows-exe and linux-elf")
	seed := fs.Int64("seed", 0, "poly seed (0 = crypto-random); windows-exe and linux-elf")
	cover := fs.Bool("cover", false, "after PackBinary, chain ApplyDefaultCover (3 junk sections of mixed entropy); windows-exe and linux-elf only")
	_ = fs.Parse(args)

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "pack: -in and -out are required")
		return 2
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: read %s: %v\n", *in, err)
		return 1
	}

	switch *format {
	case "blob":
		if *cover {
			fmt.Fprintln(os.Stderr, "pack: -cover only applies to -format=windows-exe / linux-elf")
			return 2
		}
		return runPackBlob(data, *out, *keyHex, *keyOut)
	case "windows-exe":
		return runPackBinary(data, *out, packer.FormatWindowsExe, *rounds, *seed, *cover)
	case "linux-elf":
		return runPackBinary(data, *out, packer.FormatLinuxELF, *rounds, *seed, *cover)
	default:
		fmt.Fprintf(os.Stderr, "pack: unknown format %q (want \"blob\", \"windows-exe\", or \"linux-elf\")\n", *format)
		return 1
	}
}

// runPackBlob is the legacy encrypted-bytes path (Phase 1a/1c).
// ELF inputs are pre-flight validated against Stage C+D's Z-scope
// gate so a misconfigured build fails at pack time, not at deploy.
func runPackBlob(data []byte, out, keyHex, keyOut string) int {
	if transform.DetectFormat(data) == transform.FormatELF {
		if err := packer.ValidateELF(data); err != nil {
			fmt.Fprintf(os.Stderr, "packer: input is not a loadable Go static-PIE: %v\n", err)
			fmt.Fprintln(os.Stderr, "rebuild with: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w' -o <out> <pkg>")
			return 1
		}
	}

	opts := packer.Options{}
	var err error
	if keyHex != "" {
		opts.Key, err = hex.DecodeString(keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pack: -key invalid hex: %v\n", err)
			return 2
		}
	}

	blob, key, err := packer.Pack(data, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: %v\n", err)
		return 1
	}
	if err := os.WriteFile(out, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "pack: write %s: %v\n", out, err)
		return 1
	}

	keyStr := hex.EncodeToString(key) + "\n"
	if keyOut != "" {
		if err := os.WriteFile(keyOut, []byte(keyStr), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "pack: write key to %s: %v\n", keyOut, err)
			return 1
		}
	} else {
		fmt.Print(keyStr)
	}

	fmt.Fprintf(os.Stderr, "packed %d bytes → %s (%d bytes)\n", len(data), out, len(blob))
	return 0
}

// runPackBinary wraps the payload in a polymorphic host binary via
// PackBinary. The AEAD key is printed to stdout — it is NOT stored in
// the output binary, so the caller must capture it for out-of-band
// delivery.
//
// When cover is true, the output is additionally run through
// ApplyDefaultCover. ELF inputs without PHT slack (Go static-PIE)
// surface a non-fatal warning and ship the bare PackBinary output;
// PE always succeeds because section-table slack is plentiful.
func runPackBinary(data []byte, out string, format packer.Format, rounds int, seed int64, cover bool) int {
	hostBytes, key, err := packer.PackBinary(data, packer.PackBinaryOptions{
		Format:       format,
		Stage1Rounds: rounds,
		Seed:         seed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: %v\n", err)
		return 1
	}
	finalBytes := hostBytes
	if cover {
		// Use seed+1 so the cover layer's RNG diverges from the
		// PackBinary RNG. Falling back to the bare output on the
		// PHT-slack limitation matches the worked-example flow.
		coverSeed := seed + 1
		if coverSeed == 0 {
			coverSeed = 1
		}
		covered, coverErr := packer.ApplyDefaultCover(hostBytes, coverSeed)
		switch {
		case coverErr == nil:
			finalBytes = covered
			fmt.Fprintf(os.Stderr, "cover: %d → %d bytes\n", len(hostBytes), len(covered))
		default:
			fmt.Fprintf(os.Stderr, "cover: skipped (%v)\n", coverErr)
		}
	}
	if err := os.WriteFile(out, finalBytes, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pack: write %s: %v\n", out, err)
		return 1
	}
	fmt.Printf("%x\n", key)
	fmt.Fprintf(os.Stderr, "packed %d bytes → %s (%d bytes)\n", len(data), out, len(finalBytes))
	return 0
}

func runUnpack(args []string) int {
	fs := flag.NewFlagSet("unpack", flag.ExitOnError)
	in := fs.String("in", "", "input blob path")
	out := fs.String("out", "", "recovered output path")
	keyHex := fs.String("key", "", "AEAD key as 64-char hex (required)")
	_ = fs.Parse(args)

	if *in == "" || *out == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "unpack: -in, -out, -key all required")
		return 2
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unpack: -key invalid hex: %v\n", err)
		return 2
	}

	blob, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unpack: read %s: %v\n", *in, err)
		return 1
	}
	data, err := packer.Unpack(blob, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unpack: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "unpack: write %s: %v\n", *out, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "unpacked → %s (%d bytes)\n", *out, len(data))
	return 0
}

// stringSliceFlag accumulates repeated -pl flags.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return fmt.Sprintf("%v", *s) }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

// runBundle implements `packer bundle` — C6 multi-target wire format.
//
// One -pl flag per payload, syntax: <file>:<vendor>:<min>-<max>
// where vendor ∈ {intel, amd, *} and min/max are Windows build numbers
// or "*" for "no bound on this side".
func runBundle(args []string) int {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	out := fs.String("out", "", "output bundle blob path")
	fallback := fs.String("fallback", "exit", "no-match behaviour: exit | crash | first")
	inspect := fs.String("inspect", "", "inspect an existing bundle blob and exit (path)")
	var pls stringSliceFlag
	fs.Var(&pls, "pl", "payload spec: <file>:<vendor>:<min>-<max>; repeatable")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if *inspect != "" {
		return runBundleInspect(*inspect)
	}
	if *out == "" || len(pls) == 0 {
		fmt.Fprintln(os.Stderr, "bundle: -out and at least one -pl required (or use -inspect)")
		return 2
	}

	payloads := make([]packer.BundlePayload, 0, len(pls))
	for i, spec := range pls {
		bp, err := parseBundleSpec(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bundle: -pl[%d] %q: %v\n", i, spec, err)
			return 1
		}
		payloads = append(payloads, bp)
	}

	var fb packer.BundleFallbackBehaviour
	switch *fallback {
	case "exit":
		fb = packer.BundleFallbackExit
	case "crash":
		fb = packer.BundleFallbackCrash
	case "first":
		fb = packer.BundleFallbackFirst
	default:
		fmt.Fprintf(os.Stderr, "bundle: unknown -fallback %q (want exit|crash|first)\n", *fallback)
		return 2
	}

	blob, err := packer.PackBinaryBundle(payloads, packer.BundleOptions{FallbackBehaviour: fb})
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle:", err)
		return 1
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "bundle: write:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "bundle: wrote %d bytes to %s (%d payloads, fallback=%s)\n",
		len(blob), *out, len(payloads), *fallback)
	return 0
}

// parseBundleSpec parses a `-pl <file>:<vendor>:<min>-<max>` spec.
func parseBundleSpec(spec string) (packer.BundlePayload, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) != 3 {
		return packer.BundlePayload{}, fmt.Errorf("expected <file>:<vendor>:<min>-<max>, got %d colon-separated parts", len(parts))
	}
	file, vendorStr, rangeStr := parts[0], parts[1], parts[2]

	bin, err := os.ReadFile(file)
	if err != nil {
		return packer.BundlePayload{}, fmt.Errorf("read payload: %w", err)
	}

	pred := packer.FingerprintPredicate{}
	switch strings.ToLower(vendorStr) {
	case "intel":
		copy(pred.VendorString[:], "GenuineIntel")
		pred.PredicateType |= packer.PTCPUIDVendor
	case "amd":
		copy(pred.VendorString[:], "AuthenticAMD")
		pred.PredicateType |= packer.PTCPUIDVendor
	case "*", "":
		// wildcard — leave PTCPUIDVendor unset; if range is also wildcard,
		// fall back to PTMatchAll below.
	default:
		return packer.BundlePayload{}, fmt.Errorf("vendor %q: want intel | amd | *", vendorStr)
	}

	rng := strings.SplitN(rangeStr, "-", 2)
	if len(rng) != 2 {
		return packer.BundlePayload{}, fmt.Errorf("range %q: expected <min>-<max>", rangeStr)
	}
	parseBound := func(s string) (uint32, error) {
		if s == "" || s == "*" {
			return 0, nil
		}
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("build %q: %w", s, err)
		}
		return uint32(v), nil
	}
	bMin, err := parseBound(rng[0])
	if err != nil {
		return packer.BundlePayload{}, err
	}
	bMax, err := parseBound(rng[1])
	if err != nil {
		return packer.BundlePayload{}, err
	}
	pred.BuildMin = bMin
	pred.BuildMax = bMax
	if bMin != 0 || bMax != 0 {
		pred.PredicateType |= packer.PTWinBuild
	}

	if pred.PredicateType == 0 {
		pred.PredicateType = packer.PTMatchAll
	}
	return packer.BundlePayload{Binary: bin, Fingerprint: pred}, nil
}

// runBundleInspect walks a bundle blob and prints its header + per-entry
// summary to stdout. Build-host debugging aid.
func runBundleInspect(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle inspect:", err)
		return 1
	}
	if len(blob) < packer.BundleHeaderSize {
		fmt.Fprintln(os.Stderr, "bundle inspect: file shorter than header")
		return 1
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	version := binary.LittleEndian.Uint16(blob[4:6])
	count := binary.LittleEndian.Uint16(blob[6:8])
	fpOff := binary.LittleEndian.Uint32(blob[8:12])
	plOff := binary.LittleEndian.Uint32(blob[12:16])
	dataOff := binary.LittleEndian.Uint32(blob[16:20])
	fb := binary.LittleEndian.Uint32(blob[20:24])

	fmt.Printf("bundle %s — %d bytes\n", path, len(blob))
	fmt.Printf("  magic=%#x version=%#x count=%d fb=%d\n", magic, version, count, fb)
	fmt.Printf("  fpTable=%#x plTable=%#x data=%#x\n", fpOff, plOff, dataOff)
	for i := 0; i < int(count); i++ {
		off := int(fpOff) + i*packer.BundleFingerprintEntrySize
		predType := blob[off]
		var vendor string
		if predType&packer.PTCPUIDVendor != 0 {
			vendor = strings.TrimRight(string(blob[off+4:off+16]), "\x00")
		} else {
			vendor = "*"
		}
		bMin := binary.LittleEndian.Uint32(blob[off+16 : off+20])
		bMax := binary.LittleEndian.Uint32(blob[off+20 : off+24])
		plOffI := int(plOff) + i*packer.BundlePayloadEntrySize
		dRVA := binary.LittleEndian.Uint32(blob[plOffI : plOffI+4])
		dSize := binary.LittleEndian.Uint32(blob[plOffI+4 : plOffI+8])
		fmt.Printf("  [%d] pred=%#02x vendor=%-12s build=[%d, %d] data=%#x..+%d\n",
			i, predType, vendor, bMin, bMax, dRVA, dSize)
	}
	return 0
}
