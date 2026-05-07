// Command packer is a thin CLI wrapper around
// [github.com/oioio-space/maldev/pe/packer].
//
// Usage:
//
//	packer pack   -in <file> -out <file> [-key <hex32>] [-keyout <file>]
//	              [-format blob|windows-exe] [-rounds N] [-seed S]
//	packer unpack -in <file> -out <file>  -key <hex32>
//
// pack:
//   - reads `-in`,
//   - when -format=blob (default): runs Pack with default options
//     (AES-GCM, no compression) and writes the encrypted blob to
//     `-out`, printing the AEAD key to stdout as hex (or to
//     `-keyout` when set).
//   - when -format=windows-exe (Phase 1e-A): runs PackBinary, writes
//     a runnable PE32+ to `-out`, and prints the RC4 key to stdout.
//     Use -rounds (default 3) and -seed (default 0 = crypto-random)
//     to tune the polymorphic stage-1 decoder.
//
// unpack:
//   - reads `-in`,
//   - runs Unpack with the `-key` hex string,
//   - writes the recovered bytes to `-out`.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer"
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
  packer pack   -in <file> -out <file> [-format blob|windows-exe]
                [-key <hex32>] [-keyout <file>]
                [-rounds N] [-seed S]
  packer unpack -in <file> -out <file>  -key <hex32>

Formats:
  blob         (default) AES-GCM encrypted bytes; key printed as 64-char hex
  windows-exe  Phase 1e-A runnable PE32+; RC4 key printed as hex.
               -rounds (default 3) and -seed (default 0 = crypto-random)
               tune the polymorphic SGN-style stage-1 decoder.
`)
}

func runPack(args []string) int {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	in := fs.String("in", "", "input file (PE EXE or arbitrary bytes)")
	out := fs.String("out", "", "output file path")
	keyHex := fs.String("key", "", "AEAD key as 64-char hex (default: generate fresh)")
	keyOut := fs.String("keyout", "", "write the AEAD key to this file (hex); default: stdout")
	format := fs.String("format", "blob", `output format: "blob" (legacy: encrypted bytes) or "windows-exe" (Phase 1e-A: runnable PE32+)`)
	rounds := fs.Int("rounds", 3, "SGN polymorphism rounds (1-10); windows-exe only")
	seed := fs.Int64("seed", 0, "poly seed (0 = crypto-random); windows-exe only")
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
		return runPackBlob(data, *out, *keyHex, *keyOut)
	case "windows-exe":
		return runPackWindowsExe(data, *out, *rounds, *seed)
	default:
		fmt.Fprintf(os.Stderr, "pack: unknown format %q (want \"blob\" or \"windows-exe\")\n", *format)
		return 1
	}
}

// runPackBlob is the legacy encrypted-bytes path (Phase 1a/1c).
// ELF inputs are pre-flight validated against Stage C+D's Z-scope
// gate so a misconfigured build fails at pack time, not at deploy.
func runPackBlob(data []byte, out, keyHex, keyOut string) int {
	if len(data) >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
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

// runPackWindowsExe is the Phase 1e-A path: wraps the payload in a
// polymorphic PE32+ with an SGN-encoded stage-1 decoder.
// The RC4 key printed to stdout must be captured — it is NOT stored
// in the output PE.
func runPackWindowsExe(data []byte, out string, rounds int, seed int64) int {
	hostBytes, key, err := packer.PackBinary(data, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: rounds,
		Seed:         seed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: %v\n", err)
		return 1
	}
	if err := os.WriteFile(out, hostBytes, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pack: write %s: %v\n", out, err)
		return 1
	}
	// Print the key so the operator can capture it for out-of-band
	// delivery; the packed PE contains no key material.
	fmt.Printf("%x\n", key)
	fmt.Fprintf(os.Stderr, "packed %d bytes → %s (%d bytes)\n", len(data), out, len(hostBytes))
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
