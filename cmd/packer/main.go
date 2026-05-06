// Command packer is a thin CLI wrapper around
// [github.com/oioio-space/maldev/pe/packer].
//
// Usage:
//
//	packer pack   -in <file> -out <file> [-key <hex32>] [-keyout <file>]
//	packer unpack -in <file> -out <file>  -key <hex32>
//
// pack:
//   - reads `-in`,
//   - runs Pack with default options (AES-GCM, no compression),
//   - writes the blob to `-out`,
//   - prints the AEAD key to stdout as hex (or to `-keyout` when set).
//
// unpack:
//   - reads `-in`,
//   - runs Unpack with the `-key` hex string,
//   - writes the recovered bytes to `-out`.
//
// The CLI today (Phase 1a) wraps only the encrypt + embed
// pipeline. Phase 1b will add the reflective loader + a
// `pack-and-wrap` mode that emits a runnable PE.
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
  packer pack   -in <file> -out <file> [-key <hex32>] [-keyout <file>]
  packer unpack -in <file> -out <file>  -key <hex32>

The pack subcommand prints the generated AES-GCM key to stdout
(or to -keyout) as a 64-char hex string. Save it — Unpack
needs it.
`)
}

func runPack(args []string) int {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	in := fs.String("in", "", "input file (any bytes)")
	out := fs.String("out", "", "output blob path")
	keyHex := fs.String("key", "", "AEAD key as 64-char hex (default: generate fresh)")
	keyOut := fs.String("keyout", "", "write the AEAD key to this file (hex); default: stdout")
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

	// ELF inputs go through Stage C+D's Z-scope gate. Pack-time
	// pre-flight saves a deploy-and-fail cycle when the operator
	// forgot a build flag.
	if len(data) >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		if err := packer.ValidateELF(data); err != nil {
			fmt.Fprintf(os.Stderr, "packer: input is not a loadable Go static-PIE: %v\n", err)
			fmt.Fprintln(os.Stderr, "rebuild with: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w' -o <out> <pkg>")
			return 1
		}
	}

	opts := packer.Options{}
	if *keyHex != "" {
		opts.Key, err = hex.DecodeString(*keyHex)
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
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "pack: write %s: %v\n", *out, err)
		return 1
	}

	keyStr := hex.EncodeToString(key) + "\n"
	if *keyOut != "" {
		if err := os.WriteFile(*keyOut, []byte(keyStr), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "pack: write key to %s: %v\n", *keyOut, err)
			return 1
		}
	} else {
		fmt.Print(keyStr)
	}

	fmt.Fprintf(os.Stderr, "packed %d bytes → %s (%d bytes)\n", len(data), *out, len(blob))
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
