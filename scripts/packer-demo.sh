#!/usr/bin/env bash
# packer-demo.sh — operator playground for the packer elevation tour.
#
# Builds a 12-byte exit42 shellcode payload + packs it 4 ways:
#   1. raw min-ELF                            (transform.BuildMinimalELF64)
#   2. all-asm bundle wrap                    (packer.WrapBundleAsExecutableLinux)
#   3. Go launcher (memfd+execve dispatch)    (cmd/bundle-launcher)
#   4. Go launcher reflective in-process      (cmd/bundle-launcher + MALDEV_REFLECTIVE=1)
#
# For each: prints size + avg entropy (via cmd/packer-vis) + runs the
# binary + reports the exit code.
#
# Linux x86-64 only. No setup required beyond the maldev source tree
# itself; everything builds from go modules.

set -eu  # no -o pipefail: tolerate `… | head -N` truncation

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIR="$(mktemp -d -t packer-demo.XXXXXX)"
trap 'rm -rf "$DIR"' EXIT

cyan()   { printf '\033[36m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
dim()    { printf '\033[2m%s\033[0m' "$*"; }

banner() { printf '\n%s\n%s\n' "$(yellow "── $1 ──")" "$(dim "$(printf '%.0s─' $(seq ${#1}))────────")"; }

# ── Build helpers ─────────────────────────────────────────────────

banner "Building tooling (cmd/packer, cmd/bundle-launcher, cmd/packer-vis)"
go build -o "$DIR/packer"      ./cmd/packer
go build -o "$DIR/launcher"    ./cmd/bundle-launcher
go build -o "$DIR/packer-vis"  ./cmd/packer-vis
echo "$(dim "  → $DIR")"

# ── Fixture: exit42 shellcode + tiny min-ELF ──────────────────────

banner "Variant 1 — raw min-ELF (transform.BuildMinimalELF64)"
cat >"$DIR/build-rawmin.go" <<'EOF'
package main

import (
	"os"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

var exit42 = []byte{
	0x31, 0xff,                   // xor edi, edi
	0x40, 0xb7, 0x2a,             // mov dil, 42
	0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
	0x0f, 0x05,                   // syscall
}

func main() {
	out, err := transform.BuildMinimalELF64(exit42)
	if err != nil { panic(err) }
	if err := os.WriteFile(os.Args[1], out, 0o755); err != nil { panic(err) }
}
EOF
go run "$DIR/build-rawmin.go" "$DIR/v1-raw"

# Two bundle blobs — one for each runtime model, since they differ on
# what counts as a 'payload':
#   - all-asm wrap JMPs into raw bytes → payload = bare shellcode (12 B)
#   - Go launcher execve's the payload → payload = a real ELF (the
#     min-ELF from variant 1 wrapping the same shellcode, 132 B)

cat >"$DIR/build-bundle.go" <<'EOF'
package main

import (
	"os"

	"github.com/oioio-space/maldev/pe/packer"
)

func main() {
	payload, err := os.ReadFile(os.Args[1])
	if err != nil { panic(err) }
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: payload,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil { panic(err) }
	if err := os.WriteFile(os.Args[2], bundle, 0o644); err != nil { panic(err) }
}
EOF

# Bundle for the all-asm path: raw shellcode payload.
printf '\x31\xff\x40\xb7\x2a\xb8\x3c\x00\x00\x00\x0f\x05' > "$DIR/exit42.bin"
go run "$DIR/build-bundle.go" "$DIR/exit42.bin"  "$DIR/bundle-shellcode.bin"
# Bundle for the Go-launcher path: variant-1's min-ELF as payload.
go run "$DIR/build-bundle.go" "$DIR/v1-raw"      "$DIR/bundle-elf.bin"

banner "Variant 2 — all-asm bundle wrap (packer.WrapBundleAsExecutableLinux)"
cat >"$DIR/build-allasm.go" <<'EOF'
package main

import (
	"os"

	"github.com/oioio-space/maldev/pe/packer"
)

func main() {
	bundle, err := os.ReadFile(os.Args[1])
	if err != nil { panic(err) }
	out, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil { panic(err) }
	if err := os.WriteFile(os.Args[2], out, 0o755); err != nil { panic(err) }
}
EOF
go run "$DIR/build-allasm.go" "$DIR/bundle-shellcode.bin" "$DIR/v2-allasm"

banner "Variant 3 — Go launcher (memfd + execve)"
"$DIR/packer" bundle -wrap "$DIR/launcher" -bundle "$DIR/bundle-elf.bin" -out "$DIR/v3-go" 2>/dev/null
chmod +x "$DIR/v3-go"

banner "Variant 4 — Go launcher (in-process reflective load)"
# Same launcher binary; runtime knob via MALDEV_REFLECTIVE=1. The
# reflective path needs a static-PIE ELF with proper PT_LOADs — our
# min-ELF doesn't carry one (single PT_LOAD covering the whole file
# is enough for direct execve, but the reflective loader expects
# Phase-1f-shaped static-PIE). So variant 4 is informational —
# expected to fail unless the payload is a Go static-PIE.
cp "$DIR/v3-go" "$DIR/v4-reflective"

# ── Run + report ──────────────────────────────────────────────────

banner "Side-by-side"

run_variant() {
	local label="$1" path="$2" extra_env="${3:-}"
	local size avg
	size=$(stat -c%s "$path")
	avg=$("$DIR/packer-vis" entropy "$path" 2>/dev/null \
		| grep -oE 'avg entropy [0-9.]+' \
		| awk '{print $3}')
	# Run and capture exit code; use timeout as safety net.
	local exit_code=0
	if [ -n "$extra_env" ]; then
		env $extra_env timeout 5s "$path" >/dev/null 2>&1 || exit_code=$?
	else
		timeout 5s "$path" >/dev/null 2>&1 || exit_code=$?
	fi
	printf "  %s  %s\n" "$(cyan "$label")" "$(dim "(${size} bytes, avg entropy ${avg:-0.00} bits/byte)")"
	printf "    exit: %d %s\n" "$exit_code" \
		"$(if [ "$exit_code" = 42 ]; then echo "$(dim "← payload fired ✓")"; \
		   elif [ "$exit_code" = 0 ]; then echo "$(dim "← clean exit")"; \
		   else echo "$(dim "← unexpected")"; fi)"
}

run_variant "1. raw min-ELF             " "$DIR/v1-raw"
run_variant "2. all-asm bundle wrap     " "$DIR/v2-allasm"
run_variant "3. Go launcher (memfd)     " "$DIR/v3-go"
run_variant "4. Go launcher (reflective)" "$DIR/v4-reflective" "MALDEV_REFLECTIVE=1"

banner "packerscope round-trip"
"$DIR/packer-vis" bundle "$DIR/bundle-shellcode.bin" 2>/dev/null | head -8
echo ""
go build -o "$DIR/packerscope" ./cmd/packerscope
"$DIR/packerscope" detect "$DIR/v2-allasm"
"$DIR/packerscope" detect "$DIR/v3-go"

echo
echo "$(dim "All artefacts under $DIR (auto-cleaned on exit).")"
echo "$(dim "Doc walkthrough: docs/examples/packer-elevation-tour.md")"
