//go:build windows

// cleanup-suite — panorama 10 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/cleanup/ads.md         — NTFS Alternate Data Streams
//   - docs/techniques/cleanup/timestomp.md   — MFT timestamp rewrite
//   - docs/techniques/cleanup/memory-wipe.md — SecureZero
//
// Skips selfdelete on purpose — it would terminate the process and break
// the matrix runner. The other three are bounded operations that leave
// the host clean (each Write/Set is paired with a check + cleanup).
//
// Tests anti-forensic primitives. Most should work for any user that
// has write access to the target file: the matrix should show admin +
// lowuser parity for files in C:\Users\Public\maldev (the scratch dir
// the provisioning script grants to lowuser).
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oioio-space/maldev/cleanup/ads"
	"github.com/oioio-space/maldev/cleanup/memory"
	"github.com/oioio-space/maldev/cleanup/timestomp"
)

func main() {
	// Use the lowuser-writable scratch dir provisioned by the runner so
	// admin and lowuser exercise the same path.
	dir := `C:\Users\Public\maldev`
	host := filepath.Join(dir, "carrier.bin")

	// Carrier file: tiny, write fresh each run.
	if err := os.WriteFile(host, []byte("decoy"), 0o644); err != nil {
		fmt.Printf("create carrier: %v\n", err)
		return
	}
	defer os.Remove(host)

	// 1. ADS round-trip (ads.md "Simple"): write → read → list → delete.
	fmt.Printf("=== ADS ===\n")
	payload := []byte("c2=1.2.3.4")
	if err := ads.Write(host, "config", payload); err != nil {
		fmt.Printf("ads.Write: %v\n", err)
	} else {
		fmt.Printf("ads.Write: OK (%d bytes)\n", len(payload))
	}
	if got, err := ads.Read(host, "config"); err != nil {
		fmt.Printf("ads.Read: %v\n", err)
	} else if !bytes.Equal(got, payload) {
		fmt.Printf("ads.Read: MISMATCH got=%q want=%q\n", got, payload)
	} else {
		fmt.Printf("ads.Read: OK round-trip\n")
	}
	if streams, err := ads.List(host); err != nil {
		fmt.Printf("ads.List: %v\n", err)
	} else {
		fmt.Printf("ads.List: %v\n", streams)
	}
	if err := ads.Delete(host, "config"); err != nil {
		fmt.Printf("ads.Delete: %v\n", err)
	} else {
		fmt.Printf("ads.Delete: OK\n")
	}

	// 2. Timestomp (timestomp.md "Simple"): rewrite mtime + atime to look
	//    5 years old, then verify via os.Stat.
	fmt.Printf("\n=== Timestomp ===\n")
	old := time.Now().Add(-5 * 365 * 24 * time.Hour)
	if err := timestomp.Set(host, old, old); err != nil {
		fmt.Printf("timestomp.Set: %v\n", err)
	} else {
		fmt.Printf("timestomp.Set: OK\n")
	}
	if info, err := os.Stat(host); err == nil {
		delta := time.Since(info.ModTime()).Round(24 * time.Hour)
		fmt.Printf("file mtime now reads as %v in the past\n", delta)
	}

	// 3. SecureZero (memory-wipe.md "Simple"): wipe a key buffer in place.
	fmt.Printf("\n=== Memory wipe ===\n")
	key := []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
	memory.SecureZero(key)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	fmt.Printf("memory.SecureZero: zeroed=%v\n", allZero)
}
