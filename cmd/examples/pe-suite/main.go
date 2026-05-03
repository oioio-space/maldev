//go:build windows

// pe-suite — panorama 11 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/pe/imports.md           — imports.List
//   - docs/techniques/pe/strip-sanitize.md    — strip.Sanitize
//   - docs/techniques/pe/certificate-theft.md — cert.Has + cert.Read
//   - docs/techniques/pe/pe-to-shellcode.md   — srdi.ConvertFile
//
// PE manipulation is parse-only or transform-on-bytes — no privileged
// syscalls. The matrix should show admin/lowuser parity since both
// can read C:\Windows\System32\notepad.exe (a world-readable signed
// PE that exists on every Windows install).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oioio-space/maldev/pe/cert"
	"github.com/oioio-space/maldev/pe/imports"
	"github.com/oioio-space/maldev/pe/srdi"
	"github.com/oioio-space/maldev/pe/strip"
)

func main() {
	target := `C:\Windows\System32\notepad.exe`

	// 1. imports.List (imports.md "Simple"). World-readable PE.
	fmt.Println("=== imports.List notepad.exe ===")
	if imps, err := imports.List(target); err != nil {
		fmt.Printf("List: %v\n", err)
	} else {
		fmt.Printf("List OK: %d imports\n", len(imps))
		for i, imp := range imps {
			if i >= 3 {
				break
			}
			fmt.Printf("  %s!%s\n", imp.DLL, imp.Function)
		}
	}

	// 2. cert.Has + cert.Read (certificate-theft.md API). Signed system PE
	//    must report Has=true; lowuser should read it just fine because the
	//    Authenticode signature lives in the file's overlay.
	fmt.Println("\n=== cert.Has + Read notepad.exe ===")
	if has, err := cert.Has(target); err != nil {
		fmt.Printf("Has: %v\n", err)
	} else {
		fmt.Printf("Has: %v\n", has)
	}
	if c, err := cert.Read(target); err != nil {
		fmt.Printf("Read: %v\n", err)
	} else if c == nil {
		fmt.Printf("Read: nil cert\n")
	} else {
		fmt.Printf("Read: OK\n")
	}

	// 3. strip.Sanitize on a buffer the example owns (writeable scratch
	//    dir under Users\Public\maldev — already provisioned for lowuser).
	fmt.Println("\n=== strip.Sanitize ===")
	raw, err := os.ReadFile(target)
	if err != nil {
		fmt.Printf("read source: %v\n", err)
	} else {
		clean := strip.Sanitize(raw)
		out := filepath.Join(`C:\Users\Public\maldev`, "panorama11-sanitized.exe")
		if err := os.WriteFile(out, clean, 0o644); err != nil {
			fmt.Printf("write sanitized: %v\n", err)
		} else {
			delta := len(raw) - len(clean)
			fmt.Printf("Sanitize OK: in=%d out=%d delta=%d\n", len(raw), len(clean), delta)
			os.Remove(out)
		}
	}

	// 4. srdi.ConvertFile (pe-to-shellcode.md "Simple"). Pure transform.
	fmt.Println("\n=== srdi.ConvertFile (PE → shellcode) ===")
	cfg := srdi.DefaultConfig()
	if sc, err := srdi.ConvertFile(target, cfg); err != nil {
		fmt.Printf("ConvertFile: %v\n", err)
	} else {
		fmt.Printf("ConvertFile OK: %d bytes of position-independent code\n", len(sc))
	}
}
