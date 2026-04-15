// Generator for pe/winres/masquerade sub-packages.
//
// Reads each reference exe from %SystemRoot%\System32 read-only, extracts
// its .rsrc (icons + VERSIONINFO + manifest), then emits for each
// (identity × variant) tuple a sub-package containing:
//
//	<variant>_windows.go      — empty package declaration (+ build tag)
//	<variant>_stub.go         — !windows stub
//	resource_windows_amd64.syso — COFF object linked automatically by `go build`
//
// Variants:
//
//	base   — manifest asInvoker
//	admin  — manifest requireAdministrator
//
// Usage:
//
//	go run ./pe/winres/internal/gen
//	go run ./pe/winres/internal/gen -out C:/path/to/pe/winres -sys32 C:/Windows/System32
//
// Safe on host: the reference exes are opened read-only.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tc-hib/winres"
)

type variant struct {
	name    string
	subdir  string // "" means base-level (identity root dir)
	execLvl winres.ExecutionLevel
}

var variants = []variant{
	{"base", "", winres.AsInvoker},
	{"admin", "admin", winres.RequireAdministrator},
}

// identities lists every System32 reference binary we masquerade as.
var identities = []string{
	"cmd",
	"svchost",
	"taskmgr",
	"explorer", // lives at %SystemRoot%\explorer.exe, handled as special case
	"notepad",
}

func main() {
	outRoot := flag.String("out", filepath.Join("pe", "winres"), "output root (should end with pe/winres)")
	sys32 := flag.String("sys32", os.ExpandEnv(`${SystemRoot}\System32`), "System32 path")
	winroot := flag.String("winroot", os.ExpandEnv(`${SystemRoot}`), "Windows root (for explorer.exe)")
	flag.Parse()

	if *outRoot == "" {
		log.Fatal("-out required")
	}

	for _, id := range identities {
		exePath := filepath.Join(*sys32, id+".exe")
		if id == "explorer" {
			exePath = filepath.Join(*winroot, "explorer.exe")
		}
		if _, err := os.Stat(exePath); err != nil {
			log.Printf("SKIP %s: %v", id, err)
			continue
		}
		log.Printf("processing %s <- %s", id, exePath)
		if err := generateIdentity(*outRoot, id, exePath); err != nil {
			log.Fatalf("%s: %v", id, err)
		}
	}
	log.Println("done")
}

// generateIdentity loads one reference exe and emits all variants.
func generateIdentity(outRoot, id, exePath string) error {
	f, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", exePath, err)
	}
	defer f.Close()

	rs, err := winres.LoadFromEXE(f)
	if err != nil {
		return fmt.Errorf("LoadFromEXE: %w", err)
	}

	// Keep the original AssemblyIdentity (if any) so tools that inspect the
	// manifest name see the real identity. Fall back to a synthetic one if
	// the reference exe has no manifest or it can't be parsed.
	baseManifest := winres.AppManifest{
		Identity:      winres.AssemblyIdentity{Name: id + ".exe", Version: [4]uint16{1, 0, 0, 0}},
		Compatibility: winres.Win10AndAbove,
	}
	if origBytes := rs.Get(winres.RT_MANIFEST, winres.ID(1), 0); len(origBytes) > 0 {
		if parsed, err := winres.AppManifestFromXML(origBytes); err == nil {
			baseManifest = parsed
		}
	}

	for _, v := range variants {
		dir := filepath.Join(outRoot, "masquerade", id)
		if v.subdir != "" {
			dir = filepath.Join(dir, v.subdir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}

		// Re-load rs per variant because SetManifest mutates the set.
		f2, err := os.Open(exePath)
		if err != nil {
			return err
		}
		rsCopy, err := winres.LoadFromEXE(f2)
		f2.Close()
		if err != nil {
			return err
		}

		m := baseManifest
		m.ExecutionLevel = v.execLvl
		// UIAccess MUST be false to co-exist with non-signed binaries.
		m.UIAccess = false
		rsCopy.SetManifest(m)

		sysoPath := filepath.Join(dir, "resource_windows_amd64.syso")
		if err := writeSYSO(rsCopy, sysoPath); err != nil {
			return fmt.Errorf("write %s: %w", sysoPath, err)
		}

		if err := writePackageFiles(dir, id, v); err != nil {
			return err
		}
		log.Printf("  wrote %s/{resource_windows_amd64.syso,%s_windows.go,%s_stub.go}",
			shortPath(dir), packageName(id, v), packageName(id, v))
	}
	return nil
}

func writeSYSO(rs *winres.ResourceSet, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return rs.WriteObject(f, winres.ArchAMD64)
}

// packageName returns the Go package identifier for a given identity/variant.
// "cmd" + base → "cmd", "cmd" + admin → "admin".
func packageName(id string, v variant) string {
	if v.subdir == "" {
		return id
	}
	return v.subdir
}

func writePackageFiles(dir, id string, v variant) error {
	pkg := packageName(id, v)
	goName := pkg

	// Windows-only file, carries the syso (syso file tag does the real work).
	win := fmt.Sprintf(`//go:build windows

// Package %s embeds the manifest + icons + VERSIONINFO of %s.exe
// with %s.
//
// Blank-import this package to take on the %s.exe identity:
//
//	import _ %q
//
// MITRE ATT&CK: T1036.005
package %s
`,
		pkg, id, describe(v), id,
		packageImportPath(id, v),
		pkg,
	)
	if err := os.WriteFile(filepath.Join(dir, goName+"_windows.go"), []byte(win), 0o644); err != nil {
		return err
	}

	// Cross-platform stub so the package still compiles on non-Windows.
	stub := fmt.Sprintf(`//go:build !windows

package %s
`, pkg)
	if err := os.WriteFile(filepath.Join(dir, goName+"_stub.go"), []byte(stub), 0o644); err != nil {
		return err
	}
	return nil
}

func describe(v variant) string {
	switch v.execLvl {
	case winres.RequireAdministrator:
		return "requestedExecutionLevel=requireAdministrator (prompts UAC)"
	case winres.HighestAvailable:
		return "requestedExecutionLevel=highestAvailable"
	default:
		return "requestedExecutionLevel=asInvoker"
	}
}

func packageImportPath(id string, v variant) string {
	p := "github.com/oioio-space/maldev/pe/winres/masquerade/" + id
	if v.subdir != "" {
		p += "/" + v.subdir
	}
	return p
}

func shortPath(dir string) string {
	parts := strings.Split(filepath.ToSlash(dir), "/")
	if len(parts) < 4 {
		return dir
	}
	return ".../" + strings.Join(parts[len(parts)-4:], "/")
}
