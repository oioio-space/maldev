// Generator for pe/masquerade/preset sub-packages.
//
// Reads each reference exe from %SystemRoot%\System32 read-only, extracts
// its .rsrc (icons + VERSIONINFO + manifest), then emits for each
// (identity x variant) tuple a sub-package containing:
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
//	go run ./pe/masquerade/internal/gen
//	go run ./pe/masquerade/internal/gen -out C:/path/to/pe/masquerade -sys32 C:/Windows/System32
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

	"github.com/oioio-space/maldev/pe/masquerade"
	"github.com/oioio-space/maldev/pe/masquerade/donors"
)

type variant struct {
	name   string
	subdir string // "" means base-level (identity root dir)
	level  masquerade.ExecLevel
}

var variants = []variant{
	{"base", "", masquerade.AsInvoker},
	{"admin", "admin", masquerade.RequireAdministrator},
}

func (v variant) desc() string {
	s := "requestedExecutionLevel=" + v.level.String()
	if v.level == masquerade.RequireAdministrator {
		s += " (prompts UAC)"
	}
	return s
}

// Donor list now lives in pe/masquerade/internal/donors so the
// cmd/cert-snapshot tool can iterate the same identities without
// duplicating the slice. Add a new identity there.

func main() {
	outRoot := flag.String("out", filepath.Join("pe", "masquerade"), "output root (should end with pe/masquerade)")
	flag.Parse()

	if *outRoot == "" {
		log.Fatal("-out required")
	}

	for _, id := range donors.All {
		exePath := os.ExpandEnv(id.Path)
		if _, err := os.Stat(exePath); err != nil {
			log.Printf("SKIP %s: %v", id.ID, err)
			continue
		}
		log.Printf("processing %s <- %s", id.ID, exePath)
		if err := generateIdentity(*outRoot, id.ID, exePath); err != nil {
			log.Printf("SKIP %s: %v", id.ID, err)
			continue
		}
	}
	log.Println("done")
}

func generateIdentity(outRoot, id, exePath string) error {
	res, err := masquerade.Extract(exePath)
	if err != nil {
		return fmt.Errorf("extract %s: %w", exePath, err)
	}

	for _, v := range variants {
		dir := filepath.Join(outRoot, "preset", id)
		if v.subdir != "" {
			dir = filepath.Join(dir, v.subdir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}

		sysoPath := filepath.Join(dir, "resource_windows_amd64.syso")
		if err := res.GenerateSyso(sysoPath, masquerade.AMD64, v.level); err != nil {
			return fmt.Errorf("generate %s: %w", sysoPath, err)
		}

		if err := writePackageFiles(dir, id, v); err != nil {
			return err
		}
		log.Printf("  wrote %s", shortPath(dir))
	}
	return nil
}

// packageName returns the Go package identifier for a given identity/variant.
// "cmd" + base -> "cmd", "cmd" + admin -> "admin".
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
		pkg, id, v.desc(), id,
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

func packageImportPath(id string, v variant) string {
	p := "github.com/oioio-space/maldev/pe/masquerade/preset/" + id
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
