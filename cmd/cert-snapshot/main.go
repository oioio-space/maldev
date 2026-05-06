// Command cert-snapshot dumps the Authenticode WIN_CERTIFICATE
// blob of every donor PE listed in
// pe/masquerade/internal/donors.All to a target directory.
//
// Operators run this once on a host that has the donors installed,
// commit the resulting `<id>.bin` blobs to a build-side directory
// (typically gitignored — these are large binaries), then graft
// onto the implant at build time without needing the donor
// available:
//
//	go run ./cmd/cert-snapshot -out ./ignore/certs
//	# later, on a different build host:
//	c, _ := os.ReadFile("./ignore/certs/claude.bin")
//	cert.Write("implant.exe", &cert.Certificate{Raw: c})
//
// The grafted signature is NOT cryptographically valid (the PE
// hash differs); this only fools static "does the file have a
// signature blob?" checks and the file-properties UI. Real
// validity needs the donor's private key, which is not on disk.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oioio-space/maldev/pe/cert"
	"github.com/oioio-space/maldev/pe/masquerade/donors"
)

func main() {
	out := flag.String("out", filepath.Join("ignore", "certs"), "output directory for <id>.bin cert blobs")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *out, err)
	}

	var ok, skipped int
	for _, d := range donors.All {
		exePath := os.ExpandEnv(d.Path)
		c, err := cert.Read(exePath)
		if err != nil {
			log.Printf("SKIP %s: %v", d.ID, err)
			skipped++
			continue
		}
		dst := filepath.Join(*out, d.ID+".bin")
		if err := os.WriteFile(dst, c.Raw, 0o644); err != nil {
			log.Fatalf("write %s: %v", dst, err)
		}
		log.Printf("wrote %s (%d bytes) <- %s", shortPath(dst), len(c.Raw), exePath)
		ok++
	}
	fmt.Printf("\ncert-snapshot: %d written, %d skipped\n", ok, skipped)
}

func shortPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	cwd, _ := os.Getwd()
	if rel, err := filepath.Rel(cwd, abs); err == nil {
		return rel
	}
	return p
}
