package sekurlsa

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestRealDumpDiagnostics is a v0.30.0 debug helper gated by
// MALDEV_REALDUMP=path env var. Given a real lsass minidump, it
// counts every default-template signature's matches in each of the
// six provider DLL modules' mapped bytes — telling us whether the
// signature is missing, ambiguous (multiple matches), or correctly
// pinpointed.
//
// Run: MALDEV_REALDUMP=ignore/lsass-dumps/win10-22h2-19045.dmp \
//      go test ./credentials/sekurlsa/... -run TestRealDumpDiagnostics -v
func TestRealDumpDiagnostics(t *testing.T) {
	dumpPath := os.Getenv("MALDEV_REALDUMP")
	if dumpPath == "" {
		t.Skip("set MALDEV_REALDUMP=<path> to run real-dump diagnostics")
	}

	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatalf("open dump: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	r, err := openReader(f, st.Size())
	if err != nil {
		t.Fatalf("openReader: %v", err)
	}

	// Snapshot module list as the public Result projection.
	res := &Result{
		BuildNumber:  r.systemInfo.BuildNumber,
		Architecture: archFromMinidump(r.systemInfo.ProcessorArchitecture),
		Modules:      modulesFromReader(r),
	}
	t.Logf("Build %d, %s, %d modules", res.BuildNumber, res.Architecture, len(res.Modules))

	// Per-module byte body fetch (same pattern as the walkers).
	bodyFor := func(name string) ([]byte, Module, bool) {
		m, ok := res.ModuleByName(name)
		if !ok {
			return nil, Module{}, false
		}
		body, err := r.ReadVA(m.BaseOfImage, int(m.SizeOfImage))
		if err != nil {
			t.Logf("ReadVA %s: %v", name, err)
			return nil, m, false
		}
		return body, m, true
	}

	tmpl := templateFor(res.BuildNumber)
	if tmpl == nil {
		t.Fatalf("no template for build %d", res.BuildNumber)
	}

	type probe struct {
		name    string
		modules []string
		sig     []byte
	}
	probes := []probe{
		{"LSA primary", []string{"lsasrv.dll"}, tmpl.IVPattern},
		{"MSV1_0 list head", []string{"lsasrv.dll"}, tmpl.LogonSessionListPattern},
		{"Wdigest list head", []string{"wdigest.dll"}, tmpl.WdigestListPattern},
		{"DPAPI list head", []string{"lsasrv.dll", "dpapisrv.dll"}, tmpl.DPAPIListPattern},
		{"TSPkg list head", []string{"tspkg.dll"}, tmpl.TSPkgListPattern},
		{"Kerberos list head", []string{"kerberos.dll"}, tmpl.KerberosListPattern},
	}

	for _, p := range probes {
		if len(p.sig) == 0 {
			t.Logf("%-20s: signature empty in template (provider not in default)", p.name)
			continue
		}
		hit := false
		for _, modName := range p.modules {
			body, m, ok := bodyFor(modName)
			if !ok {
				t.Logf("%-20s: module %q not in dump", p.name, modName)
				continue
			}
			count := 0
			idx := 0
			first := -1
			for {
				i := bytes.Index(body[idx:], p.sig)
				if i < 0 {
					break
				}
				if first < 0 {
					first = i
				}
				count++
				idx = i + 1
			}
			if count > 0 {
				hit = true
				t.Logf("%-20s in %-15s: %d match(es), first at module-RVA 0x%X (= VA 0x%X)",
					p.name, modName, count, first, m.BaseOfImage+uint64(first))
			} else {
				t.Logf("%-20s in %-15s: no match (%d-byte sig: %s)",
					p.name, modName, len(p.sig), hexShort(p.sig))
			}
		}
		if !hit {
			t.Logf("%-20s: NO MATCH in any candidate module", p.name)
		}
	}

}

// hexShort emits a compact hex preview of a byte slice for log lines.
func hexShort(b []byte) string {
	parts := make([]string, len(b))
	for i, by := range b {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	return strings.Join(parts, " ")
}
