// Probe for the privesc-e2e chain. When the packed payload spawns,
// THIS binary's main() runs in the elevated context (SYSTEM via the
// scheduled task that triggered the hijacked LoadLibrary).
//
// Writes:
//   C:\ProgramData\maldev-marker\whoami.txt
//
// Format (single line, easy to grep):
//   <whoami_output>|pid=<pid>|t=<unix_seconds>
//
// On any error, still try to write something — the orchestrator
// reads this file and asserts the user identity.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const markerDir = `C:\ProgramData\maldev-marker`
const markerFile = `whoami.txt`

func main() {
	// Bisection breadcrumb: written FIRST so we can tell whether Go's
	// runtime made it past init when launched as a thread injected by
	// the Mode-8 stub. If this line appears but `whoami.txt` doesn't,
	// the failure is exec.Command (PATH? SYSTEM env? handle limit?).
	_ = os.MkdirAll(markerDir, 0o755)
	_ = os.WriteFile(filepath.Join(markerDir, "probe-started.txt"),
		[]byte(fmt.Sprintf("started pid=%d t=%d\n", os.Getpid(), time.Now().Unix())),
		0o644)

	// Use the absolute path — SYSTEM's PATH may not include System32
	// the way an interactive user expects, and whoami.exe IS there.
	whoamiExe := `C:\Windows\System32\whoami.exe`
	out, err := exec.Command(whoamiExe).Output()
	if err != nil {
		bail("whoami exec: %v", err)
	}
	identity := strings.TrimSpace(string(out))
	line := fmt.Sprintf("%s|pid=%d|t=%d\n", identity, os.Getpid(), time.Now().Unix())
	if err := os.WriteFile(filepath.Join(markerDir, markerFile), []byte(line), 0o644); err != nil {
		bail("write: %v", err)
	}
}

func bail(format string, args ...any) {
	_ = os.MkdirAll(markerDir, 0o755)
	_ = os.WriteFile(filepath.Join(markerDir, markerFile),
		[]byte("ERROR: "+fmt.Sprintf(format, args...)+"\n"), 0o644)
	os.Exit(1)
}
