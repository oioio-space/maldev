// Victim binary: deliberately vulnerable to DLL search-order
// hijack. Calls LoadLibraryW("hijackme.dll") with no path — Windows
// searches the application directory FIRST, so any non-admin user
// who can write to the victim's directory can hijack the load.
//
// Deployed at C:\Vulnerable\victim.exe under a SYSTEM-context
// scheduled task triggered by the orchestrator from a low-privilege
// shell. Logs LoadLibrary's outcome so the test harness can
// diagnose failures (DLL not found vs. wrong arch vs. successful
// hijack).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const logDir = `C:\ProgramData\maldev-marker`
const logFile = `victim.log`

func main() {
	_ = os.MkdirAll(logDir, 0o755)
	logf := func(format string, args ...any) {
		line := fmt.Sprintf("[%s] ", time.Now().Format(time.RFC3339)) +
			fmt.Sprintf(format, args...) + "\n"
		f, err := os.OpenFile(filepath.Join(logDir, logFile),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = f.WriteString(line)
			_ = f.Close()
		}
	}
	logf("victim start, pid=%d", os.Getpid())
	h, err := windows.LoadLibrary("hijackme.dll")
	if err != nil {
		logf("LoadLibrary failed: %v (no hijack DLL planted, or wrong arch)", err)
		return
	}
	logf("LoadLibrary succeeded: handle=%#x — hijack DLL ran in our context", uintptr(h))
}
