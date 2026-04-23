// Command sleepmask-demo runs encrypted-sleep scenarios against a
// concurrent memory scanner. See docs/techniques/evasion/sleep-mask.md.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

func main() {
	scenario := flag.String("scenario", "self", "self | host")
	hostBinary := flag.String("host-binary", `C:\Windows\System32\notepad.exe`, "path for host scenario")
	cipher := flag.String("cipher", "xor", "xor | rc4 | aes")
	strategy := flag.String("strategy", "inline", "inline | timerqueue | ekko")
	useBusyTrig := flag.Bool("inline-busytrig", false, "inline only: use BusyWaitTrig")
	cycles := flag.Int("cycles", 3, "number of beacon cycles")
	sleepDur := flag.Duration("sleep", 5*time.Second, "per-cycle sleep")
	scanner := flag.Bool("scanner", true, "concurrent scanner")
	scanInt := flag.Duration("scanner-interval", 100*time.Millisecond, "scanner poll interval")
	verbose := flag.Bool("verbose", true, "per-step logging")
	flag.Parse()

	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "sleepmask-demo: Windows only")
		os.Exit(1)
	}

	cfg := demoConfig{
		HostBinary:      *hostBinary,
		CipherName:      *cipher,
		StrategyName:    *strategy,
		UseBusyTrig:     *useBusyTrig,
		Cycles:          *cycles,
		Sleep:           *sleepDur,
		EnableScanner:   *scanner,
		ScannerInterval: *scanInt,
		Verbose:         *verbose,
	}

	switch *scenario {
	case "self":
		if err := runSelf(cfg); err != nil {
			log.Fatalf("self scenario: %v", err)
		}
	case "host":
		if err := runHost(cfg); err != nil {
			log.Fatalf("host scenario: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: self, host)\n", *scenario)
		os.Exit(1)
	}
}

type demoConfig struct {
	HostBinary      string
	CipherName      string
	StrategyName    string
	UseBusyTrig     bool
	Cycles          int
	Sleep           time.Duration
	EnableScanner   bool
	ScannerInterval time.Duration
	Verbose         bool
}
