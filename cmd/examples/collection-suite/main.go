//go:build windows

// collection-suite — panorama 13 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/collection/clipboard.md   — clipboard.ReadText / WriteText
//   - docs/techniques/collection/screenshot.md  — screenshot.Capture
//   - docs/techniques/collection/keylogging.md  — keylog.Start (probed only)
//
// Tests user-data collection. clipboard + screenshot bind to the WinSta /
// session in which the process runs — admin SSH and lowuser scheduled task
// both run in session 0, which has *no* clipboard window-station and no
// active desktop, so most of these calls are expected to surface a clear
// error rather than fake data. The matrix captures exactly which.
//
// Keylogger is started + cancelled within 100ms so the example terminates.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/collection/clipboard"
	"github.com/oioio-space/maldev/collection/keylog"
	"github.com/oioio-space/maldev/collection/screenshot"
)

func main() {
	// 1. Clipboard (clipboard.md "Simple"). Read-only — the doc exposes
	//    ReadText + Watch but no WriteText, so we just probe the read path.
	fmt.Println("=== Clipboard ===")
	if got, err := clipboard.ReadText(); err != nil {
		fmt.Printf("ReadText: %v\n", err)
	} else {
		fmt.Printf("ReadText: OK (%d chars)\n", len(got))
	}

	// 2. Screenshot (screenshot.md "Simple"). PNG bytes only, no file write.
	fmt.Println("\n=== Screenshot ===")
	if png, err := screenshot.Capture(); err != nil {
		fmt.Printf("Capture: %v\n", err)
	} else {
		fmt.Printf("Capture: OK %d-byte PNG\n", len(png))
	}

	// 3. Keylogger (keylogging.md "Simple") — start, sleep 100 ms, cancel
	//    so the example exits. Real implants would loop forever.
	fmt.Println("\n=== Keylogger ===")
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := keylog.Start(ctx)
	if err != nil {
		fmt.Printf("Start: %v\n", err)
	} else {
		fmt.Printf("Start: OK\n")
		time.Sleep(100 * time.Millisecond)
		cancel()
		// Drain any pending events so the goroutine can exit cleanly.
		drained := 0
		for range ch {
			drained++
		}
		fmt.Printf("drained %d events after cancel\n", drained)
	}
}
