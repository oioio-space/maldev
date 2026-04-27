//go:build windows

package dllhijack_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/dllhijack"
)

// ScanAll aggregates Services + Processes + ScheduledTasks +
// AutoElevate. Each Opportunity carries the binary,
// resolved-vs-hijacked DLL paths, and an integrity-gain hint.
func ExampleScanAll() {
	opps, err := dllhijack.ScanAll()
	if err != nil {
		// partial failures common — opps still populated
	}
	ranked := dllhijack.Rank(opps)
	for _, o := range ranked[:min(5, len(ranked))] {
		fmt.Printf("%s %s → drop %s (instead of %s)\n",
			o.Kind, o.DisplayName, o.HijackedPath, o.ResolvedDLL)
	}
}

// ScanAutoElevate walks System32 .exe binaries whose manifest
// carries autoElevate=true (fodhelper, sdclt, …). The
// matching DLL hijack is a UAC-bypass primitive (T1548.002).
func ExampleScanAutoElevate() {
	opps, _ := dllhijack.ScanAutoElevate()
	for _, o := range opps {
		fmt.Printf("UAC-bypass: drop %s in %s\n",
			o.ResolvedDLL, o.HijackedPath)
	}
}
