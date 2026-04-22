package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RunOpts tunes optional RunVM behaviours. The zero value reproduces the
// original fire-and-forget run: console passthrough only, no coverage,
// no persisted logs.
type RunOpts struct {
	// ReportDir is a host-side directory. When non-empty, RunVM:
	//   - injects `-coverprofile=<guest-tmp>/cover.out` into the test flags
	//     (only if the user hasn't already passed one),
	//   - tees the guest's stdout/stderr into <ReportDir>/<label>/test.log,
	//   - pulls cover.out back into <ReportDir>/<label>/cover.out via Fetch,
	// where <label> is the VM's stable label (vbox_name or libvirt_name).
	ReportDir string
}

// RunVM orchestrates a full VM test cycle: start, wait-ready, push source,
// exec tests, stop, restore snapshot. Stop+Restore run regardless of earlier
// failures so the VM always returns to its INIT state for the next run.
func RunVM(ctx context.Context, drv Driver, vm *VMConfig, hostRoot, packages, flags string, opts RunOpts) int {
	label := vmLabel(drv, vm)
	fmt.Printf("=== VM: %s ===\n", label)

	if err := drv.Start(ctx, vm); err != nil {
		fmt.Printf("start failed: %v\n", err)
		return 1
	}
	defer func() {
		if err := drv.Stop(ctx, vm); err != nil {
			fmt.Printf("stop: %v\n", err)
		}
		if err := drv.Restore(ctx, vm); err != nil {
			fmt.Printf("restore snapshot %q: %v\n", vm.Snapshot, err)
		}
	}()

	if err := drv.WaitReady(ctx, vm); err != nil {
		fmt.Printf("wait-ready failed: %v\n", err)
		return 1
	}
	if err := drv.Push(ctx, vm, hostRoot); err != nil {
		fmt.Printf("push failed: %v\n", err)
		return 1
	}

	var (
		logWriter    io.Writer
		logFile      *os.File
		guestCover   string
		hostCover    string
		effectiveFlg = flags
	)
	if opts.ReportDir != "" {
		hostLabelDir := filepath.Join(opts.ReportDir, safeLabel(label))
		if err := os.MkdirAll(hostLabelDir, 0o755); err != nil {
			fmt.Printf("mkdir %s: %v\n", hostLabelDir, err)
			return 1
		}
		logPath := filepath.Join(hostLabelDir, "test.log")
		if f, err := os.Create(logPath); err != nil {
			fmt.Printf("create %s: %v\n", logPath, err)
			return 1
		} else {
			logFile = f
			logWriter = f
		}
		guestCover = guestCoverPath(vm.Platform)
		hostCover = filepath.Join(hostLabelDir, "cover.out")
		effectiveFlg = injectCoverprofile(flags, guestCover)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	fmt.Printf("Running tests: go test %s %s\n", packages, effectiveFlg)
	code, err := drv.Exec(ctx, vm, packages, effectiveFlg, logWriter)
	if err != nil {
		fmt.Printf("exec failed: %v\n", err)
		return 1
	}

	if opts.ReportDir != "" && hostCover != "" {
		if ferr := drv.Fetch(ctx, vm, guestCover, hostCover); ferr != nil {
			fmt.Printf("fetch cover.out (%s → %s): %v\n", guestCover, hostCover, ferr)
			// Non-fatal: tests ran, we just don't get coverage this cycle.
		}
		// Also pull the clrhost subprocess profile when present. Written by
		// testutil.RunCLROperation — absence is fine (pe/clr tests may have
		// been skipped or the VM lacks .NET 3.5).
		if guestClr := guestClrhostCoverPath(vm.Platform); guestClr != "" {
			hostClr := filepath.Join(filepath.Dir(hostCover), "clrhost-cover.out")
			if ferr := drv.Fetch(ctx, vm, guestClr, hostClr); ferr != nil {
				// Quiet warning only: file often doesn't exist, which is expected.
				fmt.Printf("fetch clrhost-cover.out: %v (non-fatal)\n", ferr)
			}
		}
	}

	fmt.Printf("=== %s: exit code %d ===\n", label, code)
	return code
}

func vmLabel(drv Driver, vm *VMConfig) string {
	switch drv.Name() {
	case "vbox":
		return vm.VBoxName
	case "libvirt":
		return vm.LibvirtName
	}
	if vm.VBoxName != "" {
		return vm.VBoxName
	}
	return vm.LibvirtName
}

// safeLabel turns a VM label into something safe for a filesystem path —
// virsh domain names can legally contain characters like ':' or '/'.
func safeLabel(label string) string {
	if label == "" {
		return "vm"
	}
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(label)
}

// guestCoverPath returns the in-guest path where -coverprofile should be
// written. We keep it in a predictable location per platform so Fetch can
// find it without extra round-trips.
func guestCoverPath(platform string) string {
	if platform == "windows" {
		// OpenSSH on Windows parses POSIX paths transparently; cmd.exe
		// accepts forward slashes too. Using C:/Users/Public keeps the
		// path writable by any user the VM runs tests as.
		return "C:/Users/Public/maldev-cover.out"
	}
	return "/tmp/maldev-cover.out"
}

// guestClrhostCoverPath returns the predictable guest path where
// testutil.RunCLROperation writes the clrhost subprocess coverage profile.
// Empty string disables the fetch (no CLR on that platform).
func guestClrhostCoverPath(platform string) string {
	if platform == "windows" {
		return "C:/Users/Public/clrhost-cover.out"
	}
	return ""
}

// injectCoverprofile adds `-coverprofile=<path>` (plus a safe default
// `-covermode=atomic`) to the user-supplied test flag string if neither
// flag is already present. User-supplied values always win — we never
// clobber an explicit choice.
func injectCoverprofile(flags, path string) string {
	hasCover := strings.Contains(flags, "-coverprofile")
	hasMode := strings.Contains(flags, "-covermode")
	extras := []string{}
	if !hasCover {
		extras = append(extras, "-coverprofile="+path)
	}
	if !hasMode {
		extras = append(extras, "-covermode=atomic")
	}
	if len(extras) == 0 {
		return flags
	}
	if strings.TrimSpace(flags) == "" {
		return strings.Join(extras, " ")
	}
	return flags + " " + strings.Join(extras, " ")
}
