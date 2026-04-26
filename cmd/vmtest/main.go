// Command vmtest runs the maldev Go test suite inside isolated VMs with
// snapshot restore between runs. Two drivers are supported: VirtualBox
// (guestcontrol + shared folder) and libvirt (virsh + ssh + rsync).
//
// Usage:
//
//	vmtest [flags] <windows|windows11|linux|all> [packages] [test-flags]
//
// Examples:
//
//	vmtest windows
//	vmtest windows11 "./credentials/..." "-v"
//	vmtest linux "./persistence/..." "-v"
//	vmtest all "./..." "-count=1"
//
// Configuration lives in scripts/vm-test/config.yaml (committed) with a
// per-host override in scripts/vm-test/config.local.yaml (gitignored) and
// environment-variable overrides (MALDEV_VM_*, MALDEV_VBOX_EXE).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const (
	defaultConfigPath = "scripts/vm-test/config.yaml"
	defaultLocalPath  = "scripts/vm-test/config.local.yaml"
	defaultPackages   = "./..."
	defaultTestFlags  = "-count=1"
)

func main() {
	var (
		driverFlag = flag.String("driver", "", "driver: vbox, libvirt (auto-detected if empty)")
		configPath = flag.String("config", defaultConfigPath, "path to config YAML")
		localPath  = flag.String("local", defaultLocalPath, "path to local-override YAML (optional)")
		reportDir  = flag.String("report-dir", "", "host directory to collect test.log + cover.out per VM (empty = no artifacts)")
	)
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	target := args[0]
	packages := defaultPackages
	testFlags := defaultTestFlags
	if len(args) >= 2 && args[1] != "" {
		packages = args[1]
	}
	if len(args) >= 3 && args[2] != "" {
		testFlags = args[2]
	}

	cfg, err := LoadConfig(*configPath, *localPath)
	if err != nil {
		die("config: %v", err)
	}
	if *driverFlag != "" {
		cfg.Driver = *driverFlag
	}
	if cfg.Driver == "" {
		die("no driver available; install VirtualBox or libvirt, or set --driver / MALDEV_VM_DRIVER")
	}

	drv, err := SelectDriver(cfg)
	if err != nil {
		die("driver: %v", err)
	}
	fmt.Printf("=== Driver: %s ===\n", drv.Name())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nvmtest: interrupt received, stopping...")
		cancel()
	}()

	var targets []string
	switch target {
	case "windows", "win":
		targets = []string{"windows"}
	case "windows11", "win11":
		targets = []string{"windows11"}
	case "linux", "lin":
		targets = []string{"linux"}
	case "all":
		targets = []string{"windows", "windows11", "linux"}
	default:
		die("unknown target %q (want windows|windows11|linux|all)", target)
	}

	projectRoot, err := filepath.Abs(".")
	if err != nil {
		die("project root: %v", err)
	}

	rc := 0
	for _, name := range targets {
		vm, ok := cfg.VMs[name]
		if !ok {
			die("vm %q not in config", name)
		}
		code := RunVM(ctx, drv, &vm, projectRoot, packages, testFlags, RunOpts{ReportDir: *reportDir})
		if code != 0 {
			rc = code
		}
	}
	os.Exit(rc)
}

func usage() {
	fmt.Fprintf(os.Stderr,
		"usage: vmtest [flags] <windows|windows11|linux|all> [packages] [test-flags]\n\n"+
			"Runs Go tests inside isolated VMs with snapshot restore between runs.\n\n"+
			"Examples:\n"+
			"  vmtest windows\n"+
			"  vmtest windows11 \"./credentials/...\" \"-v\"\n"+
			"  vmtest linux \"./persistence/...\" \"-v\"\n"+
			"  vmtest all \"./...\" \"-count=1\"\n\n"+
			"Flags:\n")
	flag.PrintDefaults()
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "vmtest: "+f+"\n", a...)
	os.Exit(1)
}
