//go:build ignore

// vm-test-memscan.go — memscan verification matrix runner.
//
// Spawns memscan-server + memscan-harness inside a Windows VM and verifies
// ~60 static byte patterns across SSN resolvers, AMSI/ETW patches, and
// ntdll unhook. Replaces the old gitignored scripts/vm-test-x64dbg-mcp.go.
//
// Usage:
//
//	go run scripts/vm-test-memscan.go               # full matrix
//	go run scripts/vm-test-memscan.go -only SSN     # only SSN group
//	go run scripts/vm-test-memscan.go -host 1.2.3.4 # override VM IP
//	go run scripts/vm-test-memscan.go -skip-build   # reuse .exe in guest
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

const (
	memscanPort     = 50300
	guestDir        = `C:\memscan`
	guestServer     = `C:\memscan\memscan-server.exe`
	guestHarness    = `C:\memscan\memscan-harness.exe`
	guestServerLog  = `C:\memscan\server.log`
	guestServerErr  = `C:\memscan\server.err.log`
	guestHarnessLog = `C:\memscan\harness.log`
	guestHarnessErr = `C:\memscan\harness.err.log`

	taskServer  = "memscan-server"
	taskHarness = "memscan-harness"
)

func main() {
	hostOverride := flag.String("host", "", "override VM SSH host (else auto-discover via virsh)")
	skipBuild := flag.Bool("skip-build", false, "skip cross-compile step")
	skipPush := flag.Bool("skip-push", false, "skip scp step")
	only := flag.String("only", "", "only run matrix rows whose group matches (SSN|AMSI|ETW|Unhook)")
	flag.Parse()

	if err := realMain(*hostOverride, *skipBuild, *skipPush, *only); err != nil {
		fmt.Fprintf(os.Stderr, "\nmemscan-test: %v\n", err)
		os.Exit(1)
	}
}

func realMain(hostOverride string, skipBuild, skipPush bool, only string) error {
	vm, err := loadWindowsVM()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if hostOverride != "" {
		vm.SSHHost = hostOverride
	}
	if vm.SSHHost == "" && vm.LibvirtName != "" {
		ip, err := virshDomifaddr(vm.LibvirtName)
		if err != nil {
			return fmt.Errorf("resolve IP for %s: %w", vm.LibvirtName, err)
		}
		vm.SSHHost = ip
	}
	if vm.SSHHost == "" {
		return errors.New("no SSH host: set -host or MALDEV_VM_WINDOWS_SSH_HOST")
	}
	fmt.Printf("=== target: %s@%s key=%s ===\n", vm.User, vm.SSHHost, vm.SSHKey)

	if !skipBuild {
		fmt.Println("Cross-compiling memscan-server + memscan-harness (GOOS=windows)...")
		tmp, err := os.MkdirTemp("", "memscan-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if err := goBuildWindows("./cmd/memscan-server", filepath.Join(tmp, "memscan-server.exe")); err != nil {
			return err
		}
		if err := goBuildWindows("./cmd/memscan-harness", filepath.Join(tmp, "memscan-harness.exe")); err != nil {
			return err
		}
		if !skipPush {
			fmt.Println("Pushing binaries into guest...")
			if err := sshExec(vm, fmt.Sprintf(`cmd.exe /c "if not exist %s mkdir %s"`, guestDir, guestDir)); err != nil {
				return fmt.Errorf("mkdir guest: %w", err)
			}
			if err := scpPush(vm, filepath.Join(tmp, "memscan-server.exe"), guestServer); err != nil {
				return err
			}
			if err := scpPush(vm, filepath.Join(tmp, "memscan-harness.exe"), guestHarness); err != nil {
				return err
			}
		}
	}

	// Fresh state for this run.
	_ = sshExec(vm, killTask(taskServer))
	_ = sshExec(vm, killTask(taskHarness))
	_ = sshExec(vm, `cmd.exe /c "taskkill /F /IM memscan-server.exe /IM memscan-harness.exe 2>nul & del /Q C:\memscan\*.log 2>nul"`)

	// Start the server once; shared across all matrix rows.
	fmt.Println("Starting memscan-server in guest...")
	startCmd := detachedSpawn(taskServer, guestServer,
		fmt.Sprintf("-addr 0.0.0.0:%d", memscanPort),
		guestServerLog, guestServerErr)
	if err := sshExec(vm, startCmd); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		_ = sshExec(vm, killTask(taskServer))
		_ = sshExec(vm, killTask(taskHarness))
		_ = sshExec(vm, `cmd.exe /c "taskkill /F /IM memscan-server.exe /IM memscan-harness.exe 2>nul"`)
	}()

	base := fmt.Sprintf("http://%s:%d", vm.SSHHost, memscanPort)
	if err := waitHTTP(base+"/health", 20*time.Second); err != nil {
		return fmt.Errorf("server not reachable: %w", err)
	}
	fmt.Printf("memscan-server healthy at %s\n\n", base)

	// Run the matrix.
	matrix := buildMatrix()
	if only != "" {
		filtered := matrix[:0]
		for _, v := range matrix {
			if strings.EqualFold(v.group, only) {
				filtered = append(filtered, v)
			}
		}
		matrix = filtered
	}
	if len(matrix) == 0 {
		return fmt.Errorf("no matrix rows match -only=%q", only)
	}
	return runMatrix(vm, base, matrix)
}

// -------------------------------------------------------------------
// Matrix + verification primitives

type verif struct {
	group   string
	name    string
	harness []string
	check   func(ctx *checkCtx, ready map[string]string) ([]subResult, error)
}

type checkCtx struct {
	base    string
	session string
}

type subResult struct {
	label  string
	detail string
	ok     bool
}

// runMatrix executes every verif sequentially, printing per-row output
// and a final tally. Exit is non-zero if any sub-check failed.
func runMatrix(vm *vmEntry, base string, matrix []verif) error {
	type rowOutcome struct {
		v       verif
		subs    []subResult
		fatal   error // orchestration-level failure (harness didn't start etc.)
	}

	groupedStart := map[string]int{}
	groupedOrder := []string{}
	for i, v := range matrix {
		if _, ok := groupedStart[v.group]; !ok {
			groupedStart[v.group] = i
			groupedOrder = append(groupedOrder, v.group)
		}
	}
	sort.Slice(groupedOrder, func(i, j int) bool {
		return groupedStart[groupedOrder[i]] < groupedStart[groupedOrder[j]]
	})

	outcomes := make([]rowOutcome, 0, len(matrix))
	passSubs, failSubs := 0, 0

	for i, v := range matrix {
		fmt.Printf("[%d/%d] %s/%s ...\n", i+1, len(matrix), v.group, v.name)

		// Fresh harness per verif: kill any prior, clear its log.
		_ = sshExec(vm, killTask(taskHarness))
		_ = sshExec(vm, `cmd.exe /c "taskkill /F /IM memscan-harness.exe 2>nul & del /Q `+guestHarnessLog+` `+guestHarnessErr+` 2>nul"`)

		spawn := detachedSpawn(taskHarness, guestHarness,
			strings.Join(v.harness, " "), guestHarnessLog, guestHarnessErr)
		if err := sshExec(vm, spawn); err != nil {
			outcomes = append(outcomes, rowOutcome{v: v, fatal: fmt.Errorf("spawn harness: %w", err)})
			continue
		}
		line, err := waitReadyLine(vm, guestHarnessLog, 15*time.Second)
		if err != nil {
			errLog, _ := sshOutput(vm, fmt.Sprintf(`cmd.exe /c "type %s 2>nul & type %s 2>nul"`, guestHarnessLog, guestHarnessErr))
			outcomes = append(outcomes, rowOutcome{v: v, fatal: fmt.Errorf("harness READY timeout: %v\n%s", err, errLog)})
			continue
		}
		ready := parseReadyFields(line)
		pid, _ := strconv.ParseUint(ready["pid"], 10, 32)

		session, err := httpAttach(base, uint32(pid))
		if err != nil {
			outcomes = append(outcomes, rowOutcome{v: v, fatal: fmt.Errorf("attach pid %d: %w", pid, err)})
			continue
		}

		subs, err := v.check(&checkCtx{base: base, session: session}, ready)
		_ = httpDetach(base, session)

		if err != nil {
			outcomes = append(outcomes, rowOutcome{v: v, fatal: err})
		} else {
			outcomes = append(outcomes, rowOutcome{v: v, subs: subs})
			for _, s := range subs {
				if s.ok {
					passSubs++
				} else {
					failSubs++
				}
			}
		}
	}

	// Print report grouped by v.group.
	fmt.Println("\n" + strings.Repeat("=", 72))
	fmt.Println("memscan verification matrix — report")
	fmt.Println(strings.Repeat("=", 72))

	byGroup := map[string][]rowOutcome{}
	for _, o := range outcomes {
		byGroup[o.v.group] = append(byGroup[o.v.group], o)
	}
	fatals := 0
	for _, g := range groupedOrder {
		rows := byGroup[g]
		if len(rows) == 0 {
			continue
		}
		fmt.Printf("\n%s (%d row(s))\n", g, len(rows))
		for _, r := range rows {
			if r.fatal != nil {
				fmt.Printf("  ✗ %-40s  FATAL: %v\n", r.v.name, r.fatal)
				fatals++
				continue
			}
			mark := "✓"
			for _, s := range r.subs {
				if !s.ok {
					mark = "✗"
					break
				}
			}
			fmt.Printf("  %s %s\n", mark, r.v.name)
			for _, s := range r.subs {
				sub := "✓"
				if !s.ok {
					sub = "✗"
				}
				fmt.Printf("      %s %-28s %s\n", sub, s.label, s.detail)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("-", 72))
	fmt.Printf("total sub-checks: %d passed / %d failed (%d fatal row(s))\n", passSubs, failSubs, fatals)
	fmt.Println(strings.Repeat("-", 72))
	if failSubs > 0 || fatals > 0 {
		return fmt.Errorf("%d failed sub-check(s), %d fatal row(s)", failSubs, fatals)
	}
	return nil
}

// buildMatrix constructs the full 60-verification suite.
func buildMatrix() []verif {
	var out []verif

	callers := []string{"winapi", "nativeapi", "direct", "indirect"}
	resolvers := []string{"hellsgate", "halosgate", "tartarus", "hashgate"}
	ssnFns := []string{
		"NtAllocateVirtualMemory", "NtProtectVirtualMemory",
		"NtCreateThreadEx", "NtClose",
	}
	for _, r := range resolvers {
		for _, fn := range ssnFns {
			out = append(out, verif{
				group:   "SSN",
				name:    fmt.Sprintf("%s/%s", r, fn),
				harness: []string{"-group", "ssn", "-resolver", r, "-fn", fn},
				check:   checkSSN,
			})
		}
	}

	for _, c := range callers {
		out = append(out, verif{
			group:   "AMSI",
			name:    c,
			harness: []string{"-group", "amsi", "-caller", c},
			check:   checkAMSI,
		})
	}

	for _, c := range callers {
		out = append(out, verif{
			group:   "ETW",
			name:    c,
			harness: []string{"-group", "etw", "-caller", c},
			check:   checkETW,
		})
	}

	for _, variant := range []string{"classic", "full"} {
		for _, c := range callers {
			out = append(out, verif{
				group:   "Unhook",
				name:    fmt.Sprintf("%s/%s", variant, c),
				harness: []string{"-group", "unhook", "-variant", variant, "-caller", c},
				check:   checkUnhook,
			})
		}
	}

	// Inject: self-inject canary via each supported method × caller.
	// ThreadPoolExec is a no-Caller standalone — one row only.
	// QueueUserAPC ("apc") is excluded: it requires an alertable target
	// thread, and the harness's Go runtime threads are never in alertable
	// wait. A remote-target harness (notepad) would be needed — Phase 4.
	injectMethods := []string{"ct", "etwthr", "apcex", "sectionmap"}
	for _, m := range injectMethods {
		for _, c := range callers {
			out = append(out, verif{
				group:   "Inject",
				name:    fmt.Sprintf("%s/%s", m, c),
				harness: []string{"-group", "inject", "-method", m, "-caller", c},
				check:   checkInject,
			})
		}
	}
	out = append(out, verif{
		group:   "Inject",
		name:    "threadpool",
		harness: []string{"-group", "inject", "-method", "threadpool"},
		check:   checkInject,
	})

	return out
}

// -------------------------------------------------------------------
// Check functions (one per group)

func checkSSN(ctx *checkCtx, r map[string]string) ([]subResult, error) {
	addr, err := parseHexAny(r["addr"])
	if err != nil {
		return nil, fmt.Errorf("parse addr: %w", err)
	}
	expected, err := strconv.ParseUint(strings.TrimPrefix(r["ssn"], "0x"), 16, 16)
	if err != nil {
		return nil, fmt.Errorf("parse ssn: %w", err)
	}
	buf, err := httpRead(ctx.base, ctx.session, addr+4, 2)
	if err != nil {
		return nil, err
	}
	got := uint16(buf[0]) | uint16(buf[1])<<8
	ok := got == uint16(expected)
	detail := fmt.Sprintf("expected 0x%04X, got 0x%04X (bytes % X @+4)", expected, got, buf)
	return []subResult{{label: "ssn@+4", detail: detail, ok: ok}}, nil
}

func checkAMSI(ctx *checkCtx, r map[string]string) ([]subResult, error) {
	sbAddr, err := parseHexAny(r["scanbuffer_addr"])
	if err != nil {
		return nil, fmt.Errorf("parse scanbuffer_addr: %w", err)
	}
	osAddr, err := parseHexAny(r["opensession_addr"])
	if err != nil {
		return nil, fmt.Errorf("parse opensession_addr: %w", err)
	}
	flipOff, err := strconv.ParseUint(r["opensession_flip_offset"], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse flip_offset: %w", err)
	}

	var subs []subResult

	// 1. AmsiScanBuffer → 31 C0 C3
	sbBuf, err := httpRead(ctx.base, ctx.session, sbAddr, 3)
	if err != nil {
		subs = append(subs, subResult{label: "ScanBuffer", detail: err.Error()})
	} else {
		want := []byte{0x31, 0xC0, 0xC3}
		ok := bytes.Equal(sbBuf, want)
		subs = append(subs, subResult{
			label:  "ScanBuffer",
			detail: fmt.Sprintf("% X (want 31 C0 C3)", sbBuf),
			ok:     ok,
		})
	}

	// 2. AmsiOpenSession → byte at flip_offset flipped JZ (0x74) → JNZ (0x75)
	osBuf, err := httpRead(ctx.base, ctx.session, osAddr+uintptr(flipOff), 1)
	if err != nil {
		subs = append(subs, subResult{label: "OpenSession", detail: err.Error()})
	} else {
		ok := len(osBuf) == 1 && osBuf[0] == 0x75
		subs = append(subs, subResult{
			label:  "OpenSession",
			detail: fmt.Sprintf("@+%d = 0x%02X (want 0x75, JZ→JNZ)", flipOff, osBuf[0]),
			ok:     ok,
		})
	}

	// 3. PatchAll = ScanBuffer AND OpenSession.
	all := true
	for _, s := range subs {
		if !s.ok {
			all = false
			break
		}
	}
	subs = append(subs, subResult{
		label:  "PatchAll",
		detail: "both sub-patches applied",
		ok:     all,
	})
	return subs, nil
}

func checkETW(ctx *checkCtx, r map[string]string) ([]subResult, error) {
	names := []string{
		"EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull",
		"EtwEventWriteString", "EtwEventWriteTransfer", "NtTraceEvent",
	}
	want := []byte{0x48, 0x33, 0xC0, 0xC3}
	var subs []subResult
	for _, n := range names {
		key := strings.ToLower(n) + "_addr"
		if r[key] == "" || r[key] == "0" {
			subs = append(subs, subResult{
				label:  n,
				detail: "(absent on this Windows version, skipped)",
				ok:     true, // treat as pass — nothing to verify
			})
			continue
		}
		addr, err := parseHexAny(r[key])
		if err != nil {
			subs = append(subs, subResult{label: n, detail: fmt.Sprintf("parse addr: %v", err)})
			continue
		}
		buf, err := httpRead(ctx.base, ctx.session, addr, 4)
		if err != nil {
			subs = append(subs, subResult{label: n, detail: err.Error()})
			continue
		}
		ok := bytes.Equal(buf, want)
		subs = append(subs, subResult{
			label:  n,
			detail: fmt.Sprintf("% X (want 48 33 C0 C3)", buf),
			ok:     ok,
		})
	}
	return subs, nil
}

func checkInject(ctx *checkCtx, r map[string]string) ([]subResult, error) {
	marker := r["marker_hex"]
	if marker == "" {
		return nil, fmt.Errorf("harness did not report marker_hex")
	}
	// Scan RX/RWX pages first (where shellcode allocations land); fall back
	// to "any" so .rdata-embedded source bytes also match — the latter would
	// be a false positive from the harness's own static data, so we prefer
	// rx/rwx as the stronger signal.
	hits, err := httpFind(ctx.base, ctx.session, marker, "rwx", 16)
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		// Some injectors use RX (not RWX) post-protect change: retry.
		hits, err = httpFind(ctx.base, ctx.session, marker, "rx", 16)
		if err != nil {
			return nil, err
		}
	}
	detail := fmt.Sprintf("marker found at %d RX/RWX address(es): %v", len(hits), hits)
	ok := len(hits) > 0
	return []subResult{{label: r["method"], detail: detail, ok: ok}}, nil
}

func checkUnhook(ctx *checkCtx, r map[string]string) ([]subResult, error) {
	addr, err := parseHexAny(r["target_addr"])
	if err != nil {
		return nil, fmt.Errorf("parse target_addr: %w", err)
	}
	buf, err := httpRead(ctx.base, ctx.session, addr, 4)
	if err != nil {
		return nil, err
	}
	want := []byte{0x4C, 0x8B, 0xD1, 0xB8}
	ok := bytes.Equal(buf, want)
	return []subResult{{
		label:  r["target"],
		detail: fmt.Sprintf("% X (want 4C 8B D1 B8 — mov r10,rcx; mov eax,<ssn>)", buf),
		ok:     ok,
	}}, nil
}

// -------------------------------------------------------------------
// Config loading — minimal duplicate of cmd/vmtest/config.go deep-merge.
// Phase 3 should extract this into internal/vmconfig/.

type vmEntry struct {
	Platform    string `yaml:"platform"`
	LibvirtName string `yaml:"libvirt_name"`
	VBoxName    string `yaml:"vbox_name"`
	User        string `yaml:"user"`
	SSHPort     int    `yaml:"ssh_port"`
	SSHKey      string `yaml:"ssh_key"`
	SSHHost     string `yaml:"ssh_host"`
}

func loadWindowsVM() (*vmEntry, error) {
	base, err := readYAMLMap("scripts/vm-test/config.yaml")
	if err != nil {
		return nil, err
	}
	if local, err := readYAMLMap("scripts/vm-test/config.local.yaml"); err == nil {
		deepMerge(base, local)
	}
	merged, _ := yaml.Marshal(base)
	var all struct {
		VMs map[string]vmEntry `yaml:"vms"`
	}
	if err := yaml.Unmarshal(merged, &all); err != nil {
		return nil, err
	}
	vm, ok := all.VMs["windows"]
	if !ok {
		return nil, errors.New("no 'windows' entry in config")
	}
	if v := os.Getenv("MALDEV_VM_WINDOWS_SSH_HOST"); v != "" {
		vm.SSHHost = v
	}
	if v := os.Getenv("MALDEV_VM_WINDOWS_SSH_KEY"); v != "" {
		vm.SSHKey = v
	}
	if v := os.Getenv("MALDEV_VM_WINDOWS_USER"); v != "" {
		vm.User = v
	}
	if vm.SSHPort == 0 {
		vm.SSHPort = 22
	}
	if strings.HasPrefix(vm.SSHKey, "~/") {
		home, _ := os.UserHomeDir()
		vm.SSHKey = filepath.Join(home, vm.SSHKey[2:])
	}
	return &vm, nil
}

func readYAMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if dv, ok := dst[k]; ok {
			if dm, ok1 := dv.(map[string]any); ok1 {
				if sm, ok2 := v.(map[string]any); ok2 {
					deepMerge(dm, sm)
					continue
				}
			}
		}
		dst[k] = v
	}
}

// -------------------------------------------------------------------
// virsh / ssh / scp / go helpers

func virshDomifaddr(name string) (string, error) {
	for _, src := range []string{"lease", "agent", "arp"} {
		cmd := exec.Command("virsh", "-c", "qemu:///session", "domifaddr", name, "--source", src)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "ipv4") {
				continue
			}
			for _, f := range strings.Fields(line) {
				if i := strings.IndexByte(f, '/'); i > 0 {
					f = f[:i]
				}
				if ip := net.ParseIP(f); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					return ip.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no IPv4 found for %s", name)
}

func sshBaseArgs(vm *vmEntry) []string {
	return []string{
		"-i", vm.SSHKey,
		"-p", strconv.Itoa(vm.SSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
	}
}

func sshExec(vm *vmEntry, remote string) error {
	args := append(sshBaseArgs(vm), fmt.Sprintf("%s@%s", vm.User, vm.SSHHost), remote)
	return exec.Command("ssh", args...).Run()
}

func sshOutput(vm *vmEntry, remote string) (string, error) {
	args := append(sshBaseArgs(vm), fmt.Sprintf("%s@%s", vm.User, vm.SSHHost), remote)
	out, err := exec.Command("ssh", args...).Output()
	return string(out), err
}

func scpPush(vm *vmEntry, src, dst string) error {
	dstFwd := strings.ReplaceAll(dst, `\`, "/")
	args := []string{
		"-i", vm.SSHKey,
		"-P", strconv.Itoa(vm.SSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		src, fmt.Sprintf("%s@%s:%s", vm.User, vm.SSHHost, dstFwd),
	}
	return exec.Command("scp", args...).Run()
}

func goBuildWindows(pkg, out string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// -------------------------------------------------------------------
// Detached-spawn via Task Scheduler (breaks out of ssh JobObject)

func detachedSpawn(taskName, exe, args, outLog, errLog string) string {
	inner := fmt.Sprintf(`%s %s > %s 2> %s`, exe, args, outLog, errLog)
	script := fmt.Sprintf(
		`schtasks /Create /F /SC ONCE /ST 23:59 /TN %s /TR 'cmd /c \"%s\"' | Out-Null; schtasks /Run /TN %s | Out-Null`,
		taskName, inner, taskName)
	return "powershell -EncodedCommand " + encodePSCommand(script)
}

func killTask(taskName string) string {
	script := fmt.Sprintf(
		`schtasks /End /TN %s 2>$null | Out-Null; schtasks /Delete /TN %s /F 2>$null | Out-Null`,
		taskName, taskName)
	return "powershell -EncodedCommand " + encodePSCommand(script)
}

func encodePSCommand(s string) string {
	u16 := utf16.Encode([]rune(s))
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, u16)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// -------------------------------------------------------------------
// waitHTTP / waitReadyLine / parseReady

func waitHTTP(url string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func waitReadyLine(vm *vmEntry, logPath string, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out, err := sshOutput(vm, fmt.Sprintf(`cmd.exe /c "type %s 2>nul"`, logPath))
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "READY ") {
					return strings.TrimSpace(line), nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for READY in %s", logPath)
}

// parseReadyFields turns "READY k1=v1 k2=v2" into {"k1":"v1","k2":"v2"}.
func parseReadyFields(line string) map[string]string {
	out := map[string]string{}
	line = strings.TrimPrefix(line, "READY ")
	for _, tok := range strings.Fields(line) {
		if i := strings.IndexByte(tok, '='); i > 0 {
			out[tok[:i]] = tok[i+1:]
		}
	}
	return out
}

// -------------------------------------------------------------------
// HTTP client for the memscan server

func httpPost(url string, body any) (map[string]any, error) {
	buf, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode %s (status %d): %v: %s", url, resp.StatusCode, err, string(raw))
	}
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("%s: HTTP %d: %v", url, resp.StatusCode, out["error"])
	}
	return out, nil
}

func httpAttach(base string, pid uint32) (string, error) {
	out, err := httpPost(base+"/attach", map[string]any{"pid": pid})
	if err != nil {
		return "", err
	}
	return out["session"].(string), nil
}

func httpDetach(base, session string) error {
	_, err := httpPost(base+"/detach", map[string]any{"session": session})
	return err
}

func httpFind(base, session, patternHex, regions string, maxHits int) ([]string, error) {
	out, err := httpPost(base+"/find", map[string]any{
		"session":     session,
		"pattern_hex": patternHex,
		"regions":     regions,
		"max_hits":    maxHits,
	})
	if err != nil {
		return nil, err
	}
	raw, _ := out["matches"].([]any)
	addrs := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			addrs = append(addrs, s)
		}
	}
	return addrs, nil
}

func httpRead(base, session string, addr uintptr, size uint32) ([]byte, error) {
	out, err := httpPost(base+"/read", map[string]any{
		"session": session,
		"addr":    fmt.Sprintf("0x%x", addr),
		"size":    size,
	})
	if err != nil {
		return nil, err
	}
	s, _ := out["data"].(string)
	return base64.StdEncoding.DecodeString(s)
}

func parseHexAny(v any) (uintptr, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("expected hex string, got %T", v)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}
	return uintptr(n), nil
}
