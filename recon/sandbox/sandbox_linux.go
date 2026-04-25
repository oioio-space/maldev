//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/oioio-space/maldev/useragent"

	"github.com/oioio-space/maldev/recon/antidebug"
	"github.com/oioio-space/maldev/recon/antivm"
	"github.com/oioio-space/maldev/recon/timing"
	"github.com/oioio-space/maldev/process/enum"
	"golang.org/x/sys/unix"
)

// Checker orchestrates sandbox and VM detection checks.
type Checker struct {
	cfg Config
}

// New returns a Checker configured with cfg.
func New(cfg Config) *Checker { return &Checker{cfg: cfg} }

// IsDebuggerPresent returns true if the process is being debugged.
func (c *Checker) IsDebuggerPresent() bool { return antidebug.IsDebuggerPresent() }

// IsRunningInVM returns true if any hypervisor indicator is detected.
func (c *Checker) IsRunningInVM() bool { return antivm.IsRunningInVM() }

// BusyWait runs a CPU-burning wait without calling sleep (avoids sandbox time-skip).
func (c *Checker) BusyWait() { timing.BusyWait(c.cfg.EvasionTimeout) }

// RAMBytes returns the total physical RAM in bytes using /proc/meminfo.
func (c *Checker) RAMBytes() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return kb * 1024, nil
			}
		}
	}
	return 0, nil
}

// HasEnoughRAM returns true if total RAM meets the configured minimum.
func (c *Checker) HasEnoughRAM() (bool, error) {
	ram, err := c.RAMBytes()
	if err != nil {
		return false, err
	}
	minBytes := uint64(c.cfg.MinRAMGB * 1024 * 1024 * 1024)
	return ram >= minBytes, nil
}

// HasEnoughDisk returns true if the configured disk path meets the minimum size.
// Uses unix.Statfs instead of shelling out to df.
func (c *Checker) HasEnoughDisk() (bool, error) {
	path := c.cfg.DiskPath
	if path == "" {
		path = "/"
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, err
	}
	// Total bytes = block count * block size
	totalBytes := uint64(stat.Blocks) * uint64(stat.Bsize)
	minBytes := uint64(c.cfg.MinDiskGB * 1024 * 1024 * 1024)
	return totalBytes >= minBytes, nil
}

// HasEnoughCPU returns true if the logical CPU count meets the configured minimum.
func (c *Checker) HasEnoughCPU() bool { return runtime.NumCPU() >= c.cfg.MinCPUCores }

// BadUsername returns true if the current username is in the bad-usernames list.
func (c *Checker) BadUsername() (bool, string, error) {
	u, err := user.Current()
	if err != nil {
		return false, "", err
	}
	for _, bad := range c.cfg.BadUsernames {
		if strings.EqualFold(u.Username, bad) {
			return true, u.Username, nil
		}
	}
	return false, "", nil
}

// BadHostname returns true if the hostname is in the bad-hostnames list.
func (c *Checker) BadHostname() (bool, string, error) {
	h, err := os.Hostname()
	if err != nil {
		return false, "", err
	}
	for _, bad := range c.cfg.BadHostnames {
		if strings.EqualFold(h, bad) {
			return true, h, nil
		}
	}
	return false, "", nil
}

// CheckProcesses returns true if any running process matches the configured bad process names.
// Uses case-insensitive substring matching against c.cfg.BadProcesses.
func (c *Checker) CheckProcesses(ctx context.Context) (bool, string, error) {
	procs, err := enum.List()
	if err != nil {
		return false, "", err
	}
	for _, p := range procs {
		if ctx.Err() != nil {
			return false, "", ctx.Err()
		}
		lower := strings.ToLower(p.Name)
		for _, bad := range c.cfg.BadProcesses {
			if strings.Contains(lower, strings.ToLower(bad)) {
				return true, p.Name, nil
			}
		}
	}
	return false, "", nil
}

// FakeDomainReachable returns true if cfg.FakeDomain responds to HTTP GET.
func (c *Checker) FakeDomainReachable(ctx context.Context) (bool, int, error) {
	if c.cfg.FakeDomain == "" {
		return false, 0, nil
	}
	u, err := url.Parse(c.cfg.FakeDomain)
	if err != nil {
		return false, 0, err
	}
	uaDB, err := useragent.Load()
	if err != nil {
		return false, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", uaDB.RandomString("Mozilla/5.0"))
	timeout := c.cfg.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, nil
	}
	defer resp.Body.Close()
	return true, resp.StatusCode, nil
}

// CheckProcessCount returns true if the number of running processes is
// suspiciously low, indicating a fresh analysis VM.
func (c *Checker) CheckProcessCount(ctx context.Context) (bool, string, error) {
	procs, err := enum.List()
	if err != nil {
		return false, "", err
	}
	if len(procs) < c.cfg.MinProcesses {
		return true, fmt.Sprintf("only %d processes running (minimum %d)", len(procs), c.cfg.MinProcesses), nil
	}
	return false, "", nil
}

// CheckConnectivity returns true if the internet is NOT reachable,
// which may indicate a sandboxed/isolated environment.
func (c *Checker) CheckConnectivity(ctx context.Context) (bool, string, error) {
	if c.cfg.ConnectivityURL == "" {
		return false, "", nil
	}
	client := &http.Client{Timeout: c.cfg.RequestTimeout}
	req, err := http.NewRequestWithContext(ctx, "HEAD", c.cfg.ConnectivityURL, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return true, "no internet connectivity", nil
	}
	resp.Body.Close()
	return false, "", nil
}

// CheckAll runs every detection check and returns a Result for each.
func (c *Checker) CheckAll(ctx context.Context) []Result {
	var results []Result

	results = append(results, Result{
		Name:     "debugger",
		Detected: c.IsDebuggerPresent(),
		Detail:   "debugger attached to process",
	})

	results = append(results, Result{
		Name:     "vm",
		Detected: c.IsRunningInVM(),
		Detail:   "hypervisor indicators found",
	})

	cpuOK := c.HasEnoughCPU()
	results = append(results, Result{
		Name:     "cpu",
		Detected: !cpuOK,
		Detail:   fmt.Sprintf("CPU cores: %d, minimum: %d", runtime.NumCPU(), c.cfg.MinCPUCores),
	})

	ramOK, ramErr := c.HasEnoughRAM()
	results = append(results, Result{
		Name:     "ram",
		Detected: ramErr == nil && !ramOK,
		Detail:   fmt.Sprintf("minimum RAM: %dGB", int(c.cfg.MinRAMGB)),
		Err:      ramErr,
	})

	diskOK, diskErr := c.HasEnoughDisk()
	results = append(results, Result{
		Name:     "disk",
		Detected: diskErr == nil && !diskOK,
		Detail:   fmt.Sprintf("minimum disk: %dGB on %s", int(c.cfg.MinDiskGB), c.cfg.DiskPath),
		Err:      diskErr,
	})

	badUser, userName, userErr := c.BadUsername()
	results = append(results, Result{
		Name:     "username",
		Detected: userErr == nil && badUser,
		Detail:   "suspicious username: " + userName,
		Err:      userErr,
	})

	badHost, hostName, hostErr := c.BadHostname()
	results = append(results, Result{
		Name:     "hostname",
		Detected: hostErr == nil && badHost,
		Detail:   "suspicious hostname: " + hostName,
		Err:      hostErr,
	})

	domainReachable, statusCode, domainErr := c.FakeDomainReachable(ctx)
	detail := "fake domain unreachable (expected)"
	if domainReachable {
		detail = fmt.Sprintf("fake domain reachable, status %d", statusCode)
	}
	results = append(results, Result{
		Name:     "domain",
		Detected: domainErr == nil && domainReachable,
		Detail:   detail,
		Err:      domainErr,
	})

	procFound, procName, procErr := c.CheckProcesses(ctx)
	results = append(results, Result{
		Name:     "process",
		Detected: procErr == nil && procFound,
		Detail:   "analysis tool detected: " + procName,
		Err:      procErr,
	})

	lowProcs, lowProcsDetail, lowProcsErr := c.CheckProcessCount(ctx)
	results = append(results, Result{
		Name:     "process_count",
		Detected: lowProcsErr == nil && lowProcs,
		Detail:   lowProcsDetail,
		Err:      lowProcsErr,
	})

	noInternet, noInternetDetail, noInternetErr := c.CheckConnectivity(ctx)
	results = append(results, Result{
		Name:     "connectivity",
		Detected: noInternetErr == nil && noInternet,
		Detail:   noInternetDetail,
		Err:      noInternetErr,
	})

	return results
}

// IsSandboxed runs all configured checks and returns true if any indicator is found.
// When StopOnFirst is true (default), it returns on the first detection.
// When StopOnFirst is false, it runs all checks and returns a combined summary.
func (c *Checker) IsSandboxed(ctx context.Context) (bool, string, error) {
	if c.cfg.StopOnFirst {
		return c.isSandboxedStopOnFirst(ctx)
	}

	results := c.CheckAll(ctx)
	var reasons []string
	for _, r := range results {
		if r.Detected {
			reasons = append(reasons, r.Detail)
		}
	}
	if len(reasons) > 0 {
		return true, strings.Join(reasons, "; "), nil
	}
	return false, "", nil
}

func (c *Checker) isSandboxedStopOnFirst(ctx context.Context) (bool, string, error) {
	if c.IsDebuggerPresent() {
		return true, "debugger detected", nil
	}
	if c.IsRunningInVM() {
		return true, "virtual machine detected", nil
	}
	if !c.HasEnoughCPU() {
		return true, "insufficient CPU cores", nil
	}
	if ok, err := c.HasEnoughRAM(); err == nil && !ok {
		return true, "insufficient RAM", nil
	}
	if ok, err := c.HasEnoughDisk(); err == nil && !ok {
		return true, "insufficient disk space", nil
	}
	if found, name, err := c.BadUsername(); err == nil && found {
		return true, "suspicious username: " + name, nil
	}
	if found, name, err := c.BadHostname(); err == nil && found {
		return true, "suspicious hostname: " + name, nil
	}
	if found, _, err := c.FakeDomainReachable(ctx); err == nil && found {
		return true, "fake domain reachable (sandbox DNS)", nil
	}
	if found, name, err := c.CheckProcesses(ctx); err == nil && found {
		return true, "analysis tool detected: " + name, nil
	}
	if found, detail, err := c.CheckProcessCount(ctx); err == nil && found {
		return true, detail, nil
	}
	if found, detail, err := c.CheckConnectivity(ctx); err == nil && found {
		return true, detail, nil
	}
	return false, "", nil
}
