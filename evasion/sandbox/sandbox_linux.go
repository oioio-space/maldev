//go:build linux

package sandbox

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/oioio-space/maldev/evasion/antidebug"
	"github.com/oioio-space/maldev/evasion/antivm"
	"github.com/oioio-space/maldev/evasion/timing"
)

// Checker orchestrates sandbox and VM detection checks.
type Checker struct {
	cfg Config
}

// NewChecker returns a Checker configured with cfg.
func NewChecker(cfg Config) *Checker { return &Checker{cfg: cfg} }

// NewCheckerDefault returns a Checker with DefaultConfig.
func NewCheckerDefault() *Checker { return NewChecker(DefaultConfig()) }

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

// HasEnoughDisk returns true if the root filesystem meets the configured minimum.
func (c *Checker) HasEnoughDisk() (bool, error) {
	out, err := exec.Command("df", "--output=size", "-B1", "/").Output()
	if err != nil {
		return false, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return false, nil
	}
	bytes, err := strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return false, err
	}
	minBytes := uint64(c.cfg.MinDiskGB * 1024 * 1024 * 1024)
	return bytes >= minBytes, nil
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

// FakeDomainReachable returns true if cfg.FakeDomain responds to HTTP GET.
func (c *Checker) FakeDomainReachable() (bool, int, error) {
	if c.cfg.FakeDomain == "" {
		return false, 0, nil
	}
	u, err := url.Parse(c.cfg.FakeDomain)
	if err != nil {
		return false, 0, err
	}
	uas, err := LoadUserAgents()
	if err != nil {
		return false, 0, err
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", uas.GetRandom().String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0, nil
	}
	defer resp.Body.Close()
	return true, resp.StatusCode, nil
}

// IsSandboxed runs all configured checks and returns true on the first indicator found.
func (c *Checker) IsSandboxed() (bool, string, error) {
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
	if found, _, err := c.FakeDomainReachable(); err == nil && found {
		return true, "fake domain reachable (sandbox DNS)", nil
	}
	return false, "", nil
}
