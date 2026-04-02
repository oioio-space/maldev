//go:build windows

package sandbox

import (
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/evasion/antidebug"
	"github.com/oioio-space/maldev/evasion/antivm"
	"github.com/oioio-space/maldev/evasion/timing"
	"golang.org/x/sys/windows"
)

const sizeGB = 1 << (10 * 3)

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

// BusyWait runs a CPU-burning wait without calling Sleep (avoids sandbox time-skip).
func (c *Checker) BusyWait() { timing.BusyWait(c.cfg.EvasionTimeout) }

// RAMBytes returns the total physical RAM in bytes.
func (c *Checker) RAMBytes() (uint64, error) {
	ms := &api.MEMORYSTATUSEX{DwLength: uint32(unsafe.Sizeof(api.MEMORYSTATUSEX{}))}
	ret, _, e := api.ProcGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(ms)))
	if ret == 0 {
		return 0, os.NewSyscallError("GlobalMemoryStatusEx", e)
	}
	return ms.UllTotalPhys, nil
}

// HasEnoughRAM returns true if total RAM meets the configured minimum.
func (c *Checker) HasEnoughRAM() (bool, error) {
	ram, err := c.RAMBytes()
	if err != nil {
		return false, err
	}
	minBytes := uint64(c.cfg.MinRAMGB * float64(sizeGB))
	return ram >= minBytes, nil
}

// DiskFreeBytes returns the total size in bytes of the volume containing the given path.
func DiskFreeBytes(p string) (uint64, error) {
	ptr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	var total uint64
	ret, _, e := api.ProcGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		0,
		uintptr(unsafe.Pointer(&total)),
		0,
	)
	if ret == 0 {
		return 0, os.NewSyscallError("GetDiskFreeSpaceExW", e)
	}
	return total, nil
}

// HasEnoughDisk returns true if the system drive meets the configured minimum.
func (c *Checker) HasEnoughDisk() (bool, error) {
	total, err := DiskFreeBytes(`C:\`)
	if err != nil {
		return false, err
	}
	minBytes := uint64(c.cfg.MinDiskGB * float64(sizeGB))
	return total >= minBytes, nil
}

// HasEnoughCPU returns true if the logical CPU count meets the configured minimum.
func (c *Checker) HasEnoughCPU() bool { return runtime.NumCPU() >= c.cfg.MinCPUCores }

// BadUsername returns true if the current username is in the bad-usernames list.
func (c *Checker) BadUsername() (bool, string, error) {
	u, err := user.Current()
	if err != nil {
		return false, "", err
	}
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	for _, bad := range c.cfg.BadUsernames {
		if strings.EqualFold(name, bad) {
			return true, name, nil
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

// FakeDomainReachable returns true if cfg.FakeDomain responds to HTTP GET,
// which is characteristic of sandbox network interception.
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
	ua := uas.GetRandom()
	if ua != nil {
		req.Header.Set("User-Agent", ua.String())
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, nil // unreachable — expected for a fake domain
	}
	defer resp.Body.Close()
	return true, resp.StatusCode, nil
}

// IsSandboxed runs all configured checks and returns true on the first indicator found.
// The returned string describes which check triggered.
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
