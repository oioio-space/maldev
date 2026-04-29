//go:build windows

package service

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Sentinel errors for service operations.
var (
	ErrServiceExists   = errors.New("service already exists")
	ErrServiceNotFound = errors.New("service not found")
	ErrAccessDenied    = errors.New("access denied")
)

// StartType controls when the service starts.
type StartType uint32

const (
	StartAuto    StartType = iota // Start at boot (SERVICE_AUTO_START)
	StartDelayed                  // Start after boot delay (auto + delayed)
	StartManual                   // Manual start only
)

// Config describes a Windows service to install.
type Config struct {
	Name        string    // Service name (internal identifier)
	DisplayName string    // Human-readable display name
	Description string    // Service description
	BinPath     string    // Full path to the service executable
	Args        string    // Command-line arguments (appended to BinPath)
	StartType   StartType // When the service starts

	// Account / Password — optional service-account override. Empty
	// Account (the default) installs the service as
	// `LocalSystem`. Use formats accepted by the SCM:
	//   - ".\\<user>" or "<host>\\<user>" — local account
	//   - "<DOMAIN>\\<user>"               — domain account
	//   - "NT AUTHORITY\\NetworkService" / "NT AUTHORITY\\LocalService"
	//     — built-in low-privilege service accounts (no password)
	//
	// The account MUST hold `SeServiceLogonRight`. Built-in
	// service accounts (`NT AUTHORITY\LocalService`,
	// `NT AUTHORITY\NetworkService`) already do; for everything else
	// call [GrantSeServiceLogonRight] before [Install] (or any other
	// LSA grant tool — `secedit`, `ntrights`, group policy).
	Account  string
	Password string
}

// Install creates a Windows service with the given configuration.
// Requires administrator privileges.
func Install(cfg *Config) error {
	if cfg.Name == "" {
		return fmt.Errorf("service name must not be empty")
	}
	if cfg.BinPath == "" {
		return fmt.Errorf("binary path must not be empty")
	}

	m, err := mgr.Connect()
	if err != nil {
		return mapError(err)
	}
	defer m.Disconnect()

	// Split args into separate strings; mgr.CreateService appends them
	// after the binary path as individual argv entries.
	var args []string
	if cfg.Args != "" {
		args = strings.Fields(cfg.Args)
	}

	s, err := m.CreateService(cfg.Name, cfg.BinPath, mgr.Config{
		DisplayName:      cfg.DisplayName,
		Description:      cfg.Description,
		StartType:        mapStartType(cfg.StartType),
		ServiceStartName: cfg.Account,  // empty → LocalSystem (default)
		Password:         cfg.Password, // ignored for built-in NT AUTHORITY\* accounts
	}, args...)
	if err != nil {
		return mapError(err)
	}
	defer s.Close()

	// Delayed auto-start is a separate flag set after creation.
	if cfg.StartType == StartDelayed {
		// Best-effort: the service is already created, so a failure
		// here only means the delayed flag was not applied.
		_ = setDelayedStart(s)
	}

	return nil
}

// Uninstall removes a Windows service by name.
// Stops the service first if it is running.
func Uninstall(name string) error {
	m, s, err := openService(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	// Best-effort stop before deletion.
	_ = stopService(s)

	if err := s.Delete(); err != nil {
		return mapError(err)
	}
	return nil
}

// Mechanism implements persistence.Mechanism for Windows services.
// Satisfies the interface via duck typing (no parent package import).
type Mechanism struct {
	cfg *Config
}

// Service returns a persistence.Mechanism that manages a Windows service.
func Service(cfg *Config) *Mechanism {
	return &Mechanism{cfg: cfg}
}

func (m *Mechanism) Name() string              { return "service:" + m.cfg.Name }
func (m *Mechanism) Install() error             { return Install(m.cfg) }
func (m *Mechanism) Uninstall() error           { return Uninstall(m.cfg.Name) }
func (m *Mechanism) Installed() (bool, error)   { return Exists(m.cfg.Name), nil }

// Exists checks if a Windows service exists.
func Exists(name string) bool {
	m, s, err := openService(name)
	if err != nil {
		return false
	}
	s.Close()
	m.Disconnect()
	return true
}

// IsRunning checks if a named service is currently running.
func IsRunning(name string) bool {
	m, s, err := openService(name)
	if err != nil {
		return false
	}
	defer m.Disconnect()
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false
	}
	return status.State == svc.Running
}

// Start starts a named service.
func Start(name string) error {
	m, s, err := openService(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	if err := s.Start(); err != nil {
		return mapError(err)
	}
	return nil
}

// Stop stops a named service.
func Stop(name string) error {
	m, s, err := openService(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	return stopService(s)
}

// openService connects to the SCM and opens the named service.
// The caller must close both the service and manager when done.
func openService(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, mapError(err)
	}

	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		return nil, nil, mapError(err)
	}
	return m, s, nil
}

const (
	stopTimeout      = 10 * time.Second
	stopPollInterval = 300 * time.Millisecond
)

// stopService sends a stop control and waits briefly for the service to stop.
func stopService(s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		return mapError(err)
	}

	// Wait up to stopTimeout for the service to reach stopped state.
	deadline := time.Now().Add(stopTimeout)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(stopPollInterval)
		status, err = s.Query()
		if err != nil {
			return mapError(err)
		}
	}
	return nil
}

// mapStartType converts a StartType to the mgr package constant.
func mapStartType(st StartType) uint32 {
	switch st {
	case StartDelayed:
		// Delayed auto-start uses auto as the base type;
		// the delayed flag is set separately after creation.
		return mgr.StartAutomatic
	case StartManual:
		return mgr.StartManual
	default:
		return mgr.StartAutomatic
	}
}

// setDelayedStart enables the delayed auto-start flag on a service.
func setDelayedStart(s *mgr.Service) error {
	info := struct{ DelayedAutostart uint32 }{1}
	return windows.ChangeServiceConfig2(s.Handle,
		windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
		(*byte)(unsafe.Pointer(&info)))
}

// mapError translates common Windows errors to sentinel values
// so callers can use errors.Is without depending on OS-specific codes.
func mapError(err error) error {
	if err == nil {
		return nil
	}

	var errno windows.Errno
	if !errors.As(err, &errno) {
		return err
	}

	switch errno {
	case windows.ERROR_SERVICE_EXISTS:
		return fmt.Errorf("%w", ErrServiceExists)
	case windows.ERROR_SERVICE_DOES_NOT_EXIST:
		return fmt.Errorf("%w", ErrServiceNotFound)
	case windows.ERROR_ACCESS_DENIED:
		return fmt.Errorf("%w", ErrAccessDenied)
	default:
		return err
	}
}
