//go:build windows

package registry

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// ErrNotFound is returned when the requested registry value does not exist.
var ErrNotFound = errors.New("registry value not found")

// Hive specifies which registry root to use.
type Hive int

const (
	HiveCurrentUser  Hive = iota // HKCU — per-user, no elevation required
	HiveLocalMachine             // HKLM — machine-wide, requires elevation
)

// KeyType specifies which autostart key to target.
type KeyType int

const (
	KeyRun     KeyType = iota // Persistent across reboots
	KeyRunOnce                // Deleted after first execution
)

// keyPath returns the full registry subkey path for the given hive and key type.
func keyPath(keyType KeyType) string {
	switch keyType {
	case KeyRunOnce:
		return `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	default:
		return `Software\Microsoft\Windows\CurrentVersion\Run`
	}
}

// rootKey maps a Hive to the corresponding registry.Key root.
func rootKey(hive Hive) registry.Key {
	switch hive {
	case HiveLocalMachine:
		return registry.LOCAL_MACHINE
	default:
		return registry.CURRENT_USER
	}
}

// Set creates or updates a string value in the specified Run/RunOnce key.
func Set(hive Hive, keyType KeyType, name, value string) error {
	k, err := registry.OpenKey(rootKey(hive), keyPath(keyType),
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue(name, value); err != nil {
		return fmt.Errorf("set registry value: %w", err)
	}
	return nil
}

// Get retrieves a string value from the specified Run/RunOnce key.
// Returns ErrNotFound if the value does not exist.
func Get(hive Hive, keyType KeyType, name string) (string, error) {
	k, err := registry.OpenKey(rootKey(hive), keyPath(keyType), registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	val, _, err := k.GetStringValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get registry value: %w", err)
	}
	return val, nil
}

// Delete removes a value from the specified Run/RunOnce key.
func Delete(hive Hive, keyType KeyType, name string) error {
	k, err := registry.OpenKey(rootKey(hive), keyPath(keyType), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.DeleteValue(name); err != nil {
		return fmt.Errorf("delete registry value: %w", err)
	}
	return nil
}

// RunKey returns a persistence.Mechanism that manages a Run/RunOnce registry
// value. Satisfies the persistence.Mechanism interface via duck typing.
func RunKey(hive Hive, keyType KeyType, name, value string) *RunKeyMechanism {
	return &RunKeyMechanism{hive: hive, keyType: keyType, name: name, value: value}
}

// RunKeyMechanism implements persistence.Mechanism for registry Run/RunOnce keys.
type RunKeyMechanism struct {
	hive    Hive
	keyType KeyType
	name    string
	value   string
}

func (m *RunKeyMechanism) Name() string {
	h := "HKCU"
	if m.hive == HiveLocalMachine {
		h = "HKLM"
	}
	k := "Run"
	if m.keyType == KeyRunOnce {
		k = "RunOnce"
	}
	return "registry:" + h + ":" + k
}

func (m *RunKeyMechanism) Install() error   { return Set(m.hive, m.keyType, m.name, m.value) }
func (m *RunKeyMechanism) Uninstall() error { return Delete(m.hive, m.keyType, m.name) }
func (m *RunKeyMechanism) Installed() (bool, error) {
	return Exists(m.hive, m.keyType, m.name)
}

// Exists checks whether a value exists in the specified Run/RunOnce key.
func Exists(hive Hive, keyType KeyType, name string) (bool, error) {
	_, err := Get(hive, keyType, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
