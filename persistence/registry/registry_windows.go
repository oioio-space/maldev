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
