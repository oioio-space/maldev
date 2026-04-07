//go:build windows

package startup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oioio-space/maldev/system/lnk"
)

const (
	// Relative path from AppData/Roaming to the user's Startup folder.
	userStartupRel = `Microsoft\Windows\Start Menu\Programs\Startup`

	// Absolute path for the machine-wide Startup folder.
	machineStartupDir = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
)

// UserDir returns the current user's Startup folder path.
func UserDir() (string, error) {
	appData, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(appData, userStartupRel), nil
}

// MachineDir returns the machine-wide Startup folder path.
func MachineDir() (string, error) {
	return machineStartupDir, nil
}

// Install creates a .lnk shortcut in the user's Startup folder.
// name is the shortcut filename (without .lnk extension).
// targetPath is the executable to run at logon.
// args are optional command-line arguments.
func Install(name, targetPath, args string) error {
	dir, err := UserDir()
	if err != nil {
		return err
	}
	return install(dir, name, targetPath, args)
}

// InstallMachine creates a .lnk shortcut in the machine-wide Startup folder.
// Requires elevated privileges.
func InstallMachine(name, targetPath, args string) error {
	dir, err := MachineDir()
	if err != nil {
		return err
	}
	return install(dir, name, targetPath, args)
}

// install creates a .lnk shortcut in the given directory.
func install(dir, name, targetPath, args string) error {
	lnkPath := filepath.Join(dir, name+".lnk")

	b := lnk.New().
		SetTargetPath(targetPath).
		SetArguments(args)

	return b.Save(lnkPath)
}

// Remove removes a .lnk shortcut from the user's Startup folder.
func Remove(name string) error {
	dir, err := UserDir()
	if err != nil {
		return err
	}
	return remove(dir, name)
}

// RemoveMachine removes a .lnk shortcut from the machine-wide Startup folder.
func RemoveMachine(name string) error {
	dir, err := MachineDir()
	if err != nil {
		return err
	}
	return remove(dir, name)
}

// remove deletes a .lnk file from the given directory.
func remove(dir, name string) error {
	lnkPath := filepath.Join(dir, name+".lnk")
	if err := os.Remove(lnkPath); err != nil {
		return fmt.Errorf("remove shortcut: %w", err)
	}
	return nil
}

// Exists checks if a shortcut exists in the user's Startup folder.
func Exists(name string) bool {
	dir, err := UserDir()
	if err != nil {
		return false
	}
	lnkPath := filepath.Join(dir, name+".lnk")
	_, err = os.Stat(lnkPath)
	return err == nil
}
