//go:build windows

package startup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oioio-space/maldev/persistence/lnk"
	"github.com/oioio-space/maldev/recon/folder"
	"golang.org/x/sys/windows"
)

// UserDir returns the current user's Startup folder path via
// SHGetKnownFolderPath(FOLDERID_Startup) — typically
// `%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp`.
func UserDir() (string, error) {
	dir, err := folder.GetKnown(windows.FOLDERID_Startup, 0)
	if err != nil {
		return "", fmt.Errorf("resolve user startup dir: %w", err)
	}
	return dir, nil
}

// MachineDir returns the machine-wide Startup folder path via
// SHGetKnownFolderPath(FOLDERID_CommonStartup) — typically
// `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`.
func MachineDir() (string, error) {
	dir, err := folder.GetKnown(windows.FOLDERID_CommonStartup, 0)
	if err != nil {
		return "", fmt.Errorf("resolve machine startup dir: %w", err)
	}
	return dir, nil
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

// Shortcut returns a persistence.Mechanism that manages a StartUp folder
// LNK shortcut. Satisfies persistence.Mechanism via duck typing.
func Shortcut(name, targetPath, args string) *ShortcutMechanism {
	return &ShortcutMechanism{name: name, targetPath: targetPath, args: args}
}

// ShortcutMechanism implements persistence.Mechanism for StartUp folder shortcuts.
type ShortcutMechanism struct {
	name       string
	targetPath string
	args       string
}

func (m *ShortcutMechanism) Name() string              { return "startup:user" }
func (m *ShortcutMechanism) Install() error             { return Install(m.name, m.targetPath, m.args) }
func (m *ShortcutMechanism) Uninstall() error           { return Remove(m.name) }
func (m *ShortcutMechanism) Installed() (bool, error)   { return Exists(m.name), nil }

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
