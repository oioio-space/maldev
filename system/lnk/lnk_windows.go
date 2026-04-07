//go:build windows

package lnk

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WindowStyle controls how the shortcut's target window appears on launch.
type WindowStyle int

const (
	// StyleHidden launches the target with no visible window.
	StyleHidden WindowStyle = 0
	// StyleNormal launches the target in a normal window.
	StyleNormal WindowStyle = 1
	// StyleMaximized launches the target in a maximized window.
	StyleMaximized WindowStyle = 3
	// StyleMinimized launches the target in a minimized window.
	StyleMinimized WindowStyle = 7
)

// Shortcut holds the properties for a Windows .lnk file.
// Use [New] to create an instance, configure it with the Set* methods,
// and call [Shortcut.Save] to write the file.
type Shortcut struct {
	targetPath   string
	arguments    string
	workingDir   string
	iconLocation string
	description  string
	hotkey       string
	windowStyle  WindowStyle
	styleSet     bool // track whether the caller explicitly set a style
}

// New returns a zero-value [Shortcut] ready for configuration.
func New() *Shortcut {
	return &Shortcut{}
}

// SetTargetPath sets the executable or document the shortcut points to.
func (s *Shortcut) SetTargetPath(path string) *Shortcut {
	s.targetPath = path
	return s
}

// SetArguments sets command-line arguments passed to the target.
func (s *Shortcut) SetArguments(args string) *Shortcut {
	s.arguments = args
	return s
}

// SetWorkingDir sets the working directory for the target process.
func (s *Shortcut) SetWorkingDir(dir string) *Shortcut {
	s.workingDir = dir
	return s
}

// SetIconLocation sets the icon path (e.g. "shell32.dll,3").
func (s *Shortcut) SetIconLocation(icon string) *Shortcut {
	s.iconLocation = icon
	return s
}

// SetDescription sets the shortcut's descriptive text (tooltip).
func (s *Shortcut) SetDescription(desc string) *Shortcut {
	s.description = desc
	return s
}

// SetHotkey sets the keyboard shortcut (e.g. "Ctrl+Alt+T").
func (s *Shortcut) SetHotkey(hotkey string) *Shortcut {
	s.hotkey = hotkey
	return s
}

// SetWindowStyle sets how the target window is displayed on launch.
func (s *Shortcut) SetWindowStyle(style WindowStyle) *Shortcut {
	s.windowStyle = style
	s.styleSet = true
	return s
}

// Save creates or overwrites the .lnk file at the given path using COM/OLE.
// The caller does not need to manage COM initialization; Save handles the
// full lifecycle (CoInitializeEx, object creation, cleanup) internally.
func (s *Shortcut) Save(path string) error {
	// COM calls must stay on the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_SPEED_OVER_MEMORY); err != nil {
		// S_FALSE (0x00000001) means COM was already initialized on this
		// thread — safe to continue, but we must still balance the call
		// with CoUninitialize.
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 0x00000001 {
			return fmt.Errorf("lnk: COM init: %w", err)
		}
	}
	defer ole.CoUninitialize()

	shell, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return fmt.Errorf("lnk: create shell object: %w", err)
	}
	defer shell.Release()

	dispatch, err := shell.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("lnk: query dispatch: %w", err)
	}
	defer dispatch.Release()

	cs, err := oleutil.CallMethod(dispatch, "CreateShortcut", path)
	if err != nil {
		return fmt.Errorf("lnk: create shortcut dispatch: %w", err)
	}
	shortcutDisp := cs.ToIDispatch()
	defer shortcutDisp.Release()

	// Apply every non-empty property. Omitting empty fields lets the
	// system defaults take effect, which avoids writing garbage into the
	// .lnk structure.
	props := []struct {
		name string
		val  string
	}{
		{"TargetPath", s.targetPath},
		{"Arguments", s.arguments},
		{"WorkingDirectory", s.workingDir},
		{"IconLocation", s.iconLocation},
		{"Description", s.description},
		{"Hotkey", s.hotkey},
	}
	for _, p := range props {
		if p.val == "" {
			continue
		}
		if _, err := oleutil.PutProperty(shortcutDisp, p.name, p.val); err != nil {
			return fmt.Errorf("lnk: set %s: %w", p.name, err)
		}
	}

	if s.styleSet {
		if _, err := oleutil.PutProperty(shortcutDisp, "WindowStyle", int(s.windowStyle)); err != nil {
			return fmt.Errorf("lnk: set WindowStyle: %w", err)
		}
	}

	if _, err := oleutil.CallMethod(shortcutDisp, "Save"); err != nil {
		return fmt.Errorf("lnk: save: %w", err)
	}

	return nil
}
