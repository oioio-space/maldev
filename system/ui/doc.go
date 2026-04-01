//go:build windows

// Package ui provides Windows UI utilities such as message boxes and system sounds.
//
// Platform: Windows
// Detection: Low -- message boxes are standard Windows UI elements.
//
// The Show function wraps MessageBoxW with a type-safe API for button types,
// modality, icons, default buttons, and additional options. The Beep function
// plays a system alert sound via MessageBeep.
//
// Example:
//
//	resp, _ := ui.Show("Alert", "Operation complete", ui.MB_OK, ui.MB_ICONINFORMATION)
//	if resp == ui.IDOK {
//	    // user acknowledged
//	}
package ui
