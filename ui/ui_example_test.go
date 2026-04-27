//go:build windows

package ui_test

import (
	"fmt"

	"github.com/oioio-space/maldev/ui"
)

// Show wraps MessageBoxW. Returns the button the user pressed.
func ExampleShow() {
	resp, err := ui.Show("Alert", "Operation complete", ui.MB_OK, ui.MB_ICONINFORMATION)
	if err != nil {
		fmt.Println("show:", err)
		return
	}
	if resp == ui.IDOK {
		fmt.Println("acknowledged")
	}
}

// Beep plays the standard Windows notification sound. Useful as a
// minimal "hello" prompt during red-team exercises.
func ExampleBeep() {
	ui.Beep()
}
