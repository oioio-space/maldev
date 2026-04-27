//go:build windows

package lnk_test

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/lnk"
)

// New is the fluent builder. Chain SetTargetPath / SetArguments /
// SetWindowStyle, then Save.
func ExampleNew() {
	err := lnk.New().
		SetTargetPath(`C:\Users\Public\impl.exe`).
		SetArguments("--quiet").
		SetWindowStyle(lnk.StyleMinimized).
		Save(`C:\Users\Public\Updater.lnk`)
	if err != nil {
		fmt.Println("save:", err)
	}
}
