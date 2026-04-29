//go:build windows

package lnk_test

import (
	"bytes"
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

// BuildBytes serialises the shortcut entirely in memory — useful
// when the operator wants to encrypt, embed, or transport the LNK
// without touching the disk at any point.
func ExampleShortcut_BuildBytes() {
	raw, err := lnk.New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetArguments("/c whoami").
		SetWindowStyle(lnk.StyleMinimized).
		BuildBytes()
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Printf("lnk bytes: %d\n", len(raw))
}

// WriteTo streams the same zero-disk serialisation into any
// io.Writer the operator controls.
func ExampleShortcut_WriteTo() {
	var buf bytes.Buffer
	if _, err := lnk.New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		WriteTo(&buf); err != nil {
		fmt.Println("write:", err)
	}
}
