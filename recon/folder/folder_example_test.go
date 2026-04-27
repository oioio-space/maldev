//go:build windows

package folder_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/folder"
)

// Get resolves a Windows special folder path. The OS handles
// per-user / per-machine + folder-redirection differences
// transparently.
func ExampleGet() {
	appdata := folder.Get(folder.CSIDL_APPDATA, false)
	startup := folder.Get(folder.CSIDL_STARTUP, false)
	fmt.Println(appdata, startup)
}
