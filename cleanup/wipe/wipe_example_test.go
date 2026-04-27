package wipe_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/cleanup/wipe"
)

// File overwrites a file with cryptographically random data N times,
// then deletes it. Three passes is the DoD 5220.22-M baseline; one is
// usually enough to defeat undelete utilities.
func ExampleFile() {
	tmp, _ := os.CreateTemp("", "wipe-*")
	tmp.Write([]byte("sensitive data"))
	tmp.Close()

	if err := wipe.File(tmp.Name(), 3); err != nil {
		fmt.Println("wipe:", err)
		return
	}
	if _, err := os.Stat(tmp.Name()); os.IsNotExist(err) {
		fmt.Println("file removed")
	}
	// Output: file removed
}
