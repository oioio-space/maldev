package parse_test

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/parse"
)

// Open reads a PE file from disk and returns a *File wrapping the
// stdlib debug/pe representation plus the raw bytes for downstream
// pe/strip and pe/morph workflows.
func ExampleOpen() {
	f, err := parse.Open(`C:\Windows\System32\notepad.exe`)
	if err != nil {
		return
	}
	fmt.Printf("sections: %d\n", len(f.PE.Sections))
}
