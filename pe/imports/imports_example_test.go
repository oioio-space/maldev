package imports_test

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/imports"
)

// List walks the PE import directory and returns every (DLL,
// Function) pair the binary depends on.
func ExampleList() {
	imps, err := imports.List(`C:\Windows\System32\notepad.exe`)
	if err != nil {
		return
	}
	for _, imp := range imps[:min(3, len(imps))] {
		fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
	}
}
