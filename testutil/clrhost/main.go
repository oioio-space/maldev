// clrhost is a test helper binary that runs pe/clr operations in a
// fresh Windows process next to a committed <exe>.config enabling
// useLegacyV2RuntimeActivationPolicy — so mscoree honours the legacy v2
// activation path that Go test binaries cannot trigger on Win10+.
//
// Spawn it from testutil.RunCLROperation; never depend on it from tests
// directly. Exit codes:
//
//	0  — operation succeeded
//	2  — pe/clr.Load failed (environmental; test should Skip)
//	3  — operation returned an unexpected error (test should Fail)
//	4  — unknown --op flag
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/oioio-space/maldev/pe/clr"
)

func main() {
	op := flag.String("op", "", "operation: load | exec-empty | exec-dll-validation")
	flag.Parse()

	rt, err := clr.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load: %v\n", err)
		os.Exit(2)
	}
	defer rt.Close()

	switch *op {
	case "load":
		fmt.Println("LOAD_OK")
	case "exec-empty":
		if err := rt.ExecuteAssembly(nil, nil); err == nil || !strings.Contains(err.Error(), "empty") {
			fmt.Fprintf(os.Stderr, "expected 'empty' error, got: %v\n", err)
			os.Exit(3)
		}
		fmt.Println("EXEC_EMPTY_OK")
	case "exec-dll-validation":
		cases := []struct {
			name    string
			dll     []byte
			typ     string
			method  string
			arg     string
		}{
			{"empty dll", nil, "T", "M", ""},
			{"missing type", []byte{0x4D, 0x5A}, "", "M", ""},
			{"missing method", []byte{0x4D, 0x5A}, "T", "", ""},
		}
		for _, c := range cases {
			if err := rt.ExecuteDLL(c.dll, c.typ, c.method, c.arg); err == nil {
				fmt.Fprintf(os.Stderr, "%s: expected error, got nil\n", c.name)
				os.Exit(3)
			}
		}
		fmt.Println("EXEC_DLL_VALIDATION_OK")
	default:
		fmt.Fprintf(os.Stderr, "unknown --op: %q\n", *op)
		os.Exit(4)
	}
}
