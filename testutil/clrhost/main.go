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
	op := flag.String("op", "", "operation: load | exec-empty | exec-dll-validation | exec-dll-real")
	dllPath := flag.String("dll-path", "", "path to a .NET DLL for --op=exec-dll-real (reads at runtime, not embedded)")
	dllType := flag.String("dll-type", "Maldev.TestClass", "type name (Namespace.Type) for --op=exec-dll-real")
	dllMethod := flag.String("dll-method", "Run", "method name for --op=exec-dll-real")
	dllArg := flag.String("dll-arg", "hello", "string arg for --op=exec-dll-real")
	flag.Parse()

	// Force-write <exe>.config with useLegacyV2RuntimeActivationPolicy=true
	// on every invocation. The committed clrhost.exe.config that buildClrhost
	// copies next to the binary has sometimes failed to be honoured by
	// mscoree after a snapshot revert (observed: ICorRuntimeHost unavailable
	// even when .NET 3.5 is enabled). Writing again just before Load is
	// idempotent and removes the flakiness.
	if err := clr.InstallRuntimeActivationPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "InstallRuntimeActivationPolicy: %v\n", err)
		// Don't exit — Load may still succeed if the committed config holds.
	}

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
	case "exec-dll-real":
		// Real assembly path: exercises SafeArray+method-dispatch code in
		// pe/clr/clr_windows.go (ExecuteDLL → loadAssembly → newBstrSafeArray
		// → defaultDomainDispatch → newByteSafeArray / newVariantSafeArrayWithOne).
		// The DLL is passed by path rather than embedded: an embedded blob
		// significantly changes the PE layout, and on some Win10 builds
		// mscoree then refuses to honour <exe>.config legacy-v2 activation
		// (observed: exit-2 "ICorRuntimeHost unavailable" regression).
		if *dllPath == "" {
			fmt.Fprintln(os.Stderr, "exec-dll-real: --dll-path is required")
			os.Exit(4)
		}
		dll, rerr := os.ReadFile(*dllPath)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", *dllPath, rerr)
			os.Exit(4)
		}
		if err := rt.ExecuteDLL(dll, *dllType, *dllMethod, *dllArg); err != nil {
			fmt.Fprintf(os.Stderr, "ExecuteDLL failed: %v\n", err)
			os.Exit(3)
		}
		fmt.Println("EXEC_DLL_REAL_OK")
	default:
		fmt.Fprintf(os.Stderr, "unknown --op: %q\n", *op)
		os.Exit(4)
	}
}
