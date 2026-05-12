// Probe EXE: prints os.Args to a marker file, then exits.
// Used by TestPackBinary_Args_E2E to verify that command-line
// arguments passed to a packed EXE are correctly forwarded to
// the original payload.
//
// Build via testdata/Makefile target `probe_args`:
//   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
//     go build -ldflags='-s -w' -o probe_args.exe ./probe_args.go
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	out := strings.Join(os.Args, "|")
	_ = os.WriteFile(`C:\maldev-args-marker.txt`, []byte(out), 0o644)
	fmt.Println(out)
}
