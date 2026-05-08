// Builds via testdata/Makefile:
//
//	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
//	  go build -ldflags='-s -w' -o winhello.exe ./winhello.go
//
// The resulting PE32+ is the Windows-side packer test fixture
// (see TestPackBinary_WindowsPE_PackTimeMultiSeed). Stripped
// (-s -w) to keep the checked-in size near 1.6 MB and to better
// resemble a real operator payload.
//
// Note: this file lives under pe/packer/testdata which Go's
// build system ignores — the package literal exists only so the
// `go build ./winhello.go` invocation can find a main.

package main

import "fmt"

func main() { fmt.Println("hello from windows") }
