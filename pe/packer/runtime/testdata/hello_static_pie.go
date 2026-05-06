// Build (see Makefile):
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
//	  go build -buildmode=pie \
//	  -ldflags='-s -w -d' \
//	  -o hello_static_pie ./hello_static_pie.go
//
// The resulting binary is the runtime test fixture: a Go
// static-PIE that prints "hello from packer\n" and exits.
// Stripped (-s -w) to keep the checked-in size near 1.5 MB
// AND to better resemble a real operator payload (which
// typically also strips symbols).
package main

func main() { print("hello from packer\n") }
