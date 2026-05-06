// Build (see Makefile):
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
//	  go build -buildmode=pie \
//	  -ldflags='-s -w' \
//	  -o hello_static_pie ./hello_static_pie.go
//
// The resulting binary is the runtime test fixture: a Go
// static-PIE that prints "hello from packer\n" and exits.
// Stripped (-s -w) to keep the checked-in size near 1.5 MB
// AND to better resemble a real operator payload (which
// typically also strips symbols).
//
// Note: -ldflags='-d' is intentionally absent. That flag drops
// PT_DYNAMIC and all RELA entries, leaving absolute pointers in
// .data.rel.ro unrelocated — the binary would fault at any load
// address other than the compile-time base. Without -d the linker
// emits a proper RELA table (R_X86_64_RELATIVE entries) that the
// Stage B mapper applies, and the binary runs correctly under ASLR.
package main

func main() { print("hello from packer\n") }
