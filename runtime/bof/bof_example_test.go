//go:build windows

package bof_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/runtime/bof"
)

// Load parses a COFF .o file. Validates machine type, sections, and
// symbol table.
func ExampleLoad() {
	data, err := os.ReadFile(`C:\Users\Public\hello.x64.o`)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	b, err := bof.Load(data)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	fmt.Printf("entry: %s, %d bytes\n", b.Entry, len(b.Data))
}

// NewArgs builds a Beacon-format argument blob the BOF reads via
// BeaconDataParse: each value prefixed with its length.
func ExampleNewArgs() {
	args := bof.NewArgs()
	args.AddString("hello world")
	args.AddInt(42)
	_ = args.Pack()
}

// Execute runs the parsed BOF with packed args. Returns the BOF's
// stdout-equivalent (Beacon BeaconOutput buffer).
func ExampleBOF_Execute() {
	data, _ := os.ReadFile(`C:\Users\Public\hello.x64.o`)
	b, _ := bof.Load(data)
	args := bof.NewArgs()
	args.AddString("world")
	out, err := b.Execute(args.Pack())
	if err != nil {
		fmt.Println("exec:", err)
		return
	}
	fmt.Println(string(out))
}
