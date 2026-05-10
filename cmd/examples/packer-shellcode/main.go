// packer-shellcode — runnable companion to Mode 6 of
// docs/techniques/pe/packer.md.
//
// Reads raw shellcode bytes from a file (msfvenom output, hand-rolled
// stage-1, etc.) and produces a runnable PE32+ (Windows) or ELF64
// (Linux) host that runs the shellcode at the entry point — with or
// without the SGN-style stub envelope.
//
// Demonstrates the four operational shapes of Mode 6:
//
//	plain ELF       (no encryption, smallest output ~400 B)
//	encrypted ELF   (SGN stub, ~8 KiB)
//	plain PE        (no encryption, smallest output ~1 KiB)
//	encrypted PE    (SGN stub, ~8 KiB)
//
// Plus the symmetric defender path:
//
//	UnwrapShellcode  reverse the plain wrap → recover raw bytes
//
// Usage:
//
//	go build -o /tmp/packer-shellcode ./cmd/examples/packer-shellcode
//	/tmp/packer-shellcode <shellcode.bin> <output-prefix>
//
// Produces 4 files alongside <output-prefix>:
//
//	<prefix>-plain.elf
//	<prefix>-enc.elf
//	<prefix>-plain.exe
//	<prefix>-enc.exe
//
// Cross-platform pack-time — runs on linux/windows/darwin. Each
// produced binary runs on the platform matching its detected format.
package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <shellcode.bin> <output-prefix>\n", os.Args[0])
		os.Exit(2)
	}
	sc, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read shellcode: %v\n", err)
		os.Exit(1)
	}
	if len(sc) == 0 {
		fmt.Fprintln(os.Stderr, "shellcode file is empty")
		os.Exit(1)
	}
	prefix := os.Args[2]
	seed := time.Now().UnixNano()

	wrap := func(name string, opts packer.PackShellcodeOptions) {
		opts.Seed = seed
		out, key, err := packer.PackShellcode(sc, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(1)
		}
		path := prefix + "-" + name
		if err := os.WriteFile(path, out, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("%-12s %d B → %s", name, len(out), path)
		if key != nil {
			fmt.Printf("  key=%x...", key[:4])
		}
		fmt.Println()
	}

	wrap("plain.elf", packer.PackShellcodeOptions{Format: packer.FormatLinuxELF})
	wrap("enc.elf", packer.PackShellcodeOptions{Format: packer.FormatLinuxELF, Encrypt: true})
	wrap("plain.exe", packer.PackShellcodeOptions{Format: packer.FormatWindowsExe})
	wrap("enc.exe", packer.PackShellcodeOptions{Format: packer.FormatWindowsExe, Encrypt: true})

	// Defender side: the plain wrap is reversible without a key.
	plainPath := prefix + "-plain.elf"
	plain, _ := os.ReadFile(plainPath)
	recovered, err := packer.UnwrapShellcode(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UnwrapShellcode: %v\n", err)
		os.Exit(1)
	}
	if bytes.Equal(recovered, sc) {
		fmt.Printf("\nUnwrap %-7s %d B recovered byte-perfect from %s\n",
			"plain.elf", len(recovered), plainPath)
	} else {
		fmt.Fprintf(os.Stderr, "\nUnwrap mismatch: got %d B, want %d B\n",
			len(recovered), len(sc))
		os.Exit(1)
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  Linux:   chmod +x", prefix+"-{plain,enc}.elf && ./"+prefix+"-plain.elf; echo $?")
	fmt.Println("  Windows: copy *.exe to a Windows host, run, observe exit code via $LASTEXITCODE")
}
