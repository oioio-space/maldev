package timestomp_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oioio-space/maldev/cleanup/timestomp"
)

// Set assigns specific access and modification times to a file. Useful
// when you want a deterministic "old" date rather than cloning a
// reference file.
func ExampleSet() {
	tmp, _ := os.CreateTemp("", "stomp-*")
	defer os.Remove(tmp.Name())
	tmp.Close()

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := timestomp.Set(tmp.Name(), old, old); err != nil {
		fmt.Println("set:", err)
		return
	}
	fi, _ := os.Stat(tmp.Name())
	fmt.Println(fi.ModTime().Year())
	// Output: 2020
}

// CopyFrom clones timestamps from a reference file to a target. Common
// pattern: clone notepad.exe to make a dropped artefact look like a
// system binary.
func ExampleCopyFrom() {
	dir, _ := os.MkdirTemp("", "stomp-*")
	defer os.RemoveAll(dir)

	ref := filepath.Join(dir, "ref")
	tgt := filepath.Join(dir, "tgt")
	_ = os.WriteFile(ref, []byte("reference"), 0o644)
	_ = os.WriteFile(tgt, []byte("target"), 0o644)
	old := time.Date(2018, 6, 1, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(ref, old, old)

	if err := timestomp.CopyFrom(ref, tgt); err != nil {
		fmt.Println("copy:", err)
		return
	}
	fi, _ := os.Stat(tgt)
	fmt.Println(fi.ModTime().Year())
	// Output: 2018
}
