package enum_test

import (
	"fmt"

	"github.com/oioio-space/maldev/process/enum"
)

// FindByName returns every running process whose image base
// matches the given name (case-insensitive on Windows).
// Empty when nothing matches.
func ExampleFindByName() {
	procs, err := enum.FindByName("explorer.exe")
	if err != nil {
		return
	}
	for _, p := range procs {
		fmt.Printf("PID=%d PPID=%d\n", p.PID, p.PPID)
	}
}

// List walks every running process — Windows via
// CreateToolhelp32Snapshot, Linux via /proc.
func ExampleList() {
	procs, err := enum.List()
	if err != nil {
		return
	}
	fmt.Printf("%d processes\n", len(procs))
}
