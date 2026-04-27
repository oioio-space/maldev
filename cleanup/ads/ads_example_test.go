//go:build windows

package ads_test

import (
	"fmt"

	"github.com/oioio-space/maldev/cleanup/ads"
)

// Write a payload into a named NTFS Alternate Data Stream, then read it
// back. The file's default stream is unaffected.
func ExampleWrite() {
	const path = `C:\Users\Public\desktop.ini`

	if err := ads.Write(path, "config", []byte("c2=1.2.3.4")); err != nil {
		fmt.Println("write:", err)
		return
	}

	data, err := ads.Read(path, "config")
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Println(string(data))

	_ = ads.Delete(path, "config")
}

// List enumerates every named stream attached to a file.
func ExampleList() {
	streams, err := ads.List(`C:\Users\Public\desktop.ini`)
	if err != nil {
		fmt.Println("list:", err)
		return
	}
	for _, s := range streams {
		fmt.Println(s)
	}
}
