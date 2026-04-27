package useragent_test

import (
	"fmt"
	"strings"

	"github.com/oioio-space/maldev/useragent"
)

// Load parses the embedded JSON snapshot. Cheap; safe to call once per
// process.
func ExampleLoad() {
	db, err := useragent.Load()
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	if len(db) == 0 {
		fmt.Println("empty db")
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// Filter selects entries matching a predicate, then Random picks one
// uniformly — common pattern when you want "Chrome on Windows" specifically.
func ExampleDB_Filter() {
	db, _ := useragent.Load()
	chrome := db.Filter(func(e *useragent.Entry) bool {
		return strings.Contains(e.Text, "Chrome")
	})
	_ = chrome // chrome.Random() picks one
}
