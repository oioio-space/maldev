package random_test

import (
	"fmt"
	"time"

	"github.com/oioio-space/maldev/random"
)

// 32 random bytes for a fresh AES key.
func ExampleBytes() {
	key, err := random.Bytes(32)
	if err != nil {
		fmt.Println("rand:", err)
		return
	}
	fmt.Println(len(key))
	// Output: 32
}

// Random duration — useful for callback jitter so beacons don't beat
// at predictable intervals.
func ExampleDuration() {
	jitter, _ := random.Duration(100*time.Millisecond, 500*time.Millisecond)
	if jitter < 100*time.Millisecond || jitter > 500*time.Millisecond {
		fmt.Println("out of range")
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// Alphanumeric string of n characters.
func ExampleString() {
	s, _ := random.String(8)
	fmt.Println(len(s))
	// Output: 8
}
