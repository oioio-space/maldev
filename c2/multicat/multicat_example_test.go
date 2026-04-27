package multicat_test

import (
	"fmt"

	"github.com/oioio-space/maldev/c2/multicat"
)

// New builds a manager. Listen attaches it to a transport.Listener
// (TCP or TLS); inbound shells are demultiplexed into numbered
// sessions. Lifecycle events surface on the Events channel.
func ExampleNew() {
	mgr := multicat.New()
	for ev := range mgr.Events() {
		fmt.Printf("[%v] session %v\n", ev.Type, ev.Session)
	}
}
