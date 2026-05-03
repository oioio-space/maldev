//go:build windows

package main

import (
	"io"

	// DOC-DRIFT (c2/namedpipe.md): doc imports `c2/namedpipe`; real path
	// is `c2/transport/namedpipe`.
	"github.com/oioio-space/maldev/c2/transport/namedpipe"
)

// namedpipeNewListener wraps the documented constructor in a thin shim so
// the audit can detect signature drift in one place.
func namedpipeNewListener(name string) (io.Closer, error) {
	return namedpipe.NewListener(name)
}
