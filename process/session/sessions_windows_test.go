//go:build windows

package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	sessions, err := List()
	require.NoError(t, err)
	// Every Windows box has at least the Services session (ID 0) and an
	// RDP-Tcp listener, so List must return at least those two.
	require.NotEmpty(t, sessions)

	var sawServices bool
	for _, s := range sessions {
		t.Logf("session id=%d name=%q state=%s user=%q domain=%q",
			s.ID, s.Name, s.State, s.User, s.Domain)
		if s.ID == 0 {
			sawServices = true
		}
	}
	assert.True(t, sawServices, "session 0 (Services) must always be reported")
}

func TestActiveSubsetOfList(t *testing.T) {
	all, err := List()
	require.NoError(t, err)
	active, err := Active()
	require.NoError(t, err)

	ids := map[uint32]bool{}
	for _, s := range all {
		ids[s.ID] = true
	}
	for _, s := range active {
		assert.True(t, ids[s.ID], "Active session %d must also appear in List", s.ID)
		assert.Equal(t, StateActive, s.State)
		assert.NotEmpty(t, s.User, "Active filter must exclude sessions without a user")
	}
}

func TestSessionStateString(t *testing.T) {
	cases := []struct {
		state SessionState
		want  string
	}{
		{StateActive, "Active"},
		{StateDisconnected, "Disconnected"},
		{StateListen, "Listen"},
		{SessionState(99), "Unknown(99)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.state.String())
	}
}
