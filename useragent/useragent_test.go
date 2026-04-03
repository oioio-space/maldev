package useragent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	db, err := Load()
	require.NoError(t, err)
	assert.NotEmpty(t, db, "should load at least one user agent")
}

func TestRandom(t *testing.T) {
	db, err := Load()
	require.NoError(t, err)

	ua := db.Random()
	require.NotNil(t, ua)
	assert.NotEmpty(t, ua.Text)
	assert.NotEmpty(t, ua.String())
}

func TestRandomString(t *testing.T) {
	db, err := Load()
	require.NoError(t, err)
	s := db.RandomString("fallback")
	assert.NotEqual(t, "fallback", s)
}

func TestRandomString_EmptyDB(t *testing.T) {
	var db DB
	s := db.RandomString("fallback")
	assert.Equal(t, "fallback", s)
}

func TestRandom_EmptyDB(t *testing.T) {
	var db DB
	assert.Nil(t, db.Random())
}

func TestFilter(t *testing.T) {
	db, err := Load()
	require.NoError(t, err)

	chrome := db.Filter(func(e *Entry) bool {
		return strings.Contains(e.Text, "Chrome")
	})
	assert.NotEmpty(t, chrome)
	for _, e := range chrome {
		assert.Contains(t, e.Text, "Chrome")
	}
}

func TestChrome(t *testing.T) {
	db, _ := Load()
	chrome := db.Chrome()
	assert.NotEmpty(t, chrome)
}

func TestFirefox(t *testing.T) {
	db, _ := Load()
	ff := db.Firefox()
	// Firefox may or may not be in the DB — just verify no panic
	_ = ff
}

func TestWindows(t *testing.T) {
	db, _ := Load()
	win := db.Windows()
	assert.NotEmpty(t, win, "should have Windows user agents")
}

func TestChainedFilter(t *testing.T) {
	db, _ := Load()
	winChrome := db.Windows().Chrome()
	if len(winChrome) > 0 {
		ua := winChrome.Random()
		assert.Contains(t, ua.Text, "Chrome")
		assert.Contains(t, ua.System, "Win")
	}
}
