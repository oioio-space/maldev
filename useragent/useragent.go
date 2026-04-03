package useragent

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
)

//go:embed useragents.json
var embeddedJSON []byte

// Entry represents a single browser User-Agent string with usage metadata.
type Entry struct {
	Percent string `json:"percent"` // Usage share (e.g., "26.4%")
	Text    string `json:"useragent"`
	System  string `json:"system"` // OS description (e.g., "Win10")
}

// String returns the User-Agent string.
func (e *Entry) String() string { return e.Text }

// DB is a collection of User-Agent entries.
type DB []*Entry

var (
	cachedDB   DB
	cachedErr  error
	loadOnce   sync.Once
)

// Load parses the embedded useragents.json and returns a cached DB.
// The JSON is parsed only once; subsequent calls return the same DB.
func Load() (DB, error) {
	loadOnce.Do(func() {
		cachedErr = json.Unmarshal(embeddedJSON, &cachedDB)
	})
	return cachedDB, cachedErr
}

// Random returns a random Entry from the database.
// Returns nil if the DB is empty.
func (db DB) Random() *Entry {
	if len(db) == 0 {
		return nil
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(db))))
	return db[n.Int64()]
}

// RandomString returns a random User-Agent string, or fallback if DB is empty.
func (db DB) RandomString(fallback string) string {
	e := db.Random()
	if e == nil {
		return fallback
	}
	return e.Text
}

// Filter returns a new DB containing only entries for which fn returns true.
func (db DB) Filter(fn func(e *Entry) bool) DB {
	var out DB
	for _, e := range db {
		if fn(e) {
			out = append(out, e)
		}
	}
	return out
}

// Chrome returns entries containing "Chrome" in the User-Agent string.
func (db DB) Chrome() DB {
	return db.Filter(func(e *Entry) bool { return strings.Contains(e.Text, "Chrome") })
}

// Firefox returns entries containing "Firefox" in the User-Agent string.
func (db DB) Firefox() DB {
	return db.Filter(func(e *Entry) bool { return strings.Contains(e.Text, "Firefox") })
}

// Windows returns entries for Windows systems.
func (db DB) Windows() DB {
	return db.Filter(func(e *Entry) bool { return strings.Contains(e.System, "Win") })
}
