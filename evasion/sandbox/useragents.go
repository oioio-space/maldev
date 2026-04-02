package sandbox

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"math/big"
)

//go:embed useragents.json
var userAgentsJSON []byte

// UserAgent represents a single browser user-agent string with usage metadata.
type UserAgent struct {
	Percent string `json:"percent"`
	Text    string `json:"useragent"`
	System  string `json:"system"`
}

// String returns the user-agent string.
func (ua UserAgent) String() string { return ua.Text }

// UserAgents is a slice of UserAgent pointers.
type UserAgents []*UserAgent

// LoadUserAgents parses the embedded useragents.json and returns a UserAgents list.
func LoadUserAgents() (*UserAgents, error) {
	uas := new(UserAgents)
	if err := json.Unmarshal(userAgentsJSON, uas); err != nil {
		return nil, err
	}
	return uas, nil
}

// Random returns a random UserAgent from the list, or nil if the list is empty.
func (uas *UserAgents) Random() *UserAgent {
	if len(*uas) == 0 {
		return nil
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(*uas))))
	return (*uas)[n.Int64()]
}

// Filter returns a new UserAgents containing only entries for which fn returns true.
func (uas *UserAgents) Filter(fn func(ua *UserAgent) bool) *UserAgents {
	out := new(UserAgents)
	*out = make(UserAgents, 0)
	for _, ua := range *uas {
		if fn(ua) {
			*out = append(*out, ua)
		}
	}
	return out
}
