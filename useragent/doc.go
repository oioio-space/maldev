// Package useragent provides a curated database of real browser User-Agent
// strings for realistic HTTP traffic generation.
//
// Technique: User-Agent spoofing for network traffic blending.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — selecting a User-Agent string is a pure data operation.
// Platform: Cross-platform.
//
// How it works: Embeds a JSON database of real-world browser User-Agent strings
// with usage percentage and OS metadata. Provides random selection (weighted by
// real-world prevalence is possible via Filter) and filtering by OS/browser.
// Used by c2/transport and c2/meterpreter to generate realistic HTTP headers
// that blend with legitimate browser traffic.
//
// Limitations:
//   - The embedded database is a snapshot — update useragents.json periodically.
//   - Random selection is uniform; for weighted selection, use Filter + Random.
//
// Example:
//
//	db, _ := useragent.Load()
//	ua := db.Random()           // random User-Agent string
//	chrome := db.Filter(func(u *useragent.Entry) bool {
//	    return strings.Contains(u.Text, "Chrome")
//	})
package useragent
