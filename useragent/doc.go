// Package useragent provides a curated database of real-world browser
// User-Agent strings for HTTP traffic blending.
//
// Embeds a JSON snapshot keyed by browser/OS with usage-percentage
// metadata. `Load` parses the embedded snapshot; `DB.Random` picks a
// random entry; `DB.Filter` selects by predicate (e.g.,
// `Chrome`-only); `DB.Filter(...).Random()` chains. Used by
// `c2/transport` and `c2/meterpreter` to set realistic User-Agent
// headers.
//
// # MITRE ATT&CK
//
//   - T1071.001 (Application Layer Protocol: Web Protocols) — supplies
//     the User-Agent header for HTTP-based C2.
//
// # Detection level
//
// very-quiet
//
// Pure data — picking a string is invisible.
//
// # Example
//
// See [ExampleLoad] and [ExampleDB_Random] in useragent_example_test.go.
//
// # See also
//
//   - [github.com/oioio-space/maldev/c2/transport] — HTTP transport consumer
//
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
package useragent
