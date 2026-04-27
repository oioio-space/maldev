// Package drive enumerates Windows logical drives and watches
// for newly connected removable / network volumes.
//
// Drive enumeration via `GetLogicalDrives` + `GetDriveTypeW` +
// `GetVolumeInformationW`. Each [Info] carries letter, type
// (`Fixed` / `Removable` / `Network` / …), and volume metadata
// (name, serial, filesystem). [Watcher] polls a snapshot at a
// configurable interval and emits Add / Remove events as
// drives appear and disappear.
//
// Used to discover USB-key insertion (data-staging trigger),
// new SMB shares (lateral-movement candidates), and
// removable-media events for triggered-execution payloads.
//
// # MITRE ATT&CK
//
//   - T1120 (Peripheral Device Discovery)
//   - T1083 (File and Directory Discovery) — sibling discovery primitive
//
// # Detection level
//
// quiet
//
// Drive enumeration is standard system behaviour; every
// shell, file manager, AV, and backup tool calls these APIs
// continuously. Polling intervals are configurable — sub-100 ms
// polling may stand out behaviourally on idle systems.
//
// # Example
//
// See [ExampleNew] and [ExampleNewWatcher] in drive_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/drive.md
//   - [github.com/oioio-space/maldev/recon/folder] — sibling Windows special-folder resolution
//   - [github.com/oioio-space/maldev/cleanup] — pair to clean staged data on removable media
//
// [github.com/oioio-space/maldev/recon/folder]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/folder
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package drive
