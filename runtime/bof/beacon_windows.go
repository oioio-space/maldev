//go:build windows

package bof

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

// beaconOutput is a thread-safe buffer for capturing BOF output.
type beaconOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newBeaconOutput() *beaconOutput {
	return &beaconOutput{}
}

func (o *beaconOutput) printf(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(&o.buf, format, args...)
}

func (o *beaconOutput) write(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf.Write(data)
}

func (o *beaconOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *beaconOutput) Bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	b := o.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Args packs arguments into the format expected by the BOF entry point.
// BOF loaders expect a flat buffer where each argument is prefixed with
// its length — this mirrors the Cobalt Strike BeaconDataParse convention.
type Args struct {
	buf bytes.Buffer
}

// NewArgs allocates an empty argument packer.
func NewArgs() *Args {
	return &Args{}
}

// Wire format: little-endian to match the CS canonical (TrustedSec
// COFFLoader / Outflank read length prefixes via native-int memcpy,
// which is LE on x64). The consumer side in beacon_api_windows.go
// uses binary.LittleEndian for the same reason — keep this in sync.

// AddInt appends a 32-bit signed integer in little-endian byte order.
func (a *Args) AddInt(v int32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	a.buf.Write(b[:])
}

// AddShort appends a 16-bit signed integer in little-endian byte order.
func (a *Args) AddShort(v int16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(v))
	a.buf.Write(b[:])
}

// AddString appends a null-terminated string with a 4-byte little-endian
// length prefix. The length includes the null terminator.
func (a *Args) AddString(s string) {
	length := uint32(len(s) + 1) // +1 for the null terminator
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], length)
	a.buf.Write(lb[:])
	a.buf.WriteString(s)
	a.buf.WriteByte(0)
}

// AddBytes appends a byte slice with a 4-byte little-endian length prefix.
func (a *Args) AddBytes(data []byte) {
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], uint32(len(data)))
	a.buf.Write(lb[:])
	a.buf.Write(data)
}

// Pack returns the serialised argument buffer ready for BOF.Execute.
func (a *Args) Pack() []byte {
	b := a.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
