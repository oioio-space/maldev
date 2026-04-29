//go:build windows

package ads

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/win/api"
)

// StreamInfo describes an alternate data stream (defined here for Windows build;
// the !windows stub defines its own identical type).
type StreamInfo struct {
	Name string
	Size int64
}

// findStreamData matches the WIN32_FIND_STREAM_DATA structure.
type findStreamData struct {
	StreamSize int64
	StreamName [296]uint16 // MAX_PATH + 36
}

// Use win/api.Kernel32 — the single source of truth for DLL handles.
var (
	procFindFirstStreamW = api.Kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = api.Kernel32.NewProc("FindNextStreamW")
)

// List returns all alternate data streams on a file (excludes the default :$DATA stream).
func List(path string) ([]StreamInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	var fsd findStreamData
	handle, _, callErr := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0, // FindStreamInfoStandard
		uintptr(unsafe.Pointer(&fsd)),
		0,
	)
	if handle == uintptr(windows.InvalidHandle) {
		if errors.Is(callErr, windows.ERROR_HANDLE_EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("FindFirstStreamW: %w", callErr)
	}
	defer windows.FindClose(windows.Handle(handle)) //nolint:errcheck // best-effort cleanup

	var streams []StreamInfo
	for {
		name := windows.UTF16ToString(fsd.StreamName[:])
		streamName := parseStreamName(name)
		if streamName != "" {
			streams = append(streams, StreamInfo{
				Name: streamName,
				Size: fsd.StreamSize,
			})
		}

		fsd = findStreamData{}
		r, _, callErr := procFindNextStreamW.Call(
			handle,
			uintptr(unsafe.Pointer(&fsd)),
		)
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_HANDLE_EOF) {
				break
			}
			return streams, fmt.Errorf("FindNextStreamW: %w", callErr)
		}
	}

	return streams, nil
}

// parseStreamName extracts the user-friendly name from ":name:$DATA".
// Returns empty string for the default stream "::$DATA".
func parseStreamName(raw string) string {
	if !strings.HasPrefix(raw, ":") {
		return ""
	}
	raw = raw[1:] // strip leading ":"
	idx := strings.Index(raw, ":")
	if idx <= 0 {
		return "" // default stream "::$DATA"
	}
	return raw[:idx]
}

// Read reads the content of a named alternate data stream.
func Read(path, streamName string) ([]byte, error) {
	adsPath := path + ":" + streamName
	return os.ReadFile(adsPath)
}

// Write creates or overwrites a named alternate data stream. Equivalent
// to [WriteVia] with a nil Creator.
func Write(path, streamName string, data []byte) error {
	return WriteVia(nil, path, streamName, data)
}

// WriteVia routes the ADS write through the operator-supplied
// [stealthopen.Creator]. nil falls back to a [stealthopen.StandardCreator]
// (plain os.Create) — same byte content as [Write]. Use a non-nil
// Creator to layer transactional NTFS, encryption, or a stealth write
// primitive over the ADS landing.
func WriteVia(creator stealthopen.Creator, path, streamName string, data []byte) error {
	adsPath := path + ":" + streamName
	wc, err := stealthopen.UseCreator(creator).Create(adsPath)
	if err != nil {
		return err
	}
	defer wc.Close()
	_, err = wc.Write(data)
	return err
}

// Delete removes a named alternate data stream.
func Delete(path, streamName string) error {
	return os.Remove(path + ":" + streamName)
}
