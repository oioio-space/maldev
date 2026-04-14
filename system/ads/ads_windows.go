//go:build windows

package ads

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
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

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW = modKernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modKernel32.NewProc("FindNextStreamW")
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
		if callErr == windows.ERROR_HANDLE_EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("FindFirstStreamW: %w", callErr)
	}
	defer windows.FindClose(windows.Handle(handle))

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
			if callErr == windows.ERROR_HANDLE_EOF {
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

// Write creates or overwrites a named alternate data stream.
func Write(path, streamName string, data []byte) error {
	adsPath := path + ":" + streamName
	return os.WriteFile(adsPath, data, 0644)
}

// Delete removes a named alternate data stream.
func Delete(path, streamName string) error {
	adsPath := path + ":" + streamName
	err := os.Remove(adsPath)
	if err != nil {
		return fmt.Errorf("delete ADS %q: %w", streamName, err)
	}
	return nil
}
