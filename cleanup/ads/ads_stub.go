//go:build !windows

package ads

import "errors"

// StreamInfo describes an alternate data stream.
type StreamInfo struct {
	Name string
	Size int64
}

// List returns an error on non-Windows platforms.
func List(path string) ([]StreamInfo, error) {
	return nil, errors.New("ADS not supported on this platform")
}

// Read returns an error on non-Windows platforms.
func Read(path, streamName string) ([]byte, error) {
	return nil, errors.New("ADS not supported on this platform")
}

// Write returns an error on non-Windows platforms.
func Write(path, streamName string, data []byte) error {
	return errors.New("ADS not supported on this platform")
}

// Delete returns an error on non-Windows platforms.
func Delete(path, streamName string) error {
	return errors.New("ADS not supported on this platform")
}

// CreateUndeletable returns an error on non-Windows platforms.
func CreateUndeletable(dir string, data []byte) (string, error) {
	return "", errors.New("undeletable files not supported on this platform")
}

// ReadUndeletable returns an error on non-Windows platforms.
func ReadUndeletable(path string) ([]byte, error) {
	return nil, errors.New("undeletable files not supported on this platform")
}
