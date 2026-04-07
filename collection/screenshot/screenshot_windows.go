//go:build windows

package screenshot

import (
	"bytes"
	"errors"
	"image"
	"image/png"

	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// GDI constants.
const (
	srcCopy        = 0x00CC0020
	biRGBFormat    = 0
	dibRGBColors   = 0
	bitsPerPixel   = 32
	smCxScreen     = 0
	smCyScreen     = 1
	monitorDefault = 1 // MONITOR_DEFAULTTOPRIMARY
)

// Sentinel errors.
var (
	ErrCapture       = errors.New("screen capture failed")
	ErrInvalidRect   = errors.New("invalid capture rectangle")
	ErrDisplayIndex  = errors.New("display index out of range")
)

// GDI / user32 procs not available in x/sys/windows.
var (
	procGetDC                = api.User32.NewProc("GetDC")
	procReleaseDC            = api.User32.NewProc("ReleaseDC")
	procGetSystemMetrics     = api.User32.NewProc("GetSystemMetrics")
	procEnumDisplayMonitors  = api.User32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfoW      = api.User32.NewProc("GetMonitorInfoW")

	procCreateCompatibleDC     = api.Gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = api.Gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = api.Gdi32.NewProc("SelectObject")
	procBitBlt                 = api.Gdi32.NewProc("BitBlt")
	procGetDIBits              = api.Gdi32.NewProc("GetDIBits")
	procDeleteObject           = api.Gdi32.NewProc("DeleteObject")
	procDeleteDC               = api.Gdi32.NewProc("DeleteDC")
)

// bitmapInfoHeader mirrors the Win32 BITMAPINFOHEADER structure.
type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// rect mirrors the Win32 RECT structure.
type rect struct {
	Left, Top, Right, Bottom int32
}

// monitorInfo mirrors the Win32 MONITORINFO structure.
type monitorInfo struct {
	CbSize    uint32
	RcMonitor rect
	RcWork    rect
	DwFlags   uint32
}

// Capture takes a screenshot of the primary display and returns PNG bytes.
func Capture() ([]byte, error) {
	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	if w == 0 || h == 0 {
		return nil, ErrCapture
	}
	return CaptureRect(0, 0, int(w), int(h))
}

// CaptureRect takes a screenshot of a specific screen region.
func CaptureRect(x, y, width, height int) ([]byte, error) {
	if width <= 0 || height <= 0 {
		return nil, ErrInvalidRect
	}

	// Screen DC.
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, ErrCapture
	}
	defer procReleaseDC.Call(0, hdcScreen) //nolint:errcheck

	// Memory DC.
	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, ErrCapture
	}
	defer procDeleteDC.Call(hdcMem) //nolint:errcheck

	// Bitmap.
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(width), uintptr(height))
	if hBitmap == 0 {
		return nil, ErrCapture
	}
	defer procDeleteObject.Call(hBitmap) //nolint:errcheck

	// Select bitmap into memory DC.
	old, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	if old == 0 {
		return nil, ErrCapture
	}
	defer procSelectObject.Call(hdcMem, old) //nolint:errcheck

	// Copy pixels from screen to memory DC.
	r, _, _ := procBitBlt.Call(
		hdcMem, 0, 0, uintptr(width), uintptr(height),
		hdcScreen, uintptr(x), uintptr(y),
		srcCopy,
	)
	if r == 0 {
		return nil, ErrCapture
	}

	// Extract pixel data via GetDIBits.
	bmi := bitmapInfoHeader{
		BiSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		BiWidth:       int32(width),
		BiHeight:      -int32(height), // negative = top-down DIB
		BiPlanes:      1,
		BiBitCount:    bitsPerPixel,
		BiCompression: biRGBFormat,
	}

	pixelBytes := width * height * 4 // 32bpp = 4 bytes per pixel
	pixels := make([]byte, pixelBytes)

	r, _, _ = procGetDIBits.Call(
		hdcMem, hBitmap,
		0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		dibRGBColors,
	)
	if r == 0 {
		return nil, ErrCapture
	}

	// Convert BGRA pixels to NRGBA image.
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for i := 0; i < width*height; i++ {
		off := i * 4
		// GDI returns BGRA byte order.
		img.Pix[off+0] = pixels[off+2] // R
		img.Pix[off+1] = pixels[off+1] // G
		img.Pix[off+2] = pixels[off+0] // B
		img.Pix[off+3] = 255           // A
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// enumDisplays queries the current monitor layout. Called on every
// DisplayCount/DisplayBounds/CaptureDisplay to reflect hotplug changes.
func enumDisplays() []image.Rectangle {
	var result []image.Rectangle
	cb := func(hMonitor, hdcMonitor, lprcMonitor, dwData uintptr) uintptr {
		var mi monitorInfo
		mi.CbSize = uint32(unsafe.Sizeof(mi))
		r, _, _ := procGetMonitorInfoW.Call(hMonitor, uintptr(unsafe.Pointer(&mi)))
		if r != 0 {
			result = append(result, image.Rect(
				int(mi.RcMonitor.Left),
				int(mi.RcMonitor.Top),
				int(mi.RcMonitor.Right),
				int(mi.RcMonitor.Bottom),
			))
		}
		return 1 // continue enumeration
	}

	procEnumDisplayMonitors.Call(0, 0, windows.NewCallback(cb), 0) //nolint:errcheck
	return result
}

// DisplayCount returns the number of active displays.
func DisplayCount() int {
	return len(enumDisplays())
}

// DisplayBounds returns the pixel bounds of a display by index (0-based).
// Returns an empty rectangle if the index is out of range.
func DisplayBounds(index int) image.Rectangle {
	d := enumDisplays()
	if index < 0 || index >= len(d) {
		return image.Rectangle{}
	}
	return d[index]
}

// CaptureDisplay takes a screenshot of a specific display by index (0-based).
func CaptureDisplay(index int) ([]byte, error) {
	d := enumDisplays()
	if index < 0 || index >= len(d) {
		return nil, ErrDisplayIndex
	}
	bounds := d[index]
	return CaptureRect(
		bounds.Min.X, bounds.Min.Y,
		bounds.Dx(), bounds.Dy(),
	)
}
