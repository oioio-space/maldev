//go:build windows

// Package ui provides Windows UI utilities such as message boxes.
package ui

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// ValidationButton defines the message box button type.
type ValidationButton uint

const (
	MB_OK                 ValidationButton = 0x00000000
	MB_OKCANCEL           ValidationButton = 0x00000001
	MB_ABORTRETRYIGNORE   ValidationButton = 0x00000002
	MB_YESNOCANCEL        ValidationButton = 0x00000003
	MB_YESNO              ValidationButton = 0x00000004
	MB_RETRYCANCEL        ValidationButton = 0x00000005
	MB_CANCELTRYCONTINNUE ValidationButton = 0x00000006
	MB_HELP               ValidationButton = 0x00040000
)

// Modal defines the message box modality.
type Modal uint

const (
	MB_APPLMODAL   Modal = 0x00000000
	MB_SYSTEMMODAL Modal = 0x00001000
	MB_TASKMODAL   Modal = 0x00002000
)

// Icon defines the message box icon.
type Icon uint

const (
	MB_ICONSTOP        Icon = 0x00000010
	MB_ICONERROR       Icon = 0x00000010
	MB_ICONHAND        Icon = 0x00000010
	MB_ICONQUESTION    Icon = 0x00000020
	MB_ICONWARNING     Icon = 0x00000030
	MB_ICONEXCLAMATION Icon = 0x00000030
	MB_ICONINFORMATION Icon = 0x00000040
	MB_ICONASTERISK    Icon = 0x00000040
)

// DefaultButton defines which button is selected by default.
type DefaultButton uint

const (
	MB_DEFBUTTON1 DefaultButton = 0x00000000
	MB_DEFBUTTON2 DefaultButton = 0x00000100
	MB_DEFBUTTON3 DefaultButton = 0x00000200
	MB_DEFBUTTON4 DefaultButton = 0x00000400
)

// MoreOptions defines additional message box options.
type MoreOptions uint

const (
	MB_DEFAULT_DESKTOP_ONLY MoreOptions = 0x00020000
	MB_RIGHT                MoreOptions = 0x00080000
	MB_RTLREADING           MoreOptions = 0x00100000
	MB_SETFOREGROUND        MoreOptions = 0x00010000
	MB_TOPMOST              MoreOptions = 0x00040000
	MB_SERVICE_NOTIFICATION MoreOptions = 0x00200000
)

// Response represents the user's response to a message box.
type Response uint

const (
	IDOK       Response = 1
	IDCANCEL   Response = 2
	IDABORT    Response = 3
	IDRETRY    Response = 4
	IDIGNORE   Response = 5
	IDYES      Response = 6
	IDNO       Response = 7
	IDTRYAGAIN Response = 10
	IDCONTINUE Response = 11
)

// Show displays a message box and returns the user's response.
func Show(title string, message string, opt ...any) (Response, error) {
	var optValidationButton ValidationButton = MB_OK
	var optModal Modal = MB_APPLMODAL
	var optIcon Icon = MB_ICONINFORMATION

	var options uint

	for _, o := range opt {
		switch v := o.(type) {
		case Icon:
			optIcon = v
		case Modal:
			optModal = v
		case ValidationButton:
			optValidationButton = v
		case DefaultButton:
			options |= uint(v)
		case MoreOptions:
			options |= uint(v)
		default:
			return 0, errors.New("unknown option")
		}
	}

	options |= uint(optValidationButton) | uint(optModal) | uint(optIcon)

	title16, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}

	message16, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return 0, err
	}

	ret, _, _ := api.ProcMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(message16)),
		uintptr(unsafe.Pointer(title16)),
		uintptr(options),
	)

	return Response(ret), nil
}

// Beep plays a system beep sound.
func Beep() {
	api.ProcMessageBeep.Call(0xffffffff)
}
