//go:build windows

// Package version provides Windows version detection utilities.
package version

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

// _VER_NT_WORKSTATION indicates the machine is a workstation, not a server.
const _VER_NT_WORKSTATION = 1

// Version wraps windows.OsVersionInfoEx and provides helper methods for
// comparing and describing Windows versions.
type Version windows.OsVersionInfoEx

// String returns a human-readable Windows version name.
func (wv *Version) String() string {
	if wv.IsWorkStation() {
		switch {
		case wv.MajorVersion == 10 && wv.MinorVersion == 0:
			if wv.BuildNumber < 22000 {
				return "windows 10"
			}
			return "windows 11"
		case wv.MajorVersion == 6 && wv.MinorVersion == 3:
			return "windows 8.1"
		case wv.MajorVersion == 6 && wv.MinorVersion == 2:
			return "windows 8"
		case wv.MajorVersion == 6 && wv.MinorVersion == 1:
			return "windows 7"
		case wv.MajorVersion == 6 && wv.MinorVersion == 0:
			return "windows vista"
		case wv.MajorVersion == 5 && wv.MinorVersion == 1:
			return "windows xp"
		default:
			return "unknown"
		}
	} else {
		switch {
		case wv.MajorVersion == 10 && wv.MinorVersion == 0:
			return "windows server 2016"
		case wv.MajorVersion == 6 && wv.MinorVersion == 3:
			return "windows server 2012 r2"
		case wv.MajorVersion == 6 && wv.MinorVersion == 2:
			return "windows server 2012"
		case wv.MajorVersion == 6 && wv.MinorVersion == 1:
			return "windows server 2008 r2"
		case wv.MajorVersion == 6 && wv.MinorVersion == 0:
			return "windows server 2008"
		default:
			return "unknown"
		}
	}
}

// IsWorkStation returns true if the machine is a workstation (not a server).
func (wv *Version) IsWorkStation() bool {
	return wv.ProductType == _VER_NT_WORKSTATION
}

// IsLower returns true if wv is an older version than v.
// Comparison order: MajorVersion, MinorVersion, BuildNumber.
func (wv *Version) IsLower(v *Version) bool {
	if v.MajorVersion > wv.MajorVersion {
		return true
	}
	if v.MinorVersion > wv.MinorVersion {
		return true
	}
	if v.BuildNumber > wv.BuildNumber {
		return true
	}
	return false
}

// IsEqual returns true if wv has the same major, minor, and build as v.
func (wv *Version) IsEqual(v *Version) bool {
	return wv.MajorVersion == v.MajorVersion &&
		wv.MinorVersion == v.MinorVersion &&
		wv.BuildNumber == v.BuildNumber
}

// GetVersion returns the current Windows version via RtlGetVersion.
func GetVersion() *Version {
	wv := Version(*windows.RtlGetVersion())
	return &wv
}

// WindowsVersion is a richer version descriptor that includes the Update Build
// Revision (UBR/Revision) read from the registry and an optional Vulnerable flag
// set by vulnerability-check helpers.
type WindowsVersion struct {
	Major      uint32
	Minor      uint32
	Build      uint32
	Revision   uint32 // UBR from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
	Vulnerable bool
}

const _registryKeyPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// readUBR reads the Update Build Revision DWORD from the Windows registry.
func readUBR() (uint32, error) {
	keyPath, err := windows.UTF16PtrFromString(_registryKeyPath)
	if err != nil {
		return 0, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var key windows.Handle
	if err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, keyPath, 0, windows.KEY_READ, &key); err != nil {
		return 0, fmt.Errorf("RegOpenKeyEx: %w", err)
	}
	defer windows.RegCloseKey(key)

	valueName, err := windows.UTF16PtrFromString("UBR")
	if err != nil {
		return 0, fmt.Errorf("UTF16PtrFromString UBR: %w", err)
	}

	var valType uint32
	var buf [4]byte
	bufLen := uint32(len(buf))
	if err = windows.RegQueryValueEx(key, valueName, nil, &valType, &buf[0], &bufLen); err != nil {
		return 0, fmt.Errorf("RegQueryValueEx UBR: %w", err)
	}

	return binary.LittleEndian.Uint32(buf[:]), nil
}

// GetWindowVersion returns the current Windows version including the UBR
// (Update Build Revision) read from the registry.
func GetWindowVersion() (*WindowsVersion, error) {
	info := windows.RtlGetVersion()
	ubr, err := readUBR()
	if err != nil {
		return nil, fmt.Errorf("reading UBR: %w", err)
	}
	return &WindowsVersion{
		Major:    info.MajorVersion,
		Minor:    info.MinorVersion,
		Build:    info.BuildNumber,
		Revision: ubr,
	}, nil
}

// CheckCVE202430088Vulnerability checks if the system is vulnerable to CVE-2024-30088.
// Returns true for Windows 10/11 and Server builds before June 2024 patch.
func CheckCVE202430088Vulnerability() (*WindowsVersion, error) {
	v, err := GetWindowVersion()
	if err != nil {
		return nil, err
	}
	// Vulnerability table from CVE-2024-30088 analysis
	type entry struct{ build, maxUBR uint32 }
	table := map[uint32]uint32{
		19041: 4529, // Win10 21H2
		19042: 4529, // Win10 21H2 (alt)
		19043: 4529,
		19044: 4529, // Win10 21H2/22H2
		19045: 4529, // Win10 22H2
		22000: 3019, // Win11 21H2
		22621: 3737, // Win11 22H2
		22631: 3737, // Win11 23H2
		20348: 2522, // Server 2022
		25398: 950,  // Server 2022 23H2
	}
	if maxUBR, ok := table[v.Build]; ok {
		v.Vulnerable = v.Revision < maxUBR
	}
	return v, nil
}

// Well-known Windows version constants for use in comparisons.
var (
	WINDOWS_SERVER_2008 = &Version{
		MajorVersion: 6,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  6003,
	}

	WINDOWS_7 = &Version{
		MajorVersion: 6,
		MinorVersion: 1,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  7601,
	}

	WINDOWS_SERVER_2008_R2 = &Version{
		MajorVersion: 6,
		MinorVersion: 1,
		ProductType:  0,
		BuildNumber:  7601,
	}

	WINDOWS_8 = &Version{
		MajorVersion: 6,
		MinorVersion: 2,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  9200,
	}

	WINDOWS_SERVER_2012 = &Version{
		MajorVersion: 6,
		MinorVersion: 2,
		ProductType:  0,
		BuildNumber:  9200,
	}

	WINDOWS_8_1 = &Version{
		MajorVersion: 6,
		MinorVersion: 3,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  9600,
	}

	WINDOWS_SERVER_2012_R2 = &Version{
		MajorVersion: 6,
		MinorVersion: 3,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  9600,
	}

	WINDOWS_10_1507 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  10240,
	}

	WINDOWS_10_1511 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  10586,
	}

	WINDOWS_10_1607 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  14393,
	}

	WINDOWS_SERVER_2016_1607 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  14393,
	}

	WINDOWS_10_1703 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  15063,
	}

	WINDOWS_10_1709 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  16299,
	}

	WINDOWS_SERVER_2016_1709 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  16299,
	}

	WINDOWS_10_1803 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  17134,
	}

	WINDOWS_SERVER_2016_1803 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  17134,
	}

	WINDOWS_10_1809 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  17763,
	}

	WINDOWS_SERVER_2016_1809 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  17763,
	}

	WINDOWS_10_1903 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  18362,
	}

	WINDOWS_SERVER_2019_1903 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  18362,
	}

	WINDOWS_10_1909 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  18363,
	}

	WINDOWS_SERVER_2019_1909 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  18363,
	}

	WINDOWS_10_2004 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  19041,
	}

	WINDOWS_SERVER_2019_2004 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  19041,
	}

	WINDOWS_10_20H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  19042,
	}

	WINDOWS_SERVER_2019_20H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  19042,
	}

	WINDOWS_10_21H1 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  19043,
	}

	WINDOWS_10_21H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  19044,
	}

	WINDOWS_10_22H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  19045,
	}

	WINDOWS_SERVER_2022_21H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  0,
		BuildNumber:  20348,
	}

	WINDOWS_11_21H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  22000,
	}

	WINDOWS_11_22H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  22621,
	}

	WINDOWS_11_23H2 = &Version{
		MajorVersion: 10,
		MinorVersion: 0,
		ProductType:  _VER_NT_WORKSTATION,
		BuildNumber:  22631,
	}
)
