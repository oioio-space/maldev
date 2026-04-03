//go:build windows

package folder

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// CSIDL represents a Windows special folder identifier.
type CSIDL uint32

const (
	CSIDL_ADMINTOOLS              CSIDL = 0x30
	CSIDL_ALTSTARTUP              CSIDL = 0x1D
	CSIDL_APPDATA                 CSIDL = 0x1A
	CSIDL_BITBUCKET               CSIDL = 0x0A
	CSIDL_CDBURN_AREA             CSIDL = 0x3B
	CSIDL_COMMON_ADMINTOOLS       CSIDL = 0x2F
	CSIDL_COMMON_ALTSTARTUP       CSIDL = 0x1E
	CSIDL_COMMON_APPDATA          CSIDL = 0x23
	CSIDL_COMMON_DESKTOPDIRECTORY CSIDL = 0x19
	CSIDL_COMMON_DOCUMENTS        CSIDL = 0x2E
	CSIDL_COMMON_FAVORITES        CSIDL = 0x1F
	CSIDL_COMMON_MUSIC            CSIDL = 0x35
	CSIDL_COMMON_PICTURES         CSIDL = 0x36
	CSIDL_COMMON_PROGRAMS         CSIDL = 0x17
	CSIDL_COMMON_STARTMENU        CSIDL = 0x16
	CSIDL_COMMON_STARTUP          CSIDL = 0x18
	CSIDL_COMMON_TEMPLATES        CSIDL = 0x2D
	CSIDL_COMMON_VIDEO            CSIDL = 0x37
	CSIDL_COMPUTERSNEARME         CSIDL = 0x3D
	CSIDL_CONNECTIONS             CSIDL = 0x31
	CSIDL_CONTROLS                CSIDL = 0x03
	CSIDL_COOKIES                 CSIDL = 0x21
	CSIDL_DESKTOP                 CSIDL = 0x00
	CSIDL_DESKTOPDIRECTORY        CSIDL = 0x10
	CSIDL_DRIVES                  CSIDL = 0x11
	CSIDL_FAVORITES               CSIDL = 0x06
	CSIDL_FONTS                   CSIDL = 0x14
	CSIDL_HISTORY                 CSIDL = 0x22
	CSIDL_INTERNET                CSIDL = 0x01
	CSIDL_INTERNET_CACHE          CSIDL = 0x20
	CSIDL_LOCAL_APPDATA           CSIDL = 0x1C
	CSIDL_MYDOCUMENTS             CSIDL = 0x05
	CSIDL_MYMUSIC                 CSIDL = 0x0D
	CSIDL_MYPICTURES              CSIDL = 0x27
	CSIDL_MYVIDEO                 CSIDL = 0x0E
	CSIDL_NETHOOD                 CSIDL = 0x13
	CSIDL_NETWORK                 CSIDL = 0x12
	CSIDL_PERSONAL                CSIDL = 0x05
	CSIDL_PHOTOALBUMS             CSIDL = 0x45
	CSIDL_PLAYLISTS               CSIDL = 0x3F
	CSIDL_PRINTERS                CSIDL = 0x04
	CSIDL_PRINTHOOD               CSIDL = 0x1B
	CSIDL_PROFILE                 CSIDL = 0x28
	CSIDL_PROGRAM_FILES           CSIDL = 0x26
	CSIDL_PROGRAM_FILESX86        CSIDL = 0x2A
	CSIDL_PROGRAM_FILES_COMMON    CSIDL = 0x2B
	CSIDL_PROGRAM_FILES_COMMONX86 CSIDL = 0x2C
	CSIDL_PROGRAMS                CSIDL = 0x02
	CSIDL_RECENT                  CSIDL = 0x08
	CSIDL_RESOURCES               CSIDL = 0x38
	CSIDL_RESOURCES_LOCALIZED     CSIDL = 0x39
	CSIDL_SAMPLE_MUSIC            CSIDL = 0x40
	CSIDL_SAMPLE_PLAYLISTS        CSIDL = 0x41
	CSIDL_SAMPLE_PICTURES         CSIDL = 0x42
	CSIDL_SAMPLE_VIDEOS           CSIDL = 0x43
	CSIDL_SENDTO                  CSIDL = 0x09
	CSIDL_STARTMENU               CSIDL = 0x0B
	CSIDL_STARTUP                 CSIDL = 0x07
	CSIDL_SYSTEM                  CSIDL = 0x25
	CSIDL_SYSTEMX86               CSIDL = 0x29
	CSIDL_TEMPLATES               CSIDL = 0x15
	CSIDL_WINDOWS                 CSIDL = 0x24
)

// Get returns (and optionally creates) a Windows special folder path.
// Uses SHGetSpecialFolderPathW (Shell32). Returns empty string on failure.
func Get(csidl CSIDL, createIfNotExist bool) string {
	buf := make([]uint16, windows.MAX_PATH)

	var create uintptr
	if createIfNotExist {
		create = 1
	}

	ret, _, _ := api.ProcSHGetSpecialFolderPathW.Call(
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(csidl),
		create,
	)
	if ret == 0 {
		return ""
	}

	return windows.UTF16ToString(buf)
}
