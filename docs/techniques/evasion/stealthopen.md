# StealthOpen — NTFS Object ID File Access

[<- Back to Evasion](README.md)

## What It Does

Opens files by their 128-bit NTFS Object ID rather than by path, bypassing
path-based EDR filters on `NtCreateFile` and minifilter drivers that inspect
the filename for sensitive targets.

## How It Works

Every NTFS file can carry a 128-bit Object ID stored in the MFT
(`$OBJECT_ID` attribute). `FSCTL_CREATE_OR_GET_OBJECT_ID` assigns one,
`FSCTL_SET_OBJECT_ID` sets a specific GUID, and Win32 `OpenFileById` with
`FILE_ID_TYPE = ObjectIdType` opens the file by GUID. The resulting open
request carries the GUID — not a path — so filename-matching EDR hooks see
nothing meaningful.

## API

```go
func GetObjectID(path string) ([16]byte, error)
func SetObjectID(path string, objectID [16]byte) error
func DeleteObjectID(path string) error
func OpenByID(volumePath string, objectID [16]byte) (*os.File, error)
```

## Usage

```go
id, err := stealthopen.GetObjectID(`C:\sensitive.bin`)
// …later, without touching the path…
f, err := stealthopen.OpenByID(`C:\`, id)
```

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) |

## Detection

**Low** — Most EDR path-filters key on filename. Minifilters that resolve
Object IDs back to paths (`FltGetFileNameInformation`) or kernel callbacks
that inspect the opened `FILE_OBJECT` still see the real file.
