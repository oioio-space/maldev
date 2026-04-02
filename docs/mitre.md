# MITRE ATT&CK Coverage

[<- Back to README](../README.md)

| Technique ID | Technique Name | Package(s) |
|-------------|---------------|------------|
| T1027.002 | Obfuscated Files: Software Packing | `pe/morph` |
| T1055 | Process Injection | `inject`, `evasion/herpaderping` |
| T1055.001 | Process Injection: DLL Injection | `pe/srdi` |
| T1057 | Process Discovery | `process/enum` |
| T1059 | Command and Scripting Interpreter | `c2/shell`, `c2/meterpreter` |
| T1070.004 | Indicator Removal: File Deletion | `cleanup/selfdelete`, `cleanup/wipe` |
| T1070.006 | Indicator Removal: Timestomp | `cleanup/timestomp` |
| T1134.002 | Access Token Manipulation: Create Process with Token | `process/session` |
| T1497 | Virtualization/Sandbox Evasion | `evasion/sandbox` |
| T1497.001 | Sandbox Evasion: System Checks | `evasion/antivm` |
| T1497.003 | Sandbox Evasion: Time Based Evasion | `evasion/timing` |
| T1543.003 | Create or Modify System Process: Windows Service | `cleanup/service` |
| T1548.002 | Abuse Elevation Control: Bypass UAC | `uacbypass` |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `evasion/amsi`, `evasion/etw`, `evasion/unhook`, `evasion/acg`, `evasion/blockdlls` |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | `evasion/phant0m` |
| T1564 | Hide Artifacts | `cleanup/service` |
| T1622 | Debugger Evasion | `evasion/antidebug` |
