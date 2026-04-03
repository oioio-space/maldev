# MITRE ATT&CK Coverage

[<- Back to README](../README.md)

| Technique ID | Technique Name | Package(s) |
|-------------|---------------|------------|
| T1027 | Obfuscated Files or Information | `evasion/sleepmask`, `pe/strip` |
| T1027.002 | Obfuscated Files: Software Packing | `pe/morph` |
| T1055 | Process Injection | `inject` (CRT, APC, EarlyBird, ThreadHijack, Fiber, EtwThread, NtQueueApcThreadEx, ModuleStomp, SectionMap, Callback, ThreadPool, KernelCallbackTable, PhantomDLL), `evasion/herpaderping` |
| T1055.001 | Process Injection: DLL Injection | `pe/srdi` |
| T1055.012 | Process Injection: Process Hollowing | `inject` (SpawnWithSpoofedArgs) |
| T1057 | Process Discovery | `process/enum` |
| T1059 | Command and Scripting Interpreter | `c2/shell`, `c2/meterpreter`, `pe/bof` |
| T1082 | System Information Discovery | `win/domain`, `win/version` |
| T1083 | File and Directory Discovery | `system/folder` |
| T1070 | Indicator Removal on Host | `cleanup/memory` |
| T1070.004 | Indicator Removal: File Deletion | `cleanup/selfdelete`, `cleanup/wipe` |
| T1106 | Native API | `win/api` (PEB walk, API hashing), `win/syscall` (direct/indirect syscalls, HashGate), `win/ntapi` |
| T1070.006 | Indicator Removal: Timestomp | `cleanup/timestomp` |
| T1120 | Peripheral Device Discovery | `system/drive` |
| T1134 | Access Token Manipulation | `win/token`, `win/privilege` |
| T1134.001 | Token Impersonation/Theft | `win/impersonate`, `win/token` |
| T1134.002 | Access Token Manipulation: Create Process with Token | `process/session` |
| T1497 | Virtualization/Sandbox Evasion | `evasion/sandbox` |
| T1497.001 | Sandbox Evasion: System Checks | `evasion/antivm` |
| T1497.003 | Sandbox Evasion: Time Based Evasion | `evasion/timing` |
| T1543.003 | Create or Modify System Process: Windows Service | `cleanup/service` |
| T1548.002 | Abuse Elevation Control: Bypass UAC | `uacbypass` |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `evasion/amsi`, `evasion/etw`, `evasion/unhook`, `evasion/acg`, `evasion/blockdlls` |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | `evasion/phant0m` |
| T1564 | Hide Artifacts | `cleanup/service` |
| T1622 | Debugger Evasion | `evasion/antidebug`, `evasion/hwbp` |
