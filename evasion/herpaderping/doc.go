// Package herpaderping implements the Process Herpaderping technique.
//
// Process Herpaderping exploits a timing gap in how Windows handles
// process creation. When a process is created, the kernel caches the
// executable image in memory via an image section. Security products
// (EDR, antivirus) are notified at thread creation time, NOT at process
// creation time. This gap allows the attacker to overwrite the file on
// disk with benign content before the security callback fires.
//
// When the EDR inspects the file backing the new process, it sees the
// benign replacement -- not the original malicious payload. The actual
// code executing in memory is the original payload from the kernel cache.
//
// Technique: Process Herpaderping
// MITRE ATT&CK: T1055 (Process Injection -- defense evasion via process tampering)
// Detection: Medium -- Sysmon Event ID 25 (ProcessTampering), advanced EDR
// Platform: Windows only (x64)
//
// Reference: https://jxy-s.github.io/herpaderping/
//
// Example:
//
//	err := herpaderping.Run(herpaderping.Config{
//	    PayloadPath: "payload.exe",
//	    TargetPath:  `C:\Windows\Temp\legit.exe`,
//	    DecoyPath:   `C:\Windows\System32\svchost.exe`, // or "" for random bytes
//	})
package herpaderping
