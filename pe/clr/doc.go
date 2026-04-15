// Package clr loads the .NET Common Language Runtime (CLR) in-process via the
// ICLRMetaHost / ICorRuntimeHost COM interfaces and executes .NET assemblies
// from memory without writing them to disk.
//
// Technique: In-process CLR hosting — reflective .NET assembly execution.
// MITRE ATT&CK: T1620 (Reflective Code Loading)
// Platform: Windows (requires a .NET Framework 4.x runtime on the host).
// Detection: Medium — loading the CLR inside a non-.NET host process is a
// strong heuristic signal (clr.dll + mscoreei.dll module load), and
// AMSI v2 scans every assembly passed to AppDomain.Load_3.
//
// Prerequisite for hostile assemblies: call evasion/amsi.PatchAll() before
// ExecuteAssembly — otherwise any flagged bytes (SharpHound, Rubeus, etc.)
// will be blocked by AmsiScanBuffer.
//
// How it works: CLRCreateInstance in mscoree.dll yields an ICLRMetaHost.
// From it we enumerate installed runtimes and obtain an ICLRRuntimeInfo for
// the preferred version (v4 > any). GetInterface(CLSID_CLRRuntimeHost,
// IID_ICorRuntimeHost) returns an ICorRuntimeHost — Start() transitions it
// to the Started state. GetDefaultDomain gives the default AppDomain as an
// IUnknown which is queried for IDispatch; Load_3(SAFEARRAY[byte]) loads
// the managed assembly and EntryPoint.Invoke runs it.
//
// Example:
//
//	rt, err := clr.Load(nil)
//	if err != nil { log.Fatal(err) }
//	defer rt.Close()
//
//	assembly, _ := os.ReadFile("Seatbelt.exe")
//	_ = rt.ExecuteAssembly(assembly, []string{"-group=system"})
//
// Credit: ropnop/go-clr.
package clr
