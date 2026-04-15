//go:build windows

package clr

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// CLR COM interface GUIDs.
var (
	clsidCLRMetaHost   = ole.NewGUID("{9280188D-0E8E-4867-B30C-7FA83884E8DE}")
	iidICLRMetaHost    = ole.NewGUID("{D332DB9E-B9B3-4125-8207-A14884F53216}")
	iidICLRRuntimeInfo = ole.NewGUID("{BD39D1D2-BA2F-486A-89B0-B4B0CB466891}")
	// CLSID_CorRuntimeHost and IID_ICorRuntimeHost share the same GUID.
	clsidCorRuntimeHost = ole.NewGUID("{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}")
	iidICorRuntimeHost  = ole.NewGUID("{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}")
)

// HRESULT values we special-case.
const (
	sOK                             = 0
	sFalse                          = 1
	corProfERuntimeUninitialized    = 0x80131506
	regdbEClassNotReg               = 0x80040154 // ICorRuntimeHost legacy unavailable
	clrEShimLegacyRuntimeAlreadyBnd = 0x80131700 // v4 already bound, can't activate legacy path
)

// ErrLegacyRuntimeUnavailable indicates ICorRuntimeHost (CLR2 legacy COM
// hosting) is not registered. Typical on hosts without .NET Framework 3.5
// installed or without legacy activation policy in an app.config manifest.
// In-memory assembly execution requires this interface.
var ErrLegacyRuntimeUnavailable = fmt.Errorf("clr: ICorRuntimeHost unavailable (install .NET 3.5 and call InstallRuntimeActivationPolicy before Load)")

// legacyActivationConfig is the minimal <exe>.config contents that the CLR
// shim (mscoree.dll) reads at first-use to decide activation policy. With
// useLegacyV2RuntimeActivationPolicy=true, pure-native hosts (Go binaries
// without a managed manifest) are allowed to bind ICorRuntimeHost.
const legacyActivationConfig = `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup useLegacyV2RuntimeActivationPolicy="true">
    <supportedRuntime version="v4.0.30319"/>
    <supportedRuntime version="v2.0.50727"/>
  </startup>
</configuration>
`

// configPath returns <os.Executable()>.config — the file that mscoree
// reads to resolve activation policy for the current process.
func configPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	return exe + ".config", nil
}

// InstallRuntimeActivationPolicy writes <os.Executable()>.config next to
// the running binary, enabling legacy v2 CLR activation policy. It MUST be
// called before Load — once mscoree.dll has resolved activation policy for
// the process, the choice is frozen for the lifetime of the process.
//
// If the config file already exists it is left untouched (assume the host
// has supplied its own).
//
// Typical usage:
//
//	func main() {
//	    _ = clr.InstallRuntimeActivationPolicy()
//	    rt, err := clr.Load(nil)
//	    if err != nil { log.Fatal(err) }
//	    defer rt.Close()
//	    defer clr.RemoveRuntimeActivationPolicy() // OPSEC cleanup
//	    …
//	}
//
// Rationale: on Windows 10+, neither CLRCreateInstance nor
// CorBindToRuntimeEx will yield ICorRuntimeHost from an unmanaged host
// without this config. There is no embedded-manifest equivalent.
//
// OPSEC: the written file is a forensic artefact. Pair every install with
// a RemoveRuntimeActivationPolicy() call once Load() succeeds.
func InstallRuntimeActivationPolicy() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(legacyActivationConfig), 0o644)
}

// RemoveRuntimeActivationPolicy deletes <os.Executable()>.config. Safe to
// call any time AFTER Load() has returned — mscoree resolves and caches
// activation policy on first use, so the file is no longer consulted for
// the lifetime of the process.
//
// Missing file is treated as success. This is the OPSEC counterpart of
// InstallRuntimeActivationPolicy: it removes the on-disk forensic trace
// while keeping the loaded runtime fully functional.
func RemoveRuntimeActivationPolicy() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// VARTYPE values used below (see wtypes.h).
const (
	vtUI1  = 17
	vtBstr = 8
)

// iUnknownVtbl lays out the first three slots of every COM interface vtable.
type iUnknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

// iCLRMetaHostVtbl matches ICLRMetaHost in metahost.h.
type iCLRMetaHostVtbl struct {
	iUnknownVtbl
	GetRuntime                       uintptr
	GetVersionFromFile               uintptr
	EnumerateInstalledRuntimes       uintptr
	EnumerateLoadedRuntimes          uintptr
	RequestRuntimeLoadedNotification uintptr
	QueryLegacyV2RuntimeBinding      uintptr
	ExitProcess                      uintptr
}

// iCLRRuntimeInfoVtbl matches ICLRRuntimeInfo (partial).
type iCLRRuntimeInfoVtbl struct {
	iUnknownVtbl
	GetVersionString       uintptr
	GetRuntimeDirectory    uintptr
	IsLoaded               uintptr
	LoadErrorString        uintptr
	LoadLibrary            uintptr
	GetProcAddress         uintptr
	GetInterface           uintptr
	IsLoadable             uintptr
	SetDefaultStartupFlags uintptr
	GetDefaultStartupFlags uintptr
	BindAsLegacyV2Runtime  uintptr
	IsStarted              uintptr
}

// iCorRuntimeHostVtbl matches ICorRuntimeHost (partial — through GetDefaultDomain).
type iCorRuntimeHostVtbl struct {
	iUnknownVtbl
	CreateLogicalThreadState    uintptr
	DeleteLogicalThreadState    uintptr
	SwitchInLogicalThreadState  uintptr
	SwitchOutLogicalThreadState uintptr
	LocksHeldByLogicalThread    uintptr
	MapFile                     uintptr
	GetConfiguration            uintptr
	Start                       uintptr
	Stop                        uintptr
	CreateDomain                uintptr
	GetDefaultDomain            uintptr
}

// iEnumUnknownVtbl matches IEnumUnknown.
type iEnumUnknownVtbl struct {
	iUnknownVtbl
	Next  uintptr
	Skip  uintptr
	Reset uintptr
	Clone uintptr
}

// Runtime wraps a loaded and started ICorRuntimeHost.
type Runtime struct {
	host uintptr // ICorRuntimeHost*
}

// Load initialises the CLR in the current process and starts ICorRuntimeHost.
//
// Strategy — two paths tried in order:
//
//  1. mscoree!CorBindToRuntimeEx (legacy pre-.NET-4 hosting API). Bypasses
//     the metahost shim's default activation policy, so it works from a
//     pure-native host with no app.config / manifest / embedded legacy
//     policy. This is the path that succeeds on plain Go binaries.
//
//  2. CLRCreateInstance -> ICLRMetaHost -> GetRuntime ->
//     BindAsLegacyV2Runtime -> GetInterface. The modern documented API;
//     works only when the shim already has legacy v2 policy bound
//     (via app.config useLegacyV2RuntimeActivationPolicy or a managed
//     host). Kept as fallback for configured hosts.
//
// Returns ErrLegacyRuntimeUnavailable if neither path yields an
// ICorRuntimeHost (typically .NET 3.5 not installed).
func Load(_ *wsyscall.Caller) (*Runtime, error) {
	candidates, err := runtimeCandidates()
	if err != nil {
		return nil, err
	}

	// Path 1: CorBindToRuntimeEx first — this path succeeds on an unmanaged
	// host and avoids touching the metahost shim, which would otherwise
	// lock the process into a CLR4 activation state that blocks every
	// subsequent legacy-v2 attempt.
	host, err := corBindToRuntimeEx(candidates)
	if err == nil {
		if err := corHostStart(host); err != nil {
			releaseCOM(host)
			return nil, err
		}
		return &Runtime{host: host}, nil
	}
	diagErr := err // keep for diagnostics
	_ = diagErr

	// Path 2: fall back to the CLRCreateInstance metahost path.
	metaHost, err := createMetaHost()
	if err != nil {
		return nil, err
	}
	defer releaseCOM(metaHost)

	var lastErr error
	for _, version := range candidates {
		runtimeInfo, err := metaHostGetRuntime(metaHost, version)
		if err != nil {
			lastErr = err
			continue
		}
		_ = runtimeInfoBindLegacyV2(runtimeInfo)
		host, err := runtimeInfoGetCorHost(runtimeInfo)
		releaseCOM(runtimeInfo)
		if err != nil {
			lastErr = err
			continue
		}
		if err := corHostStart(host); err != nil {
			releaseCOM(host)
			lastErr = err
			continue
		}
		return &Runtime{host: host}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrLegacyRuntimeUnavailable
}

// runtimeCandidates returns installed .NET versions ordered with v4 first,
// then v2.x. Safe default when enumeration returns nothing.
func runtimeCandidates() ([]string, error) {
	metaHost, err := createMetaHost()
	if err != nil {
		return nil, err
	}
	defer releaseCOM(metaHost)
	versions, _ := enumerateRuntimes(metaHost)

	var out []string
	for _, v := range versions {
		if len(v) >= 2 && v[1] == '4' {
			out = append(out, v)
		}
	}
	for _, v := range versions {
		if len(v) >= 2 && v[1] == '2' {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		out = []string{"v4.0.30319"}
	}
	return out, nil
}

// corBindToRuntimeEx tries each candidate version with the legacy
// mscoree!CorBindToRuntimeEx entry point, yielding ICorRuntimeHost on
// success. Returns ErrLegacyRuntimeUnavailable on REGDB_E_CLASSNOTREG,
// otherwise the raw HRESULT.
func corBindToRuntimeEx(candidates []string) (uintptr, error) {
	const startupLoaderOptimizationMultiCore = 0x80
	var lastErr error
	for _, version := range candidates {
		versionW, err := windows.UTF16PtrFromString(version)
		if err != nil {
			lastErr = err
			continue
		}
		var host uintptr
		r, _, _ := api.ProcCorBindToRuntimeEx.Call(
			uintptr(unsafe.Pointer(versionW)),
			0, // pwszBuildFlavor (NULL = server workstation auto)
			startupLoaderOptimizationMultiCore,
			uintptr(unsafe.Pointer(clsidCorRuntimeHost)),
			uintptr(unsafe.Pointer(iidICorRuntimeHost)),
			uintptr(unsafe.Pointer(&host)),
		)
		if r == sOK {
			return host, nil
		}
		if uint32(r) == regdbEClassNotReg {
			lastErr = ErrLegacyRuntimeUnavailable
			continue
		}
		lastErr = fmt.Errorf("CorBindToRuntimeEx(%s): HRESULT 0x%X", version, uint32(r))
	}
	if lastErr == nil {
		lastErr = ErrLegacyRuntimeUnavailable
	}
	return 0, lastErr
}

// InstalledRuntimes returns the version strings of every .NET runtime
// installed on the system (e.g. "v2.0.50727", "v4.0.30319").
func InstalledRuntimes() ([]string, error) {
	metaHost, err := createMetaHost()
	if err != nil {
		return nil, err
	}
	defer releaseCOM(metaHost)
	return enumerateRuntimes(metaHost)
}

// Close releases the ICorRuntimeHost reference (but does not Stop the CLR —
// the runtime cannot be cleanly unloaded from the process it started in).
func (rt *Runtime) Close() {
	if rt != nil && rt.host != 0 {
		releaseCOM(rt.host)
		rt.host = 0
	}
}

// ExecuteAssembly loads a .NET EXE from memory into the default AppDomain
// and invokes its entry point with args.
func (rt *Runtime) ExecuteAssembly(assembly []byte, args []string) error {
	if len(assembly) == 0 {
		return fmt.Errorf("empty assembly")
	}
	domainDisp, err := rt.defaultDomainDispatch()
	if err != nil {
		return err
	}
	defer domainDisp.Release()

	asmObj, err := loadAssembly(domainDisp, assembly)
	if err != nil {
		return err
	}
	defer asmObj.Release()

	epVar, err := oleutil.GetProperty(asmObj, "EntryPoint")
	if err != nil {
		return fmt.Errorf("get EntryPoint: %w", err)
	}
	ep := epVar.ToIDispatch()
	defer ep.Release()

	argsVariant, cleanup, err := buildInvokeArgs(args)
	if err != nil {
		return err
	}
	defer cleanup()

	if _, err := oleutil.CallMethod(ep, "Invoke",
		ole.NewVariant(ole.VT_NULL, 0), argsVariant); err != nil {
		return fmt.Errorf("EntryPoint.Invoke: %w", err)
	}
	return nil
}

// ExecuteDLL loads a .NET DLL from memory, resolves typeName.methodName,
// and invokes it with a single string argument.
func (rt *Runtime) ExecuteDLL(dll []byte, typeName, methodName, arg string) error {
	if len(dll) == 0 {
		return fmt.Errorf("empty dll")
	}
	if typeName == "" || methodName == "" {
		return fmt.Errorf("typeName and methodName are required")
	}
	domainDisp, err := rt.defaultDomainDispatch()
	if err != nil {
		return err
	}
	defer domainDisp.Release()

	asmObj, err := loadAssembly(domainDisp, dll)
	if err != nil {
		return err
	}
	defer asmObj.Release()

	typeVar, err := oleutil.CallMethod(asmObj, "GetType_2", typeName)
	if err != nil {
		return fmt.Errorf("GetType_2(%s): %w", typeName, err)
	}
	typeObj := typeVar.ToIDispatch()
	defer typeObj.Release()

	instVar, err := oleutil.CallMethod(asmObj, "CreateInstance", typeName)
	if err != nil {
		return fmt.Errorf("CreateInstance(%s): %w", typeName, err)
	}
	inst := instVar.ToIDispatch()
	defer inst.Release()

	if _, err := oleutil.CallMethod(typeObj, "InvokeMember_3",
		methodName,
		256, // BindingFlags.InvokeMethod
		ole.NewVariant(ole.VT_NULL, 0),
		instVar,
		[]string{arg},
	); err != nil {
		return fmt.Errorf("InvokeMember_3(%s): %w", methodName, err)
	}
	return nil
}

// createMetaHost calls CLRCreateInstance to obtain an ICLRMetaHost*.
func createMetaHost() (uintptr, error) {
	var metaHost uintptr
	r, _, _ := api.ProcCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&metaHost)),
	)
	if r != sOK {
		return 0, fmt.Errorf("CLRCreateInstance: HRESULT 0x%X", uint32(r))
	}
	return metaHost, nil
}

// pickRuntime chooses the preferred installed runtime (v4 first).
// If enumeration fails or returns empty, falls back to a safe default.
func pickRuntime(metaHost uintptr) (string, error) {
	versions, err := enumerateRuntimes(metaHost)
	if err != nil || len(versions) == 0 {
		return "v4.0.30319", nil
	}
	for _, v := range versions {
		if len(v) >= 2 && v[1] == '4' {
			return v, nil
		}
	}
	return versions[len(versions)-1], nil
}

func enumerateRuntimes(metaHost uintptr) ([]string, error) {
	vtbl := (*iCLRMetaHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(metaHost))))

	var enumUnk uintptr
	r, _, _ := syscall.SyscallN(vtbl.EnumerateInstalledRuntimes,
		metaHost,
		uintptr(unsafe.Pointer(&enumUnk)),
	)
	if r != sOK {
		return nil, fmt.Errorf("EnumerateInstalledRuntimes: HRESULT 0x%X", uint32(r))
	}
	defer releaseCOM(enumUnk)

	enumVtbl := (*iEnumUnknownVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(enumUnk))))
	var versions []string
	for {
		var runtimeInfo uintptr
		var fetched uint32
		r, _, _ := syscall.SyscallN(enumVtbl.Next,
			enumUnk,
			1,
			uintptr(unsafe.Pointer(&runtimeInfo)),
			uintptr(unsafe.Pointer(&fetched)),
		)
		if fetched == 0 || r == sFalse {
			break
		}
		if r != sOK {
			return versions, fmt.Errorf("IEnumUnknown.Next: HRESULT 0x%X", uint32(r))
		}
		ver := runtimeVersion(runtimeInfo)
		releaseCOM(runtimeInfo)
		if ver != "" {
			versions = append(versions, ver)
		}
	}
	return versions, nil
}

func metaHostGetRuntime(metaHost uintptr, version string) (uintptr, error) {
	versionW, err := windows.UTF16PtrFromString(version)
	if err != nil {
		return 0, fmt.Errorf("invalid version string: %w", err)
	}
	vtbl := (*iCLRMetaHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(metaHost))))
	var runtimeInfo uintptr
	r, _, _ := syscall.SyscallN(vtbl.GetRuntime,
		metaHost,
		uintptr(unsafe.Pointer(versionW)),
		uintptr(unsafe.Pointer(iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&runtimeInfo)),
	)
	if r != sOK {
		return 0, fmt.Errorf("ICLRMetaHost.GetRuntime(%s): HRESULT 0x%X", version, uint32(r))
	}
	return runtimeInfo, nil
}

func runtimeInfoBindLegacyV2(runtimeInfo uintptr) error {
	vtbl := (*iCLRRuntimeInfoVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(runtimeInfo))))
	r, _, _ := syscall.SyscallN(vtbl.BindAsLegacyV2Runtime, runtimeInfo)
	if r != sOK {
		return fmt.Errorf("BindAsLegacyV2Runtime: HRESULT 0x%X", uint32(r))
	}
	return nil
}

func runtimeInfoGetCorHost(runtimeInfo uintptr) (uintptr, error) {
	vtbl := (*iCLRRuntimeInfoVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(runtimeInfo))))
	var host uintptr
	r, _, _ := syscall.SyscallN(vtbl.GetInterface,
		runtimeInfo,
		uintptr(unsafe.Pointer(clsidCorRuntimeHost)),
		uintptr(unsafe.Pointer(iidICorRuntimeHost)),
		uintptr(unsafe.Pointer(&host)),
	)
	switch uint32(r) {
	case regdbEClassNotReg, clrEShimLegacyRuntimeAlreadyBnd:
		return 0, ErrLegacyRuntimeUnavailable
	}
	if r != sOK {
		return 0, fmt.Errorf("ICLRRuntimeInfo.GetInterface(ICorRuntimeHost): HRESULT 0x%X", uint32(r))
	}
	return host, nil
}

func corHostStart(host uintptr) error {
	vtbl := (*iCorRuntimeHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(host))))
	r, _, _ := syscall.SyscallN(vtbl.Start, host)
	if r != sOK && uint32(r) != corProfERuntimeUninitialized {
		return fmt.Errorf("ICorRuntimeHost.Start: HRESULT 0x%X", uint32(r))
	}
	return nil
}

func runtimeVersion(runtimeInfo uintptr) string {
	vtbl := (*iCLRRuntimeInfoVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(runtimeInfo))))
	buf := make([]uint16, 64)
	size := uint32(len(buf))
	r, _, _ := syscall.SyscallN(vtbl.GetVersionString,
		runtimeInfo,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r != sOK {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// defaultDomainDispatch returns the default AppDomain as an IDispatch.
// Caller must Release() the returned dispatch.
func (rt *Runtime) defaultDomainDispatch() (*ole.IDispatch, error) {
	vtbl := (*iCorRuntimeHostVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(rt.host))))
	var domainUnk uintptr
	r, _, _ := syscall.SyscallN(vtbl.GetDefaultDomain,
		rt.host,
		uintptr(unsafe.Pointer(&domainUnk)),
	)
	if r != sOK {
		return nil, fmt.Errorf("ICorRuntimeHost.GetDefaultDomain: HRESULT 0x%X", uint32(r))
	}
	defer releaseCOM(domainUnk)

	unknown := (*ole.IUnknown)(unsafe.Pointer(domainUnk))
	disp, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("AppDomain QI IDispatch: %w", err)
	}
	return disp, nil
}

// loadAssembly calls AppDomain.Load_3(rawAssembly) and returns the Assembly
// object as IDispatch. Caller must Release().
func loadAssembly(domain *ole.IDispatch, data []byte) (*ole.IDispatch, error) {
	sa, err := newByteSafeArray(data)
	if err != nil {
		return nil, err
	}
	defer destroySafeArray(sa)

	variant := ole.NewVariant(ole.VT_ARRAY|vtUI1, int64(sa))
	result, err := oleutil.CallMethod(domain, "Load_3", &variant)
	if err != nil {
		return nil, fmt.Errorf("AppDomain.Load_3: %w", err)
	}
	return result.ToIDispatch(), nil
}

// buildInvokeArgs builds the args VARIANT expected by MethodInfo.Invoke:
// VT_NULL for no args, VT_ARRAY|VT_BSTR SAFEARRAY otherwise.
// The returned cleanup function frees the SAFEARRAY / BSTRs.
func buildInvokeArgs(args []string) (ole.VARIANT, func(), error) {
	if len(args) == 0 {
		return ole.NewVariant(ole.VT_NULL, 0), func() {}, nil
	}
	// EntryPoint signature is Main(string[] args) — a single parameter of
	// type string[]. MethodInfo.Invoke takes object[] where each element is
	// a parameter, so we need an outer SAFEARRAY of length 1 whose element
	// is the BSTR[] SAFEARRAY of user args.
	inner, err := newBstrSafeArray(args)
	if err != nil {
		return ole.VARIANT{}, nil, err
	}
	outer, err := newVariantSafeArrayWithOne(ole.VT_ARRAY|vtBstr, uintptr(inner))
	if err != nil {
		destroySafeArray(inner)
		return ole.VARIANT{}, nil, err
	}
	cleanup := func() {
		destroySafeArray(outer)
		destroySafeArray(inner)
	}
	return ole.NewVariant(ole.VT_ARRAY|ole.VT_VARIANT, int64(outer)), cleanup, nil
}

// --- SAFEARRAY helpers ---

func newByteSafeArray(data []byte) (uintptr, error) {
	sa, _, _ := api.ProcSafeArrayCreateVector.Call(vtUI1, 0, uintptr(len(data)))
	if sa == 0 {
		return 0, fmt.Errorf("SafeArrayCreateVector(UI1) failed")
	}
	var dataPtr uintptr
	r, _, _ := api.ProcSafeArrayAccessData.Call(sa, uintptr(unsafe.Pointer(&dataPtr)))
	if r != sOK {
		api.ProcSafeArrayDestroy.Call(sa) //nolint:errcheck
		return 0, fmt.Errorf("SafeArrayAccessData: HRESULT 0x%X", uint32(r))
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), len(data))
	copy(dst, data)
	api.ProcSafeArrayUnaccessData.Call(sa) //nolint:errcheck
	return sa, nil
}

func newBstrSafeArray(strs []string) (uintptr, error) {
	sa, _, _ := api.ProcSafeArrayCreateVector.Call(vtBstr, 0, uintptr(len(strs)))
	if sa == 0 {
		return 0, fmt.Errorf("SafeArrayCreateVector(BSTR) failed")
	}
	for i, s := range strs {
		bstr, err := sysAllocString(s)
		if err != nil {
			api.ProcSafeArrayDestroy.Call(sa) //nolint:errcheck
			return 0, err
		}
		idx := int32(i)
		r, _, _ := api.ProcSafeArrayPutElement.Call(
			sa,
			uintptr(unsafe.Pointer(&idx)),
			bstr,
		)
		api.ProcSysFreeString.Call(bstr) //nolint:errcheck — PutElement copies the BSTR
		if r != sOK {
			api.ProcSafeArrayDestroy.Call(sa) //nolint:errcheck
			return 0, fmt.Errorf("SafeArrayPutElement[%d]: HRESULT 0x%X", i, uint32(r))
		}
	}
	return sa, nil
}

// newVariantSafeArrayWithOne creates a length-1 SAFEARRAY of VARIANT whose
// single element wraps innerSafeArray as a VT_ARRAY|elemVT variant.
func newVariantSafeArrayWithOne(elemVT ole.VT, innerSafeArray uintptr) (uintptr, error) {
	const vtVariant = 12
	sa, _, _ := api.ProcSafeArrayCreateVector.Call(vtVariant, 0, 1)
	if sa == 0 {
		return 0, fmt.Errorf("SafeArrayCreateVector(VARIANT) failed")
	}
	v := ole.NewVariant(elemVT, int64(innerSafeArray))
	var idx int32
	r, _, _ := api.ProcSafeArrayPutElement.Call(
		sa,
		uintptr(unsafe.Pointer(&idx)),
		uintptr(unsafe.Pointer(&v)),
	)
	if r != sOK {
		api.ProcSafeArrayDestroy.Call(sa) //nolint:errcheck
		return 0, fmt.Errorf("SafeArrayPutElement(VARIANT): HRESULT 0x%X", uint32(r))
	}
	return sa, nil
}

func sysAllocString(s string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid string: %w", err)
	}
	bstr, _, _ := api.ProcSysAllocString.Call(uintptr(unsafe.Pointer(p)))
	if bstr == 0 {
		return 0, fmt.Errorf("SysAllocString failed")
	}
	return bstr, nil
}

func destroySafeArray(sa uintptr) {
	if sa != 0 {
		api.ProcSafeArrayDestroy.Call(sa) //nolint:errcheck
	}
}

// releaseCOM invokes IUnknown::Release on a raw COM interface pointer.
func releaseCOM(ptr uintptr) {
	if ptr == 0 {
		return
	}
	vtbl := (*iUnknownVtbl)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(ptr))))
	syscall.SyscallN(vtbl.Release, ptr) //nolint:errcheck
}
