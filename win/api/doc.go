//go:build windows

// Package api is the single source of truth for all Windows DLL handles,
// procedure references, and shared structures used across the maldev library.
//
// Platform: Windows
// Detection: Low -- loading system DLLs is normal process behavior.
//
// All other maldev modules MUST import DLL handles and procedure pointers
// from this package instead of declaring their own LazyDLL instances.
// This prevents duplicate handles and ensures consistent DLL search path
// restriction via NewLazySystemDLL (which limits loading to System32).
//
// Exported DLL handles: Kernel32, Ntdll, Advapi32, User32, Shell32, Userenv, Netapi32.
package api
