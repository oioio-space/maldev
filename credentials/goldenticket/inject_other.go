//go:build !windows

package goldenticket

// Submit is the Windows ticket-cache injection entry point. The
// LsaCallAuthenticationPackage(KerbSubmitTicketMessage) primitive has
// no Linux equivalent, so this build returns ErrPlatformUnsupported
// unconditionally. Callers on Linux should write the kirbi to disk
// (Forge already returns the bytes) and have a Windows-side process
// import it via Submit, mimikatz `kerberos::ptt`, or
// `klist purge && klist import`.
func Submit(kirbi []byte) error {
	_ = kirbi
	return ErrPlatformUnsupported
}
