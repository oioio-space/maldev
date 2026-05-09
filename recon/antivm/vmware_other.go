//go:build !amd64

package antivm

// vmwareBackdoorRaw is unimplemented on non-amd64 architectures: the
// VMware backdoor port lives in the x86 I/O space and only x86 / amd64
// can issue an `IN EAX, DX` instruction. Kept as a no-op so the
// platform-agnostic [BackdoorVMware] wrapper compiles everywhere; the
// privilege gate ensures it is never reached at runtime.
func vmwareBackdoorRaw(eaxIn, ecxIn uint32, regs *[4]uint32) {
	_ = eaxIn
	_ = ecxIn
	_ = regs
}

const (
	vmwareMagic         uint32 = 0x564D5868
	vmwarePort          uint32 = 0x5658
	vmwareCmdGetVersion uint32 = 0x0A
	vmwareSignature     uint32 = vmwareMagic
)
