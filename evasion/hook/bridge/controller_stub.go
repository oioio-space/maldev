//go:build !windows

package bridge

import "io"

// Controller is a no-op stub on non-Windows platforms. All methods are safe
// to call and return zero values so hook code compiles cross-platform.
type Controller struct{}

// Standalone returns a no-op Controller.
func Standalone() *Controller { return &Controller{} }

// Connect returns a no-op Controller; the connection is not used.
func Connect(_ io.ReadWriteCloser) *Controller { return &Controller{} }

func (c *Controller) SetArgBlock(_ *ArgBlock)           {}
func (c *Controller) Args() *ArgBlock                   { return &ArgBlock{} }
func (c *Controller) CallOriginal(_ ...uintptr) uintptr { return 0 }
func (c *Controller) SetReturn(_ uintptr)               {}
func (c *Controller) Log(_ string, _ ...interface{})    {}
func (c *Controller) Exfil(_ string, _ []byte)          {}
func (c *Controller) Ask(_ string, _ []byte) Decision   { return Allow }
func (c *Controller) Heartbeat() error                  { return nil }
func (c *Controller) Close() error                      { return nil }
