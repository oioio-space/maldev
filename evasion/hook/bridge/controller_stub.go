//go:build !windows

package bridge

import "io"

// CommandHandler processes an RPC command.
type CommandHandler func(data []byte) ([]byte, error)

// Controller is a no-op stub on non-Windows platforms.
type Controller struct{}

func Standalone() *Controller                             { return &Controller{} }
func Connect(_ io.ReadWriteCloser) *Controller            { return &Controller{} }
func (c *Controller) Register(_ string, _ CommandHandler) {}
func (c *Controller) SetArgBlock(_ *ArgBlock)             {}
func (c *Controller) Args() *ArgBlock                     { return &ArgBlock{} }
func (c *Controller) CallOriginal(_ ...uintptr) uintptr   { return 0 }
func (c *Controller) SetReturn(_ uintptr)                 {}
func (c *Controller) Log(_ string, _ ...interface{})      {}
func (c *Controller) Exfil(_ string, _ []byte)            {}
func (c *Controller) Ask(_ string, _ []byte) Decision     { return Allow }
func (c *Controller) Heartbeat() error                    { return nil }
func (c *Controller) Serve() error                        { return nil }
func (c *Controller) Close() error                        { return nil }
