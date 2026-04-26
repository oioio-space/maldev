// Package dcerpc is a STUB. The vendored msrpc/{pac,dtyp,adts/claims/...}
// subset references the dcerpc surface in a few places, but only as:
//   - `_ = (*dcerpc.SyntaxID)(nil)` static-check declarations injected
//     by the upstream go-msrpc IDL codegen.
//   - Type signatures for client/server interfaces (ClaimsClient,
//     ClaimsServer) that the maldev golden-ticket use case never calls.
//
// We expose just enough type machinery for the vendored code to
// compile. Method bodies on the stubbed interfaces are unimplemented —
// callers that try to actually USE a dcerpc.Conn at runtime will get
// ErrStubbed. The real DCERPC transport will arrive when chantier VI
// (DCSync) lands; at that point this stub gets replaced by a vendored
// upstream subset or a hand-rolled MS-DRSR client.
package dcerpc

import (
	"context"
	"errors"

	"github.com/oioio-space/maldev/internal/msrpc/midl/uuid"
	"github.com/oioio-space/maldev/internal/msrpc/ndr"
)

// ErrStubbed is returned (or panicked-with) by stubbed Conn methods if
// production code somehow reaches the transport layer through the
// vendored claims client. PAC marshaling never reaches here.
var ErrStubbed = errors.New("dcerpc: stub — DCERPC transport not vendored, see internal/msrpc/dcerpc/syntax.go")

// SyntaxID is the (interface UUID, version) pair that identifies an
// RPC interface. Mirrors upstream go-msrpc/dcerpc/types.go layout so
// the vendored claims package's `&dcerpc.SyntaxID{...}` literals
// continue to compile verbatim.
type SyntaxID struct {
	IfUUID         *uuid.UUID
	IfVersionMajor uint16
	IfVersionMinor uint16
}

// Operation is the vendored alias for ndr.Operation. Used by the
// generated server-handler signatures. Reuses the real ndr operation
// type so the MarshalNDR / UnmarshalNDR methods on PAC types remain
// type-compatible.
type Operation = ndr.Operation

// Option is the marker interface for DCERPC bind options.
// Implementations live in the (non-vendored) upstream dcerpc/options.go.
type Option interface {
	is_rpcOption()
}

// CallOption is the marker interface for per-call DCERPC options.
type CallOption interface {
	is_rpcCallOption()
}

// ServerHandle is the upstream signature for a generated server
// dispatcher. Vendored only so the claims server.go compiles; the
// returned function is never called from the golden-ticket path.
type ServerHandle func(context.Context, int, ndr.Reader) (Operation, error)

// Conn is the upstream client/server connection interface. All methods
// stub-fail at runtime — vendoring this interface satisfies the
// vendored claims client, but callers that actually try to bind/invoke
// hit ErrStubbed.
type Conn interface {
	Bind(context.Context, ...Option) (Conn, error)
	AlterContext(context.Context, ...Option) error
	Context() context.Context
	Invoke(context.Context, Operation, ...CallOption) error
	InvokeObject(context.Context, *uuid.UUID, Operation, ...CallOption) error
	Close(context.Context) error
	RegisterServer(ServerHandle, ...Option)
	Error(context.Context, any) error
}

// abstractSyntaxOpt carries the WithAbstractSyntax option payload.
// Implementing the marker interface satisfies dcerpc.Option without
// exposing any behavior — the real bind never runs.
type abstractSyntaxOpt struct{ Syntax *SyntaxID }

func (abstractSyntaxOpt) is_rpcOption() {}

// WithAbstractSyntax mirrors upstream's bind-time option that pins
// the abstract syntax (interface UUID + version). Stubbed: callers
// constructing this still compile, but no transport consumes it.
func WithAbstractSyntax(s *SyntaxID) Option { return abstractSyntaxOpt{Syntax: s} }
