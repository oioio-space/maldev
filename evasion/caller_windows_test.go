//go:build windows

package evasion

import (
	"testing"

	"github.com/stretchr/testify/assert"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func TestAsCaller_Nil(t *testing.T) {
	assert.Nil(t, AsCaller(nil))
}

func TestAsCaller_ValidCaller(t *testing.T) {
	resolver := wsyscall.NewHellsGate()
	caller := wsyscall.New(wsyscall.MethodDirect, resolver)
	result := AsCaller(caller)
	assert.NotNil(t, result)
}

func TestAsCaller_WrongType(t *testing.T) {
	assert.Nil(t, AsCaller("not a caller"))
}

func TestAsCaller_NilTypedPointer(t *testing.T) {
	assert.Nil(t, AsCaller((*wsyscall.Caller)(nil)))
}
