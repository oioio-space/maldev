package bridge

import "fmt"

// Decision represents the implant's response to a hook call.
type Decision int

const (
	Allow  Decision = iota
	Block
	Modify
)

// ArgBlock holds captured arguments from a hooked function call.
type ArgBlock struct {
	Args           [18]uintptr
	TrampolineAddr uintptr
}

func (a *ArgBlock) NonZeroArgs() []int {
	var indices []int
	for i, v := range a.Args {
		if v != 0 {
			indices = append(indices, i)
		}
	}
	return indices
}

func (a *ArgBlock) NonZeroCount() int {
	n := 0
	for _, v := range a.Args {
		if v != 0 {
			n++
		}
	}
	return n
}

func (a *ArgBlock) Int(i int) int64 {
	if i < 0 || i >= 18 {
		return 0
	}
	return int64(a.Args[i])
}

func (a *ArgBlock) GoString() string {
	return fmt.Sprintf("ArgBlock{NonZero: %d}", a.NonZeroCount())
}
