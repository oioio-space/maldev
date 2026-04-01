//go:build go1.21

package slices

import (
	"cmp"
	stdslices "slices"
)

func Contains[S ~[]E, E comparable](s S, v E) bool         { return stdslices.Contains(s, v) }
func Index[S ~[]E, E comparable](s S, v E) int             { return stdslices.Index(s, v) }
func Equal[S ~[]E, E comparable](s1, s2 S) bool            { return stdslices.Equal(s1, s2) }
func Reverse[S ~[]E, E any](s S)                           { stdslices.Reverse(s) }
func Sort[S ~[]E, E cmp.Ordered](x S)                      { stdslices.Sort(x) }
func SortFunc[S ~[]E, E any](x S, less func(a, b E) int)   { stdslices.SortFunc(x, less) }
func Compact[S ~[]E, E comparable](s S) S                  { return stdslices.Compact(s) }
func Clone[S ~[]E, E any](s S) S                           { return stdslices.Clone(s) }
func ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool { return stdslices.ContainsFunc(s, f) }
func EqualFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, eq func(E1, E2) bool) bool {
	return stdslices.EqualFunc(s1, s2, eq)
}
func Clip[S ~[]E, E any](s S) S    { return stdslices.Clip(s) }
func Grow[S ~[]E, E any](s S, n int) S { return stdslices.Grow(s, n) }
