//go:build go1.21

package cmp

import stdcmp "cmp"

type Ordered = stdcmp.Ordered

func Compare[T Ordered](x, y T) int { return stdcmp.Compare(x, y) }
func Less[T Ordered](x, y T) bool  { return stdcmp.Less(x, y) }
func Or[T comparable](vals ...T) T  { return stdcmp.Or(vals...) }
