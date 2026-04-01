//go:build !go1.21

// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package slices defines various functions useful with slices of any type.
package slices

import (
	"math/bits"
	"unsafe"

	"github.com/oioio-space/maldev/core/compat/cmp"
)

// Equal reports whether two slices are equal: the same length and all
// elements equal. If the lengths are different, Equal returns false.
// Otherwise, the elements are compared in increasing index order, and the
// comparison stops at the first unequal pair.
// Floating point NaNs are not considered equal.
func Equal[S ~[]E, E comparable](s1, s2 S) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

// EqualFunc reports whether two slices are equal using an equality
// function on each pair of elements. If the lengths are different,
// EqualFunc returns false. Otherwise, the elements are compared in
// increasing index order, and the comparison stops at the first index
// for which eq returns false.
func EqualFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, eq func(E1, E2) bool) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i, v1 := range s1 {
		v2 := s2[i]
		if !eq(v1, v2) {
			return false
		}
	}
	return true
}

// Compare compares the elements of s1 and s2, using [cmp.Compare] on each pair
// of elements. The elements are compared sequentially, starting at index 0,
// until one element is not equal to the other.
// The result of comparing the first non-matching elements is returned.
// If both slices are equal until one of them ends, the shorter slice is
// considered less than the longer one.
// The result is 0 if s1 == s2, -1 if s1 < s2, and +1 if s1 > s2.
func Compare[S ~[]E, E cmp.Ordered](s1, s2 S) int {
	for i, v1 := range s1 {
		if i >= len(s2) {
			return +1
		}
		v2 := s2[i]
		if c := cmp.Compare(v1, v2); c != 0 {
			return c
		}
	}
	if len(s1) < len(s2) {
		return -1
	}
	return 0
}

// CompareFunc is like [Compare] but uses a custom comparison function on each
// pair of elements.
// The result is the first non-zero result of cmp; if cmp always
// returns 0 the result is 0 if len(s1) == len(s2), -1 if len(s1) < len(s2),
// and +1 if len(s1) > len(s2).
func CompareFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, cmpFn func(E1, E2) int) int {
	for i, v1 := range s1 {
		if i >= len(s2) {
			return +1
		}
		v2 := s2[i]
		if c := cmpFn(v1, v2); c != 0 {
			return c
		}
	}
	if len(s1) < len(s2) {
		return -1
	}
	return 0
}

// Index returns the index of the first occurrence of v in s,
// or -1 if not present.
func Index[S ~[]E, E comparable](s S, v E) int {
	for i := range s {
		if v == s[i] {
			return i
		}
	}
	return -1
}

// IndexFunc returns the first index i satisfying f(s[i]),
// or -1 if none do.
func IndexFunc[S ~[]E, E any](s S, f func(E) bool) int {
	for i := range s {
		if f(s[i]) {
			return i
		}
	}
	return -1
}

// Contains reports whether v is present in s.
func Contains[S ~[]E, E comparable](s S, v E) bool {
	return Index(s, v) >= 0
}

// ContainsFunc reports whether at least one
// element e of s satisfies f(e).
func ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool {
	return IndexFunc(s, f) >= 0
}

// Insert inserts the values v... into s at index i,
// returning the modified slice.
func Insert[S ~[]E, E any](s S, i int, v ...E) S {
	m := len(v)
	if m == 0 {
		return s
	}
	n := len(s)
	if i == n {
		return append(s, v...)
	}
	if n+m > cap(s) {
		s2 := append(s[:i], make(S, n+m-i)...)
		copy(s2[i:], v)
		copy(s2[i+m:], s[i:])
		return s2
	}
	s = s[:n+m]

	if !overlaps(v, s[i+m:]) {
		copy(s[i+m:], s[i:])
		copy(s[i:], v)
		return s
	}

	copy(s[n:], v)
	rotateRight(s[i:], m)
	return s
}

// Delete removes the elements s[i:j] from s, returning the modified slice.
func Delete[S ~[]E, E any](s S, i, j int) S {
	_ = s[i:j] // bounds check
	return append(s[:i], s[j:]...)
}

// DeleteFunc removes any elements from s for which del returns true,
// returning the modified slice.
func DeleteFunc[S ~[]E, E any](s S, del func(E) bool) S {
	for i, v := range s {
		if del(v) {
			j := i
			for i++; i < len(s); i++ {
				v = s[i]
				if !del(v) {
					s[j] = v
					j++
				}
			}
			return s[:j]
		}
	}
	return s
}

// Replace replaces the elements s[i:j] by the given v, and returns the
// modified slice.
func Replace[S ~[]E, E any](s S, i, j int, v ...E) S {
	_ = s[i:j]

	if i == j {
		return Insert(s, i, v...)
	}
	if j == len(s) {
		return append(s[:i], v...)
	}

	tot := len(s[:i]) + len(v) + len(s[j:])
	if tot > cap(s) {
		s2 := append(s[:i], make(S, tot-i)...)
		copy(s2[i:], v)
		copy(s2[i+len(v):], s[j:])
		return s2
	}

	r := s[:tot]

	if i+len(v) <= j {
		copy(r[i:], v)
		if i+len(v) != j {
			copy(r[i+len(v):], s[j:])
		}
		return r
	}

	if !overlaps(r[i+len(v):], v) {
		copy(r[i+len(v):], s[j:])
		copy(r[i:], v)
		return r
	}

	y := len(v) - (j - i)

	if !overlaps(r[i:j], v) {
		copy(r[i:j], v[y:])
		copy(r[len(s):], v[:y])
		rotateRight(r[i:], y)
		return r
	}
	if !overlaps(r[len(s):], v) {
		copy(r[len(s):], v[:y])
		copy(r[i:j], v[y:])
		rotateRight(r[i:], y)
		return r
	}

	k := startIdx(v, s[j:])
	copy(r[i:], v)
	copy(r[i+len(v):], r[i+k:])
	return r
}

// Clone returns a copy of the slice.
// The elements are copied using assignment, so this is a shallow clone.
func Clone[S ~[]E, E any](s S) S {
	if s == nil {
		return nil
	}
	return append(S([]E{}), s...)
}

// Compact replaces consecutive runs of equal elements with a single copy.
func Compact[S ~[]E, E comparable](s S) S {
	if len(s) < 2 {
		return s
	}
	i := 1
	for k := 1; k < len(s); k++ {
		if s[k] != s[k-1] {
			if i != k {
				s[i] = s[k]
			}
			i++
		}
	}
	return s[:i]
}

// CompactFunc is like [Compact] but uses an equality function to compare elements.
func CompactFunc[S ~[]E, E any](s S, eq func(E, E) bool) S {
	if len(s) < 2 {
		return s
	}
	i := 1
	for k := 1; k < len(s); k++ {
		if !eq(s[k], s[k-1]) {
			if i != k {
				s[i] = s[k]
			}
			i++
		}
	}
	return s[:i]
}

// Grow increases the slice's capacity, if necessary, to guarantee space for
// another n elements.
func Grow[S ~[]E, E any](s S, n int) S {
	if n < 0 {
		panic("cannot be negative")
	}
	if n -= cap(s) - len(s); n > 0 {
		s = append(s[:cap(s)], make([]E, n)...)[:len(s)]
	}
	return s
}

// Clip removes unused capacity from the slice, returning s[:len(s):len(s)].
func Clip[S ~[]E, E any](s S) S {
	return s[:len(s):len(s)]
}

// Reverse reverses the elements of the slice in place.
func Reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// Sort sorts a slice of any ordered type in ascending order.
// When sorting floating-point numbers, NaNs are ordered before other values.
func Sort[S ~[]E, E cmp.Ordered](x S) {
	n := len(x)
	pdqsortOrdered(x, 0, n, bits.Len(uint(n)))
}

// SortFunc sorts the slice x in ascending order as determined by the cmp
// function. This sort is not guaranteed to be stable.
func SortFunc[S ~[]E, E any](x S, cmpFn func(a, b E) int) {
	n := len(x)
	pdqsortCmpFunc(x, 0, n, bits.Len(uint(n)), cmpFn)
}

// SortStableFunc sorts the slice x while keeping the original order of equal
// elements, using cmp to compare elements in the same way as [SortFunc].
func SortStableFunc[S ~[]E, E any](x S, cmpFn func(a, b E) int) {
	stableCmpFunc(x, len(x), cmpFn)
}

// IsSorted reports whether x is sorted in ascending order.
func IsSorted[S ~[]E, E cmp.Ordered](x S) bool {
	for i := len(x) - 1; i > 0; i-- {
		if cmp.Less(x[i], x[i-1]) {
			return false
		}
	}
	return true
}

// IsSortedFunc reports whether x is sorted in ascending order, with cmp as the
// comparison function as defined by [SortFunc].
func IsSortedFunc[S ~[]E, E any](x S, cmpFn func(a, b E) int) bool {
	for i := len(x) - 1; i > 0; i-- {
		if cmpFn(x[i], x[i-1]) < 0 {
			return false
		}
	}
	return true
}

// MinFunc returns the minimal value in x, using cmp to compare elements.
func MinFunc[S ~[]E, E any](x S, cmpFn func(a, b E) int) E {
	if len(x) < 1 {
		panic("slices.MinFunc: empty list")
	}
	m := x[0]
	for i := 1; i < len(x); i++ {
		if cmpFn(x[i], m) < 0 {
			m = x[i]
		}
	}
	return m
}

// MaxFunc returns the maximal value in x, using cmp to compare elements.
func MaxFunc[S ~[]E, E any](x S, cmpFn func(a, b E) int) E {
	if len(x) < 1 {
		panic("slices.MaxFunc: empty list")
	}
	m := x[0]
	for i := 1; i < len(x); i++ {
		if cmpFn(x[i], m) > 0 {
			m = x[i]
		}
	}
	return m
}

// BinarySearch searches for target in a sorted slice and returns the position
// where target is found, or the position where target would appear in the
// sort order; it also returns a bool saying whether the target is really found
// in the slice.
func BinarySearch[S ~[]E, E cmp.Ordered](x S, target E) (int, bool) {
	n := len(x)
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1)
		if cmp.Less(x[h], target) {
			i = h + 1
		} else {
			j = h
		}
	}
	return i, i < n && (x[i] == target || (isNaN(x[i]) && isNaN(target)))
}

// BinarySearchFunc works like [BinarySearch], but uses a custom comparison function.
func BinarySearchFunc[S ~[]E, E, T any](x S, target T, cmpFn func(E, T) int) (int, bool) {
	n := len(x)
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1)
		if cmpFn(x[h], target) < 0 {
			i = h + 1
		} else {
			j = h
		}
	}
	return i, i < n && cmpFn(x[i], target) == 0
}

type sortedHint int

const (
	unknownHint sortedHint = iota
	increasingHint
	decreasingHint
)

type xorshift uint64

func (r *xorshift) Next() uint64 {
	*r ^= *r << 13
	*r ^= *r >> 17
	*r ^= *r << 5
	return uint64(*r)
}

func nextPowerOfTwo(length int) uint {
	return 1 << bits.Len(uint(length))
}

func isNaN[T cmp.Ordered](x T) bool {
	return x != x
}

func rotateLeft[E any](s []E, r int) {
	for r != 0 && r != len(s) {
		if r*2 <= len(s) {
			swap(s[:r], s[len(s)-r:])
			s = s[:len(s)-r]
		} else {
			swap(s[:len(s)-r], s[r:])
			s, r = s[len(s)-r:], r*2-len(s)
		}
	}
}

func rotateRight[E any](s []E, r int) {
	rotateLeft(s, len(s)-r)
}

func swap[E any](x, y []E) {
	for i := 0; i < len(x); i++ {
		x[i], y[i] = y[i], x[i]
	}
}

func overlaps[E any](a, b []E) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	elemSize := unsafe.Sizeof(a[0])
	if elemSize == 0 {
		return false
	}
	return uintptr(unsafe.Pointer(&a[0])) <= uintptr(unsafe.Pointer(&b[len(b)-1]))+(elemSize-1) &&
		uintptr(unsafe.Pointer(&b[0])) <= uintptr(unsafe.Pointer(&a[len(a)-1]))+(elemSize-1)
}

func startIdx[E any](haystack, needle []E) int {
	p := &needle[0]
	for i := range haystack {
		if p == &haystack[i] {
			return i
		}
	}
	panic("needle not found")
}

// --- zsortordered ---

func insertionSortOrdered[E cmp.Ordered](data []E, a, b int) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && cmp.Less(data[j], data[j-1]); j-- {
			data[j], data[j-1] = data[j-1], data[j]
		}
	}
}

func siftDownOrdered[E cmp.Ordered](data []E, lo, hi, first int) {
	root := lo
	for {
		child := 2*root + 1
		if child >= hi {
			break
		}
		if child+1 < hi && cmp.Less(data[first+child], data[first+child+1]) {
			child++
		}
		if !cmp.Less(data[first+root], data[first+child]) {
			return
		}
		data[first+root], data[first+child] = data[first+child], data[first+root]
		root = child
	}
}

func heapSortOrdered[E cmp.Ordered](data []E, a, b int) {
	first := a
	lo := 0
	hi := b - a

	for i := (hi - 1) / 2; i >= 0; i-- {
		siftDownOrdered(data, i, hi, first)
	}

	for i := hi - 1; i >= 0; i-- {
		data[first], data[first+i] = data[first+i], data[first]
		siftDownOrdered(data, lo, i, first)
	}
}

func pdqsortOrdered[E cmp.Ordered](data []E, a, b, limit int) {
	const maxInsertion = 12

	var (
		wasBalanced    = true
		wasPartitioned = true
	)

	for {
		length := b - a

		if length <= maxInsertion {
			insertionSortOrdered(data, a, b)
			return
		}

		if limit == 0 {
			heapSortOrdered(data, a, b)
			return
		}

		if !wasBalanced {
			breakPatternsOrdered(data, a, b)
			limit--
		}

		pivot, hint := choosePivotOrdered(data, a, b)
		if hint == decreasingHint {
			reverseRangeOrdered(data, a, b)
			pivot = (b - 1) - (pivot - a)
			hint = increasingHint
		}

		if wasBalanced && wasPartitioned && hint == increasingHint {
			if partialInsertionSortOrdered(data, a, b) {
				return
			}
		}

		if a > 0 && !cmp.Less(data[a-1], data[pivot]) {
			mid := partitionEqualOrdered(data, a, b, pivot)
			a = mid
			continue
		}

		mid, alreadyPartitioned := partitionOrdered(data, a, b, pivot)
		wasPartitioned = alreadyPartitioned

		leftLen, rightLen := mid-a, b-mid
		balanceThreshold := length / 8
		if leftLen < rightLen {
			wasBalanced = leftLen >= balanceThreshold
			pdqsortOrdered(data, a, mid, limit)
			a = mid + 1
		} else {
			wasBalanced = rightLen >= balanceThreshold
			pdqsortOrdered(data, mid+1, b, limit)
			b = mid
		}
	}
}

func partitionOrdered[E cmp.Ordered](data []E, a, b, pivot int) (newpivot int, alreadyPartitioned bool) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1

	for i <= j && cmp.Less(data[i], data[a]) {
		i++
	}
	for i <= j && !cmp.Less(data[j], data[a]) {
		j--
	}
	if i > j {
		data[j], data[a] = data[a], data[j]
		return j, true
	}
	data[i], data[j] = data[j], data[i]
	i++
	j--

	for {
		for i <= j && cmp.Less(data[i], data[a]) {
			i++
		}
		for i <= j && !cmp.Less(data[j], data[a]) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	data[j], data[a] = data[a], data[j]
	return j, false
}

func partitionEqualOrdered[E cmp.Ordered](data []E, a, b, pivot int) (newpivot int) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1

	for {
		for i <= j && !cmp.Less(data[a], data[i]) {
			i++
		}
		for i <= j && cmp.Less(data[a], data[j]) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	return i
}

func partialInsertionSortOrdered[E cmp.Ordered](data []E, a, b int) bool {
	const (
		maxSteps         = 5
		shortestShifting = 50
	)
	i := a + 1
	for j := 0; j < maxSteps; j++ {
		for i < b && !cmp.Less(data[i], data[i-1]) {
			i++
		}

		if i == b {
			return true
		}

		if b-a < shortestShifting {
			return false
		}

		data[i], data[i-1] = data[i-1], data[i]

		if i-a >= 2 {
			for j := i - 1; j >= 1; j-- {
				if !cmp.Less(data[j], data[j-1]) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
		if b-i >= 2 {
			for j := i + 1; j < b; j++ {
				if !cmp.Less(data[j], data[j-1]) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
	}
	return false
}

func breakPatternsOrdered[E cmp.Ordered](data []E, a, b int) {
	length := b - a
	if length >= 8 {
		random := xorshift(length)
		modulus := nextPowerOfTwo(length)

		for idx := a + (length/4)*2 - 1; idx <= a+(length/4)*2+1; idx++ {
			other := int(uint(random.Next()) & (modulus - 1))
			if other >= length {
				other -= length
			}
			data[idx], data[a+other] = data[a+other], data[idx]
		}
	}
}

func choosePivotOrdered[E cmp.Ordered](data []E, a, b int) (pivot int, hint sortedHint) {
	const (
		shortestNinther = 50
		maxSwaps        = 4 * 3
	)

	l := b - a

	var (
		swaps int
		i     = a + l/4*1
		j     = a + l/4*2
		k     = a + l/4*3
	)

	if l >= 8 {
		if l >= shortestNinther {
			i = medianAdjacentOrdered(data, i, &swaps)
			j = medianAdjacentOrdered(data, j, &swaps)
			k = medianAdjacentOrdered(data, k, &swaps)
		}
		j = medianOrdered(data, i, j, k, &swaps)
	}

	switch swaps {
	case 0:
		return j, increasingHint
	case maxSwaps:
		return j, decreasingHint
	default:
		return j, unknownHint
	}
}

func order2Ordered[E cmp.Ordered](data []E, a, b int, swaps *int) (int, int) {
	if cmp.Less(data[b], data[a]) {
		*swaps++
		return b, a
	}
	return a, b
}

func medianOrdered[E cmp.Ordered](data []E, a, b, c int, swaps *int) int {
	a, b = order2Ordered(data, a, b, swaps)
	b, c = order2Ordered(data, b, c, swaps)
	a, b = order2Ordered(data, a, b, swaps)
	return b
}

func medianAdjacentOrdered[E cmp.Ordered](data []E, a int, swaps *int) int {
	return medianOrdered(data, a-1, a, a+1, swaps)
}

func reverseRangeOrdered[E cmp.Ordered](data []E, a, b int) {
	i := a
	j := b - 1
	for i < j {
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
}

func swapRangeOrdered[E cmp.Ordered](data []E, a, b, n int) {
	for i := 0; i < n; i++ {
		data[a+i], data[b+i] = data[b+i], data[a+i]
	}
}

func stableOrdered[E cmp.Ordered](data []E, n int) {
	blockSize := 20
	a, b := 0, blockSize
	for b <= n {
		insertionSortOrdered(data, a, b)
		a = b
		b += blockSize
	}
	insertionSortOrdered(data, a, n)

	for blockSize < n {
		a, b = 0, 2*blockSize
		for b <= n {
			symMergeOrdered(data, a, a+blockSize, b)
			a = b
			b += 2 * blockSize
		}
		if m := a + blockSize; m < n {
			symMergeOrdered(data, a, m, n)
		}
		blockSize *= 2
	}
}

func symMergeOrdered[E cmp.Ordered](data []E, a, m, b int) {
	if m-a == 1 {
		i := m
		j := b
		for i < j {
			h := int(uint(i+j) >> 1)
			if cmp.Less(data[h], data[a]) {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := a; k < i-1; k++ {
			data[k], data[k+1] = data[k+1], data[k]
		}
		return
	}

	if b-m == 1 {
		i := a
		j := m
		for i < j {
			h := int(uint(i+j) >> 1)
			if !cmp.Less(data[m], data[h]) {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := m; k > i; k-- {
			data[k], data[k-1] = data[k-1], data[k]
		}
		return
	}

	mid := int(uint(a+b) >> 1)
	n := mid + m
	var start, r int
	if m > mid {
		start = n - b
		r = mid
	} else {
		start = a
		r = m
	}
	p := n - 1

	for start < r {
		c := int(uint(start+r) >> 1)
		if !cmp.Less(data[p-c], data[c]) {
			start = c + 1
		} else {
			r = c
		}
	}

	end := n - start
	if start < m && m < end {
		rotateOrdered(data, start, m, end)
	}
	if a < start && start < mid {
		symMergeOrdered(data, a, start, mid)
	}
	if mid < end && end < b {
		symMergeOrdered(data, mid, end, b)
	}
}

func rotateOrdered[E cmp.Ordered](data []E, a, m, b int) {
	i := m - a
	j := b - m

	for i != j {
		if i > j {
			swapRangeOrdered(data, m-i, m, j)
			i -= j
		} else {
			swapRangeOrdered(data, m-i, m+j-i, i)
			j -= i
		}
	}
	swapRangeOrdered(data, m-i, m, i)
}

// --- zsortanyfunc ---

func insertionSortCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && (cmpFn(data[j], data[j-1]) < 0); j-- {
			data[j], data[j-1] = data[j-1], data[j]
		}
	}
}

func siftDownCmpFunc[E any](data []E, lo, hi, first int, cmpFn func(a, b E) int) {
	root := lo
	for {
		child := 2*root + 1
		if child >= hi {
			break
		}
		if child+1 < hi && (cmpFn(data[first+child], data[first+child+1]) < 0) {
			child++
		}
		if !(cmpFn(data[first+root], data[first+child]) < 0) {
			return
		}
		data[first+root], data[first+child] = data[first+child], data[first+root]
		root = child
	}
}

func heapSortCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) {
	first := a
	lo := 0
	hi := b - a

	for i := (hi - 1) / 2; i >= 0; i-- {
		siftDownCmpFunc(data, i, hi, first, cmpFn)
	}

	for i := hi - 1; i >= 0; i-- {
		data[first], data[first+i] = data[first+i], data[first]
		siftDownCmpFunc(data, lo, i, first, cmpFn)
	}
}

func pdqsortCmpFunc[E any](data []E, a, b, limit int, cmpFn func(a, b E) int) {
	const maxInsertion = 12

	var (
		wasBalanced    = true
		wasPartitioned = true
	)

	for {
		length := b - a

		if length <= maxInsertion {
			insertionSortCmpFunc(data, a, b, cmpFn)
			return
		}

		if limit == 0 {
			heapSortCmpFunc(data, a, b, cmpFn)
			return
		}

		if !wasBalanced {
			breakPatternsCmpFunc(data, a, b, cmpFn)
			limit--
		}

		pivot, hint := choosePivotCmpFunc(data, a, b, cmpFn)
		if hint == decreasingHint {
			reverseRangeCmpFunc(data, a, b, cmpFn)
			pivot = (b - 1) - (pivot - a)
			hint = increasingHint
		}

		if wasBalanced && wasPartitioned && hint == increasingHint {
			if partialInsertionSortCmpFunc(data, a, b, cmpFn) {
				return
			}
		}

		if a > 0 && !(cmpFn(data[a-1], data[pivot]) < 0) {
			mid := partitionEqualCmpFunc(data, a, b, pivot, cmpFn)
			a = mid
			continue
		}

		mid, alreadyPartitioned := partitionCmpFunc(data, a, b, pivot, cmpFn)
		wasPartitioned = alreadyPartitioned

		leftLen, rightLen := mid-a, b-mid
		balanceThreshold := length / 8
		if leftLen < rightLen {
			wasBalanced = leftLen >= balanceThreshold
			pdqsortCmpFunc(data, a, mid, limit, cmpFn)
			a = mid + 1
		} else {
			wasBalanced = rightLen >= balanceThreshold
			pdqsortCmpFunc(data, mid+1, b, limit, cmpFn)
			b = mid
		}
	}
}

func partitionCmpFunc[E any](data []E, a, b, pivot int, cmpFn func(a, b E) int) (newpivot int, alreadyPartitioned bool) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1

	for i <= j && (cmpFn(data[i], data[a]) < 0) {
		i++
	}
	for i <= j && !(cmpFn(data[j], data[a]) < 0) {
		j--
	}
	if i > j {
		data[j], data[a] = data[a], data[j]
		return j, true
	}
	data[i], data[j] = data[j], data[i]
	i++
	j--

	for {
		for i <= j && (cmpFn(data[i], data[a]) < 0) {
			i++
		}
		for i <= j && !(cmpFn(data[j], data[a]) < 0) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	data[j], data[a] = data[a], data[j]
	return j, false
}

func partitionEqualCmpFunc[E any](data []E, a, b, pivot int, cmpFn func(a, b E) int) (newpivot int) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1

	for {
		for i <= j && !(cmpFn(data[a], data[i]) < 0) {
			i++
		}
		for i <= j && (cmpFn(data[a], data[j]) < 0) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	return i
}

func partialInsertionSortCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) bool {
	const (
		maxSteps         = 5
		shortestShifting = 50
	)
	i := a + 1
	for j := 0; j < maxSteps; j++ {
		for i < b && !(cmpFn(data[i], data[i-1]) < 0) {
			i++
		}

		if i == b {
			return true
		}

		if b-a < shortestShifting {
			return false
		}

		data[i], data[i-1] = data[i-1], data[i]

		if i-a >= 2 {
			for j := i - 1; j >= 1; j-- {
				if !(cmpFn(data[j], data[j-1]) < 0) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
		if b-i >= 2 {
			for j := i + 1; j < b; j++ {
				if !(cmpFn(data[j], data[j-1]) < 0) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
	}
	return false
}

func breakPatternsCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) {
	length := b - a
	if length >= 8 {
		random := xorshift(length)
		modulus := nextPowerOfTwo(length)

		for idx := a + (length/4)*2 - 1; idx <= a+(length/4)*2+1; idx++ {
			other := int(uint(random.Next()) & (modulus - 1))
			if other >= length {
				other -= length
			}
			data[idx], data[a+other] = data[a+other], data[idx]
		}
	}
}

func choosePivotCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) (pivot int, hint sortedHint) {
	const (
		shortestNinther = 50
		maxSwaps        = 4 * 3
	)

	l := b - a

	var (
		swaps int
		i     = a + l/4*1
		j     = a + l/4*2
		k     = a + l/4*3
	)

	if l >= 8 {
		if l >= shortestNinther {
			i = medianAdjacentCmpFunc(data, i, &swaps, cmpFn)
			j = medianAdjacentCmpFunc(data, j, &swaps, cmpFn)
			k = medianAdjacentCmpFunc(data, k, &swaps, cmpFn)
		}
		j = medianCmpFunc(data, i, j, k, &swaps, cmpFn)
	}

	switch swaps {
	case 0:
		return j, increasingHint
	case maxSwaps:
		return j, decreasingHint
	default:
		return j, unknownHint
	}
}

func order2CmpFunc[E any](data []E, a, b int, swaps *int, cmpFn func(a, b E) int) (int, int) {
	if cmpFn(data[b], data[a]) < 0 {
		*swaps++
		return b, a
	}
	return a, b
}

func medianCmpFunc[E any](data []E, a, b, c int, swaps *int, cmpFn func(a, b E) int) int {
	a, b = order2CmpFunc(data, a, b, swaps, cmpFn)
	b, c = order2CmpFunc(data, b, c, swaps, cmpFn)
	a, b = order2CmpFunc(data, a, b, swaps, cmpFn)
	return b
}

func medianAdjacentCmpFunc[E any](data []E, a int, swaps *int, cmpFn func(a, b E) int) int {
	return medianCmpFunc(data, a-1, a, a+1, swaps, cmpFn)
}

func reverseRangeCmpFunc[E any](data []E, a, b int, cmpFn func(a, b E) int) {
	i := a
	j := b - 1
	for i < j {
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
}

func swapRangeCmpFunc[E any](data []E, a, b, n int, cmpFn func(a, b E) int) {
	for i := 0; i < n; i++ {
		data[a+i], data[b+i] = data[b+i], data[a+i]
	}
}

func stableCmpFunc[E any](data []E, n int, cmpFn func(a, b E) int) {
	blockSize := 20
	a, b := 0, blockSize
	for b <= n {
		insertionSortCmpFunc(data, a, b, cmpFn)
		a = b
		b += blockSize
	}
	insertionSortCmpFunc(data, a, n, cmpFn)

	for blockSize < n {
		a, b = 0, 2*blockSize
		for b <= n {
			symMergeCmpFunc(data, a, a+blockSize, b, cmpFn)
			a = b
			b += 2 * blockSize
		}
		if m := a + blockSize; m < n {
			symMergeCmpFunc(data, a, m, n, cmpFn)
		}
		blockSize *= 2
	}
}

func symMergeCmpFunc[E any](data []E, a, m, b int, cmpFn func(a, b E) int) {
	if m-a == 1 {
		i := m
		j := b
		for i < j {
			h := int(uint(i+j) >> 1)
			if cmpFn(data[h], data[a]) < 0 {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := a; k < i-1; k++ {
			data[k], data[k+1] = data[k+1], data[k]
		}
		return
	}

	if b-m == 1 {
		i := a
		j := m
		for i < j {
			h := int(uint(i+j) >> 1)
			if !(cmpFn(data[m], data[h]) < 0) {
				i = h + 1
			} else {
				j = h
			}
		}
		for k := m; k > i; k-- {
			data[k], data[k-1] = data[k-1], data[k]
		}
		return
	}

	mid := int(uint(a+b) >> 1)
	n := mid + m
	var start, r int
	if m > mid {
		start = n - b
		r = mid
	} else {
		start = a
		r = m
	}
	p := n - 1

	for start < r {
		c := int(uint(start+r) >> 1)
		if !(cmpFn(data[p-c], data[c]) < 0) {
			start = c + 1
		} else {
			r = c
		}
	}

	end := n - start
	if start < m && m < end {
		rotateCmpFunc(data, start, m, end, cmpFn)
	}
	if a < start && start < mid {
		symMergeCmpFunc(data, a, start, mid, cmpFn)
	}
	if mid < end && end < b {
		symMergeCmpFunc(data, mid, end, b, cmpFn)
	}
}

func rotateCmpFunc[E any](data []E, a, m, b int, cmpFn func(a, b E) int) {
	i := m - a
	j := b - m

	for i != j {
		if i > j {
			swapRangeCmpFunc(data, m-i, m, j, cmpFn)
			i -= j
		} else {
			swapRangeCmpFunc(data, m-i, m+j-i, i, cmpFn)
			j -= i
		}
	}
	swapRangeCmpFunc(data, m-i, m, i, cmpFn)
}

// Ensure stableOrdered is referenced to avoid "declared and not used" in some Go versions.
var _ = stableOrdered[int]
