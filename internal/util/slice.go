// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package util

// Map returns a new slice containing f applied to each element of in.
func Map[S ~[]E, E, R any](in S, f func(E) R) []R {
	out := make([]R, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
