// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package githttp

import "testing"

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		name string
		link string
		want string
	}{
		{"empty", "", ""},
		{"no next rel", `<https://api.github.com/...?page=2>; rel="prev"`, ""},
		{"basic next", `<https://api.github.com/r?page=2>; rel="next", <https://api.github.com/r?page=5>; rel="last"`, "https://api.github.com/r?page=2"},
		{"next without spaces", `<https://api.github.com/r?page=2>;rel="next"`, "https://api.github.com/r?page=2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NextPageURL(tc.link); got != tc.want {
				t.Errorf("NextPageURL(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}
