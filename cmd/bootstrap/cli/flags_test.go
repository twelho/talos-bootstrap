// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package cli

import (
	"reflect"
	"testing"
)

func TestNodeOverridesSet(t *testing.T) {
	cases := []struct {
		name    string
		inputs  []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:   "bare node",
			inputs: []string{"node-a"},
			want:   map[string]string{"node-a": ""},
		},
		{
			name:   "node with endpoint",
			inputs: []string{"node-a=10.0.0.1"},
			want:   map[string]string{"node-a": "10.0.0.1"},
		},
		{
			name:   "comma-separated bare nodes",
			inputs: []string{"a, b ,c"},
			want:   map[string]string{"a": "", "b": "", "c": ""},
		},
		{
			name:   "repeated flag overrides",
			inputs: []string{"a=1.1.1.1", "b=2.2.2.2"},
			want:   map[string]string{"a": "1.1.1.1", "b": "2.2.2.2"},
		},
		{
			name:   "last value wins",
			inputs: []string{"a=1.1.1.1", "a=2.2.2.2"},
			want:   map[string]string{"a": "2.2.2.2"},
		},
		{
			name:   "ipv6 endpoint via repeated flag",
			inputs: []string{"a=[fd00::1]:50000"},
			want:   map[string]string{"a": "[fd00::1]:50000"},
		},
		{
			name:    "empty node name rejected",
			inputs:  []string{"=1.2.3.4"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n nodeOverrides
			var setErr error
			for _, in := range tc.inputs {
				if err := n.Set(in); err != nil {
					setErr = err
					break
				}
			}
			if tc.wantErr {
				if setErr == nil {
					t.Fatalf("expected error, got nodes=%v", n.Nodes)
				}
				return
			}
			if setErr != nil {
				t.Fatalf("unexpected error: %v", setErr)
			}
			if !reflect.DeepEqual(n.Nodes, tc.want) {
				t.Errorf("got %v, want %v", n.Nodes, tc.want)
			}
		})
	}
}
