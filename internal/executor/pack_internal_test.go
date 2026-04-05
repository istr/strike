package executor

import (
	"slices"
	"testing"
)

func TestAppendEnv(t *testing.T) {
	tests := []struct {
		name     string
		env      []string
		key      string
		value    string
		expected []string
	}{
		{
			name:     "append to empty",
			env:      nil,
			key:      "FOO",
			value:    "bar",
			expected: []string{"FOO=bar"},
		},
		{
			name:     "append new key",
			env:      []string{"A=1"},
			key:      "B",
			value:    "2",
			expected: []string{"A=1", "B=2"},
		},
		{
			name:     "replace existing key",
			env:      []string{"A=1", "B=old"},
			key:      "B",
			value:    "new",
			expected: []string{"A=1", "B=new"},
		},
		{
			name:     "replace first key",
			env:      []string{"A=old", "B=2"},
			key:      "A",
			value:    "new",
			expected: []string{"A=new", "B=2"},
		},
		{
			name:     "key prefix not confused",
			env:      []string{"FOO=1"},
			key:      "FOOBAR",
			value:    "2",
			expected: []string{"FOO=1", "FOOBAR=2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendEnv(tt.env, tt.key, tt.value)
			if !slices.Equal(got, tt.expected) {
				t.Errorf("appendEnv(%v, %q, %q) = %v, want %v",
					tt.env, tt.key, tt.value, got, tt.expected)
			}
		})
	}
}
