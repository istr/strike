package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestCmdRunChecksSourceDateFirst pins the run-start check of ADR-059 D7: a
// malformed SOURCE_DATE_EPOCH fails the run before the lane is read, and so
// before any step starts and any deploy pushes. The lane path names no file:
// with a well-formed or an empty value the same run fails on that path
// instead, which shows the order of the two checks. No case reaches an
// engine.
func TestCmdRunChecksSourceDateFirst(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "malformed", value: "tomorrow", wantErr: "SOURCE_DATE_EPOCH"},
		{name: "well-formed", value: "1700000000", wantErr: "absent.yaml"},
		{name: "empty", value: "", wantErr: "absent.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", tt.value)
			err := cmdRun(context.Background(), filepath.Join(t.TempDir(), "absent.yaml"), nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}
