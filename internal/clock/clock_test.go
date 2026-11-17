package clock_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/istr/strike/internal/clock"
)

// TestReproducible pins the contract of the reproducible clock: an empty
// SOURCE_DATE_EPOCH is the Unix epoch, a count of seconds written as
// "date +%s" prints it is that second, both in UTC, and every other value is
// an error that names the variable -- no malformed value becomes the epoch
// (ADR-059 D7). An unset variable reads as an empty one, so the empty case
// covers both.
func TestReproducible(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int64
		wantErr bool
	}{
		{name: "empty", value: "", want: 0},
		{name: "zero", value: "0", want: 0},
		{name: "seconds", value: "1700000000", want: 1700000000},
		{name: "last second of RFC 3339", value: "253402300799", want: 253402300799},
		{name: "first second past RFC 3339", value: "253402300800", wantErr: true},
		{name: "past int64", value: "9223372036854775808", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "negative zero", value: "-0", wantErr: true},
		{name: "plus sign", value: "+1", wantErr: true},
		{name: "leading zero", value: "01", wantErr: true},
		{name: "double zero", value: "00", wantErr: true},
		{name: "fraction", value: "1.5", wantErr: true},
		{name: "exponent", value: "1e9", wantErr: true},
		{name: "hexadecimal", value: "0x10", wantErr: true},
		{name: "underscore", value: "1_000", wantErr: true},
		{name: "surrounding space", value: " 1 ", wantErr: true},
		{name: "word", value: "tomorrow", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", tt.value)
			got, err := clock.Reproducible()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "SOURCE_DATE_EPOCH") {
					t.Fatalf("Reproducible() = %v, %v, want an error naming SOURCE_DATE_EPOCH", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reproducible(): %v", err)
			}
			if want := time.Unix(tt.want, 0); !got.Equal(want) {
				t.Errorf("Reproducible() = %v, want %v", got, want)
			}
			if got.Location() != time.UTC {
				t.Errorf("Reproducible() location = %v, want UTC", got.Location())
			}
		})
	}
}

func TestWallIsMonotonicWithinTest(t *testing.T) {
	a := clock.Wall()
	b := clock.Wall()
	if b.Before(a) {
		t.Errorf("Wall() went backwards: a=%v b=%v", a, b)
	}
}

func TestSinceReturnsPositiveDuration(t *testing.T) {
	start := clock.Wall().Add(-clock.Hour)
	if d := clock.Since(start); d < clock.Hour {
		t.Errorf("Since(an hour ago) = %v, want at least 1h", d)
	}
}

// TestWait pins both ends of the one wait: a duration that elapses returns
// nil, and a done context returns its error without sitting the duration
// out. No case waits: the elapsing case waits zero, and the done case is
// canceled before the call.
func TestWait(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		ctx  context.Context
		want error
		name string
		d    clock.Duration
	}{
		{name: "elapsed", ctx: context.Background(), d: 0, want: nil},
		{name: "context done", ctx: canceled, d: clock.Hour, want: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := clock.Wait(tt.ctx, tt.d); !errors.Is(err, tt.want) {
				t.Errorf("Wait() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseDurationRoundTrips(t *testing.T) {
	d, err := clock.ParseDuration("1h30m")
	if err != nil {
		t.Fatalf("ParseDuration: %v", err)
	}
	if d != 90*clock.Minute {
		t.Errorf("ParseDuration(\"1h30m\") = %v, want 90m", d)
	}
}

func TestParseDurationRejectsGarbage(t *testing.T) {
	_, err := clock.ParseDuration("not-a-duration")
	if err == nil {
		t.Error("ParseDuration on garbage input: expected error, got nil")
	}
}

func TestUnixMatchesTimeUnix(t *testing.T) {
	got := clock.Unix(1700000000, 0)
	want := time.Unix(1700000000, 0)
	if !got.Equal(want) {
		t.Errorf("clock.Unix disagrees with time.Unix: got=%v want=%v", got, want)
	}
}
