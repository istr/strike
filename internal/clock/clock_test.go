package clock_test

import (
	"testing"
	"time"

	"github.com/istr/strike/internal/clock"
)

func TestReproducibleReturnsEpochZeroWhenUnset(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	got := clock.Reproducible()
	want := time.Unix(0, 0).UTC()
	if !got.Equal(want) {
		t.Errorf("Reproducible() = %v, want %v", got, want)
	}
}

func TestReproducibleParsesSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	got := clock.Reproducible()
	want := time.Unix(1700000000, 0).UTC()
	if !got.Equal(want) {
		t.Errorf("Reproducible() = %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("Reproducible() location = %v, want UTC", got.Location())
	}
}

func TestReproducibleFallsBackOnMalformed(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "not-a-number")
	got := clock.Reproducible()
	want := time.Unix(0, 0).UTC()
	if !got.Equal(want) {
		t.Errorf("Reproducible() = %v, want %v", got, want)
	}
}

func TestWallIsMonotonicWithinTest(t *testing.T) {
	a := clock.Wall()
	time.Sleep(time.Millisecond)
	b := clock.Wall()
	if !b.After(a) {
		t.Errorf("Wall() not increasing: a=%v b=%v", a, b)
	}
}

func TestSinceReturnsPositiveDuration(t *testing.T) {
	start := clock.Wall()
	time.Sleep(time.Millisecond)
	d := clock.Since(start)
	if d <= 0 {
		t.Errorf("Since(start) = %v, want > 0", d)
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
