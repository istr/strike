package executor_test

import (
	"testing"
	"time"

	"github.com/istr/strike/internal/executor"
)

func TestReproducibleTimestamp_Default(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	ts := executor.ReproducibleTimestamp()
	if !ts.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("expected epoch 0, got %v", ts)
	}
}

func TestReproducibleTimestamp_FromEnv(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	ts := executor.ReproducibleTimestamp()
	want := time.Unix(1700000000, 0).UTC()
	if !ts.Equal(want) {
		t.Fatalf("expected %v, got %v", want, ts)
	}
}

func TestReproducibleTimestamp_InvalidFallsBack(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "not-a-number")
	ts := executor.ReproducibleTimestamp()
	if !ts.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("expected epoch 0 on invalid input, got %v", ts)
	}
}
