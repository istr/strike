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

func TestProbeBaseImageSBOM_InvalidRef(t *testing.T) {
	source, _, err := executor.ProbeBaseImageSBOM("not a valid ref!!!")
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
	if source != executor.SBOMSourceNone {
		t.Errorf("source = %d, want SBOMSourceNone", source)
	}
}

func TestProbeBaseImageSBOM_NotDigestRef(t *testing.T) {
	source, _, err := executor.ProbeBaseImageSBOM("docker.io/library/alpine:3.19")
	if err == nil {
		t.Fatal("expected error for tag-only ref")
	}
	if source != executor.SBOMSourceNone {
		t.Errorf("source = %d, want SBOMSourceNone", source)
	}
}

func TestSBOMSourceConstants(t *testing.T) {
	if executor.SBOMSourceReferrer == executor.SBOMSourceFallback {
		t.Error("SBOMSourceReferrer and SBOMSourceFallback should differ")
	}
	if executor.SBOMSourceReferrer == executor.SBOMSourceNone {
		t.Error("SBOMSourceReferrer and SBOMSourceNone should differ")
	}
}
