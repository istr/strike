package executor_test

import (
	"testing"

	"github.com/istr/strike/internal/executor"
)

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
