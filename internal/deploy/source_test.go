package deploy_test

import (
	"testing"

	"github.com/istr/strike/internal/deploy"
)

func TestParseGitLogOutput(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantMethod    string // first signer's method, if any
		wantSigners   int
		wantUnsigned  int
		wantAllSigned bool
		wantNil       bool
	}{
		{
			name:          "gpg signed commit",
			input:         "abc123def456abc123def456abc123def456abc1|G|ABCD1234|Signer Name|dev@ex.com",
			wantSigners:   1,
			wantAllSigned: true,
			wantMethod:    "gpg",
		},
		{
			name:         "unsigned commit",
			input:        "abc123def456abc123def456abc123def456abc1|N|||dev@ex.com",
			wantUnsigned: 1,
		},
		{
			name:         "mixed signed and unsigned",
			input:        "abc123def456abc123def456abc123def456abc1|G|SHA256:fp|key|a@b\nabc123def456abc123def456abc123def456abc2|N|||c@d",
			wantSigners:  1,
			wantUnsigned: 1,
			wantMethod:   "ssh",
		},
		{
			name:    "empty string",
			input:   "",
			wantNil: true,
		},
		{
			name:          "malformed line skipped",
			input:         "bad|line\nabc123def456abc123def456abc123def456abc1|G|FP|Name|dev@ex.com",
			wantSigners:   1,
			wantAllSigned: true,
			wantMethod:    "gpg",
		},
		{
			name:          "unknown/expired validity treated as signed",
			input:         "abc123def456abc123def456abc123def456abc1|U|FP|Name|a@b\ndef123abc456def123abc456def123abc456def1|X|FP|Name|c@d",
			wantSigners:   2,
			wantAllSigned: true,
		},
		{
			name:         "bad signature treated as unsigned",
			input:        "abc123def456abc123def456abc123def456abc1|B|||dev@ex.com",
			wantUnsigned: 1,
		},
		{
			name:          "identity falls back to author email",
			input:         "abc123def456abc123def456abc123def456abc1|G|FP||dev@ex.com",
			wantSigners:   1,
			wantAllSigned: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deploy.ParseGitLog(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			checkCounts(t, got, tt.wantSigners, tt.wantUnsigned, tt.wantAllSigned)
			if tt.wantMethod != "" && len(got.Signers) > 0 && got.Signers[0].Method != tt.wantMethod {
				t.Errorf("method: got %q, want %q", got.Signers[0].Method, tt.wantMethod)
			}
		})
	}
}

func checkCounts(t *testing.T, got *deploy.SourceProvenance, wantSigners, wantUnsigned int, wantAllSigned bool) {
	t.Helper()
	if len(got.Signers) != wantSigners {
		t.Errorf("signers: got %d, want %d", len(got.Signers), wantSigners)
	}
	if len(got.UnsignedCommits) != wantUnsigned {
		t.Errorf("unsigned: got %d, want %d", len(got.UnsignedCommits), wantUnsigned)
	}
	if got.AllSigned != wantAllSigned {
		t.Errorf("all_signed: got %v, want %v", got.AllSigned, wantAllSigned)
	}
}

func TestAllSignedFlag(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "all signed",
			input: "abc123def456abc123def456abc123def456abc1|G|FP|Name|a@b\ndef123abc456def123abc456def123abc456def1|G|FP|Name|c@d",
			want:  true,
		},
		{
			name:  "one unsigned",
			input: "abc123def456abc123def456abc123def456abc1|G|FP|Name|a@b\ndef123abc456def123abc456def123abc456def1|N|||c@d",
		},
		{
			name:  "no commits is nil",
			input: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deploy.ParseGitLog(tt.input)
			if got == nil {
				if tt.want {
					t.Error("expected all_signed=true but got nil")
				}
				return
			}
			if got.AllSigned != tt.want {
				t.Errorf("all_signed: got %v, want %v", got.AllSigned, tt.want)
			}
		})
	}
}

func TestInferSignMethod(t *testing.T) {
	tests := []struct {
		fingerprint string
		want        string
	}{
		{"SHA256:abc123", "ssh"},
		{"ABCD1234", "gpg"},
		{"", "gpg"},
	}
	for _, tt := range tests {
		got := deploy.InferSignMethod(tt.fingerprint)
		if got != tt.want {
			t.Errorf("inferSignMethod(%q) = %q, want %q", tt.fingerprint, got, tt.want)
		}
	}
}
