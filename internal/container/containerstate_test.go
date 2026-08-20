package container_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestContainerList(t *testing.T) {
	const twoContainers = `[{"Id":"a1","Names":["stack_caddy_1"],` +
		`"Image":"caddy@sha256:aa","State":"exited"},` +
		`{"Id":"b2","Names":["stack_zot_1"],` +
		`"Image":"zot@sha256:bb","State":"running"}]`
	tests := []struct {
		name      string
		body      string
		status    int
		wantCount int
		wantErr   bool
	}{
		{"two containers", twoContainers, http.StatusOK, 2, false},
		{"no match", `[]`, http.StatusOK, 0, false},
		{"engine error", `{}`, http.StatusInternalServerError, 0, true},
		{"malformed body", `not json`, http.StatusOK, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("all"); got != "true" {
					t.Errorf("all = %q, want true", got)
				}
				if got, want := r.URL.Query().Get("filters"), `{"label":["k=v"]}`; got != want {
					t.Errorf("filters = %q, want %q", got, want)
				}
				w.WriteHeader(tt.status)
				mustWrite(t, w, []byte(tt.body))
			}))
			got, err := eng.ContainerList(t.Context(), "k=v")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ContainerList error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != tt.wantCount {
				t.Fatalf("len = %d, want %d", len(got), tt.wantCount)
			}
			if tt.wantCount == 0 {
				return
			}
			if got[0].ID != "a1" {
				t.Errorf("ID = %q, want a1", got[0].ID)
			}
			if len(got[0].Names) != 1 || got[0].Names[0] != "stack_caddy_1" {
				t.Errorf("Names = %v, want [stack_caddy_1]", got[0].Names)
			}
			if got[0].Image != "caddy@sha256:aa" {
				t.Errorf("Image = %q, want caddy@sha256:aa", got[0].Image)
			}
			if got[0].State != "exited" {
				t.Errorf("State = %q, want exited", got[0].State)
			}
			if got[1].State != "running" {
				t.Errorf("State[1] = %q, want running", got[1].State)
			}
		})
	}
}

func TestContainerStart(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"started", http.StatusNoContent, false},
		{"already running", http.StatusNotModified, false},
		{"no such container", http.StatusNotFound, true},
		{"engine error", http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if want := "/containers/c1/start"; !strings.HasSuffix(r.URL.Path, want) {
					t.Errorf("path = %q, want suffix %q", r.URL.Path, want)
				}
				w.WriteHeader(tt.status)
			}))
			if err := eng.ContainerStart(t.Context(), "c1"); (err != nil) != tt.wantErr {
				t.Fatalf("ContainerStart error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
