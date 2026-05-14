package testutil_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/istr/strike/internal/testutil"
)

func TestWriteBody(t *testing.T) {
	want := []byte("hello body")
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutil.WriteBody(t, w, want)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("resp body close: %v", cErr)
		}
	}()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	want := payload{Name: "test"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutil.WriteJSON(t, w, want)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("resp body close: %v", cErr)
		}
	}()
	var got payload
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
