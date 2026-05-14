package testutil_test

import (
	"errors"
	"os"
	"testing"

	"github.com/istr/strike/internal/testutil"
)

func TestCloseLog_Success(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closelog-test-")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	testutil.CloseLog(t, f, "test")
}

func TestCloseLog_Failure(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closelog-test-")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("initial close: %v", err)
	}

	// The second close logs via t.Logf; no panic, no test failure.
	testutil.CloseLog(t, f, "double close")
}

type errCloser struct{}

func (errCloser) Close() error { return errors.New("test close error") }

func TestCloseLog_ErrorCloser(t *testing.T) {
	testutil.CloseLog(t, errCloser{}, "err closer")
}
