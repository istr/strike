package testutil_test

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/istr/strike/internal/testutil"
)

func TestStartEchoSocket(t *testing.T) {
	sockPath := testutil.StartEchoSocket(t)

	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer testutil.CloseLog(t, conn, "echo conn")

	want := []byte("echo test payload")
	n, writeErr := conn.Write(want)
	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	if n != len(want) {
		t.Fatalf("short write: %d/%d", n, len(want))
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		if cwErr := uc.CloseWrite(); cwErr != nil {
			t.Fatalf("close write: %v", cwErr)
		}
	}

	got, readErr := io.ReadAll(conn)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
