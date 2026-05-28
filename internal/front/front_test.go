package front_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/istr/strike/internal/front"
)

func TestNew_AddrLoopback(t *testing.T) {
	f, err := front.New(context.Background())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Errorf("Close: %v", cErr)
		}
	})

	addr := f.Addr()
	if !addr.Addr().IsLoopback() {
		t.Errorf("Addr = %s, want loopback", addr)
	}
	if addr.Port() == 0 {
		t.Error("Addr port is 0, want a bound port")
	}
}

func TestStart_FailsClosed(t *testing.T) {
	f, err := front.New(context.Background())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Errorf("Close: %v", cErr)
		}
	})
	f.Start()

	var d net.Dialer
	conn, dialErr := d.DialContext(context.Background(), "tcp", f.Addr().String())
	if dialErr != nil {
		t.Fatalf("dial front: %v", dialErr)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Errorf("conn.Close: %v", cErr)
		}
	}()

	// The front accepts then immediately closes: the client sees EOF and no
	// relayed bytes. A correct skeleton closes promptly, so no read deadline
	// is needed; a broken serve loop that never closes is caught by the
	// package test timeout.
	buf := make([]byte, 1)
	n, rErr := conn.Read(buf)
	if n != 0 {
		t.Errorf("read %d bytes, want 0 (front must not relay)", n)
	}
	if !errors.Is(rErr, io.EOF) {
		t.Errorf("read err = %v, want io.EOF", rErr)
	}
}
