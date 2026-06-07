package rule

import (
	"net"
	"testing"
)

func TestMeteredConnRecordsReadAndWrite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	var gotUser, gotRule, gotDialer string
	var gotRX, gotTX uint64
	SetTrafficRecorder(func(user, ruleName, dialer string, rx, tx uint64) {
		gotUser = user
		gotRule = ruleName
		gotDialer = dialer
		gotRX += rx
		gotTX += tx
	})
	defer SetTrafficRecorder(nil)

	conn := newMeteredConn(left, "alice", "office", "DIRECT")
	go func() {
		_, _ = right.Write([]byte("pong"))
		buf := make([]byte, 4)
		_, _ = right.Read(buf)
	}()

	buf := make([]byte, 4)
	if n, err := conn.Read(buf); err != nil || n != 4 {
		t.Fatalf("Read() n=%d err=%v", n, err)
	}
	if n, err := conn.Write([]byte("ping")); err != nil || n != 4 {
		t.Fatalf("Write() n=%d err=%v", n, err)
	}
	if gotUser != "alice" || gotRule != "office" || gotDialer != "DIRECT" {
		t.Fatalf("labels = %q %q %q", gotUser, gotRule, gotDialer)
	}
	if gotRX != 4 || gotTX != 4 {
		t.Fatalf("traffic rx=%d tx=%d", gotRX, gotTX)
	}
}
