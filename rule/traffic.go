package rule

import (
	"net"
	"sync/atomic"
)

// TrafficRecorder records proxied TCP bytes. rx is bytes read from the selected
// upstream dialer, tx is bytes written to it.
type TrafficRecorder func(user, ruleName, dialer string, rx, tx uint64)

var trafficRecorder atomic.Value

// SetTrafficRecorder installs a process-wide traffic recorder.
func SetTrafficRecorder(rec TrafficRecorder) {
	if rec == nil {
		trafficRecorder.Store(TrafficRecorder(func(string, string, string, uint64, uint64) {}))
		return
	}
	trafficRecorder.Store(rec)
}

func recordTraffic(user, ruleName, dialer string, rx, tx uint64) {
	rec, ok := trafficRecorder.Load().(TrafficRecorder)
	if !ok || rec == nil {
		return
	}
	rec(user, ruleName, dialer, rx, tx)
}

type meteredConn struct {
	net.Conn
	user     string
	ruleName string
	dialer   string
}

func newMeteredConn(c net.Conn, user, ruleName, dialer string) net.Conn {
	if c == nil {
		return nil
	}
	return &meteredConn{
		Conn:     c,
		user:     user,
		ruleName: ruleName,
		dialer:   dialer,
	}
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		recordTraffic(c.user, c.ruleName, c.dialer, uint64(n), 0)
	}
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		recordTraffic(c.user, c.ruleName, c.dialer, 0, uint64(n))
	}
	return n, err
}
