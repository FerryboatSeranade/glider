package proxy

import (
	"net"
	"sync/atomic"
)

// Switcher forwards calls to the current proxy implementation.
// It allows hot-swapping the underlying proxy without restarting listeners.
type Switcher struct {
	v atomic.Value // stores Proxy
}

// NewSwitcher returns a new switcher with initial proxy.
func NewSwitcher(p Proxy) *Switcher {
	s := &Switcher{}
	s.v.Store(p)
	return s
}

// Set replaces the current proxy.
func (s *Switcher) Set(p Proxy) {
	s.v.Store(p)
}

func (s *Switcher) current() Proxy {
	if v := s.v.Load(); v != nil {
		return v.(Proxy)
	}
	return nil
}

// Current returns the current proxy.
func (s *Switcher) Current() Proxy {
	return s.current()
}

// Dial connects to the given address via the proxy.
func (s *Switcher) Dial(network, addr string) (c net.Conn, dialer Dialer, err error) {
	return s.current().Dial(network, addr)
}

// DialUDP connects to the given address via the proxy.
func (s *Switcher) DialUDP(network, addr string) (pc net.PacketConn, dialer UDPDialer, err error) {
	return s.current().DialUDP(network, addr)
}

// NextDialer returns the next dialer.
func (s *Switcher) NextDialer(dstAddr string) Dialer {
	return s.current().NextDialer(dstAddr)
}

// Record records result while using the dialer from proxy.
func (s *Switcher) Record(dialer Dialer, success bool) {
	s.current().Record(dialer, success)
}

// DialWithUser connects to the given address via the proxy with a user hint.
func (s *Switcher) DialWithUser(user, network, addr string) (c net.Conn, dialer Dialer, err error) {
	if p, ok := s.current().(UserDialer); ok {
		return p.DialWithUser(user, network, addr)
	}
	return s.current().Dial(network, addr)
}

// DialUDPWithUser connects to the given address via the proxy with a user hint.
func (s *Switcher) DialUDPWithUser(user, network, addr string) (pc net.PacketConn, dialer UDPDialer, err error) {
	if p, ok := s.current().(UserDialer); ok {
		return p.DialUDPWithUser(user, network, addr)
	}
	return s.current().DialUDP(network, addr)
}

// NextDialerWithUser returns the next dialer with a user hint.
func (s *Switcher) NextDialerWithUser(user, dstAddr string) Dialer {
	if p, ok := s.current().(UserDialer); ok {
		return p.NextDialerWithUser(user, dstAddr)
	}
	return s.current().NextDialer(dstAddr)
}
