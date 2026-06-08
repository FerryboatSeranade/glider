package tls

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
)

// TLS struct.
type TLS struct {
	dialer proxy.Dialer
	proxy  proxy.Proxy
	addr   string

	config *stdtls.Config

	serverName string
	skipVerify bool

	certFile   string
	keyFile    string
	certDir    string
	certMu     sync.Mutex
	cert       *stdtls.Certificate
	certMod    time.Time
	keyMod     time.Time
	certByName map[string]*namedCertificate

	alpn []string

	server proxy.Server
}

type namedCertificate struct {
	cert    *stdtls.Certificate
	certMod time.Time
	keyMod  time.Time
}

func init() {
	proxy.RegisterDialer("tls", NewTLSDialer)
	proxy.RegisterServer("tls", NewTLSServer)
}

// NewTLS returns a tls struct.
func NewTLS(s string, d proxy.Dialer, p proxy.Proxy) (*TLS, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.F("[tls] parse url err: %s", err)
		return nil, err
	}

	query := u.Query()
	t := &TLS{
		dialer:     d,
		proxy:      p,
		addr:       u.Host,
		serverName: query.Get("serverName"),
		skipVerify: query.Get("skipVerify") == "true",
		certFile:   query.Get("cert"),
		keyFile:    query.Get("key"),
		certDir:    query.Get("certDir"),
		alpn:       query["alpn"],
	}

	if t.addr != "" {
		if _, port, _ := net.SplitHostPort(t.addr); port == "" {
			t.addr = net.JoinHostPort(t.addr, "443")
		}
		if t.serverName == "" {
			t.serverName = t.addr[:strings.LastIndex(t.addr, ":")]
		}
	}

	return t, nil
}

// NewTLSDialer returns a tls dialer.
func NewTLSDialer(s string, d proxy.Dialer) (proxy.Dialer, error) {
	t, err := NewTLS(s, d, nil)
	if err != nil {
		return nil, err
	}

	t.config = &stdtls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
		NextProtos:         t.alpn,
		MinVersion:         stdtls.VersionTLS12,
	}

	if t.certFile != "" {
		certData, err := os.ReadFile(t.certFile)
		if err != nil {
			return nil, fmt.Errorf("[tls] read cert file error: %s", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certData) {
			return nil, fmt.Errorf("[tls] can not append cert file: %s", t.certFile)
		}
		t.config.RootCAs = certPool
	}

	return t, err
}

// NewTLSServer returns a tls transport layer before the real server.
func NewTLSServer(s string, p proxy.Proxy) (proxy.Server, error) {
	schemes := strings.SplitN(s, ",", 2)
	t, err := NewTLS(schemes[0], nil, p)
	if err != nil {
		return nil, err
	}

	if (t.certFile == "") != (t.keyFile == "") {
		return nil, errors.New("[tls] cert and key file path must be specified together")
	}
	if t.certFile == "" && t.certDir == "" {
		return nil, errors.New("[tls] cert/key or certDir must be specified")
	}
	if t.certFile != "" {
		if _, err := t.loadCertificateIfChanged(); err != nil {
			log.F("[tls] unable to load cert: %s, key %s", t.certFile, t.keyFile)
			return nil, err
		}
	}

	t.config = &stdtls.Config{
		GetCertificate: t.getCertificate,
		NextProtos:     t.alpn,
		MinVersion:     stdtls.VersionTLS12,
	}

	if len(schemes) > 1 {
		t.server, err = proxy.ServerFromURL(schemes[1], p)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

func (s *TLS) getCertificate(hello *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
	if hello != nil {
		cert, matched, err := s.loadCertificateForServerName(hello.ServerName)
		if matched {
			if err != nil && s.certFile != "" && s.keyFile != "" {
				log.F("[tls] unable to load SNI cert for %s, trying fallback certificate: %v", hello.ServerName, err)
				return s.loadCertificateIfChanged()
			}
			return cert, err
		}
	}
	return s.loadCertificateIfChanged()
}

func (s *TLS) loadCertificateIfChanged() (*stdtls.Certificate, error) {
	s.certMu.Lock()
	defer s.certMu.Unlock()

	return loadCertificateFilesIfChanged(s.certFile, s.keyFile, &s.cert, &s.certMod, &s.keyMod)
}

func (s *TLS) loadCertificateForServerName(serverName string) (*stdtls.Certificate, bool, error) {
	certName, certFile, keyFile, ok := s.certificateFilesForServerName(serverName)
	if !ok {
		return nil, false, nil
	}

	s.certMu.Lock()
	defer s.certMu.Unlock()

	if s.certByName == nil {
		s.certByName = make(map[string]*namedCertificate)
	}
	cache := s.certByName[certName]
	if cache == nil {
		cache = &namedCertificate{}
		s.certByName[certName] = cache
	}
	cert, err := loadCertificateFilesIfChanged(certFile, keyFile, &cache.cert, &cache.certMod, &cache.keyMod)
	return cert, true, err
}

func (s *TLS) certificateFilesForServerName(serverName string) (string, string, string, bool) {
	if strings.TrimSpace(s.certDir) == "" {
		return "", "", "", false
	}
	name, ok := normalizeTLSServerName(serverName)
	if !ok {
		return "", "", "", false
	}
	for _, candidate := range tlsCertificateNameCandidates(name) {
		certFile := filepath.Join(s.certDir, candidate, "fullchain.pem")
		keyFile := filepath.Join(s.certDir, candidate, "privkey.pem")
		if fileExists(certFile) || fileExists(keyFile) {
			return candidate, certFile, keyFile, true
		}
	}
	return "", "", "", false
}

func loadCertificateFilesIfChanged(certFile, keyFile string, cert **stdtls.Certificate, certMod, keyMod *time.Time) (*stdtls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("[tls] cert and key file path must be specified")
	}
	certInfo, err := os.Stat(certFile)
	if err != nil {
		if *cert != nil {
			log.F("[tls] stat cert %s failed, keeping previous certificate: %v", certFile, err)
			return *cert, nil
		}
		return nil, err
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		if *cert != nil {
			log.F("[tls] stat key %s failed, keeping previous certificate: %v", keyFile, err)
			return *cert, nil
		}
		return nil, err
	}
	if *cert != nil && certInfo.ModTime().Equal(*certMod) && keyInfo.ModTime().Equal(*keyMod) {
		return *cert, nil
	}
	loaded, err := stdtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if *cert != nil {
			log.F("[tls] reload cert %s, key %s failed, keeping previous certificate: %v", certFile, keyFile, err)
			return *cert, nil
		}
		return nil, err
	}
	*cert = &loaded
	*certMod = certInfo.ModTime().Truncate(time.Nanosecond)
	*keyMod = keyInfo.ModTime().Truncate(time.Nanosecond)
	return *cert, nil
}

func normalizeTLSServerName(serverName string) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(serverName)), ".")
	if name == "" || len(name) > 253 || strings.ContainsAny(name, `/\`) {
		return "", false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}
	return name, true
}

func tlsCertificateNameCandidates(serverName string) []string {
	candidates := []string{serverName}
	labels := strings.Split(serverName, ".")
	if len(labels) > 2 {
		candidates = append(candidates, "*."+strings.Join(labels[1:], "."))
	}
	return candidates
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ListenAndServe listens on server's addr and serves connections.
func (s *TLS) ListenAndServe() {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatalf("[tls] failed to listen on %s: %v", s.addr, err)
		return
	}
	defer l.Close()

	log.F("[tls] listening TCP on %s with TLS", s.addr)

	for {
		c, err := l.Accept()
		if err != nil {
			log.F("[tls] failed to accept: %v", err)
			continue
		}

		go s.Serve(c)
	}
}

// Serve serves a connection.
func (s *TLS) Serve(cc net.Conn) {
	c := stdtls.Server(cc, s.config)

	if s.server != nil {
		s.server.Serve(c)
		return
	}

	defer c.Close()

	rc, dialer, err := s.proxy.Dial("tcp", "")
	if err != nil {
		log.F("[tls] %s <-> %s via %s, error in dial: %v", c.RemoteAddr(), s.addr, dialer.Addr(), err)
		s.proxy.Record(dialer, false)
		return
	}
	defer rc.Close()

	log.F("[tls] %s <-> %s", c.RemoteAddr(), dialer.Addr())

	if err = proxy.Relay(c, rc); err != nil {
		log.F("[tls] %s <-> %s, relay error: %v", c.RemoteAddr(), dialer.Addr(), err)
		// record remote conn failure only
		if !strings.Contains(err.Error(), s.addr) {
			s.proxy.Record(dialer, false)
		}
	}
}

// Addr returns forwarder's address.
func (s *TLS) Addr() string {
	if s.addr == "" {
		return s.dialer.Addr()
	}
	return s.addr
}

// Dial connects to the address addr on the network net via the proxy.
func (s *TLS) Dial(network, addr string) (net.Conn, error) {
	cc, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		log.F("[tls] dial to %s error: %s", s.addr, err)
		return nil, err
	}

	c := stdtls.Client(cc, s.config)
	err = c.Handshake()
	return c, err
}

// DialUDP connects to the given address via the proxy.
func (s *TLS) DialUDP(network, addr string) (net.PacketConn, error) {
	return nil, proxy.ErrNotSupported
}

func init() {
	proxy.AddUsage("tls", `
TLS client scheme:
  tls://host:port[?serverName=SERVERNAME][&skipVerify=true][&cert=PATH][&alpn=proto1][&alpn=proto2]
  
Proxy over tls client:
  tls://host:port[?skipVerify=true][&serverName=SERVERNAME],scheme://
  tls://host:port[?skipVerify=true],http://[user:pass@]
  tls://host:port[?skipVerify=true],socks5://[user:pass@]
  tls://host:port[?skipVerify=true],vmess://[security:]uuid@?alterID=num
  
TLS server scheme:
  tls://host:port?cert=PATH&key=PATH[&alpn=proto1][&alpn=proto2]
  tls://host:port?certDir=DIR[&cert=FALLBACK_CERT&key=FALLBACK_KEY][&alpn=proto1][&alpn=proto2]
  
Proxy over tls server:
  tls://host:port?cert=PATH&key=PATH,scheme://
  tls://host:port?certDir=DIR,scheme://
  tls://host:port?cert=PATH&key=PATH,http://
  tls://host:port?cert=PATH&key=PATH,socks5://
  tls://host:port?cert=PATH&key=PATH,ss://method:pass@
`)
}
