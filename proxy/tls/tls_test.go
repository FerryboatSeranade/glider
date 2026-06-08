package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCertificateIfChangedReloadsUpdatedFiles(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	writeTestCertificate(t, certFile, keyFile, "first.example.com", 1, time.Now())

	s := &TLS{certFile: certFile, keyFile: keyFile}
	first, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() initial error = %v", err)
	}
	if got := certDNSName(t, first); got != "first.example.com" {
		t.Fatalf("initial certificate DNSName = %q, want first.example.com", got)
	}

	again, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() cached error = %v", err)
	}
	if again != first {
		t.Fatalf("loadCertificateIfChanged() returned a new pointer without file changes")
	}

	nextModTime := time.Now().Add(2 * time.Second)
	writeTestCertificate(t, certFile, keyFile, "second.example.com", 2, nextModTime)

	second, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() reload error = %v", err)
	}
	if second == first {
		t.Fatalf("loadCertificateIfChanged() reused cached certificate after file changes")
	}
	if got := certDNSName(t, second); got != "second.example.com" {
		t.Fatalf("reloaded certificate DNSName = %q, want second.example.com", got)
	}
}

func TestLoadCertificateIfChangedKeepsPreviousCertificateOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	writeTestCertificate(t, certFile, keyFile, "stable.example.com", 1, time.Now())

	s := &TLS{certFile: certFile, keyFile: keyFile}
	first, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() initial error = %v", err)
	}

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", certFile, err)
	}
	nextModTime := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, nextModTime, nextModTime); err != nil {
		t.Fatalf("Chtimes(%s) error = %v", certFile, err)
	}

	afterFailure, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() reload failure error = %v, want cached certificate", err)
	}
	if afterFailure != first {
		t.Fatalf("loadCertificateIfChanged() did not keep previous certificate after reload failure")
	}
	if got := certDNSName(t, afterFailure); got != "stable.example.com" {
		t.Fatalf("cached certificate DNSName = %q, want stable.example.com", got)
	}
}

func TestLoadCertificateIfChangedKeepsPreviousCertificateWhenKeyTemporarilyMissing(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	writeTestCertificate(t, certFile, keyFile, "stable.example.com", 1, time.Now())

	s := &TLS{certFile: certFile, keyFile: keyFile}
	first, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() initial error = %v", err)
	}

	if err := os.Remove(keyFile); err != nil {
		t.Fatalf("Remove(%s) error = %v", keyFile, err)
	}

	afterMissingKey, err := s.loadCertificateIfChanged()
	if err != nil {
		t.Fatalf("loadCertificateIfChanged() missing key error = %v, want cached certificate", err)
	}
	if afterMissingKey != first {
		t.Fatalf("loadCertificateIfChanged() did not keep previous certificate when key was missing")
	}
	if got := certDNSName(t, afterMissingKey); got != "stable.example.com" {
		t.Fatalf("cached certificate DNSName = %q, want stable.example.com", got)
	}
}

func TestGetCertificateUsesCertDirByServerName(t *testing.T) {
	dir := t.TempDir()
	writeDomainTestCertificate(t, dir, "alpha.example.com", 1)
	writeDomainTestCertificate(t, dir, "beta.example.com", 2)

	s := &TLS{certDir: dir}

	alpha, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "alpha.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(alpha) error = %v", err)
	}
	if got := certDNSName(t, alpha); got != "alpha.example.com" {
		t.Fatalf("alpha certificate DNSName = %q, want alpha.example.com", got)
	}

	beta, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "beta.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(beta) error = %v", err)
	}
	if got := certDNSName(t, beta); got != "beta.example.com" {
		t.Fatalf("beta certificate DNSName = %q, want beta.example.com", got)
	}
	if beta == alpha {
		t.Fatalf("getCertificate() reused the same certificate for different SNI names")
	}
}

func TestGetCertificateKeepsPreviousSNINameCertificateOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	writeDomainTestCertificate(t, dir, "alpha.example.com", 1)

	s := &TLS{certDir: dir}
	first, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "alpha.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(alpha) initial error = %v", err)
	}

	certFile := filepath.Join(dir, "alpha.example.com", "fullchain.pem")
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", certFile, err)
	}
	nextModTime := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, nextModTime, nextModTime); err != nil {
		t.Fatalf("Chtimes(%s) error = %v", certFile, err)
	}

	afterFailure, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "alpha.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(alpha) reload failure error = %v, want cached certificate", err)
	}
	if afterFailure != first {
		t.Fatalf("getCertificate(alpha) did not keep previous certificate after reload failure")
	}
	if got := certDNSName(t, afterFailure); got != "alpha.example.com" {
		t.Fatalf("cached SNI certificate DNSName = %q, want alpha.example.com", got)
	}
}

func TestGetCertificateFallsBackToStaticCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fallback.pem")
	keyFile := filepath.Join(dir, "fallback-key.pem")
	writeTestCertificate(t, certFile, keyFile, "fallback.example.com", 1, time.Now())

	s := &TLS{
		certDir:  filepath.Join(dir, "certs"),
		certFile: certFile,
		keyFile:  keyFile,
	}

	cert, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "missing.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(missing) error = %v", err)
	}
	if got := certDNSName(t, cert); got != "fallback.example.com" {
		t.Fatalf("fallback certificate DNSName = %q, want fallback.example.com", got)
	}
}

func TestGetCertificateFallsBackToStaticCertificateWhenSNIInitialLoadFails(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	brokenDir := filepath.Join(certDir, "broken.example.com")
	if err := os.MkdirAll(brokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", brokenDir, err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "fullchain.pem"), []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("WriteFile(broken cert) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "privkey.pem"), []byte("not a key"), 0600); err != nil {
		t.Fatalf("WriteFile(broken key) error = %v", err)
	}

	certFile := filepath.Join(dir, "fallback.pem")
	keyFile := filepath.Join(dir, "fallback-key.pem")
	writeTestCertificate(t, certFile, keyFile, "fallback.example.com", 1, time.Now())

	s := &TLS{
		certDir:  certDir,
		certFile: certFile,
		keyFile:  keyFile,
	}

	cert, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "broken.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(broken) error = %v, want fallback certificate", err)
	}
	if got := certDNSName(t, cert); got != "fallback.example.com" {
		t.Fatalf("fallback certificate DNSName = %q, want fallback.example.com", got)
	}
}

func TestGetCertificateUsesWildcardCertDirCandidate(t *testing.T) {
	dir := t.TempDir()
	writeDomainTestCertificate(t, dir, "*.example.com", 1)

	s := &TLS{certDir: dir}

	cert, err := s.getCertificate(&stdtls.ClientHelloInfo{ServerName: "www.example.com"})
	if err != nil {
		t.Fatalf("getCertificate(wildcard) error = %v", err)
	}
	if got := certDNSName(t, cert); got != "*.example.com" {
		t.Fatalf("wildcard certificate DNSName = %q, want *.example.com", got)
	}
}

func TestNewTLSServerAcceptsCertDirWithoutStaticCertificate(t *testing.T) {
	server, err := NewTLSServer("tls://:0?certDir="+url.QueryEscape(t.TempDir()), nil)
	if err != nil {
		t.Fatalf("NewTLSServer(certDir) error = %v", err)
	}
	tlsServer, ok := server.(*TLS)
	if !ok {
		t.Fatalf("NewTLSServer(certDir) returned %T, want *TLS", server)
	}
	if tlsServer.config == nil || tlsServer.config.GetCertificate == nil {
		t.Fatalf("NewTLSServer(certDir) did not configure dynamic certificate lookup")
	}
}

func TestNewTLSServerRejectsIncompleteStaticCertificate(t *testing.T) {
	if _, err := NewTLSServer("tls://:0?cert=/tmp/fullchain.pem", nil); err == nil || !strings.Contains(err.Error(), "specified together") {
		t.Fatalf("NewTLSServer(cert only) error = %v, want specified together", err)
	}
	if _, err := NewTLSServer("tls://:0?key=/tmp/privkey.pem", nil); err == nil || !strings.Contains(err.Error(), "specified together") {
		t.Fatalf("NewTLSServer(key only) error = %v, want specified together", err)
	}
}

func TestCertDirSelectionDuringTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	writeDomainTestCertificate(t, dir, "alpha.example.com", 1)
	writeDomainTestCertificate(t, dir, "beta.example.com", 2)

	s := &TLS{
		certDir: dir,
	}
	s.config = &stdtls.Config{
		GetCertificate: s.getCertificate,
		MinVersion:     stdtls.VersionTLS12,
		MaxVersion:     stdtls.VersionTLS12,
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverConn := stdtls.Server(serverSide, s.config)
		serverErr <- serverConn.Handshake()
	}()

	clientConn := stdtls.Client(clientSide, &stdtls.Config{
		ServerName:         "beta.example.com",
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS12,
		MaxVersion:         stdtls.VersionTLS12,
	})
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if err := waitForHandshake(t, serverErr); err != nil {
		t.Fatalf("server Handshake() error = %v", err)
	}

	state := clientConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatalf("client saw no peer certificates")
	}
	if got := firstDNSName(t, state.PeerCertificates[0]); got != "beta.example.com" {
		t.Fatalf("handshake certificate DNSName = %q, want beta.example.com", got)
	}
	_ = clientSide.Close()
	_ = serverSide.Close()
}

func waitForHandshake(t *testing.T, ch <-chan error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeDomainTestCertificate(t *testing.T, certDir, domain string, serial int64) {
	t.Helper()
	dir := filepath.Join(certDir, domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", dir, err)
	}
	writeTestCertificate(t, filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"), domain, serial, time.Now())
}

func writeTestCertificate(t *testing.T, certFile, keyFile, dnsName string, serial int64, modTime time.Time) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", keyFile, err)
	}
	if err := os.Chtimes(certFile, modTime, modTime); err != nil {
		t.Fatalf("Chtimes(%s) error = %v", certFile, err)
	}
	if err := os.Chtimes(keyFile, modTime, modTime); err != nil {
		t.Fatalf("Chtimes(%s) error = %v", keyFile, err)
	}
}

func certDNSName(t *testing.T, cert *stdtls.Certificate) string {
	t.Helper()
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("certificate is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if len(parsed.DNSNames) == 0 {
		t.Fatalf("certificate has no DNS names")
	}
	return parsed.DNSNames[0]
}

func firstDNSName(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	if cert == nil {
		t.Fatalf("certificate is nil")
	}
	if len(cert.DNSNames) == 0 {
		t.Fatalf("certificate has no DNS names")
	}
	return cert.DNSNames[0]
}
