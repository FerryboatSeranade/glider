package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func cloudflareAPIBaseOverrideForTest(t *testing.T, baseURL string) func() {
	t.Helper()
	old := cloudflareAPIBaseURL
	cloudflareAPIBaseURL = baseURL
	return func() {
		cloudflareAPIBaseURL = old
	}
}

func TestCertsVersionStable(t *testing.T) {
	exp := time.Now().UTC().Add(24 * time.Hour)
	a := DomainCert{Domain: "b.example.com", FullchainPEM: "cert-b", PrivateKeyPEM: "key-b", ExpiresAt: &exp}
	b := DomainCert{Domain: "a.example.com", FullchainPEM: "cert-a", PrivateKeyPEM: "key-a", ExpiresAt: &exp}
	v1, _ := certsVersion([]DomainCert{a, b})
	v2, _ := certsVersion([]DomainCert{b, a})
	if v1 == "" || v1 != v2 {
		t.Fatalf("cert versions not stable: %q %q", v1, v2)
	}
}

func TestImportedDomainCertificateValidatesPairAndVersion(t *testing.T) {
	fullchain, keyPEM, exp := testCertificatePEM(t, "proxy.example.com")
	cert, err := importedDomainCertificate("Proxy.Example.com.", fullchain, keyPEM)
	if err != nil {
		t.Fatalf("importedDomainCertificate() error = %v", err)
	}
	if cert.Version == "" {
		t.Fatalf("certificate version was empty")
	}
	if cert.FullchainPEM != fullchain || cert.PrivateKeyPEM != keyPEM {
		t.Fatalf("PEM was not normalized with trailing newline")
	}
	if cert.ExpiresAt == nil || !cert.ExpiresAt.Equal(exp) {
		t.Fatalf("expires_at = %v, want %v", cert.ExpiresAt, exp)
	}

	if _, err := importedDomainCertificate("proxy.example.com", fullchain, strings.Replace(keyPEM, "PRIVATE KEY", "BROKEN KEY", 1)); err == nil {
		t.Fatalf("importedDomainCertificate() accepted an invalid key pair")
	}
}

func TestImportedDomainCertificateValidatesDomainCoverage(t *testing.T) {
	fullchain, keyPEM, _ := testCertificatePEM(t, "other.example.com")
	if _, err := importedDomainCertificate("proxy.example.com", fullchain, keyPEM); err == nil {
		t.Fatalf("importedDomainCertificate() accepted a certificate for the wrong domain")
	}

	wildcardFullchain, wildcardKeyPEM, _ := testCertificatePEM(t, "*.example.com")
	if _, err := importedDomainCertificate("proxy.example.com", wildcardFullchain, wildcardKeyPEM); err != nil {
		t.Fatalf("importedDomainCertificate() rejected wildcard certificate: %v", err)
	}
	if _, err := importedDomainCertificate("deep.proxy.example.com", wildcardFullchain, wildcardKeyPEM); err == nil {
		t.Fatalf("importedDomainCertificate() accepted wildcard for a nested subdomain")
	}
	if _, err := importedDomainCertificate("*.example.com", wildcardFullchain, wildcardKeyPEM); err != nil {
		t.Fatalf("importedDomainCertificate() rejected matching wildcard domain: %v", err)
	}

	cnFullchain, cnKeyPEM, _ := testCertificatePEMWithNames(t, "cn.example.com", nil)
	if _, err := importedDomainCertificate("cn.example.com", cnFullchain, cnKeyPEM); err != nil {
		t.Fatalf("importedDomainCertificate() rejected CN-only certificate: %v", err)
	}

	mixedFullchain, mixedKeyPEM, _ := testCertificatePEMWithNames(t, "proxy.example.com", []string{"other.example.com"})
	if _, err := importedDomainCertificate("proxy.example.com", mixedFullchain, mixedKeyPEM); err == nil {
		t.Fatalf("importedDomainCertificate() used CN even though SANs were present")
	}
}

func TestImportedDomainCertificateRejectsInvalidValidityWindow(t *testing.T) {
	expiredFullchain, expiredKeyPEM, _ := testCertificatePEMWithWindow(t, "expired.example.com", []string{"expired.example.com"}, time.Now().UTC().Add(-48*time.Hour), time.Now().UTC().Add(-24*time.Hour))
	if _, err := importedDomainCertificate("expired.example.com", expiredFullchain, expiredKeyPEM); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("importedDomainCertificate(expired) error = %v, want expired", err)
	}

	futureFullchain, futureKeyPEM, _ := testCertificatePEMWithWindow(t, "future.example.com", []string{"future.example.com"}, time.Now().UTC().Add(24*time.Hour), time.Now().UTC().Add(48*time.Hour))
	if _, err := importedDomainCertificate("future.example.com", futureFullchain, futureKeyPEM); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("importedDomainCertificate(future) error = %v, want not valid before", err)
	}
}

func TestWriteCertificateSnapshotWritesFiles(t *testing.T) {
	dir := t.TempDir()
	exp := time.Now().UTC().Add(24 * time.Hour)
	fullchain, keyPEM, _ := testCertificatePEM(t, "proxy.example.com")
	snap := CertificateSnapshot{
		CertVersion: "cert-v1",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  fullchain,
			PrivateKeyPEM: keyPEM,
			ExpiresAt:     &exp,
		}},
		UpdatedAt: time.Now().UTC(),
	}
	if err := writeCertificateSnapshot(filepath.Join(dir, "cache"), filepath.Join(dir, "certs"), snap); err != nil {
		t.Fatalf("writeCertificateSnapshot() error = %v", err)
	}
	certPath := filepath.Join(dir, "certs", "proxy.example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "certs", "proxy.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != fullchain {
		t.Fatalf("fullchain file = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != keyPEM {
		t.Fatalf("key file = %q, err = %v", string(b), err)
	}
	loaded, err := loadCertificateSnapshot(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("loadCertificateSnapshot() error = %v", err)
	}
	if loaded.CertVersion != "cert-v1" {
		t.Fatalf("cert version = %q", loaded.CertVersion)
	}
}

func TestWriteCertificateFilesRemovesUnassignedDomains(t *testing.T) {
	dir := t.TempDir()
	fullchain, keyPEM, _ := testCertificatePEM(t, "new.example.com")
	oldDir := filepath.Join(dir, "old.example.com")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatalf("mkdir old dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "fullchain.pem"), []byte("old"), 0o600); err != nil {
		t.Fatalf("write old cert: %v", err)
	}
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "new.example.com",
		FullchainPEM:  fullchain,
		PrivateKeyPEM: keyPEM,
	}}); err != nil {
		t.Fatalf("writeCertificateFiles() error = %v", err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("old dir should be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.example.com", "fullchain.pem")); err != nil {
		t.Fatalf("new cert missing: %v", err)
	}
}

func TestWriteCertificateFilesRejectsInvalidPairWithoutOverwritingExistingFiles(t *testing.T) {
	dir := t.TempDir()
	oldFullchain, oldKeyPEM, _ := testCertificatePEM(t, "proxy.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  oldFullchain,
		PrivateKeyPEM: oldKeyPEM,
	}}); err != nil {
		t.Fatalf("initial writeCertificateFiles() error = %v", err)
	}

	badFullchain, _, _ := testCertificatePEM(t, "proxy.example.com")
	_, badKeyPEM, _ := testCertificatePEM(t, "other.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  badFullchain,
		PrivateKeyPEM: badKeyPEM,
	}}); err == nil {
		t.Fatalf("writeCertificateFiles() accepted an invalid certificate pair")
	}

	certPath := filepath.Join(dir, "proxy.example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "proxy.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != oldFullchain {
		t.Fatalf("fullchain after failed write = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != oldKeyPEM {
		t.Fatalf("key after failed write = %q, err = %v", string(b), err)
	}
}

func TestWriteCertificateFilesValidatesBatchBeforeWritingAnyFiles(t *testing.T) {
	dir := t.TempDir()
	oldFullchain, oldKeyPEM, _ := testCertificatePEM(t, "a.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "a.example.com",
		FullchainPEM:  oldFullchain,
		PrivateKeyPEM: oldKeyPEM,
	}}); err != nil {
		t.Fatalf("initial writeCertificateFiles() error = %v", err)
	}

	newFullchain, newKeyPEM, _ := testCertificatePEM(t, "a.example.com")
	badFullchain, _, _ := testCertificatePEM(t, "b.example.com")
	_, badKeyPEM, _ := testCertificatePEM(t, "other.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{
		{
			Domain:        "a.example.com",
			FullchainPEM:  newFullchain,
			PrivateKeyPEM: newKeyPEM,
		},
		{
			Domain:        "b.example.com",
			FullchainPEM:  badFullchain,
			PrivateKeyPEM: badKeyPEM,
		},
	}); err == nil {
		t.Fatalf("writeCertificateFiles() accepted an invalid certificate batch")
	}

	certPath := filepath.Join(dir, "a.example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "a.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != oldFullchain {
		t.Fatalf("fullchain after failed batch write = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != oldKeyPEM {
		t.Fatalf("key after failed batch write = %q, err = %v", string(b), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.example.com")); !os.IsNotExist(err) {
		t.Fatalf("invalid domain dir should not be written: %v", err)
	}
}

func TestWriteCertificateFilesRejectsWrongDomainCertificate(t *testing.T) {
	dir := t.TempDir()
	oldFullchain, oldKeyPEM, _ := testCertificatePEM(t, "proxy.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  oldFullchain,
		PrivateKeyPEM: oldKeyPEM,
	}}); err != nil {
		t.Fatalf("initial writeCertificateFiles() error = %v", err)
	}

	badFullchain, badKeyPEM, _ := testCertificatePEM(t, "other.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  badFullchain,
		PrivateKeyPEM: badKeyPEM,
	}}); err == nil {
		t.Fatalf("writeCertificateFiles() accepted a wrong-domain certificate")
	}

	certPath := filepath.Join(dir, "proxy.example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "proxy.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != oldFullchain {
		t.Fatalf("fullchain after failed wrong-domain write = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != oldKeyPEM {
		t.Fatalf("key after failed wrong-domain write = %q, err = %v", string(b), err)
	}
}

func TestWriteCertificateFilesRejectsExpiredCertificateWithoutOverwritingExistingFiles(t *testing.T) {
	dir := t.TempDir()
	oldFullchain, oldKeyPEM, _ := testCertificatePEM(t, "proxy.example.com")
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  oldFullchain,
		PrivateKeyPEM: oldKeyPEM,
	}}); err != nil {
		t.Fatalf("initial writeCertificateFiles() error = %v", err)
	}

	expiredFullchain, expiredKeyPEM, _ := testCertificatePEMWithWindow(t, "proxy.example.com", []string{"proxy.example.com"}, time.Now().UTC().Add(-48*time.Hour), time.Now().UTC().Add(-24*time.Hour))
	if err := writeCertificateFiles(dir, []DomainCert{{
		Domain:        "proxy.example.com",
		FullchainPEM:  expiredFullchain,
		PrivateKeyPEM: expiredKeyPEM,
	}}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("writeCertificateFiles() error = %v, want expired", err)
	}

	certPath := filepath.Join(dir, "proxy.example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "proxy.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != oldFullchain {
		t.Fatalf("fullchain after failed expired write = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != oldKeyPEM {
		t.Fatalf("key after failed expired write = %q, err = %v", string(b), err)
	}
}

func testCertificatePEM(t *testing.T, domain string) (string, string, time.Time) {
	t.Helper()
	return testCertificatePEMWithNames(t, domain, []string{domain})
}

func testCertificatePEMWithNames(t *testing.T, commonName string, dnsNames []string) (string, string, time.Time) {
	t.Helper()
	return testCertificatePEMWithWindow(t, commonName, dnsNames, time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(90*24*time.Hour))
}

func testCertificatePEMWithWindow(t *testing.T, commonName string, dnsNames []string, notBefore, notAfter time.Time) (string, string, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	notBefore = notBefore.UTC().Truncate(time.Second)
	exp := notAfter.UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     exp,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	fullchain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return fullchain, keyPEM, exp
}

func TestNodeSyncerAppliesCertificateSnapshot(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	fullchain, keyPEM, exp := testCertificatePEM(t, "proxy.example.com")
	centralConfig := testSnapshot("config-v1", nil, []dbRule{{
		Name:    "direct",
		Content: "forward=direct://\n",
	}})
	centralCerts := CertificateSnapshot{
		CertVersion: "cert-v1",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  fullchain,
			PrivateKeyPEM: keyPEM,
			ExpiresAt:     &exp,
		}},
		UpdatedAt: time.Now().UTC(),
	}
	var heartbeat NodeHeartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			_ = json.NewEncoder(w).Encode(centralConfig)
		case "/api/node/certs":
			_ = json.NewEncoder(w).Encode(centralCerts)
		case "/api/node/heartbeat":
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatalf("decode heartbeat: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	conf := &Config{
		NodeID:       "node-01",
		CentralURL:   server.URL,
		NodeToken:    "node-secret",
		CacheDir:     filepath.Join(dir, "cache"),
		CertDir:      filepath.Join(dir, "certs"),
		SyncInterval: "1h",
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.syncOnce(context.Background())
	if syncer.certVersion != "cert-v1" {
		t.Fatalf("cert version = %q", syncer.certVersion)
	}
	if _, err := os.Stat(filepath.Join(conf.CertDir, "proxy.example.com", "fullchain.pem")); err != nil {
		t.Fatalf("certificate not written: %v", err)
	}
	if len(heartbeat.CertDomains) != 1 {
		t.Fatalf("heartbeat cert domains = %#v", heartbeat.CertDomains)
	}
	if heartbeat.CertDomains[0].Domain != "proxy.example.com" {
		t.Fatalf("heartbeat cert domain = %q", heartbeat.CertDomains[0].Domain)
	}
	if heartbeat.CertDomains[0].Version == "" {
		t.Fatalf("heartbeat cert version was empty")
	}
	if heartbeat.CertDomains[0].ExpiresAt == nil || !heartbeat.CertDomains[0].ExpiresAt.Equal(exp) {
		t.Fatalf("heartbeat cert expires_at = %v, want %v", heartbeat.CertDomains[0].ExpiresAt, exp)
	}

	fullchainPath := filepath.Join(conf.CertDir, "proxy.example.com", "fullchain.pem")
	privkeyPath := filepath.Join(conf.CertDir, "proxy.example.com", "privkey.pem")
	if err := os.Remove(fullchainPath); err != nil {
		t.Fatalf("remove fullchain: %v", err)
	}
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("syncCerts() after missing cert error = %v", err)
	}
	restoredFullchain, err := os.ReadFile(fullchainPath)
	if err != nil {
		t.Fatalf("read restored fullchain: %v", err)
	}
	if string(restoredFullchain) != fullchain {
		t.Fatalf("restored fullchain = %q", restoredFullchain)
	}

	if err := os.WriteFile(privkeyPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt private key: %v", err)
	}
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("syncCerts() after corrupt key error = %v", err)
	}
	privkey, err := os.ReadFile(privkeyPath)
	if err != nil {
		t.Fatalf("read restored private key: %v", err)
	}
	if string(privkey) != keyPEM {
		t.Fatalf("restored private key = %q", privkey)
	}
}

func TestNodeSyncerUsesConditionalCertificateRequestOnlyWhenLocalSnapshotComplete(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	fullchain, keyPEM, exp := testCertificatePEM(t, "proxy.example.com")
	certSnap := CertificateSnapshot{
		CertVersion: "cert-v1",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  fullchain,
			PrivateKeyPEM: keyPEM,
			ExpiresAt:     &exp,
		}},
		UpdatedAt: time.Now().UTC(),
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/certs" {
			http.NotFound(w, r)
			return
		}
		requests++
		switch requests {
		case 1:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Fatalf("first cert request If-None-Match = %q, want empty", got)
			}
			w.Header().Set("ETag", certSnapshotETag(certSnap.CertVersion))
			_ = json.NewEncoder(w).Encode(certSnap)
		case 2:
			if got := r.Header.Get("If-None-Match"); got != certSnapshotETag(certSnap.CertVersion) {
				t.Fatalf("second cert request If-None-Match = %q, want %q", got, certSnapshotETag(certSnap.CertVersion))
			}
			w.WriteHeader(http.StatusNotModified)
		case 3:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Fatalf("repair cert request If-None-Match = %q, want empty", got)
			}
			w.Header().Set("ETag", certSnapshotETag(certSnap.CertVersion))
			_ = json.NewEncoder(w).Encode(certSnap)
		default:
			t.Fatalf("unexpected cert request %d", requests)
		}
	}))
	defer server.Close()

	conf := &Config{
		NodeID:     "node-01",
		CentralURL: server.URL,
		NodeToken:  "node-secret",
		CacheDir:   filepath.Join(dir, "cache"),
		CertDir:    filepath.Join(dir, "certs"),
	}
	syncer := NewNodeSyncer(conf, applier)
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("first syncCerts() error = %v", err)
	}
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("second syncCerts() error = %v", err)
	}

	keyPath := filepath.Join(conf.CertDir, "proxy.example.com", "privkey.pem")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("repair syncCerts() error = %v", err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != keyPEM {
		t.Fatalf("repaired key = %q, err = %v", string(b), err)
	}
	if requests != 3 {
		t.Fatalf("cert requests = %d, want 3", requests)
	}
}

func TestNodeSyncerRejectsInvalidCertificateSnapshotWithoutOverwritingFiles(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	goodFullchain, goodKeyPEM, exp := testCertificatePEM(t, "proxy.example.com")
	badFullchain, _, _ := testCertificatePEM(t, "proxy.example.com")
	_, badKeyPEM, _ := testCertificatePEM(t, "other.example.com")
	centralConfig := testSnapshot("config-v1", nil, []dbRule{{
		Name:    "direct",
		Content: "forward=direct://\n",
	}})
	goodCerts := CertificateSnapshot{
		CertVersion: "cert-good",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  goodFullchain,
			PrivateKeyPEM: goodKeyPEM,
			ExpiresAt:     &exp,
		}},
		UpdatedAt: time.Now().UTC(),
	}
	badCerts := CertificateSnapshot{
		CertVersion: "cert-bad",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  badFullchain,
			PrivateKeyPEM: badKeyPEM,
			ExpiresAt:     &exp,
		}},
		UpdatedAt: time.Now().UTC(),
	}

	var serveBadCerts bool
	var heartbeat NodeHeartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			_ = json.NewEncoder(w).Encode(centralConfig)
		case "/api/node/certs":
			if serveBadCerts {
				_ = json.NewEncoder(w).Encode(badCerts)
				return
			}
			_ = json.NewEncoder(w).Encode(goodCerts)
		case "/api/node/heartbeat":
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatalf("decode heartbeat: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	conf := &Config{
		NodeID:       "node-01",
		CentralURL:   server.URL,
		NodeToken:    "node-secret",
		CacheDir:     filepath.Join(dir, "cache"),
		CertDir:      filepath.Join(dir, "certs"),
		SyncInterval: "1h",
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.syncOnce(context.Background())
	if syncer.certVersion != "cert-good" {
		t.Fatalf("initial cert version = %q, want cert-good", syncer.certVersion)
	}

	serveBadCerts = true
	heartbeat = NodeHeartbeat{}
	syncer.syncOnce(context.Background())
	if syncer.certVersion != "cert-good" {
		t.Fatalf("cert version after invalid snapshot = %q, want cert-good", syncer.certVersion)
	}
	if heartbeat.CertError == "" {
		t.Fatalf("heartbeat cert_error was empty after invalid cert snapshot")
	}

	certPath := filepath.Join(conf.CertDir, "proxy.example.com", "fullchain.pem")
	keyPath := filepath.Join(conf.CertDir, "proxy.example.com", "privkey.pem")
	if b, err := os.ReadFile(certPath); err != nil || string(b) != goodFullchain {
		t.Fatalf("fullchain after invalid snapshot = %q, err = %v", string(b), err)
	}
	if b, err := os.ReadFile(keyPath); err != nil || string(b) != goodKeyPEM {
		t.Fatalf("key after invalid snapshot = %q, err = %v", string(b), err)
	}
}

func TestNodeSyncerAppliesEmptyCertificateSnapshot(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/node/certs" {
			requests++
			_ = json.NewEncoder(w).Encode(CertificateSnapshot{})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	conf := &Config{
		NodeID:     "node-01",
		CentralURL: server.URL,
		NodeToken:  "node-secret",
		CacheDir:   filepath.Join(dir, "cache"),
		CertDir:    filepath.Join(dir, "certs"),
	}
	oldDir := filepath.Join(conf.CertDir, "old.example.com")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatalf("mkdir old cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "fullchain.pem"), []byte("old"), 0o600); err != nil {
		t.Fatalf("write old cert: %v", err)
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.certVersion = "old-cert-version"
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("syncCerts() error = %v", err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("old cert dir should be removed for empty snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(conf.CacheDir, certsSnapshotFileName)); err != nil {
		t.Fatalf("empty cert snapshot should be cached: %v", err)
	}
	if syncer.certVersion != "" {
		t.Fatalf("cert version = %q, want empty", syncer.certVersion)
	}
	snapshotPath := filepath.Join(conf.CacheDir, certsSnapshotFileName)
	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatalf("stat empty cert snapshot: %v", err)
	}
	mtime := info.ModTime()
	time.Sleep(20 * time.Millisecond)
	if err := syncer.syncCerts(context.Background()); err != nil {
		t.Fatalf("second syncCerts() error = %v", err)
	}
	info, err = os.Stat(snapshotPath)
	if err != nil {
		t.Fatalf("stat empty cert snapshot after second sync: %v", err)
	}
	if !info.ModTime().Equal(mtime) {
		t.Fatalf("unchanged empty cert snapshot was rewritten: before %s after %s", mtime, info.ModTime())
	}
	if requests != 2 {
		t.Fatalf("cert endpoint requests = %d, want 2", requests)
	}
}

func TestSyncCloudflareDNSValidatesRecordIPType(t *testing.T) {
	ctx := context.Background()
	d := dbDomain{
		Domain: "proxy.example.com",
		Cloudflare: cloudflareDomainConfig{
			RecordType: "AAAA",
		},
	}
	node := NodeHeartbeat{NodeID: "node-01", PublicIP: "8.8.4.4"}
	if _, err := syncCloudflareDNS(ctx, d, node); err == nil {
		t.Fatalf("syncCloudflareDNS() succeeded for IPv4 with AAAA")
	}

	d.Cloudflare.RecordType = "CNAME"
	if _, err := syncCloudflareDNS(ctx, d, NodeHeartbeat{NodeID: "node-01", PublicIP: "example.net"}); err == nil {
		t.Fatalf("syncCloudflareDNS() succeeded for CNAME public_ip")
	}
}

func TestPlanCloudflareDNSRejectsNonPublicTargetIPWithoutCallingCloudflare(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatalf("Cloudflare should not be called for non-public target IP: %s %s", r.Method, r.URL.RequestURI())
	}))
	defer server.Close()
	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	tests := []string{
		"127.0.0.1",
		"10.0.0.5",
		"172.16.0.5",
		"192.168.1.5",
		"192.0.2.10",
		"198.51.100.10",
		"203.0.113.10",
		"::1",
		"fc00::1",
		"2001:db8::10",
	}
	for _, ip := range tests {
		_, err := planCloudflareDNSWithClient(context.Background(), dbDomain{Domain: "proxy.example.com"}, NodeHeartbeat{NodeID: "node-01", PublicIP: ip}, cf, true)
		if err == nil || !strings.Contains(err.Error(), "not a public IP address") {
			t.Fatalf("planCloudflareDNSWithClient(%s) error = %v, want non-public rejection", ip, err)
		}
	}
	if called {
		t.Fatalf("Cloudflare was called for non-public target IP")
	}
}

func TestSyncCloudflareDNSCreatesRecordAndStoresMetadata(t *testing.T) {
	var calls []string
	var createPayload struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if got := r.URL.Query().Get("name"); got != "proxy.example.com" {
				t.Fatalf("zone lookup name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
				Success: true,
				Result:  []cloudflareZone{{ID: "zone-1", Name: "example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			if got := r.URL.Query().Get("type"); got != "A" {
				t.Fatalf("record lookup type = %q", got)
			}
			if got := r.URL.Query().Get("name"); got != "proxy.example.com" {
				t.Fatalf("record lookup name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result:  []cloudflareDNSRecord{},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			if err := json.NewDecoder(r.Body).Decode(&createPayload); err != nil {
				t.Fatalf("decode create payload: %v", err)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareDNSRecord]{
				Success: true,
				Result: cloudflareDNSRecord{
					ID:      "record-1",
					Type:    createPayload.Type,
					Name:    createPayload.Name,
					Content: createPayload.Content,
					TTL:     createPayload.TTL,
					Proxied: createPayload.Proxied,
				},
			})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	out, err := syncCloudflareDNSWithClient(context.Background(), dbDomain{
		Domain: "proxy.example.com",
		Cloudflare: cloudflareDomainConfig{
			Proxied: true,
		},
	}, NodeHeartbeat{NodeID: "node-01", PublicIP: "8.8.4.4"}, cf)
	if err != nil {
		t.Fatalf("syncCloudflareDNSWithClient() error = %v", err)
	}
	if out.ZoneID != "zone-1" || out.ZoneName != "example.com" {
		t.Fatalf("zone metadata = %#v", out)
	}
	if out.RecordID != "record-1" || out.RecordName != "proxy.example.com" || out.RecordType != "A" {
		t.Fatalf("record metadata = %#v", out)
	}
	if out.TTL != 1 || !out.Proxied || out.LastSyncedAt == nil || out.LastError != "" {
		t.Fatalf("sync status = %#v", out)
	}
	if createPayload.Type != "A" || createPayload.Name != "proxy.example.com" || createPayload.Content != "8.8.4.4" || createPayload.TTL != 1 || !createPayload.Proxied {
		t.Fatalf("create payload = %#v", createPayload)
	}
	wantCalls := []string{
		"GET /zones?name=proxy.example.com",
		"GET /zones/zone-1/dns_records?name=proxy.example.com&type=A",
		"POST /zones/zone-1/dns_records",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestPlanCloudflareDNSShowsCreateTarget(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
				Success: true,
				Result:  []cloudflareZone{{ID: "zone-1", Name: "example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result:  []cloudflareDNSRecord{},
			})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	plan, err := planCloudflareDNSWithClient(context.Background(), dbDomain{
		Domain: "proxy.example.com",
		Cloudflare: cloudflareDomainConfig{
			Proxied: true,
		},
	}, NodeHeartbeat{NodeID: "node-01", PublicIP: "8.8.4.4"}, cf, true)
	if err != nil {
		t.Fatalf("planCloudflareDNSWithClient() error = %v", err)
	}
	if plan.Action != "create" || plan.RecordType != "A" || plan.RecordName != "proxy.example.com" {
		t.Fatalf("plan record = %#v", plan)
	}
	if plan.NodeID != "node-01" || plan.NodePublicIP != "8.8.4.4" || plan.TargetContent != "8.8.4.4" {
		t.Fatalf("plan target = %#v", plan)
	}
	if plan.ZoneID != "zone-1" || plan.ZoneName != "example.com" || plan.TTL != 1 || !plan.Proxied {
		t.Fatalf("plan metadata = %#v", plan)
	}
	wantCalls := []string{
		"GET /zones?name=proxy.example.com",
		"GET /zones/zone-1/dns_records?name=proxy.example.com&type=A",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestPlanCloudflareDNSShowsExistingUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result: []cloudflareDNSRecord{{
					ID:      "record-1",
					Type:    "AAAA",
					Name:    "v6.example.com",
					Content: "2606:4700:4700::1001",
					TTL:     300,
					Proxied: true,
				}},
			})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	plan, err := planCloudflareDNSWithClient(context.Background(), dbDomain{
		Domain: "v6.example.com",
		Cloudflare: cloudflareDomainConfig{
			ZoneID:     "zone-1",
			ZoneName:   "example.com",
			RecordName: "v6.example.com",
			TTL:        120,
		},
	}, NodeHeartbeat{NodeID: "node-01", PublicIP: "2606:4700:4700::1111"}, cf, true)
	if err != nil {
		t.Fatalf("planCloudflareDNSWithClient() error = %v", err)
	}
	if plan.Action != "update" || plan.RecordType != "AAAA" || plan.RecordID != "record-1" {
		t.Fatalf("plan record = %#v", plan)
	}
	if plan.ExistingID != "record-1" || plan.ExistingContent != "2606:4700:4700::1001" || plan.ExistingTTL != 300 || !plan.ExistingProxied {
		t.Fatalf("plan existing = %#v", plan)
	}
	if plan.TargetContent != "2606:4700:4700::1111" || plan.TTL != 120 || plan.Proxied {
		t.Fatalf("plan target = %#v", plan)
	}
}

func TestSyncCloudflareDNSUpdatesExistingIPv6Record(t *testing.T) {
	var calls []string
	var updatePayload struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			if got := r.URL.Query().Get("type"); got != "AAAA" {
				t.Fatalf("record lookup type = %q", got)
			}
			if got := r.URL.Query().Get("name"); got != "v6.example.com" {
				t.Fatalf("record lookup name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result: []cloudflareDNSRecord{{
					ID:      "record-v6-old",
					Type:    "AAAA",
					Name:    "v6.example.com",
					Content: "2606:4700:4700::1001",
					TTL:     300,
				}},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/zones/zone-1/dns_records/record-v6-old":
			if err := json.NewDecoder(r.Body).Decode(&updatePayload); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareDNSRecord]{
				Success: true,
				Result: cloudflareDNSRecord{
					ID:      "record-v6-old",
					Type:    updatePayload.Type,
					Name:    updatePayload.Name,
					Content: updatePayload.Content,
					TTL:     updatePayload.TTL,
					Proxied: updatePayload.Proxied,
				},
			})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	out, err := syncCloudflareDNSWithClient(context.Background(), dbDomain{
		Domain: "v6.example.com",
		Cloudflare: cloudflareDomainConfig{
			ZoneID:     "zone-1",
			ZoneName:   "example.com",
			RecordName: "v6.example.com",
			TTL:        120,
		},
	}, NodeHeartbeat{NodeID: "node-01", PublicIP: "2606:4700:4700::1111"}, cf)
	if err != nil {
		t.Fatalf("syncCloudflareDNSWithClient() error = %v", err)
	}
	if out.RecordID != "record-v6-old" || out.RecordType != "AAAA" || out.RecordName != "v6.example.com" {
		t.Fatalf("record metadata = %#v", out)
	}
	if out.TTL != 120 || out.Proxied || out.LastSyncedAt == nil || out.LastError != "" {
		t.Fatalf("sync status = %#v", out)
	}
	if updatePayload.Type != "AAAA" || updatePayload.Name != "v6.example.com" || updatePayload.Content != "2606:4700:4700::1111" || updatePayload.TTL != 120 || updatePayload.Proxied {
		t.Fatalf("update payload = %#v", updatePayload)
	}
	wantCalls := []string{
		"GET /zones/zone-1/dns_records?name=v6.example.com&type=AAAA",
		"PUT /zones/zone-1/dns_records/record-v6-old",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestSyncCloudflareDNSFailurePreservesPreviousRecordState(t *testing.T) {
	lastSynced := time.Now().UTC().Add(-time.Hour)
	d := dbDomain{
		Domain: "proxy.example.com",
		Cloudflare: cloudflareDomainConfig{
			ZoneID:       "zone-1",
			ZoneName:     "example.com",
			RecordID:     "record-1",
			RecordName:   "proxy.example.com",
			RecordType:   "A",
			TTL:          120,
			Proxied:      true,
			LastSyncedAt: &lastSynced,
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareDNSRecord]{
			Success: false,
			Errors:  []cloudflareAPIError{{Code: 1000, Message: "simulated outage"}},
		})
	}))
	defer server.Close()
	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL

	out, err := syncCloudflareDNSWithClient(context.Background(), d, NodeHeartbeat{NodeID: "node-01", PublicIP: "8.8.4.4"}, cf)
	if err == nil {
		t.Fatalf("syncCloudflareDNSWithClient() succeeded during outage")
	}
	if out.RecordID != "record-1" || out.ZoneName != "example.com" || out.RecordName != "proxy.example.com" {
		t.Fatalf("previous record state was not preserved: %#v", out)
	}
	if out.LastSyncedAt == nil || !out.LastSyncedAt.Equal(lastSynced) {
		t.Fatalf("last synced changed on failure: %#v", out.LastSyncedAt)
	}
	if !strings.Contains(out.LastError, "cloudflare returned 500") {
		t.Fatalf("last error = %q", out.LastError)
	}
}

type fakeTXTResolver struct {
	values []string
	err    error
}

func (r fakeTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.values, r.err
}

func TestLookupTXTValue(t *testing.T) {
	ok, err := lookupTXTValue(context.Background(), fakeTXTResolver{values: []string{"one", "target"}}, "_acme-challenge.example.com", "target")
	if err != nil || !ok {
		t.Fatalf("lookupTXTValue() = %v, %v", ok, err)
	}
	ok, err = lookupTXTValue(context.Background(), fakeTXTResolver{values: []string{"one"}}, "_acme-challenge.example.com", "target")
	if err != nil || ok {
		t.Fatalf("lookupTXTValue() missing target = %v, %v", ok, err)
	}
}

func TestDNS01RecordNameNormalizesDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "regular", domain: "Proxy.Example.COM.", want: "_acme-challenge.proxy.example.com"},
		{name: "wildcard", domain: "*.Example.COM.", want: "_acme-challenge.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dns01RecordName(tt.domain)
			if err != nil {
				t.Fatalf("dns01RecordName() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("dns01RecordName() = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := dns01RecordName("_bad.example.com"); err == nil {
		t.Fatalf("dns01RecordName() accepted invalid domain")
	}
}

func TestWaitDNS01TXTCanBeDisabled(t *testing.T) {
	t.Setenv(acmeDNSPropagationTimeoutEnv, "0s")
	if err := waitDNS01TXT(context.Background(), "_acme-challenge.invalid", "target"); err != nil {
		t.Fatalf("waitDNS01TXT() error = %v", err)
	}
}

func TestCleanupCloudflareRecordsDeletesEveryRecordAndIgnoresErrors(t *testing.T) {
	deleter := &fakeDNSRecordDeleter{
		fail: map[string]error{
			"rec-2": fmt.Errorf("simulated delete failure"),
		},
	}

	cleanupCloudflareRecords(context.Background(), deleter, "zone-1", []string{"rec-1", "rec-2", "", "rec-3"})

	want := []string{"zone-1/rec-1", "zone-1/rec-2", "zone-1/rec-3"}
	if strings.Join(deleter.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("delete calls = %#v, want %#v", deleter.calls, want)
	}
}

type fakeDNSRecordDeleter struct {
	calls []string
	fail  map[string]error
}

func (f *fakeDNSRecordDeleter) deleteRecord(_ context.Context, zoneID, recordID string) error {
	f.calls = append(f.calls, zoneID+"/"+recordID)
	return f.fail[recordID]
}

func TestCloudflareSettingsResponseMasksToken(t *testing.T) {
	resp := cloudflareSettingsToResponse(cloudflareSettings{
		APIToken:  "abcdef1234567890",
		AccountID: "acct-123",
		ACMEEmail: "admin@example.com",
		Source:    "database",
	})
	if !resp.Configured {
		t.Fatalf("token should be configured")
	}
	if resp.MaskedToken != "abcd********7890" {
		t.Fatalf("masked token = %q", resp.MaskedToken)
	}
	if resp.Source != "database" {
		t.Fatalf("source = %q", resp.Source)
	}
	if resp.AccountID != "acct-123" {
		t.Fatalf("account id = %q", resp.AccountID)
	}
}

func TestCloudflareVerifyTokenChoosesAccountEndpoint(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareTokenVerify]{
			Success: true,
			Result: cloudflareTokenVerify{
				ID:     "tok-1",
				Status: "active",
			},
		})
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	result, err := cf.verifyToken(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("verifyToken() error = %v", err)
	}
	if result.ID != "tok-1" || result.Status != "active" {
		t.Fatalf("verify result = %#v", result)
	}
	if path != "/accounts/acct-1/tokens/verify" {
		t.Fatalf("path = %q", path)
	}
}

func TestCloudflareVerifyTokenChoosesUserEndpoint(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareTokenVerify]{
			Success: true,
			Result:  cloudflareTokenVerify{Status: "active"},
		})
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	if _, err := cf.verifyToken(context.Background(), ""); err != nil {
		t.Fatalf("verifyToken() error = %v", err)
	}
	if path != "/user/tokens/verify" {
		t.Fatalf("path = %q", path)
	}
}

func TestCloudflareCheckZoneReadOnly(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if got := r.URL.Query().Get("name"); got != "proxy.example.com" {
				t.Fatalf("zone lookup name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
				Success: true,
				Result:  []cloudflareZone{{ID: "zone-1", Name: "example.com"}},
			})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	check, err := cf.checkZone(context.Background(), "Proxy.Example.com.", false)
	if err != nil {
		t.Fatalf("checkZone() error = %v", err)
	}
	if check.Domain != "proxy.example.com" || check.ZoneID != "zone-1" || check.ZoneName != "example.com" {
		t.Fatalf("zone check = %#v", check)
	}
	if !check.ZoneReadOK || check.DNSEditOK || check.TestRecord != "" {
		t.Fatalf("zone check flags = %#v", check)
	}
	wantCalls := []string{"GET /zones?name=proxy.example.com"}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestCloudflareCheckZoneDNSEditCreatesAndDeletesTXT(t *testing.T) {
	var calls []string
	var txtPayload struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if got := r.URL.Query().Get("name"); got != "example.com" {
				t.Fatalf("zone lookup name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
				Success: true,
				Result:  []cloudflareZone{{ID: "zone-1", Name: "example.com"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			if err := json.NewDecoder(r.Body).Decode(&txtPayload); err != nil {
				t.Fatalf("decode TXT payload: %v", err)
			}
			if txtPayload.Type != "TXT" || !strings.HasPrefix(txtPayload.Name, "_glider-check-") || !strings.HasSuffix(txtPayload.Name, ".example.com") {
				t.Fatalf("TXT payload = %#v", txtPayload)
			}
			_ = json.NewEncoder(w).Encode(cloudflareResponse[cloudflareDNSRecord]{
				Success: true,
				Result:  cloudflareDNSRecord{ID: "txt-1", Name: txtPayload.Name, Type: "TXT"},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-1/dns_records/txt-1":
			_ = json.NewEncoder(w).Encode(cloudflareResponse[json.RawMessage]{Success: true})
		default:
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	check, err := cf.checkZone(context.Background(), "*.Example.com.", true)
	if err != nil {
		t.Fatalf("checkZone() error = %v", err)
	}
	if check.Domain != "*.example.com" || !check.ZoneReadOK || !check.DNSEditOK {
		t.Fatalf("zone check = %#v", check)
	}
	if check.TestRecord != txtPayload.Name || check.TestRecord == "" {
		t.Fatalf("test record = %q, payload name = %q", check.TestRecord, txtPayload.Name)
	}
	wantCalls := []string{
		"GET /zones",
		"POST /zones/zone-1/dns_records",
		"DELETE /zones/zone-1/dns_records/txt-1",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestStoredSecretEncryptionRoundTrip(t *testing.T) {
	t.Setenv(settingsKeyEnv, "0123456789abcdef")
	stored, err := encodeStoredSecret("secret-token")
	if err != nil {
		t.Fatalf("encodeStoredSecret() error = %v", err)
	}
	if stored == "secret-token" {
		t.Fatalf("stored token was not encrypted")
	}
	plain, err := decodeStoredSecret(stored)
	if err != nil {
		t.Fatalf("decodeStoredSecret() error = %v", err)
	}
	if plain != "secret-token" {
		t.Fatalf("decoded token = %q", plain)
	}
}

func TestStoredSecretPlainFallbackWithoutKey(t *testing.T) {
	t.Setenv(settingsKeyEnv, "")
	stored, err := encodeStoredSecret("secret-token")
	if err != nil {
		t.Fatalf("encodeStoredSecret() error = %v", err)
	}
	if stored != "secret-token" {
		t.Fatalf("stored token = %q, want plaintext fallback", stored)
	}
	plain, err := decodeStoredSecret(stored)
	if err != nil {
		t.Fatalf("decodeStoredSecret() error = %v", err)
	}
	if plain != "secret-token" {
		t.Fatalf("decoded token = %q", plain)
	}
}

func TestCloudflareSettingsUpdateEncryptsAndPreservesToken(t *testing.T) {
	t.Setenv(settingsKeyEnv, "0123456789abcdef")
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	token := "  secret-token  "
	update, err := cloudflareSettingsUpdate(cloudflareSettings{
		AccountID:        " acct-1 ",
		ACMEEmail:        " admin@example.com ",
		ACMEDirectoryURL: " https://acme.example/directory ",
	}, &token, false, now)
	if err != nil {
		t.Fatalf("cloudflareSettingsUpdate() error = %v", err)
	}
	set := update["$set"].(bson.M)
	if set["account_id"] != "acct-1" || set["acme_email"] != "admin@example.com" || set["acme_directory_url"] != "https://acme.example/directory" {
		t.Fatalf("settings were not trimmed: %#v", set)
	}
	storedToken, ok := set["api_token"].(string)
	if !ok || storedToken == "" {
		t.Fatalf("api_token not set: %#v", set)
	}
	if storedToken == strings.TrimSpace(token) {
		t.Fatalf("api_token was stored in plaintext")
	}
	plain, err := decodeStoredSecret(storedToken)
	if err != nil {
		t.Fatalf("decodeStoredSecret() error = %v", err)
	}
	if plain != "secret-token" {
		t.Fatalf("decoded token = %q", plain)
	}
	if update["$unset"] != nil {
		t.Fatalf("unexpected unset: %#v", update["$unset"])
	}

	blank := " "
	update, err = cloudflareSettingsUpdate(cloudflareSettings{}, &blank, false, now)
	if err != nil {
		t.Fatalf("cloudflareSettingsUpdate(blank token) error = %v", err)
	}
	set = update["$set"].(bson.M)
	if _, ok := set["api_token"]; ok {
		t.Fatalf("blank token should not overwrite existing token: %#v", set)
	}

	update, err = cloudflareSettingsUpdate(cloudflareSettings{ACMEEmail: "admin@example.com"}, nil, true, now)
	if err != nil {
		t.Fatalf("cloudflareSettingsUpdate(clear token) error = %v", err)
	}
	unset := update["$unset"].(bson.M)
	if _, ok := unset["api_token"]; !ok {
		t.Fatalf("api_token was not unset: %#v", update)
	}
	set = update["$set"].(bson.M)
	if set["acme_email"] != "admin@example.com" {
		t.Fatalf("non-token settings not preserved while clearing token: %#v", set)
	}
}

func TestCertificateFailurePreservesLastUsableCertificate(t *testing.T) {
	issued := time.Now().UTC().Add(-time.Hour)
	expires := time.Now().UTC().Add(24 * time.Hour)
	current := domainCertificate{
		Version:       "cert-v1",
		FullchainPEM:  "fullchain",
		PrivateKeyPEM: "private-key",
		IssuedAt:      &issued,
		ExpiresAt:     &expires,
		LastIssuedAt:  &issued,
	}

	failed := certificateFailure(current, fmt.Errorf("acme outage"))
	if failed.Version != current.Version {
		t.Fatalf("version changed = %q", failed.Version)
	}
	if failed.FullchainPEM != current.FullchainPEM || failed.PrivateKeyPEM != current.PrivateKeyPEM {
		t.Fatalf("certificate material changed: %#v", failed)
	}
	if failed.ExpiresAt == nil || !failed.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at = %v", failed.ExpiresAt)
	}
	if failed.LastError != "acme outage" {
		t.Fatalf("last_error = %q", failed.LastError)
	}
}

func TestDomainConfigSetPreservesRuntimeState(t *testing.T) {
	set, err := domainConfigSet(&dbDomain{
		Domain:          "Proxy.Example.com.",
		Enabled:         true,
		NodeIDs:         []string{"node-a", "node-a", "node-b"},
		ActiveNodeID:    "node-a",
		FailoverEnabled: true,
		Cloudflare: cloudflareDomainConfig{
			ZoneID:       " zone-1 ",
			ZoneName:     "example.com",
			RecordID:     "record-1",
			RecordName:   "Proxy.Example.com.",
			RecordType:   "a",
			TTL:          120,
			Proxied:      true,
			LastSyncedAt: ptrTime(time.Now()),
			LastError:    "old dns error",
		},
		Certificate: domainCertificate{
			Version:       "cert-v1",
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			LastError:     "old cert error",
		},
	})
	if err != nil {
		t.Fatalf("domainConfigSet() error = %v", err)
	}
	if _, ok := set["certificate"]; ok {
		t.Fatalf("domain config set should not overwrite certificate: %#v", set)
	}
	if _, ok := set["cloudflare"]; ok {
		t.Fatalf("domain config set should not replace whole cloudflare document: %#v", set)
	}
	for _, key := range []string{"cloudflare.zone_id", "cloudflare.record_name", "cloudflare.record_type", "cloudflare.ttl", "cloudflare.proxied"} {
		if _, ok := set[key]; !ok {
			t.Fatalf("missing editable cloudflare key %s in %#v", key, set)
		}
	}
	for _, key := range []string{"cloudflare.record_id", "cloudflare.zone_name", "cloudflare.last_synced_at", "cloudflare.last_error"} {
		if _, ok := set[key]; ok {
			t.Fatalf("domain config set should preserve runtime key %s: %#v", key, set)
		}
	}
	if set["domain"] != "proxy.example.com" {
		t.Fatalf("normalized domain = %q", set["domain"])
	}
	if set["cloudflare.zone_id"] != "zone-1" {
		t.Fatalf("zone id = %q", set["cloudflare.zone_id"])
	}
	if set["cloudflare.record_name"] != "proxy.example.com" {
		t.Fatalf("record name = %q", set["cloudflare.record_name"])
	}
	if set["cloudflare.record_type"] != "A" {
		t.Fatalf("record type = %q", set["cloudflare.record_type"])
	}
	if got := set["node_ids"].([]string); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("node ids = %#v", got)
	}
	if got := set["active_node_id"]; got != "node-a" {
		t.Fatalf("active node id = %#v", got)
	}
}

func TestDomainConfigSetPreservesAutoRecordType(t *testing.T) {
	set, err := domainConfigSet(&dbDomain{
		Domain: "auto.example.com",
		Cloudflare: cloudflareDomainConfig{
			RecordType: " ",
		},
	})
	if err != nil {
		t.Fatalf("domainConfigSet() error = %v", err)
	}
	if got := set["cloudflare.record_type"]; got != "" {
		t.Fatalf("record type = %q, want empty auto", got)
	}
	if got := set["cloudflare.record_name"]; got != "auto.example.com" {
		t.Fatalf("record name = %q", got)
	}
	if got := set["cloudflare.ttl"]; got != 1 {
		t.Fatalf("ttl = %v, want 1", got)
	}
}

func TestDomainConfigSetValidatesActiveNodeAssignment(t *testing.T) {
	_, err := domainConfigSet(&dbDomain{
		Domain:       "active.example.com",
		NodeIDs:      []string{"node-a"},
		ActiveNodeID: "node-b",
	})
	if err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("domainConfigSet() error = %v, want active assignment validation", err)
	}

	set, err := domainConfigSet(&dbDomain{
		Domain:       "no-nodes.example.com",
		ActiveNodeID: "stale-node",
	})
	if err != nil {
		t.Fatalf("domainConfigSet(no nodes) error = %v", err)
	}
	if got := set["active_node_id"]; got != "" {
		t.Fatalf("active node id with no assigned nodes = %#v, want empty", got)
	}
}

func TestDomainConfigSetRejectsInvalidCloudflareRecordConfig(t *testing.T) {
	_, err := domainConfigSet(&dbDomain{
		Domain: "invalid-record.example.com",
		Cloudflare: cloudflareDomainConfig{
			RecordType: "cname",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported cloudflare record type") {
		t.Fatalf("domainConfigSet() error = %v, want unsupported record type", err)
	}

	_, err = domainConfigSet(&dbDomain{
		Domain: "invalid-ttl.example.com",
		Cloudflare: cloudflareDomainConfig{
			TTL: -1,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("domainConfigSet() error = %v, want ttl validation", err)
	}

	_, err = domainConfigSet(&dbDomain{
		Domain: "invalid-record-name.example.com",
		Cloudflare: cloudflareDomainConfig{
			RecordName: "_bad.example.com",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid domain name") {
		t.Fatalf("domainConfigSet() error = %v, want record name validation", err)
	}
}

func TestValidateDomainDNSTargetRequiresAssignedHealthyCertSyncedNode(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	d := dbDomain{
		Domain:       "proxy.example.com",
		Enabled:      true,
		NodeIDs:      []string{"node-a"},
		ActiveNodeID: "node-a",
		Certificate: domainCertificate{
			Version: "cert-v1",
		},
	}
	readyNode := func() NodeHeartbeat {
		return NodeHeartbeat{
			NodeID:    "node-a",
			PublicIP:  "8.8.4.4",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-v1",
				ExpiresAt: &exp,
			}},
		}
	}
	if err := validateDomainDNSTarget(d, readyNode(), now); err != nil {
		t.Fatalf("validateDomainDNSTarget(ready) error = %v", err)
	}

	tests := []struct {
		name string
		d    dbDomain
		node NodeHeartbeat
		want string
	}{
		{
			name: "disabled domain",
			d: func() dbDomain {
				dd := d
				dd.Enabled = false
				return dd
			}(),
			node: readyNode(),
			want: "disabled",
		},
		{
			name: "unassigned node",
			d:    d,
			node: func() NodeHeartbeat {
				n := readyNode()
				n.NodeID = "node-b"
				return n
			}(),
			want: "not assigned",
		},
		{
			name: "stale heartbeat",
			d:    d,
			node: func() NodeHeartbeat {
				n := readyNode()
				n.UpdatedAt = now.Add(-2 * time.Minute)
				return n
			}(),
			want: "stale",
		},
		{
			name: "node error",
			d:    d,
			node: func() NodeHeartbeat {
				n := readyNode()
				n.Error = "sync failed"
				return n
			}(),
			want: "unhealthy",
		},
		{
			name: "non-public ip",
			d:    d,
			node: func() NodeHeartbeat {
				n := readyNode()
				n.PublicIP = "192.0.2.10"
				return n
			}(),
			want: "not a public IP address",
		},
		{
			name: "certificate not synced",
			d:    d,
			node: func() NodeHeartbeat {
				n := readyNode()
				n.CertDomains[0].Version = "cert-old"
				return n
			}(),
			want: "has not synced certificate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainDNSTarget(tt.d, tt.node, now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateDomainDNSTarget() error = %v, want %q", err, tt.want)
			}
		})
	}

	d.Certificate.Version = ""
	missingCert := readyNode()
	missingCert.CertDomains = nil
	if err := validateDomainDNSTarget(d, missingCert, now); err != nil {
		t.Fatalf("certificate-less domain should accept healthy assigned node: %v", err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func TestDomainAssignedToNodeRequiresEnabledAndAssignment(t *testing.T) {
	d := dbDomain{
		Enabled: true,
		NodeIDs: []string{"node-a", "node-b"},
	}
	if !domainAssignedToNode(d, "node-a") {
		t.Fatalf("assigned node was not accepted")
	}
	if domainAssignedToNode(d, "node-c") {
		t.Fatalf("unassigned node was accepted")
	}
	d.Enabled = false
	if domainAssignedToNode(d, "node-a") {
		t.Fatalf("disabled domain was accepted")
	}
}

func TestCertificateSnapshotForNodeOnlyIncludesAssignedEnabledCertificates(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	expired := now.Add(-time.Hour)
	domains := []dbDomain{
		{
			Domain:  "assigned.example.com",
			Enabled: true,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				FullchainPEM:  "assigned-cert",
				PrivateKeyPEM: "assigned-key",
				ExpiresAt:     &exp,
			},
		},
		{
			Domain:  "other-node.example.com",
			Enabled: true,
			NodeIDs: []string{"node-b"},
			Certificate: domainCertificate{
				FullchainPEM:  "other-cert",
				PrivateKeyPEM: "other-key",
				ExpiresAt:     &exp,
			},
		},
		{
			Domain:  "disabled.example.com",
			Enabled: false,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				FullchainPEM:  "disabled-cert",
				PrivateKeyPEM: "disabled-key",
				ExpiresAt:     &exp,
			},
		},
		{
			Domain:  "expired.example.com",
			Enabled: true,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				FullchainPEM:  "expired-cert",
				PrivateKeyPEM: "expired-key",
				ExpiresAt:     &expired,
			},
		},
		{
			Domain:  "missing-expiry.example.com",
			Enabled: true,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				FullchainPEM:  "missing-expiry-cert",
				PrivateKeyPEM: "missing-expiry-key",
			},
		},
		{
			Domain:  "missing-key.example.com",
			Enabled: true,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				FullchainPEM: "missing-key-cert",
				ExpiresAt:    &exp,
			},
		},
		{
			Domain:  "missing-cert.example.com",
			Enabled: true,
			NodeIDs: []string{"node-a"},
			Certificate: domainCertificate{
				PrivateKeyPEM: "missing-cert-key",
				ExpiresAt:     &exp,
			},
		},
	}

	snap := certificateSnapshotForNode(domains, "node-a")
	if len(snap.Domains) != 1 {
		t.Fatalf("snapshot domains = %#v", snap.Domains)
	}
	cert := snap.Domains[0]
	if cert.Domain != "assigned.example.com" {
		t.Fatalf("domain = %q", cert.Domain)
	}
	if cert.FullchainPEM != "assigned-cert" || cert.PrivateKeyPEM != "assigned-key" {
		t.Fatalf("certificate material leaked or changed: %#v", cert)
	}
	if snap.CertVersion == "" {
		t.Fatalf("cert version was empty")
	}
	if !snap.UpdatedAt.Equal(exp) {
		t.Fatalf("updated_at = %v, want %v", snap.UpdatedAt, exp)
	}

	empty := certificateSnapshotForNode(domains, "node-missing")
	if len(empty.Domains) != 0 {
		t.Fatalf("unassigned node got certs: %#v", empty.Domains)
	}
	emptyVersion, _ := certsVersion(nil)
	if empty.CertVersion != emptyVersion {
		t.Fatalf("empty cert version = %q", empty.CertVersion)
	}
}

func TestDomainRuntimeAndFailoverRequireUnexpiredNodeCertificate(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	d := dbDomain{
		Domain:          "proxy.example.com",
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "active",
		NodeIDs:         []string{"active", "expired-cert", "ready"},
		Certificate: domainCertificate{
			Version:       "cert-v1",
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &future,
		},
	}
	nodes := map[string]NodeHeartbeat{
		"active": {NodeID: "active", UpdatedAt: now.Add(-10 * time.Minute)},
		"expired-cert": {
			NodeID:    "expired-cert",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-v1",
				ExpiresAt: &expired,
			}},
		},
		"ready": {
			NodeID:    "ready",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-v1",
				ExpiresAt: &future,
			}},
		},
	}

	expiredState := domainNodeCertState(d, "expired-cert", nodes["expired-cert"], now)
	if expiredState.CertSynced || expiredState.FailoverReady {
		t.Fatalf("expired node cert should not be synced/ready: %#v", expiredState)
	}
	readyState := domainNodeCertState(d, "ready", nodes["ready"], now)
	if !readyState.CertSynced || !readyState.FailoverReady {
		t.Fatalf("ready node cert should be synced/ready: %#v", readyState)
	}
	node, ok := failoverTarget(d, nodes)
	if !ok || node.NodeID != "ready" {
		t.Fatalf("failover target = %#v, ok = %v", node, ok)
	}
}

func TestFailoverSelectsFirstHealthyAssignedNode(t *testing.T) {
	now := time.Now().UTC()
	d := dbDomain{NodeIDs: []string{"down", "healthy", "later"}}
	nodes := map[string]NodeHeartbeat{
		"down":    {NodeID: "down", UpdatedAt: now.Add(-10 * time.Minute)},
		"healthy": {NodeID: "healthy", UpdatedAt: now},
		"later":   {NodeID: "later", UpdatedAt: now},
	}
	node, ok := firstHealthyAssignedNode(d, nodes)
	if !ok || node.NodeID != "healthy" {
		t.Fatalf("selected node = %#v, ok = %v", node, ok)
	}
}

func TestFailoverSkipsHealthyNodeWithoutSyncedDomainCertificate(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	d := dbDomain{
		Domain: "Proxy.Example.COM.",
		Certificate: domainCertificate{
			Version: "cert-v1",
		},
		NodeIDs: []string{"down", "missing-cert", "wrong-cert", "ready"},
	}
	nodes := map[string]NodeHeartbeat{
		"down":         {NodeID: "down", UpdatedAt: now.Add(-10 * time.Minute)},
		"missing-cert": {NodeID: "missing-cert", UpdatedAt: now},
		"wrong-cert": {
			NodeID:    "wrong-cert",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-old",
				ExpiresAt: &exp,
			}},
		},
		"ready": {
			NodeID:    "ready",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com.",
				Version:   "cert-v1",
				ExpiresAt: &exp,
			}},
		},
	}
	node, ok := firstHealthyAssignedNode(d, nodes)
	if !ok || node.NodeID != "ready" {
		t.Fatalf("selected node = %#v, ok = %v", node, ok)
	}

	d.Certificate.Version = ""
	node, ok = firstHealthyAssignedNode(d, nodes)
	if !ok || node.NodeID != "missing-cert" {
		t.Fatalf("certificate-less domain selected node = %#v, ok = %v", node, ok)
	}
}

func TestFailoverTargetOnlySwitchesWhenActiveIsUnhealthy(t *testing.T) {
	now := time.Now().UTC()
	nodes := map[string]NodeHeartbeat{
		"active":  {NodeID: "active", UpdatedAt: now},
		"standby": {NodeID: "standby", UpdatedAt: now},
		"error":   {NodeID: "error", UpdatedAt: now, Error: "dial failed"},
	}
	d := dbDomain{
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "active",
		NodeIDs:         []string{"active", "standby"},
	}
	if node, ok := failoverTarget(d, nodes); ok {
		t.Fatalf("healthy active node should not fail over, got %#v", node)
	}

	nodes["active"] = NodeHeartbeat{NodeID: "active", UpdatedAt: now.Add(-10 * time.Minute)}
	node, ok := failoverTarget(d, nodes)
	if !ok || node.NodeID != "standby" {
		t.Fatalf("failover target = %#v, ok = %v", node, ok)
	}

	d.FailoverEnabled = false
	if node, ok := failoverTarget(d, nodes); ok {
		t.Fatalf("disabled failover selected %#v", node)
	}
	d.FailoverEnabled = true
	d.Enabled = false
	if node, ok := failoverTarget(d, nodes); ok {
		t.Fatalf("disabled domain selected %#v", node)
	}
	d.Enabled = true
	d.NodeIDs = []string{"active", "error"}
	if node, ok := failoverTarget(d, nodes); ok {
		t.Fatalf("unhealthy candidates selected %#v", node)
	}
}

func TestEvaluateDomainFailoverUsesThresholdCooldownAndManualLock(t *testing.T) {
	now := time.Now().UTC()
	nodes := map[string]NodeHeartbeat{
		"active":  {NodeID: "active", UpdatedAt: now.Add(-10 * time.Minute)},
		"standby": {NodeID: "standby", UpdatedAt: now},
	}
	d := dbDomain{
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "active",
		NodeIDs:         []string{"active", "standby"},
		FailoverPolicy: domainFailoverPolicy{
			FailThreshold:   3,
			CooldownSeconds: 300,
		},
	}
	first := evaluateDomainFailover(d, nodes, now)
	if first.ShouldSwitch || first.State.ActiveFailureCount != 1 {
		t.Fatalf("first decision = %#v", first)
	}
	d.FailoverState = first.State
	second := evaluateDomainFailover(d, nodes, now.Add(time.Second))
	if second.ShouldSwitch || second.State.ActiveFailureCount != 2 {
		t.Fatalf("second decision = %#v", second)
	}
	d.FailoverState = second.State
	third := evaluateDomainFailover(d, nodes, now.Add(2*time.Second))
	if !third.ShouldSwitch || third.Target.NodeID != "standby" || third.State.ActiveFailureCount != 0 {
		t.Fatalf("third decision = %#v", third)
	}
	if third.State.CooldownUntil == nil || !third.State.CooldownUntil.After(now) {
		t.Fatalf("cooldown was not set: %#v", third.State)
	}

	d.ActiveNodeID = "active"
	d.FailoverState = domainFailoverState{ActiveFailureCount: 2, CooldownUntil: third.State.CooldownUntil}
	cooling := evaluateDomainFailover(d, nodes, now.Add(10*time.Second))
	if cooling.ShouldSwitch || cooling.State.ActiveFailureCount != 3 || cooling.State.LastError != "cooldown active" {
		t.Fatalf("cooling decision = %#v", cooling)
	}

	d.FailoverState = domainFailoverState{ActiveFailureCount: 2}
	d.FailoverPolicy.ManualLock = true
	locked := evaluateDomainFailover(d, nodes, now.Add(20*time.Second))
	if locked.ShouldSwitch || locked.State.LastError != "manual lock enabled" {
		t.Fatalf("locked decision = %#v", locked)
	}
}

func TestEvaluateDomainFailoverAutoFailbackToPrimary(t *testing.T) {
	now := time.Now().UTC()
	nodes := map[string]NodeHeartbeat{
		"primary": {NodeID: "primary", UpdatedAt: now},
		"standby": {NodeID: "standby", UpdatedAt: now},
	}
	d := dbDomain{
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "standby",
		NodeIDs:         []string{"primary", "standby"},
		FailoverPolicy: domainFailoverPolicy{
			AutoFailback:    true,
			PrimaryNodeID:   "primary",
			CooldownSeconds: 120,
		},
	}
	decision := evaluateDomainFailover(d, nodes, now)
	if !decision.ShouldSwitch || decision.Target.NodeID != "primary" || decision.Reason != "primary node recovered" {
		t.Fatalf("auto failback decision = %#v", decision)
	}
	if decision.State.CooldownUntil == nil || !decision.State.CooldownUntil.After(now) {
		t.Fatalf("cooldown missing after failback: %#v", decision.State)
	}

	cooldown := now.Add(30 * time.Second)
	d.FailoverState.CooldownUntil = &cooldown
	decision = evaluateDomainFailover(d, nodes, now.Add(10*time.Second))
	if decision.ShouldSwitch || decision.State.LastError != "cooldown active" {
		t.Fatalf("cooldown should block failback: %#v", decision)
	}
}

func TestNormalizeDomainValidatesPrimaryNodeAssignment(t *testing.T) {
	d := dbDomain{
		Domain:         "proxy.example.com",
		Enabled:        true,
		NodeIDs:        []string{"node-a"},
		FailoverPolicy: domainFailoverPolicy{PrimaryNodeID: "node-b"},
	}
	if err := normalizeDomain(&d); err == nil {
		t.Fatalf("normalizeDomain succeeded with unassigned primary node")
	}
	d.FailoverPolicy.PrimaryNodeID = ""
	if err := normalizeDomain(&d); err != nil {
		t.Fatalf("normalizeDomain() error = %v", err)
	}
	if d.FailoverPolicy.PrimaryNodeID != "node-a" {
		t.Fatalf("primary node default = %q, want node-a", d.FailoverPolicy.PrimaryNodeID)
	}
}

func TestCertificateRenewDue(t *testing.T) {
	now := time.Now().UTC()
	if !certificateRenewDue(dbDomain{}) {
		t.Fatalf("missing certificate should be due")
	}
	if status := certificateRenewStatus(dbDomain{}, now); status != "missing" {
		t.Fatalf("missing status = %q", status)
	}
	exp := now.Add(10 * 24 * time.Hour)
	if !certificateRenewDue(dbDomain{
		RenewBeforeDays: 30,
		Certificate: domainCertificate{
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &exp,
		},
	}) {
		t.Fatalf("certificate inside renewal window should be due")
	}
	dueDomain := dbDomain{
		RenewBeforeDays: 30,
		Certificate: domainCertificate{
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &exp,
		},
	}
	if status := certificateRenewStatus(dueDomain, now); status != "due" {
		t.Fatalf("due status = %q", status)
	}
	expired := now.Add(-time.Hour)
	if status := certificateRenewStatus(dbDomain{
		Certificate: domainCertificate{
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &expired,
		},
	}, now); status != "expired" {
		t.Fatalf("expired status = %q", status)
	}
	exp = now.Add(60 * 24 * time.Hour)
	validDomain := dbDomain{
		RenewBeforeDays: 30,
		Certificate: domainCertificate{
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &exp,
		},
	}
	if certificateRenewDue(validDomain) {
		t.Fatalf("certificate outside renewal window should not be due")
	}
	if status := certificateRenewStatus(validDomain, now); status != "valid" {
		t.Fatalf("valid status = %q", status)
	}
	if days := certificateRenewInDays(validDomain, now); days != 30 {
		t.Fatalf("renew in days = %d, want 30", days)
	}
	if days := certificateDaysRemaining(validDomain, now); days != 60 {
		t.Fatalf("days remaining = %d, want 60", days)
	}
}

func TestRenewBeforeDaysDefault(t *testing.T) {
	if got := renewBeforeDays(dbDomain{}); got != 30 {
		t.Fatalf("default renew before days = %d", got)
	}
	if got := renewBeforeDays(dbDomain{RenewBeforeDays: 14}); got != 14 {
		t.Fatalf("custom renew before days = %d", got)
	}
}

func TestBuildCertificatePlanShowsIssueAndRenewState(t *testing.T) {
	now := time.Now().UTC()
	missing := dbDomain{
		Domain:          "proxy.example.com",
		NodeIDs:         []string{"node-a", "node-b"},
		RenewBeforeDays: 20,
	}
	plan, err := buildCertificatePlan(missing, "admin@example.com", "https://acme.example/directory", "zone-1", "example.com", now)
	if err != nil {
		t.Fatalf("buildCertificatePlan(missing) error = %v", err)
	}
	if plan.Action != "issue" || plan.RenewStatus != "missing" {
		t.Fatalf("missing plan action/status = %#v", plan)
	}
	if plan.ChallengeRecord != "_acme-challenge.proxy.example.com" || plan.AssignedNodeCount != 2 {
		t.Fatalf("missing plan challenge/nodes = %#v", plan)
	}
	if plan.Email != "admin@example.com" || plan.DirectoryURL != "https://acme.example/directory" || plan.ZoneID != "zone-1" {
		t.Fatalf("missing plan metadata = %#v", plan)
	}

	expires := now.Add(60 * 24 * time.Hour)
	valid := dbDomain{
		Domain:          "proxy.example.com",
		RenewBeforeDays: 30,
		Certificate: domainCertificate{
			Version:       "cert-v1",
			FullchainPEM:  "cert",
			PrivateKeyPEM: "key",
			ExpiresAt:     &expires,
		},
	}
	plan, err = buildCertificatePlan(valid, "admin@example.com", defaultACMEDirectoryURL, "zone-1", "example.com", now)
	if err != nil {
		t.Fatalf("buildCertificatePlan(valid) error = %v", err)
	}
	if plan.Action != "not_due" || plan.RenewStatus != "valid" || plan.RenewInDays != 30 || plan.DaysRemaining != 60 {
		t.Fatalf("valid plan = %#v", plan)
	}
	if plan.CurrentVersion != "cert-v1" || plan.ExpiresAt == nil || !plan.ExpiresAt.Equal(expires) {
		t.Fatalf("valid plan certificate = %#v", plan)
	}

	dueExp := now.Add(10 * 24 * time.Hour)
	valid.Certificate.ExpiresAt = &dueExp
	plan, err = buildCertificatePlan(valid, "admin@example.com", defaultACMEDirectoryURL, "zone-1", "example.com", now)
	if err != nil {
		t.Fatalf("buildCertificatePlan(due) error = %v", err)
	}
	if plan.Action != "renew" || plan.RenewStatus != "due" {
		t.Fatalf("due plan = %#v", plan)
	}
}

func TestResolveCertificateZoneIDUsesOverrideThenStoredThenLookup(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/zones" {
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.URL.Query().Get("name"); got != "proxy.example.com" {
			t.Fatalf("zone lookup name = %q", got)
		}
		_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
			Success: true,
			Result:  []cloudflareZone{{ID: "zone-looked-up", Name: "example.com"}},
		})
	}))
	defer server.Close()

	cf, err := newCloudflareClient("token")
	if err != nil {
		t.Fatalf("newCloudflareClient() error = %v", err)
	}
	cf.baseURL = server.URL
	d := dbDomain{
		Domain: "proxy.example.com",
		Cloudflare: cloudflareDomainConfig{
			ZoneID: "zone-stored",
		},
	}
	zoneID, err := resolveCertificateZoneID(context.Background(), d, cf, " zone-override ")
	if err != nil {
		t.Fatalf("resolve override error = %v", err)
	}
	if zoneID != "zone-override" || requests != 0 {
		t.Fatalf("override zone = %q, requests = %d", zoneID, requests)
	}
	zoneID, err = resolveCertificateZoneID(context.Background(), d, cf, "")
	if err != nil {
		t.Fatalf("resolve stored error = %v", err)
	}
	if zoneID != "zone-stored" || requests != 0 {
		t.Fatalf("stored zone = %q, requests = %d", zoneID, requests)
	}
	d.Cloudflare.ZoneID = ""
	zoneID, err = resolveCertificateZoneID(context.Background(), d, cf, "")
	if err != nil {
		t.Fatalf("resolve lookup error = %v", err)
	}
	if zoneID != "zone-looked-up" || requests != 1 {
		t.Fatalf("lookup zone = %q, requests = %d", zoneID, requests)
	}
}

func TestCertificatePlanWithSettingsResolvesZoneAndDefaults(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/zones" {
			t.Fatalf("unexpected Cloudflare request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.URL.Query().Get("name"); got != "proxy.example.com" {
			t.Fatalf("zone lookup name = %q", got)
		}
		_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareZone]{
			Success: true,
			Result:  []cloudflareZone{{ID: "zone-1", Name: "example.com"}},
		})
	}))
	defer server.Close()

	origBase := cloudflareAPIBaseOverrideForTest(t, server.URL)
	defer origBase()

	plan, err := certificatePlanWithSettings(context.Background(), dbDomain{
		Domain:          "proxy.example.com",
		NodeIDs:         []string{"node-a"},
		RenewBeforeDays: 15,
	}, "", "", cloudflareSettings{
		APIToken:  "token",
		ACMEEmail: "admin@example.com",
	})
	if err != nil {
		t.Fatalf("certificatePlanWithSettings() error = %v", err)
	}
	if plan.ZoneID != "zone-1" || plan.ZoneName != "example.com" || requests != 1 {
		t.Fatalf("plan zone = %#v, requests = %d", plan, requests)
	}
	if plan.Email != "admin@example.com" || plan.DirectoryURL != defaultACMEDirectoryURL || plan.Action != "issue" {
		t.Fatalf("plan settings = %#v", plan)
	}
	if plan.ChallengeRecord != "_acme-challenge.proxy.example.com" || plan.AssignedNodeCount != 1 {
		t.Fatalf("plan challenge/nodes = %#v", plan)
	}

	_, err = certificatePlanWithSettings(context.Background(), dbDomain{Domain: "proxy.example.com"}, "", "", cloudflareSettings{APIToken: "token"})
	if err == nil {
		t.Fatalf("certificatePlanWithSettings() succeeded without ACME email")
	}
}
