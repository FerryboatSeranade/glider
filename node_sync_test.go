package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestSnapshot(t *testing.T, cacheDir string, snap ConfigSnapshot) {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(cacheDir, snapshotFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(snap); err != nil {
		t.Fatal(err)
	}
}

func writeRawCertificateSnapshot(cacheDir string, snap CertificateSnapshot) error {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(cacheDir, certsSnapshotFileName))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

func TestNodeSyncerLoadsLocalCache(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	cacheDir := filepath.Join(dir, "cache")
	snap := testSnapshot("cached-v1", nil, []dbRule{{
		Name:    "office",
		Content: "domain=cache.example\n",
	}})
	writeTestSnapshot(t, cacheDir, snap)

	syncer := NewNodeSyncer(&Config{CacheDir: cacheDir}, applier)
	if err := syncer.LoadCache(context.Background()); err != nil {
		t.Fatalf("LoadCache() error = %v", err)
	}
	if got := applier.Version(); got != "cached-v1" {
		t.Fatalf("version = %q, want cached-v1", got)
	}
}

func TestNodeSyncerLoadCacheIgnoresInvalidCertificateCache(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	cacheDir := filepath.Join(dir, "cache")
	snap := testSnapshot("cached-v1", nil, []dbRule{{
		Name:    "office",
		Content: "domain=cache.example\n",
	}})
	writeTestSnapshot(t, cacheDir, snap)

	expiredFullchain, expiredKeyPEM, expiredAt := testCertificatePEMWithWindow(t, "proxy.example.com", []string{"proxy.example.com"}, time.Now().UTC().Add(-48*time.Hour), time.Now().UTC().Add(-24*time.Hour))
	certSnap := CertificateSnapshot{
		CertVersion: "expired-cert",
		Domains: []DomainCert{{
			Domain:        "proxy.example.com",
			FullchainPEM:  expiredFullchain,
			PrivateKeyPEM: expiredKeyPEM,
			ExpiresAt:     &expiredAt,
		}},
		UpdatedAt: expiredAt,
	}
	if err := writeRawCertificateSnapshot(cacheDir, certSnap); err != nil {
		t.Fatalf("writeRawCertificateSnapshot() error = %v", err)
	}

	conf := &Config{
		CacheDir: cacheDir,
		CertDir:  filepath.Join(dir, "certs"),
	}
	syncer := NewNodeSyncer(conf, applier)
	if err := syncer.LoadCache(context.Background()); err != nil {
		t.Fatalf("LoadCache() error = %v", err)
	}
	if got := applier.Version(); got != "cached-v1" {
		t.Fatalf("config version = %q, want cached-v1", got)
	}
	if syncer.certErr == "" || !strings.Contains(syncer.certErr, "expired") {
		t.Fatalf("certErr = %q, want expired cache error", syncer.certErr)
	}
	if syncer.certVersion != "" || len(syncer.certDomains) != 0 {
		t.Fatalf("invalid cert cache was loaded: version=%q domains=%#v", syncer.certVersion, syncer.certDomains)
	}
	if _, err := os.Stat(filepath.Join(conf.CertDir, "proxy.example.com")); !os.IsNotExist(err) {
		t.Fatalf("expired cert dir should not be written: %v", err)
	}
}

func TestNodeSyncerAppliesChangedCentralVersion(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	centralSnap := testSnapshot("central-v2", nil, []dbRule{{
		Name:    "office",
		Content: "domain=central.example\n",
	}})
	var heartbeatSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			_ = json.NewEncoder(w).Encode(centralSnap)
		case "/api/node/heartbeat":
			heartbeatSeen = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	conf := &Config{
		NodeID:           "node-01",
		CentralURL:       server.URL,
		NodeToken:        "node-secret",
		SyncInterval:     "1h",
		CacheDir:         filepath.Join(dir, "cache"),
		TrafficInterface: "lo",
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.syncOnce(context.Background())

	if got := applier.Version(); got != "central-v2" {
		t.Fatalf("version = %q, want central-v2", got)
	}
	if !heartbeatSeen {
		t.Fatalf("heartbeat was not posted")
	}
	if _, err := os.Stat(filepath.Join(conf.CacheDir, snapshotFileName)); err != nil {
		t.Fatalf("cache snapshot not saved: %v", err)
	}
}

func TestNodeSyncerUsesConditionalConfigRequestForCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	centralSnap := testSnapshot("central-v2", nil, []dbRule{{
		Name:    "office",
		Content: "domain=central.example\n",
	}})
	requests := 0
	heartbeats := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			requests++
			switch requests {
			case 1:
				if got := r.Header.Get("If-None-Match"); got != "" {
					t.Fatalf("first config request If-None-Match = %q, want empty", got)
				}
				w.Header().Set("ETag", versionETag(centralSnap.ConfigVersion))
				_ = json.NewEncoder(w).Encode(centralSnap)
			case 2:
				if got := r.Header.Get("If-None-Match"); got != versionETag(centralSnap.ConfigVersion) {
					t.Fatalf("second config request If-None-Match = %q, want %q", got, versionETag(centralSnap.ConfigVersion))
				}
				w.WriteHeader(http.StatusNotModified)
			default:
				t.Fatalf("unexpected config request %d", requests)
			}
		case "/api/node/certs":
			_ = json.NewEncoder(w).Encode(CertificateSnapshot{})
		case "/api/node/heartbeat":
			heartbeats++
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
		SyncInterval: "1h",
		CacheDir:     filepath.Join(dir, "cache"),
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.syncOnce(context.Background())
	if got := applier.Version(); got != "central-v2" {
		t.Fatalf("version = %q, want central-v2", got)
	}
	snapshotPath := filepath.Join(conf.CacheDir, snapshotFileName)
	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatalf("stat config snapshot: %v", err)
	}
	mtime := info.ModTime()
	time.Sleep(20 * time.Millisecond)

	syncer.syncOnce(context.Background())
	if got := applier.Version(); got != "central-v2" {
		t.Fatalf("version after 304 = %q, want central-v2", got)
	}
	info, err = os.Stat(snapshotPath)
	if err != nil {
		t.Fatalf("stat config snapshot after 304: %v", err)
	}
	if !info.ModTime().Equal(mtime) {
		t.Fatalf("unchanged config snapshot was rewritten: before %s after %s", mtime, info.ModTime())
	}
	if requests != 2 || heartbeats != 2 {
		t.Fatalf("requests=%d heartbeats=%d, want 2/2", requests, heartbeats)
	}
}

func TestNodeSyncerKeepsRunningWhenCentralUnavailable(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	applier.SetVersion("old")
	conf := &Config{
		NodeID:       "node-01",
		CentralURL:   "http://127.0.0.1:1",
		NodeToken:    "node-secret",
		SyncInterval: "1h",
		CacheDir:     filepath.Join(dir, "cache"),
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.client.Timeout = 10 * time.Millisecond
	syncer.syncOnce(context.Background())
	if got := applier.Version(); got != "old" {
		t.Fatalf("version = %q, want old", got)
	}
	if syncer.lastErr == "" {
		t.Fatalf("lastErr was empty after central failure")
	}
}

func TestNodeSyncerDoesNotCacheFailedApply(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	cacheDir := filepath.Join(dir, "cache")
	oldSnap := testSnapshot("cached-v1", nil, []dbRule{{
		Name:    "office",
		Content: "domain=old.example\n",
	}})
	writeTestSnapshot(t, cacheDir, oldSnap)
	if err := applier.Apply(context.Background(), oldSnap); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	badSnap := testSnapshot("central-v2", []dbUser{{
		Username: "bob",
		Password: "secret",
		Rule:     "missing-rule",
	}}, []dbRule{{
		Name:    "office",
		Content: "domain=new.example\n",
	}})
	var heartbeat NodeHeartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			_ = json.NewEncoder(w).Encode(badSnap)
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
		SyncInterval: "1h",
		CacheDir:     cacheDir,
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.syncOnce(context.Background())

	if got := applier.Version(); got != "cached-v1" {
		t.Fatalf("version = %q, want cached-v1", got)
	}
	if heartbeat.ConfigVersion != "cached-v1" || heartbeat.Error == "" {
		t.Fatalf("heartbeat = %#v, want cached version and error", heartbeat)
	}
	loaded, err := syncer.loadSnapshot()
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}
	if loaded.ConfigVersion != "cached-v1" {
		t.Fatalf("cached version = %q, want cached-v1", loaded.ConfigVersion)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Content != "domain=old.example\n" {
		t.Fatalf("cache was overwritten by failed config: %#v", loaded.Rules)
	}
}

func TestNodeSyncerReportsCertSyncErrorSeparately(t *testing.T) {
	dir := t.TempDir()
	_, applier := testConfig(t, dir)
	centralSnap := testSnapshot("central-v2", nil, []dbRule{{
		Name:    "direct",
		Content: "forward=direct://\n",
	}})
	var heartbeat NodeHeartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/node/config":
			_ = json.NewEncoder(w).Encode(centralSnap)
		case "/api/node/certs":
			http.Error(w, "temporary cert outage", http.StatusInternalServerError)
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
		SyncInterval: "1h",
		CacheDir:     filepath.Join(dir, "cache"),
	}
	syncer := NewNodeSyncer(conf, applier)
	syncer.lastErr = "old config error"
	syncer.syncOnce(context.Background())

	if got := applier.Version(); got != "central-v2" {
		t.Fatalf("version = %q, want central-v2", got)
	}
	if heartbeat.ConfigVersion != "central-v2" {
		t.Fatalf("heartbeat config version = %q", heartbeat.ConfigVersion)
	}
	if heartbeat.Error != "" {
		t.Fatalf("heartbeat error = %q, want empty config error", heartbeat.Error)
	}
	if !strings.Contains(heartbeat.CertError, "central certs returned 500") {
		t.Fatalf("heartbeat cert error = %q", heartbeat.CertError)
	}
	if syncer.lastErr != "" {
		t.Fatalf("syncer lastErr = %q, want empty", syncer.lastErr)
	}
	if syncer.certErr == "" {
		t.Fatalf("syncer certErr was empty")
	}
}
