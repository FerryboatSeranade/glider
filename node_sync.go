package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nadoo/glider/pkg/log"
)

const snapshotFileName = "config_snapshot.json"

type NodeSyncer struct {
	conf    *Config
	applier *ConfigApplier
	client  *http.Client
	started time.Time
	lastErr string
	certErr string

	certVersion string
	certDomains []NodeCertState
}

func NewNodeSyncer(conf *Config, applier *ConfigApplier) *NodeSyncer {
	return &NodeSyncer{
		conf:    conf,
		applier: applier,
		client:  &http.Client{Timeout: 10 * time.Second},
		started: time.Now(),
	}
}

func (s *NodeSyncer) LoadCache(ctx context.Context) error {
	snap, err := s.loadSnapshot()
	if err != nil {
		return err
	}
	if err := s.applier.Apply(ctx, snap); err != nil {
		return err
	}
	log.Printf("[node] loaded cached config version %s", snap.ConfigVersion)
	if certSnap, err := loadCertificateSnapshot(s.conf.CacheDir); err == nil {
		if err := writeCertificateFiles(s.conf.CertDir, certSnap.Domains); err != nil {
			s.certErr = err.Error()
			log.Printf("[node] cached cert unavailable: %v", err)
			return nil
		}
		s.certVersion = certSnap.CertVersion
		s.certDomains = nodeCertStates(certSnap.Domains)
		s.certErr = ""
		log.Printf("[node] loaded cached cert version %s", certSnap.CertVersion)
	}
	return nil
}

func (s *NodeSyncer) Start(ctx context.Context) {
	interval, err := time.ParseDuration(s.conf.SyncInterval)
	if err != nil || interval <= 0 {
		interval = 30 * time.Second
	}
	go s.loop(ctx, interval)
}

func (s *NodeSyncer) loop(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.syncOnce(ctx)
			timer.Reset(interval)
		}
	}
}

func (s *NodeSyncer) syncOnce(ctx context.Context) {
	if err := s.validate(); err != nil {
		s.lastErr = err.Error()
		log.Printf("[node] sync disabled: %v", err)
		return
	}

	snap, err := s.fetchConfig(ctx)
	if err != nil {
		s.lastErr = err.Error()
		log.Printf("[node] config sync failed: %v", err)
		_ = s.postHeartbeat(ctx)
		return
	}

	if snap.ConfigVersion != "" && snap.ConfigVersion == s.applier.Version() {
		s.lastErr = ""
		if err := s.syncCerts(ctx); err != nil {
			s.certErr = err.Error()
			log.Printf("[node] cert sync failed: %v", err)
		} else {
			s.certErr = ""
			s.lastErr = ""
		}
		_ = s.postHeartbeat(ctx)
		return
	}

	if err := s.applier.Apply(ctx, snap); err != nil {
		s.lastErr = err.Error()
		log.Printf("[node] apply config failed: %v", err)
		_ = s.postHeartbeat(ctx)
		return
	}
	if err := s.saveSnapshot(snap); err != nil {
		s.lastErr = err.Error()
		log.Printf("[node] save config cache failed: %v", err)
		_ = s.postHeartbeat(ctx)
		return
	}
	s.lastErr = ""
	if err := s.syncCerts(ctx); err != nil {
		s.certErr = err.Error()
		log.Printf("[node] cert sync failed: %v", err)
		_ = s.postHeartbeat(ctx)
		return
	}
	s.certErr = ""
	s.lastErr = ""
	log.Printf("[node] applied config version %s", snap.ConfigVersion)
	_ = s.postHeartbeat(ctx)
}

func (s *NodeSyncer) validate() error {
	if strings.TrimSpace(s.conf.NodeID) == "" {
		return fmt.Errorf("node-id is empty")
	}
	if strings.TrimSpace(s.conf.CentralURL) == "" {
		return fmt.Errorf("central-url is empty")
	}
	if strings.TrimSpace(s.conf.NodeToken) == "" {
		return fmt.Errorf("node-token is empty")
	}
	return nil
}

func (s *NodeSyncer) fetchConfig(ctx context.Context) (ConfigSnapshot, error) {
	base, err := url.Parse(strings.TrimRight(s.conf.CentralURL, "/"))
	if err != nil {
		return ConfigSnapshot{}, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/node/config"
	q := base.Query()
	q.Set("node_id", s.conf.NodeID)
	base.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.conf.NodeToken)
	req.Header.Set("Accept", "application/json")
	currentVersion := s.applier.Version()
	if etag := versionETag(currentVersion); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return ConfigSnapshot{ConfigVersion: currentVersion, UpdatedAt: time.Now().UTC()}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return ConfigSnapshot{}, fmt.Errorf("central config returned %s", resp.Status)
	}
	var snap ConfigSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (s *NodeSyncer) syncCerts(ctx context.Context) error {
	snap, err := s.fetchCerts(ctx, localCertificateSnapshotComplete(s.conf.CacheDir, s.conf.CertDir, s.certVersion))
	if err != nil {
		return err
	}
	if snap.CertVersion == s.certVersion && certificateSnapshotComplete(s.conf.CacheDir, s.conf.CertDir, snap) {
		return nil
	}
	if err := writeCertificateSnapshot(s.conf.CacheDir, s.conf.CertDir, snap); err != nil {
		return err
	}
	s.certVersion = snap.CertVersion
	s.certDomains = nodeCertStates(snap.Domains)
	if snap.CertVersion != "" {
		log.Printf("[node] applied cert version %s", snap.CertVersion)
	}
	return nil
}

func certificateSnapshotComplete(cacheDir, certDir string, snap CertificateSnapshot) bool {
	if strings.TrimSpace(cacheDir) == "" {
		return false
	}
	cached, err := loadCertificateSnapshot(cacheDir)
	if err != nil {
		return false
	}
	if cached.CertVersion != snap.CertVersion || len(cached.Domains) != len(snap.Domains) {
		return false
	}
	if certDir == "" {
		certDir = defaultCertCacheDir
	}
	for i, cert := range snap.Domains {
		cachedDomain := strings.TrimSpace(strings.TrimSuffix(cached.Domains[i].Domain, "."))
		domain := strings.TrimSpace(strings.TrimSuffix(cert.Domain, "."))
		if !strings.EqualFold(cachedDomain, domain) {
			return false
		}
		normalized, err := normalizeDomainName(domain)
		if err != nil {
			return false
		}
		fullchain, err := os.ReadFile(filepath.Join(certDir, normalized, "fullchain.pem"))
		if err != nil || string(fullchain) != cert.FullchainPEM {
			return false
		}
		privkey, err := os.ReadFile(filepath.Join(certDir, normalized, "privkey.pem"))
		if err != nil || string(privkey) != cert.PrivateKeyPEM {
			return false
		}
	}
	return true
}

func localCertificateSnapshotComplete(cacheDir, certDir, version string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	cached, err := loadCertificateSnapshot(cacheDir)
	if err != nil || cached.CertVersion != version {
		return false
	}
	return certificateSnapshotComplete(cacheDir, certDir, cached)
}

func nodeCertStates(certs []DomainCert) []NodeCertState {
	states := make([]NodeCertState, 0, len(certs))
	for _, cert := range certs {
		domain := strings.TrimSpace(strings.TrimSuffix(cert.Domain, "."))
		if domain == "" {
			continue
		}
		states = append(states, NodeCertState{
			Domain:    strings.ToLower(domain),
			Version:   certificateVersion(cert),
			ExpiresAt: cert.ExpiresAt,
		})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Domain < states[j].Domain })
	return states
}

func (s *NodeSyncer) fetchCerts(ctx context.Context, conditional bool) (CertificateSnapshot, error) {
	base, err := url.Parse(strings.TrimRight(s.conf.CentralURL, "/"))
	if err != nil {
		return CertificateSnapshot{}, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/node/certs"
	q := base.Query()
	q.Set("node_id", s.conf.NodeID)
	base.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return CertificateSnapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.conf.NodeToken)
	req.Header.Set("Accept", "application/json")
	if conditional {
		if etag := certSnapshotETag(s.certVersion); etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return CertificateSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return loadCertificateSnapshot(s.conf.CacheDir)
	}
	if resp.StatusCode == http.StatusNotFound {
		return CertificateSnapshot{CertVersion: s.certVersion}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return CertificateSnapshot{}, fmt.Errorf("central certs returned %s", resp.Status)
	}
	var snap CertificateSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return CertificateSnapshot{}, err
	}
	return snap, nil
}

func (s *NodeSyncer) postHeartbeat(ctx context.Context) error {
	if strings.TrimSpace(s.conf.CentralURL) == "" || strings.TrimSpace(s.conf.NodeToken) == "" || strings.TrimSpace(s.conf.NodeID) == "" {
		return nil
	}
	base, err := url.Parse(strings.TrimRight(s.conf.CentralURL, "/") + "/api/node/heartbeat")
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	rx, tx := readInterfaceTraffic(s.conf.TrafficInterface)
	h := NodeHeartbeat{
		NodeID:        s.conf.NodeID,
		Hostname:      host,
		PublicIP:      s.conf.PublicIP,
		GliderVersion: version,
		ConfigVersion: s.applier.Version(),
		CertVersion:   s.certVersion,
		CertDomains:   s.certDomains,
		CertError:     s.certErr,
		Uptime:        int64(time.Since(s.started).Seconds()),
		RXBytes:       rx,
		TXBytes:       tx,
		Traffic:       proxyTrafficSnapshot(),
		Error:         s.lastErr,
	}
	buf := bytes.Buffer{}
	if err := json.NewEncoder(&buf).Encode(h); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.conf.NodeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("central heartbeat returned %s", resp.Status)
	}
	return nil
}

func (s *NodeSyncer) loadSnapshot() (ConfigSnapshot, error) {
	f, err := os.Open(filepath.Join(s.conf.CacheDir, snapshotFileName))
	if err != nil {
		return ConfigSnapshot{}, err
	}
	defer f.Close()
	var snap ConfigSnapshot
	if err := json.NewDecoder(f).Decode(&snap); err != nil {
		return ConfigSnapshot{}, err
	}
	return snap, nil
}

func (s *NodeSyncer) saveSnapshot(snap ConfigSnapshot) error {
	if err := os.MkdirAll(s.conf.CacheDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.conf.CacheDir, snapshotFileName)
	tmp, err := os.CreateTemp(s.conf.CacheDir, "."+snapshotFileName+".tmp-*")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
