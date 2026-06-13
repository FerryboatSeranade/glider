package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

func TestNormalizeCheckTarget(t *testing.T) {
	tests := map[string]string{
		"example.com:443":                 "example.com:443",
		"https://example.com:8443/health": "example.com:8443",
		"tcp://127.0.0.1:9000":            "127.0.0.1:9000",
	}
	for in, want := range tests {
		if got := normalizeCheckTarget(in); got != want {
			t.Fatalf("normalizeCheckTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunCheckRequiresProxy(t *testing.T) {
	srv := &adminServer{}
	if _, err := srv.runCheck(context.Background(), checkRequest{Target: "example.com:80"}); err == nil {
		t.Fatalf("runCheck succeeded without proxy")
	}
}

func TestRunCheckDefaultRouteSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	strategy := rule.Strategy{Strategy: "rr", Check: "disable", DialTimeout: 3, RelayTimeout: 0}
	sw := proxy.NewSwitcher(rule.NewProxy([]string{"direct://"}, &strategy, nil))
	srv := &adminServer{pxySw: sw}
	resp, err := srv.runCheck(context.Background(), checkRequest{Type: "default", Target: ln.Addr().String(), Timeout: "1s"})
	if err != nil {
		t.Fatalf("runCheck error = %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q, error = %q", resp.Status, resp.Error)
	}
	if resp.Dialer == "" {
		t.Fatalf("dialer was empty")
	}
}

func TestRunCheckIPInfoProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json" {
			t.Fatalf("path = %q, want /json", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9","city":"Test City","region":"Test Region","country":"US","org":"AS64500 Test Net","timezone":"Etc/UTC"}`))
	}))
	defer upstream.Close()

	strategy := rule.Strategy{Strategy: "rr", Check: "disable", DialTimeout: 3, RelayTimeout: 0}
	sw := proxy.NewSwitcher(rule.NewProxy([]string{"direct://"}, &strategy, nil))
	srv := &adminServer{pxySw: sw}
	resp, err := srv.runCheck(context.Background(), checkRequest{Type: "default", Target: upstream.URL + "/json", Timeout: "2s", Probe: "ipinfo"})
	if err != nil {
		t.Fatalf("runCheck error = %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q, error = %q", resp.Status, resp.Error)
	}
	if resp.IPInfo == nil || resp.IPInfo.IP != "203.0.113.9" || resp.IPInfo.Org != "AS64500 Test Net" {
		t.Fatalf("ip info = %#v", resp.IPInfo)
	}
	if resp.HTTPStatus != http.StatusOK {
		t.Fatalf("http status = %d", resp.HTTPStatus)
	}
}

func TestInferRequestPublicIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/node/heartbeat", nil)
	req.RemoteAddr = "10.0.0.2:4321"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9, 8.8.8.8")
	if got := inferRequestPublicIPWithTrust(req, false); got != "" {
		t.Fatalf("untrusted inferred IP = %q, want empty", got)
	}
	if got := inferRequestPublicIPWithTrust(req, true); got != "8.8.8.8" {
		t.Fatalf("trusted inferred IP = %q, want 8.8.8.8", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/node/heartbeat", nil)
	req.RemoteAddr = "1.1.1.1:4321"
	if got := inferRequestPublicIPWithTrust(req, false); got != "1.1.1.1" {
		t.Fatalf("inferred remote IP = %q, want 1.1.1.1", got)
	}
}

func TestParseCIDRListAcceptsCIDRsAndSingleIPs(t *testing.T) {
	prefixes, err := parseCIDRList("192.0.2.0/24, 2001:db8::1")
	if err != nil {
		t.Fatalf("parseCIDRList() error = %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	if !prefixes[0].Contains(netip.MustParseAddr("192.0.2.9")) {
		t.Fatalf("IPv4 CIDR did not contain expected address")
	}
	if !prefixes[1].Contains(netip.MustParseAddr("2001:db8::1")) || prefixes[1].Contains(netip.MustParseAddr("2001:db8::2")) {
		t.Fatalf("single IPv6 address prefix = %#v", prefixes[1])
	}
}

func TestAdminSourceAllowed(t *testing.T) {
	prefixes, err := parseCIDRList("198.51.100.0/24")
	if err != nil {
		t.Fatalf("parseCIDRList() error = %v", err)
	}
	srv := &adminServer{adminNets: prefixes}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:12345"
	if !srv.adminSourceAllowed(req) {
		t.Fatalf("admin source should be allowed")
	}
	req.RemoteAddr = "203.0.113.7:12345"
	if srv.adminSourceAllowed(req) {
		t.Fatalf("admin source should be denied")
	}
}

func TestAdminSourceAllowedTrustsProxyHeadersOnlyWhenEnabled(t *testing.T) {
	prefixes, err := parseCIDRList("198.51.100.0/24")
	if err != nil {
		t.Fatalf("parseCIDRList() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:12345"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")

	if (&adminServer{adminNets: prefixes}).adminSourceAllowed(req) {
		t.Fatalf("untrusted proxy header should not allow admin")
	}
	if !(&adminServer{adminNets: prefixes, trustProxyHeaders: true}).adminSourceAllowed(req) {
		t.Fatalf("trusted proxy header should allow admin")
	}
}

func TestAdminHTMLSmoke(t *testing.T) {
	required := []string{
		"Glider Control Plane",
		"Quick IP Info Check",
		"Connectivity Lab",
		"Rules Health",
		"Nodes",
		"Servers",
		"Config version",
		"Nodes synced",
		"Domain Editor",
		"Cloudflare Settings",
		"normalizeAdminToken",
		"verifyAdminToken",
		"/api/auth/check",
		"Checking token",
		"Token not saved",
		"addEventListener('keydown'",
		"Cloudflare DNS",
		"account token only",
		"token owner",
		"Zone test domain",
		"DNS edit test",
		"cfVerifyDomain",
		"cfDNSEditTest",
		"domainRecordType",
		`<option value="">Auto</option>`,
		"Preview DNS",
		"previewDomainDNS",
		"renderDNSPlan",
		"/dns-plan",
		"Preview Cert",
		"previewDomainCert",
		"renderCertPlan",
		"/cert-plan",
		"Issue Cert",
		"Import Cert",
		"/import-cert",
		"/api/domains",
		"/api/config/status",
		"/api/settings/cloudflare",
		"/api/settings/cloudflare/verify",
		"/api/nodes/",
		"/api/servers",
		"/api/jobs",
		"/api/events",
		"Server Provisioning",
		"testServerSSH",
		"preflightServerNode",
		"onboardServerNode",
		"deployServerNode",
		"restartServerNode",
		"upgradeServerNode",
		"/onboard-node",
		"/preflight-node",
		"/restart-node",
		"/upgrade-node",
		"Wait heartbeat seconds",
		"nodeSearch",
		"Provisioning Jobs",
		"jobStepsSummary",
		"steps:",
		"step.status",
		"Recent Events",
		"renderEvents",
		"pollJob",
		"runCheckFromForm",
		"runRulesHealth",
		"loadLatestRulesHealth",
		"/api/rules/health?latest=1",
		"saveCloudflareSettings",
		"verifyCloudflareToken",
		"deleteNode",
		"setNodeToken",
		"clearNodeToken",
		"/token",
		"dedicated",
		"last auth",
		"node cert sync",
		"domainCertSyncStatus",
		"domainFailoverStatus",
		"failover ready nodes",
		"failover_blocked_reason",
		"Fail threshold",
		"Cooldown seconds",
		"Manual lock active node",
		"Primary node",
		"primary_node_id",
		"failover_policy",
		"certRenewStatus",
		"cert_renew_status",
		"cert_sync_status",
		"cert days remaining",
		"cert renewal",
		"/api/check",
		"/api/nodes",
		"/api/rules/health",
		"https://ipinfo.io/json",
		"User Editor",
		"Rule Editor",
	}
	for _, needle := range required {
		if !strings.Contains(adminHTML, needle) {
			t.Fatalf("adminHTML missing %q", needle)
		}
	}
}

func TestAdminHTMLScriptSyntax(t *testing.T) {
	start := strings.Index(adminHTML, "<script>")
	end := strings.Index(adminHTML, "</script>")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("adminHTML script block not found")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available for admin HTML script syntax check")
	}
	script := adminHTML[start+len("<script>") : end]
	path := t.TempDir() + "/admin.js"
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "--check", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("admin HTML script syntax invalid: %v\n%s", err, out)
	}
}

func TestDomainRuntimeIncludesCertificateStatus(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(60 * 24 * time.Hour)
	cert := DomainCert{
		Domain:        "proxy.example.com",
		FullchainPEM:  "fullchain",
		PrivateKeyPEM: "private-key",
		ExpiresAt:     &exp,
	}
	version := certificateVersion(cert)
	d := dbDomain{
		Domain:          "proxy.example.com",
		Enabled:         true,
		NodeIDs:         []string{"node-a", "node-b"},
		RenewBeforeDays: 30,
		Certificate: domainCertificate{
			Version:       version,
			FullchainPEM:  cert.FullchainPEM,
			PrivateKeyPEM: cert.PrivateKeyPEM,
			ExpiresAt:     cert.ExpiresAt,
		},
	}
	nodes := map[string]NodeHeartbeat{
		"node-a": {
			NodeID:    "node-a",
			PublicIP:  "203.0.113.10",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    cert.Domain,
				Version:   version,
				ExpiresAt: cert.ExpiresAt,
			}},
		},
	}
	runtime := domainRuntime(d, nodes, now)
	if runtime.CertStatus != "cert issued" {
		t.Fatalf("cert status = %q", runtime.CertStatus)
	}
	if runtime.CertRenewStatus != "valid" || runtime.CertRenewInDays != 30 || runtime.CertDaysRemaining != 60 {
		t.Fatalf("renew runtime = %#v", runtime)
	}
	if runtime.CertSyncStatus != "cert synced 1/2" || runtime.CertSyncedNodes != 1 || runtime.CertAssignedNodes != 2 {
		t.Fatalf("sync runtime = %#v", runtime)
	}
	if runtime.FailoverStatus != "failover disabled" || runtime.FailoverReadyNodes != 1 {
		t.Fatalf("failover runtime = %#v", runtime)
	}
	if len(runtime.AssignedNodeStatus) != 2 {
		t.Fatalf("assigned node status = %#v", runtime.AssignedNodeStatus)
	}
	if !runtime.AssignedNodeStatus[0].CertSynced || runtime.AssignedNodeStatus[1].CertSynced {
		t.Fatalf("node sync status = %#v", runtime.AssignedNodeStatus)
	}
	if !runtime.AssignedNodeStatus[0].FailoverReady || runtime.AssignedNodeStatus[1].FailoverReady {
		t.Fatalf("node failover readiness = %#v", runtime.AssignedNodeStatus)
	}
}

func TestDomainRuntimeReportsFailoverReadiness(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	d := dbDomain{
		Domain:          "proxy.example.com",
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "active",
		NodeIDs:         []string{"active", "missing-cert", "ready"},
		Certificate: domainCertificate{
			Version: "cert-v1",
		},
	}
	nodes := map[string]NodeHeartbeat{
		"active": {
			NodeID:    "active",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-v1",
				ExpiresAt: &exp,
			}},
		},
		"missing-cert": {
			NodeID:    "missing-cert",
			UpdatedAt: now,
		},
		"ready": {
			NodeID:    "ready",
			UpdatedAt: now,
			CertDomains: []NodeCertState{{
				Domain:    "proxy.example.com",
				Version:   "cert-v1",
				ExpiresAt: &exp,
			}},
		},
	}
	runtime := domainRuntime(d, nodes, now)
	if runtime.FailoverStatus != "failover ready 1/3" || runtime.FailoverReadyNodes != 1 || runtime.FailoverBlockedReason != "" {
		t.Fatalf("failover runtime = %#v", runtime)
	}
	if !runtime.AssignedNodeStatus[0].FailoverReady || runtime.AssignedNodeStatus[1].FailoverReady || !runtime.AssignedNodeStatus[2].FailoverReady {
		t.Fatalf("node failover readiness = %#v", runtime.AssignedNodeStatus)
	}

	nodes["ready"] = NodeHeartbeat{NodeID: "ready", UpdatedAt: now}
	runtime = domainRuntime(d, nodes, now)
	if runtime.FailoverStatus != "failover blocked" || runtime.FailoverReadyNodes != 0 {
		t.Fatalf("blocked failover runtime = %#v", runtime)
	}
	if runtime.FailoverBlockedReason != "no assigned healthy node has the current certificate version" {
		t.Fatalf("blocked reason = %q", runtime.FailoverBlockedReason)
	}
}

func TestNodeProxyErrorBlocksFailoverUntilStale(t *testing.T) {
	now := time.Now().UTC()
	checked := now.Add(-time.Minute)
	d := dbDomain{
		Domain:          "proxy.example.com",
		Enabled:         true,
		FailoverEnabled: true,
		ActiveNodeID:    "active",
		NodeIDs:         []string{"active", "standby"},
		FailoverPolicy: domainFailoverPolicy{
			FailThreshold:   1,
			CooldownSeconds: 300,
		},
	}
	nodes := map[string]NodeHeartbeat{
		"active": {
			NodeID:         "active",
			UpdatedAt:      now,
			ProxyStatus:    "error",
			ProxyCheckedAt: &checked,
			ProxyError:     "connect refused",
		},
		"standby": {
			NodeID:    "standby",
			UpdatedAt: now,
		},
	}
	decision := evaluateDomainFailover(d, nodes, now)
	if !decision.ShouldSwitch || decision.Target.NodeID != "standby" {
		t.Fatalf("proxy error should trigger failover decision: %#v", decision)
	}
	if decision.Reason != "active node unhealthy" || decision.State.LastReason != "active node unhealthy" {
		t.Fatalf("unexpected failover reason: %#v", decision)
	}
	if got := activeFailureReason("active", nodes["active"]); got != "active node proxy error: connect refused" {
		t.Fatalf("activeFailureReason = %q", got)
	}

	oldCheck := now.Add(-4 * time.Minute)
	nodes["active"] = NodeHeartbeat{
		NodeID:         "active",
		UpdatedAt:      now,
		ProxyStatus:    "error",
		ProxyCheckedAt: &oldCheck,
		ProxyError:     "old failure",
	}
	decision = evaluateDomainFailover(d, nodes, now)
	if decision.ShouldSwitch {
		t.Fatalf("stale proxy error should not trigger failover: %#v", decision)
	}
}

func TestNodeProxyProbeHelpers(t *testing.T) {
	enabled := true
	disabled := false
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	user, ok := firstProbeUser([]dbUser{
		{Username: "disabled", Password: "pass", Enabled: &disabled},
		{Username: "expired", Password: "pass", Enabled: &enabled, ExpiresAt: &expired},
		{Username: "missing-pass", Enabled: &enabled},
		{Username: "usable", Password: "pass", Enabled: &enabled, ExpiresAt: &future},
	}, now)
	if !ok || user.Username != "usable" {
		t.Fatalf("firstProbeUser = %#v ok=%v", user, ok)
	}
	if got := nodeProxyProbePort(dbServer{ProxyPorts: []string{"443:443", "18080:8443"}}); got != "18080" {
		t.Fatalf("nodeProxyProbePort = %q", got)
	}
	if got := containerPortFromMapping("[::1]:9443:8443/tcp"); got != "8443" {
		t.Fatalf("containerPortFromMapping = %q", got)
	}
}

func TestHashNodeToken(t *testing.T) {
	a := hashNodeToken(" node-secret ")
	b := hashNodeToken("node-secret")
	if a == "" || a != b {
		t.Fatalf("hashNodeToken did not trim consistently: %q %q", a, b)
	}
	if a == "node-secret" {
		t.Fatalf("hashNodeToken returned the plaintext token")
	}
	if constantTimeEqual(a, hashNodeToken("other-secret")) {
		t.Fatalf("different token hashes matched")
	}
}

func TestCertSnapshotNotModifiedMatchesETag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/node/certs", nil)
	req.Header.Set("If-None-Match", `"cert-v1", "other"`)
	if !certSnapshotNotModified(req, "cert-v1") {
		t.Fatalf("expected matching If-None-Match to be treated as not modified")
	}
	if got := certSnapshotETag("cert-v1"); got != `"cert-v1"` || got != versionETag("cert-v1") {
		t.Fatalf("etag = %q", got)
	}

	req.Header.Set("If-None-Match", `"other"`)
	if certSnapshotNotModified(req, "cert-v1") {
		t.Fatalf("different If-None-Match should not match")
	}
	req.Header.Set("If-None-Match", `"config-v1"`)
	if !versionNotModified(req, "config-v1") {
		t.Fatalf("expected config version ETag to match")
	}
}

func TestAuthorizeNodeSharedToken(t *testing.T) {
	srv := &adminServer{nodeToken: "shared-secret"}
	mode, ok := srv.authorizeNodeToken(context.Background(), "node-01", " shared-secret ")
	if !ok || mode != nodeAuthModeShared {
		t.Fatalf("authorizeNodeToken mode=%q ok=%v, want shared true", mode, ok)
	}
	if mode, ok := srv.authorizeNodeToken(context.Background(), "node-01", "wrong"); ok || mode != "" {
		t.Fatalf("wrong token authorized mode=%q ok=%v", mode, ok)
	}
}
