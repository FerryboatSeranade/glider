package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

const (
	mongoURLEnv                   = "GLIDER_MONGO_URI"
	mongoDBEnv                    = "GLIDER_MONGO_DB"
	adminTokenEnv                 = "GLIDER_ADMIN_TOKEN"
	adminAllowedCIDRsEnv          = "GLIDER_ADMIN_ALLOWED_CIDRS"
	adminTrustProxyHeadersEnv     = "GLIDER_ADMIN_TRUST_PROXY_HEADERS"
	nodeTokenEnv                  = "GLIDER_NODE_TOKEN"
	acmeEmailEnv                  = "GLIDER_ACME_EMAIL"
	acmeDirectoryURLEnv           = "GLIDER_ACME_DIRECTORY_URL"
	cloudflareAccountIDEnv        = "GLIDER_CLOUDFLARE_ACCOUNT_ID"
	domainReconcileIntervalEnv    = "GLIDER_DOMAIN_RECONCILE_INTERVAL"
	certificateRenewIntervalEnv   = "GLIDER_CERT_RENEW_INTERVAL"
	rulesHealthIntervalEnv        = "GLIDER_RULES_HEALTH_INTERVAL"
	rulesHealthTargetEnv          = "GLIDER_RULES_HEALTH_TARGET"
	rulesHealthTimeoutEnv         = "GLIDER_RULES_HEALTH_TIMEOUT"
	nodeProxyHealthIntervalEnv    = "GLIDER_NODE_PROXY_HEALTH_INTERVAL"
	nodeProxyHealthTargetEnv      = "GLIDER_NODE_PROXY_HEALTH_TARGET"
	nodeProxyHealthTimeoutEnv     = "GLIDER_NODE_PROXY_HEALTH_TIMEOUT"
	defaultDomainReconcilePeriod  = 60 * time.Second
	defaultCertRenewPeriod        = 12 * time.Hour
	defaultRulesHealthPeriod      = 5 * time.Minute
	defaultRulesHealthTarget      = "https://ipinfo.io/json"
	defaultRulesHealthTimeout     = "8s"
	defaultNodeProxyHealthPeriod  = 60 * time.Second
	defaultNodeProxyHealthTarget  = "https://ipinfo.io/json"
	defaultNodeProxyHealthTimeout = "8s"
	nodeAuthModeShared            = "shared"
	nodeAuthModeDedicated         = "dedicated"
)

type adminServer struct {
	addr              string
	store             *mongoStore
	rulesDir          string
	conf              *Config
	pxySw             *proxy.Switcher
	applier           *ConfigApplier
	token             string
	nodeToken         string
	adminNets         []netip.Prefix
	trustProxyHeaders bool

	reloadMu   sync.Mutex
	lastReload time.Time
	healthMu   sync.Mutex
}

func startAdminServer(conf *Config, pxySw *proxy.Switcher, applier *ConfigApplier) {
	if conf.Admin == "" {
		return
	}

	uri := strings.TrimSpace(os.Getenv(mongoURLEnv))
	if uri == "" {
		log.Printf("[admin] %s not set, admin disabled", mongoURLEnv)
		return
	}
	dbName := strings.TrimSpace(os.Getenv(mongoDBEnv))
	if dbName == "" {
		dbName = "glider"
	}
	token := strings.TrimSpace(os.Getenv(adminTokenEnv))
	if token == "" {
		log.Printf("[admin] %s not set, admin auth disabled", adminTokenEnv)
	}
	nodeToken := strings.TrimSpace(os.Getenv(nodeTokenEnv))
	if nodeToken == "" {
		nodeToken = strings.TrimSpace(conf.NodeToken)
	}
	if nodeToken == "" {
		log.Printf("[admin] %s not set, node config API disabled", nodeTokenEnv)
	}
	adminNets, err := parseCIDRList(os.Getenv(adminAllowedCIDRsEnv))
	if err != nil {
		log.Printf("[admin] invalid %s: %v", adminAllowedCIDRsEnv, err)
		return
	}
	trustProxyHeaders := parseBool(os.Getenv(adminTrustProxyHeadersEnv))

	if pxySw != nil && conf.RulesDir == "" {
		log.Printf("[admin] rules-dir is empty, admin disabled")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := newMongoStore(ctx, uri, dbName)
	if err != nil {
		log.Printf("[admin] mongo connect error: %v", err)
		return
	}

	srv := &adminServer{
		addr:              conf.Admin,
		store:             store,
		rulesDir:          conf.RulesDir,
		conf:              conf,
		pxySw:             pxySw,
		applier:           applier,
		token:             token,
		nodeToken:         nodeToken,
		adminNets:         adminNets,
		trustProxyHeaders: trustProxyHeaders,
	}
	if srv.applier != nil {
		ctxInit, cancelInit := withTimeout(context.Background())
		defer cancelInit()
		if err := srv.reload(ctxInit); err != nil {
			log.Printf("[admin] initial reload failed: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/users", srv.handleUsers)
	mux.HandleFunc("/api/users/", srv.handleUser)
	mux.HandleFunc("/api/rules", srv.handleRules)
	mux.HandleFunc("/api/rules/", srv.handleRule)
	mux.HandleFunc("/api/reload", srv.handleReload)
	mux.HandleFunc("/api/auth/check", srv.handleAuthCheck)
	mux.HandleFunc("/api/config/status", srv.handleConfigStatus)
	mux.HandleFunc("/api/check", srv.handleCheck)
	mux.HandleFunc("/api/rules/health", srv.handleRulesHealth)
	mux.HandleFunc("/api/nodes", srv.handleNodes)
	mux.HandleFunc("/api/nodes/", srv.handleNodeAction)
	mux.HandleFunc("/api/servers", srv.handleServers)
	mux.HandleFunc("/api/servers/", srv.handleServerAction)
	mux.HandleFunc("/api/jobs", srv.handleJobs)
	mux.HandleFunc("/api/jobs/", srv.handleJobAction)
	mux.HandleFunc("/api/events", srv.handleEvents)
	mux.HandleFunc("/api/domains", srv.handleDomains)
	mux.HandleFunc("/api/domains/", srv.handleDomainAction)
	mux.HandleFunc("/api/settings/cloudflare", srv.handleCloudflareSettings)
	mux.HandleFunc("/api/settings/cloudflare/verify", srv.handleCloudflareVerify)
	mux.HandleFunc("/api/node/config", srv.handleNodeConfig)
	mux.HandleFunc("/api/node/certs", srv.handleNodeCerts)
	mux.HandleFunc("/api/node/heartbeat", srv.handleNodeHeartbeat)

	server := &http.Server{
		Addr:              srv.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("[admin] listening on %s", srv.addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[admin] server error: %v", err)
		}
	}()

	srv.startAdminWorkers(context.Background())
}

func (s *adminServer) requireToken(w http.ResponseWriter, r *http.Request) bool {
	if !s.adminSourceAllowed(r) {
		writeError(w, http.StatusForbidden, fmt.Errorf("forbidden"))
		return false
	}
	if s.token == "" {
		return true
	}
	token := tokenFromRequest(r)
	if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
	return false
}

func (s *adminServer) adminSourceAllowed(r *http.Request) bool {
	if len(s.adminNets) == 0 {
		return true
	}
	ip, ok := requestIP(r, s.trustProxyHeaders)
	if !ok {
		return false
	}
	for _, prefix := range s.adminNets {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *adminServer) requireNodeToken(w http.ResponseWriter, r *http.Request, nodeID string) bool {
	_, ok := s.authorizeNodeToken(r.Context(), strings.TrimSpace(nodeID), tokenFromRequest(r))
	if ok {
		return true
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
	return false
}

func (s *adminServer) authorizeNodeToken(ctx context.Context, nodeID, token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	if nodeID != "" && s.store != nil {
		cctx, cancel := withTimeout(ctx)
		defer cancel()
		node, err := s.store.GetNode(cctx, nodeID)
		if err == nil && strings.TrimSpace(node.TokenHash) != "" {
			if constantTimeEqual(node.TokenHash, hashNodeToken(token)) {
				return nodeAuthModeDedicated, true
			}
			return "", false
		}
	}
	if s.nodeToken == "" {
		return "", false
	}
	if constantTimeEqual(token, s.nodeToken) {
		return nodeAuthModeShared, true
	}
	return "", false
}

func hashNodeToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func tokenFromRequest(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if token := strings.TrimSpace(r.Header.Get("X-Admin-Token")); token != "" {
		return token
	}
	return ""
}

func (s *adminServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(adminHTML))
}

func (s *adminServer) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"now":    time.Now().UTC(),
	})
}

func (s *adminServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		users, err := s.store.Users(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var payload dbUser
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if payload.Username == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("username required"))
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertUser(ctx, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	username, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/users/"))
	if err != nil || username == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid username"))
		return
	}

	switch r.Method {
	case http.MethodPut:
		var payload dbUser
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		payload.Username = username
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertUser(ctx, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteUser(ctx, username); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		rules, err := s.store.Rules(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, rules)
	case http.MethodPost:
		var payload dbRule
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := validateRuleName(payload.Name); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertRule(ctx, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if s.applier != nil && s.rulesDir != "" {
			if err := writeRuleFile(s.rulesDir, payload); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleNodeConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("node_id required"))
		return
	}
	if !s.requireNodeToken(w, r, nodeID) {
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	snap, err := LoadSnapshotFromStore(ctx, s.store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if etag := versionETag(snap.ConfigVersion); etag != "" {
		w.Header().Set("ETag", etag)
		if versionNotModified(r, snap.ConfigVersion) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *adminServer) handleConfigStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	snap, err := LoadSnapshotFromStore(ctx, s.store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config_version": snap.ConfigVersion,
		"updated_at":     snap.UpdatedAt,
		"users_count":    len(snap.Users),
		"rules_count":    len(snap.Rules),
	})
}

func (s *adminServer) handleNodeCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("node_id required"))
		return
	}
	if !s.requireNodeToken(w, r, nodeID) {
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	snap, err := LoadCertificateSnapshotFromStore(ctx, s.store, nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	etag := certSnapshotETag(snap.CertVersion)
	if etag != "" {
		w.Header().Set("ETag", etag)
		if certSnapshotNotModified(r, snap.CertVersion) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *adminServer) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var payload NodeHeartbeat
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(payload.NodeID) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("node_id required"))
		return
	}
	payload.NodeID = strings.TrimSpace(payload.NodeID)
	authMode, ok := s.authorizeNodeToken(r.Context(), payload.NodeID, tokenFromRequest(r))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}
	payload.AuthMode = authMode
	if strings.TrimSpace(payload.PublicIP) == "" {
		payload.PublicIP = inferRequestPublicIPWithTrust(r, s.trustProxyHeaders)
	}
	payload.UpdatedAt = time.Now().UTC()
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	if err := s.store.UpsertNodeHeartbeat(ctx, payload); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func inferRequestPublicIP(r *http.Request) string {
	return inferRequestPublicIPWithTrust(r, parseBool(os.Getenv(adminTrustProxyHeadersEnv)))
}

func inferRequestPublicIPWithTrust(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
			for _, value := range strings.Split(r.Header.Get(header), ",") {
				if ip := publicIPString(value); ip != "" {
					return ip
				}
			}
		}
	}
	ip, ok := requestIP(r, false)
	if !ok {
		return ""
	}
	return publicIPString(ip.String())
}

func requestIP(r *http.Request, trustProxyHeaders bool) (netip.Addr, bool) {
	if trustProxyHeaders {
		if ip, ok := requestProxyHeaderIP(r); ok {
			return ip, true
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr, true
}

func requestProxyHeaderIP(r *http.Request) (netip.Addr, bool) {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		for _, value := range strings.Split(r.Header.Get(header), ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			if err == nil {
				if addr.Is4In6() {
					addr = addr.Unmap()
				}
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

func publicIPString(value string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return ""
	}
	for _, prefix := range nonPublicIPPrefixes {
		if prefix.Contains(addr) {
			return ""
		}
	}
	return addr.String()
}

func parseCIDRList(value string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]netip.Prefix, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if strings.Contains(field, "/") {
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", field, err)
			}
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", field, err)
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out, nil
}

var nonPublicIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func (s *adminServer) handleDomains(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		domains, err := s.store.Domains(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		nodes, err := s.store.Nodes(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		nodeMap := nodeMapByID(nodes)
		out := make([]domainResponse, 0, len(domains))
		now := time.Now().UTC()
		for _, d := range domains {
			out = append(out, newDomainResponse(d, nodeMap, now))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"domains": out,
			"now":     now,
		})
	case http.MethodPost:
		var payload dbDomain
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertDomain(ctx, payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type cloudflareSettingsResponse struct {
	Configured       bool      `json:"configured"`
	Source           string    `json:"source,omitempty"`
	MaskedToken      string    `json:"masked_token,omitempty"`
	AccountID        string    `json:"account_id,omitempty"`
	ACMEEmail        string    `json:"acme_email,omitempty"`
	ACMEDirectoryURL string    `json:"acme_directory_url,omitempty"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

func (s *adminServer) handleCloudflareSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := s.effectiveCloudflareSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, cloudflareSettingsToResponse(settings))
	case http.MethodPost:
		var payload struct {
			APIToken         *string `json:"api_token"`
			ClearToken       bool    `json:"clear_token"`
			AccountID        string  `json:"account_id"`
			ACMEEmail        string  `json:"acme_email"`
			ACMEDirectoryURL string  `json:"acme_directory_url"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		settings := cloudflareSettings{
			AccountID:        payload.AccountID,
			ACMEEmail:        payload.ACMEEmail,
			ACMEDirectoryURL: payload.ACMEDirectoryURL,
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpdateCloudflareSettings(ctx, settings, payload.APIToken, payload.ClearToken); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		updated, err := s.effectiveCloudflareSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, cloudflareSettingsToResponse(updated))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func cloudflareSettingsToResponse(settings cloudflareSettings) cloudflareSettingsResponse {
	source := settings.Source
	token := strings.TrimSpace(settings.APIToken)
	if token == "" {
		source = ""
	} else if source == "" {
		source = "database"
	}
	return cloudflareSettingsResponse{
		Configured:       token != "",
		Source:           source,
		MaskedToken:      maskSecret(token),
		AccountID:        settings.AccountID,
		ACMEEmail:        settings.ACMEEmail,
		ACMEDirectoryURL: settings.ACMEDirectoryURL,
		UpdatedAt:        settings.UpdatedAt,
	}
}

type cloudflareVerifyResponse struct {
	Status    string               `json:"status,omitempty"`
	ID        string               `json:"id,omitempty"`
	Scope     string               `json:"scope,omitempty"`
	NotBefore *time.Time           `json:"not_before,omitempty"`
	ExpiresOn *time.Time           `json:"expires_on,omitempty"`
	Zone      *cloudflareZoneCheck `json:"zone,omitempty"`
}

func (s *adminServer) handleCloudflareVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	var payload struct {
		Domain      string `json:"domain"`
		DNSEditTest bool   `json:"dns_edit_test"`
	}
	if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, err := s.effectiveCloudflareSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	cf, err := newCloudflareClient(settings.APIToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := cf.verifyToken(ctx, settings.AccountID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var zoneCheck *cloudflareZoneCheck
	if strings.TrimSpace(payload.Domain) != "" {
		check, err := cf.checkZone(ctx, payload.Domain, payload.DNSEditTest)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		zoneCheck = &check
	}
	scope := "user"
	if strings.TrimSpace(settings.AccountID) != "" {
		scope = "account"
	}
	writeJSON(w, http.StatusOK, cloudflareVerifyResponse{
		Status:    result.Status,
		ID:        result.ID,
		Scope:     scope,
		NotBefore: result.NotBefore,
		ExpiresOn: result.ExpiresOn,
		Zone:      zoneCheck,
	})
}

func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", 8) + secret[len(secret)-4:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (s *adminServer) effectiveCloudflareSettings(ctx context.Context) (cloudflareSettings, error) {
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	settings, err := s.store.CloudflareSettings(cctx)
	if err != nil {
		return cloudflareSettings{}, err
	}
	if strings.TrimSpace(settings.APIToken) != "" {
		settings.Source = "database"
	} else if envToken := strings.TrimSpace(os.Getenv(cloudflareAPITokenEnv)); envToken != "" {
		settings.APIToken = envToken
		settings.Source = "env"
	}
	if strings.TrimSpace(settings.ACMEEmail) == "" {
		settings.ACMEEmail = strings.TrimSpace(os.Getenv(acmeEmailEnv))
	}
	if strings.TrimSpace(settings.ACMEDirectoryURL) == "" {
		settings.ACMEDirectoryURL = strings.TrimSpace(os.Getenv(acmeDirectoryURLEnv))
	}
	if strings.TrimSpace(settings.AccountID) == "" {
		settings.AccountID = strings.TrimSpace(os.Getenv(cloudflareAccountIDEnv))
	}
	return settings, nil
}

func (s *adminServer) handleDomainAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("domain required"))
		return
	}
	domain, err := url.PathUnescape(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid domain"))
		return
	}
	domain, err = normalizeDomainName(domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		d, err := s.store.GetDomain(ctx, domain)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		nodes, err := s.store.Nodes(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, newDomainResponse(*d, nodeMapByID(nodes), time.Now().UTC()))
	case action == "" && r.Method == http.MethodPut:
		var payload dbDomain
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		payload.Domain = domain
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertDomain(ctx, payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case action == "" && r.Method == http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteDomain(ctx, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case action == "sync-dns" && r.Method == http.MethodPost:
		s.handleDomainSyncDNS(w, r, domain)
	case action == "dns-plan" && r.Method == http.MethodPost:
		s.handleDomainDNSPlan(w, r, domain)
	case action == "issue-cert" && r.Method == http.MethodPost:
		s.handleDomainIssueCert(w, r, domain)
	case action == "cert-plan" && r.Method == http.MethodPost:
		s.handleDomainCertPlan(w, r, domain)
	case action == "import-cert" && r.Method == http.MethodPost:
		s.handleDomainImportCert(w, r, domain)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func redactDomainSecrets(domains []dbDomain) []dbDomain {
	out := make([]dbDomain, len(domains))
	for i, d := range domains {
		out[i] = redactDomainSecret(d)
	}
	return out
}

func redactDomainSecret(d dbDomain) dbDomain {
	d.Certificate.FullchainPEM = ""
	d.Certificate.PrivateKeyPEM = ""
	return d
}

type domainResponse struct {
	Domain          string                 `json:"domain"`
	Enabled         bool                   `json:"enabled"`
	NodeIDs         []string               `json:"node_ids,omitempty"`
	ActiveNodeID    string                 `json:"active_node_id,omitempty"`
	FailoverEnabled bool                   `json:"failover_enabled,omitempty"`
	FailoverPolicy  domainFailoverPolicy   `json:"failover_policy,omitempty"`
	FailoverState   domainFailoverState    `json:"failover_state,omitempty"`
	RenewBeforeDays int                    `json:"renew_before_days,omitempty"`
	DNSProvider     string                 `json:"dns_provider,omitempty"`
	Cloudflare      cloudflareDomainConfig `json:"cloudflare,omitempty"`
	Certificate     domainCertificate      `json:"certificate,omitempty"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Runtime         domainRuntimeStatus    `json:"runtime"`
}

type domainRuntimeStatus struct {
	Status                string               `json:"status"`
	DNSStatus             string               `json:"dns_status"`
	CertStatus            string               `json:"cert_status"`
	CertRenewStatus       string               `json:"cert_renew_status"`
	CertDaysRemaining     int                  `json:"cert_days_remaining"`
	CertRenewInDays       int                  `json:"cert_renew_in_days"`
	CertSyncStatus        string               `json:"cert_sync_status"`
	CertSyncedNodes       int                  `json:"cert_synced_nodes"`
	CertAssignedNodes     int                  `json:"cert_assigned_nodes"`
	FailoverStatus        string               `json:"failover_status"`
	FailoverFailures      int                  `json:"failover_failures"`
	FailoverThreshold     int                  `json:"failover_threshold"`
	FailoverCooldownUntil *time.Time           `json:"failover_cooldown_until,omitempty"`
	FailoverReadyNodes    int                  `json:"failover_ready_nodes"`
	FailoverBlockedReason string               `json:"failover_blocked_reason,omitempty"`
	AssignedNodeStatus    []domainNodeCertSync `json:"assigned_node_status,omitempty"`
}

type domainNodeCertSync struct {
	NodeID         string     `json:"node_id"`
	Online         bool       `json:"online"`
	PublicIP       string     `json:"public_ip,omitempty"`
	ProxyStatus    string     `json:"proxy_status,omitempty"`
	ProxyCheckedAt *time.Time `json:"proxy_checked_at,omitempty"`
	ProxyExitIP    string     `json:"proxy_exit_ip,omitempty"`
	ProxyOrg       string     `json:"proxy_org,omitempty"`
	ProxyError     string     `json:"proxy_error,omitempty"`
	CertSynced     bool       `json:"cert_synced"`
	FailoverReady  bool       `json:"failover_ready"`
	CertVersion    string     `json:"cert_version,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	Error          string     `json:"error,omitempty"`
	CertError      string     `json:"cert_error,omitempty"`
}

func newDomainResponse(d dbDomain, nodes map[string]NodeHeartbeat, now time.Time) domainResponse {
	redacted := redactDomainSecret(d)
	return domainResponse{
		Domain:          redacted.Domain,
		Enabled:         redacted.Enabled,
		NodeIDs:         redacted.NodeIDs,
		ActiveNodeID:    redacted.ActiveNodeID,
		FailoverEnabled: redacted.FailoverEnabled,
		FailoverPolicy:  failoverPolicyWithDefaultsForDomain(redacted),
		FailoverState:   redacted.FailoverState,
		RenewBeforeDays: redacted.RenewBeforeDays,
		DNSProvider:     redacted.DNSProvider,
		Cloudflare:      redacted.Cloudflare,
		Certificate:     redacted.Certificate,
		UpdatedAt:       redacted.UpdatedAt,
		Runtime:         domainRuntime(d, nodes, now),
	}
}

func domainRuntime(d dbDomain, nodes map[string]NodeHeartbeat, now time.Time) domainRuntimeStatus {
	certSynced := 0
	failoverReady := 0
	nodeStates := make([]domainNodeCertSync, 0, len(d.NodeIDs))
	for _, nodeID := range d.NodeIDs {
		node := nodes[nodeID]
		state := domainNodeCertState(d, nodeID, node, now)
		if state.CertSynced {
			certSynced++
		}
		if state.FailoverReady && nodeID != d.ActiveNodeID {
			failoverReady++
		}
		nodeStates = append(nodeStates, state)
	}
	return domainRuntimeStatus{
		Status:                domainRuntimeStatusValue(d),
		DNSStatus:             domainDNSStatus(d),
		CertStatus:            domainCertificateStatus(d, now),
		CertRenewStatus:       certificateRenewStatus(d, now),
		CertDaysRemaining:     certificateDaysRemaining(d, now),
		CertRenewInDays:       certificateRenewInDays(d, now),
		CertSyncStatus:        domainCertSyncStatusValue(d, certSynced),
		CertSyncedNodes:       certSynced,
		CertAssignedNodes:     len(d.NodeIDs),
		FailoverStatus:        domainFailoverStatusValue(d, failoverReady),
		FailoverFailures:      d.FailoverState.ActiveFailureCount,
		FailoverThreshold:     failoverPolicyWithDefaultsForDomain(d).FailThreshold,
		FailoverCooldownUntil: d.FailoverState.CooldownUntil,
		FailoverReadyNodes:    failoverReady,
		FailoverBlockedReason: domainFailoverBlockedReason(d, failoverReady),
		AssignedNodeStatus:    nodeStates,
	}
}

func domainRuntimeStatusValue(d dbDomain) string {
	if !d.Enabled {
		return "disabled"
	}
	if strings.TrimSpace(d.Certificate.LastError) != "" || strings.TrimSpace(d.Cloudflare.LastError) != "" {
		return "error"
	}
	return "active"
}

func domainDNSStatus(d dbDomain) string {
	if strings.TrimSpace(d.Cloudflare.LastError) != "" {
		return "dns error"
	}
	if d.Cloudflare.LastSyncedAt != nil {
		return "dns synced"
	}
	return "dns pending"
}

func domainCertificateStatus(d dbDomain, now time.Time) string {
	if strings.TrimSpace(d.Certificate.LastError) != "" {
		return "cert error"
	}
	if strings.TrimSpace(d.Certificate.Version) == "" {
		return "cert missing"
	}
	if d.Certificate.ExpiresAt != nil && !d.Certificate.ExpiresAt.After(now) {
		return "cert expired"
	}
	return "cert issued"
}

func domainCertSyncStatusValue(d dbDomain, synced int) string {
	if len(d.NodeIDs) == 0 {
		return "cert nodes none"
	}
	if strings.TrimSpace(d.Certificate.Version) == "" {
		return "cert not issued"
	}
	return fmt.Sprintf("cert synced %d/%d", synced, len(d.NodeIDs))
}

func domainFailoverStatusValue(d dbDomain, ready int) string {
	if !d.Enabled {
		return "failover disabled"
	}
	if !d.FailoverEnabled {
		return "failover disabled"
	}
	policy := failoverPolicyWithDefaultsForDomain(d)
	if policy.ManualLock {
		return "failover locked"
	}
	if d.FailoverState.CooldownUntil != nil && d.FailoverState.CooldownUntil.After(time.Now().UTC()) {
		return "failover cooling down"
	}
	if len(d.NodeIDs) < 2 {
		return "failover needs nodes"
	}
	if ready == 0 {
		return "failover blocked"
	}
	return fmt.Sprintf("failover ready %d/%d", ready, len(d.NodeIDs))
}

func domainFailoverBlockedReason(d dbDomain, ready int) string {
	if !d.Enabled || !d.FailoverEnabled || len(d.NodeIDs) < 2 || ready > 0 {
		return ""
	}
	if strings.TrimSpace(d.Certificate.Version) != "" {
		return "no assigned healthy node has the current certificate version"
	}
	return "no assigned healthy node is online"
}

func domainNodeCertState(d dbDomain, nodeID string, node NodeHeartbeat, now time.Time) domainNodeCertSync {
	state := domainNodeCertSync{
		NodeID:         nodeID,
		Online:         isNodeHealthy(node),
		PublicIP:       node.PublicIP,
		ProxyStatus:    node.ProxyStatus,
		ProxyCheckedAt: node.ProxyCheckedAt,
		ProxyExitIP:    node.ProxyExitIP,
		ProxyOrg:       node.ProxyOrg,
		ProxyError:     node.ProxyError,
		Error:          node.Error,
		CertError:      node.CertError,
	}
	if state.NodeID == "" {
		state.NodeID = node.NodeID
	}
	if !node.UpdatedAt.IsZero() {
		seen := node.UpdatedAt
		state.LastSeenAt = &seen
	}
	targetDomain := strings.TrimSuffix(strings.ToLower(d.Domain), ".")
	targetVersion := strings.TrimSpace(d.Certificate.Version)
	for _, cert := range node.CertDomains {
		certDomain := strings.TrimSuffix(strings.ToLower(cert.Domain), ".")
		if certDomain != targetDomain {
			continue
		}
		state.CertVersion = cert.Version
		state.ExpiresAt = cert.ExpiresAt
		state.CertSynced = targetVersion != "" && cert.Version == targetVersion && nodeCertStateValidAt(cert, now)
		break
	}
	state.FailoverReady = state.Online && nodeReadyForDomainAt(node, d, now)
	return state
}

func nodeMapByID(nodes []NodeHeartbeat) map[string]NodeHeartbeat {
	out := make(map[string]NodeHeartbeat, len(nodes))
	for _, node := range nodes {
		out[node.NodeID] = node
	}
	return out
}

func (s *adminServer) handleDomainSyncDNS(w http.ResponseWriter, r *http.Request, domain string) {
	var payload struct {
		NodeID string `json:"node_id"`
	}
	if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := s.store.GetDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	nodeID := strings.TrimSpace(payload.NodeID)
	if nodeID == "" {
		nodeID = d.ActiveNodeID
	}
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("active node required"))
		return
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := validateDomainDNSTarget(*d, *node, time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, err := s.effectiveCloudflareSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	cf, err := newCloudflareClient(settings.APIToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan, err := planCloudflareDNSWithClient(ctx, *d, *node, cf, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfConfig, err := syncCloudflareDNSWithToken(ctx, *d, *node, settings.APIToken)
	if updateErr := s.store.UpdateDomainCloudflare(context.Background(), domain, cfConfig); updateErr != nil && err == nil {
		err = updateErr
	}
	if err == nil && nodeID != d.ActiveNodeID {
		now := time.Now().UTC()
		state := d.FailoverState
		state.ActiveFailureCount = 0
		state.LastError = ""
		state.LastReason = "manual dns sync"
		state.LastFromNodeID = d.ActiveNodeID
		state.LastToNodeID = nodeID
		state.LastSwitchAt = &now
		state.CooldownUntil = nil
		if updateErr := s.store.SwitchDomainActiveNode(context.Background(), domain, nodeID, state); updateErr != nil {
			err = updateErr
		}
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordEvent(dbEvent{
		Type:    "domain.dns_synced",
		Message: "domain DNS synced",
		Domain:  domain,
		NodeID:  nodeID,
		Metadata: map[string]any{
			"from_node_id": d.ActiveNodeID,
			"to_node_id":   nodeID,
			"record_name":  cfConfig.RecordName,
			"record_type":  cfConfig.RecordType,
			"target":       node.PublicIP,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"cloudflare":  cfConfig,
		"active_node": nodeID,
		"plan":        plan,
	})
}

func (s *adminServer) handleDomainDNSPlan(w http.ResponseWriter, r *http.Request, domain string) {
	var payload struct {
		NodeID string `json:"node_id"`
	}
	if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := s.store.GetDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	nodeID := strings.TrimSpace(payload.NodeID)
	if nodeID == "" {
		nodeID = d.ActiveNodeID
	}
	plan, err := s.domainDNSPlan(ctx, *d, nodeID, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"plan":   plan,
	})
}

func (s *adminServer) domainDNSPlan(ctx context.Context, d dbDomain, nodeID string, lookupExisting bool) (cloudflareDNSPlan, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return cloudflareDNSPlan{}, fmt.Errorf("active node required")
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return cloudflareDNSPlan{}, err
	}
	if err := validateDomainDNSTarget(d, *node, time.Now().UTC()); err != nil {
		return cloudflareDNSPlan{}, err
	}
	settings, err := s.effectiveCloudflareSettings(ctx)
	if err != nil {
		return cloudflareDNSPlan{}, err
	}
	cf, err := newCloudflareClient(settings.APIToken)
	if err != nil {
		return cloudflareDNSPlan{}, err
	}
	return planCloudflareDNSWithClient(ctx, d, *node, cf, lookupExisting)
}

func validateDomainDNSTarget(d dbDomain, node NodeHeartbeat, now time.Time) error {
	if !d.Enabled {
		return fmt.Errorf("domain %s is disabled", d.Domain)
	}
	if !domainAssignedToNode(d, node.NodeID) {
		return fmt.Errorf("node %s is not assigned to domain %s", node.NodeID, d.Domain)
	}
	if !nodeHealthyAt(node, now) {
		if node.NodeID == "" {
			return fmt.Errorf("node heartbeat is missing")
		}
		if node.Error != "" {
			return fmt.Errorf("node %s is unhealthy: %s", node.NodeID, node.Error)
		}
		return fmt.Errorf("node %s heartbeat is stale", node.NodeID)
	}
	if publicIPString(node.PublicIP) == "" {
		return fmt.Errorf("node %s public_ip is not a public IP address", node.NodeID)
	}
	if !nodeReadyForDomain(node, d) {
		return fmt.Errorf("node %s has not synced certificate for %s", node.NodeID, d.Domain)
	}
	return nil
}

type certificatePlan struct {
	Domain            string     `json:"domain,omitempty"`
	ZoneID            string     `json:"zone_id,omitempty"`
	ZoneName          string     `json:"zone_name,omitempty"`
	Email             string     `json:"email,omitempty"`
	DirectoryURL      string     `json:"directory_url,omitempty"`
	CurrentVersion    string     `json:"current_version,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	DaysRemaining     int        `json:"days_remaining"`
	RenewBeforeDays   int        `json:"renew_before_days"`
	RenewInDays       int        `json:"renew_in_days"`
	RenewStatus       string     `json:"renew_status"`
	Action            string     `json:"action"`
	ChallengeRecord   string     `json:"challenge_record,omitempty"`
	NodeIDs           []string   `json:"node_ids,omitempty"`
	AssignedNodeCount int        `json:"assigned_node_count"`
}

func (s *adminServer) handleDomainCertPlan(w http.ResponseWriter, r *http.Request, domain string) {
	var payload struct {
		Email        string `json:"email"`
		DirectoryURL string `json:"directory_url"`
	}
	if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := s.store.GetDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	plan, err := s.domainCertificatePlan(ctx, *d, payload.Email, payload.DirectoryURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"plan":   plan,
	})
}

func (s *adminServer) domainCertificatePlan(ctx context.Context, d dbDomain, email, directoryURL string) (certificatePlan, error) {
	settings, err := s.effectiveCloudflareSettings(ctx)
	if err != nil {
		return certificatePlan{}, err
	}
	return certificatePlanWithSettings(ctx, d, email, directoryURL, settings)
}

func certificatePlanWithSettings(ctx context.Context, d dbDomain, email, directoryURL string, settings cloudflareSettings) (certificatePlan, error) {
	email = firstNonEmpty(email, settings.ACMEEmail)
	if strings.TrimSpace(email) == "" {
		return certificatePlan{}, fmt.Errorf("ACME email required")
	}
	directoryURL = firstNonEmpty(directoryURL, settings.ACMEDirectoryURL, defaultACMEDirectoryURL)
	cf, err := newCloudflareClient(settings.APIToken)
	if err != nil {
		return certificatePlan{}, err
	}
	zoneID := strings.TrimSpace(d.Cloudflare.ZoneID)
	zoneName := strings.TrimSpace(d.Cloudflare.ZoneName)
	if zoneID == "" || zoneName == "" {
		zone, err := cf.findZone(ctx, d.Domain)
		if err != nil {
			return certificatePlan{}, err
		}
		if zoneID == "" {
			zoneID = zone.ID
		}
		if zoneName == "" {
			zoneName = zone.Name
		}
	}
	now := time.Now().UTC()
	return buildCertificatePlan(d, email, directoryURL, zoneID, zoneName, now)
}

func buildCertificatePlan(d dbDomain, email, directoryURL, zoneID, zoneName string, now time.Time) (certificatePlan, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	challengeRecord, err := dns01RecordName(d.Domain)
	if err != nil {
		return certificatePlan{}, err
	}
	renewStatus := certificateRenewStatus(d, now)
	action := "issue"
	if strings.TrimSpace(d.Certificate.Version) != "" {
		action = "renew"
		if renewStatus == "valid" {
			action = "not_due"
		}
	}
	return certificatePlan{
		Domain:            d.Domain,
		ZoneID:            zoneID,
		ZoneName:          zoneName,
		Email:             email,
		DirectoryURL:      directoryURL,
		CurrentVersion:    d.Certificate.Version,
		ExpiresAt:         d.Certificate.ExpiresAt,
		DaysRemaining:     certificateDaysRemaining(d, now),
		RenewBeforeDays:   renewBeforeDays(d),
		RenewInDays:       certificateRenewInDays(d, now),
		RenewStatus:       renewStatus,
		Action:            action,
		ChallengeRecord:   challengeRecord,
		NodeIDs:           append([]string(nil), d.NodeIDs...),
		AssignedNodeCount: len(d.NodeIDs),
	}, nil
}

func (s *adminServer) handleDomainIssueCert(w http.ResponseWriter, r *http.Request, domain string) {
	var payload struct {
		Email        string `json:"email"`
		DirectoryURL string `json:"directory_url"`
	}
	if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	d, err := s.store.GetDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	settings, err := s.effectiveCloudflareSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	email := firstNonEmpty(payload.Email, settings.ACMEEmail)
	directoryURL := firstNonEmpty(payload.DirectoryURL, settings.ACMEDirectoryURL)
	plan, planErr := s.domainCertificatePlan(ctx, *d, email, directoryURL)
	if planErr != nil {
		writeError(w, http.StatusBadRequest, planErr)
		return
	}
	cert, err := issueCertificateWithCloudflareTokenZone(ctx, *d, email, directoryURL, settings.APIToken, plan.ZoneID)
	if err != nil {
		failed := certificateFailure(d.Certificate, err)
		_ = s.store.UpdateDomainCertificate(context.Background(), domain, failed)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpdateDomainCertificate(context.Background(), domain, cert); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"cert_version": cert.Version,
		"expires_at":   cert.ExpiresAt,
		"plan":         plan,
	})
}

func (s *adminServer) handleDomainImportCert(w http.ResponseWriter, r *http.Request, domain string) {
	var payload struct {
		FullchainPEM  string `json:"fullchain_pem"`
		PrivateKeyPEM string `json:"private_key_pem"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	d, err := s.store.GetDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	cert, err := importedDomainCertificate(d.Domain, payload.FullchainPEM, payload.PrivateKeyPEM)
	if err != nil {
		failed := certificateFailure(d.Certificate, err)
		_ = s.store.UpdateDomainCertificate(context.Background(), domain, failed)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpdateDomainCertificate(context.Background(), domain, cert); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"cert_version": cert.Version,
		"expires_at":   cert.ExpiresAt,
	})
}

func (s *adminServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	nodes, err := s.store.Nodes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
		"now":   time.Now().UTC(),
	})
}

func (s *adminServer) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid node id"))
		return
	}
	nodeID, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(nodeID) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid node id"))
		return
	}
	nodeID = strings.TrimSpace(nodeID)
	if len(parts) == 2 && parts[1] == "token" {
		s.handleNodeTokenAction(w, r, nodeID)
		return
	}
	if len(parts) != 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteNode(ctx, nodeID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleNodeTokenAction(w http.ResponseWriter, r *http.Request, nodeID string) {
	switch r.Method {
	case http.MethodPut:
		var payload struct {
			Token string `json:"token"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		token := strings.TrimSpace(payload.Token)
		if token == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("token required"))
			return
		}
		if len(token) < 16 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("node token must be at least 16 characters"))
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.SetNodeTokenHash(ctx, nodeID, hashNodeToken(token)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "node_id": nodeID, "has_token": true})
	case http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.ClearNodeTokenHash(ctx, nodeID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "node_id": nodeID, "has_token": false})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleServers(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		servers, err := s.store.Servers(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"servers": servers,
			"now":     time.Now().UTC(),
		})
	case http.MethodPost:
		var payload serverUpsertPayload
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		server, secrets := serverFromPayload(payload)
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertServer(ctx, server, secrets); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.saved",
			Message:  "server saved",
			ServerID: server.ServerID,
			NodeID:   firstNonEmpty(server.NodeID, server.ServerID),
			Metadata: map[string]any{"host": server.Host, "ssh_user": server.SSHUser},
		})
		saved, err := s.store.GetServer(ctx, server.ServerID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, redactServerSecrets(*saved))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleServerAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/servers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("server id required"))
		return
	}
	serverID, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(serverID) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid server id"))
		return
	}
	serverID = strings.TrimSpace(serverID)
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		server, err := s.store.GetServer(ctx, serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, redactServerSecrets(*server))
	case action == "" && r.Method == http.MethodPut:
		var payload serverUpsertPayload
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		payload.ServerID = serverID
		server, secrets := serverFromPayload(payload)
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertServer(ctx, server, secrets); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.saved",
			Message:  "server saved",
			ServerID: serverID,
			NodeID:   firstNonEmpty(server.NodeID, server.ServerID),
			Metadata: map[string]any{"host": server.Host, "ssh_user": server.SSHUser},
		})
		saved, err := s.store.GetServer(ctx, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, redactServerSecrets(*saved))
	case action == "" && r.Method == http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteServer(ctx, serverID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.deleted",
			Severity: "warn",
			Message:  "server deleted",
			ServerID: serverID,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case action == "test-ssh" && r.Method == http.MethodPost:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		job, err := s.createSSHTestJob(ctx, serverID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.ssh_test_queued",
			Message:  "ssh test queued",
			ServerID: serverID,
			JobID:    job.JobID,
		})
		writeJSON(w, http.StatusAccepted, job)
	case action == "preflight-node" && r.Method == http.MethodPost:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		job, err := s.createPreflightNodeJob(ctx, serverID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.preflight_queued",
			Message:  "node preflight queued",
			ServerID: serverID,
			NodeID:   job.NodeID,
			JobID:    job.JobID,
			Metadata: map[string]any{"deploy_dir": job.Request.DeployDir, "image": job.Request.Image},
		})
		writeJSON(w, http.StatusAccepted, job)
	case action == "deploy-node" && r.Method == http.MethodPost:
		var payload deployNodePayload
		if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		job, err := s.createDeployNodeJob(ctx, serverID, payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.deploy_queued",
			Message:  "node deploy queued",
			ServerID: serverID,
			NodeID:   job.NodeID,
			JobID:    job.JobID,
			Metadata: map[string]any{"image": job.Request.Image, "deploy_dir": job.Request.DeployDir},
		})
		writeJSON(w, http.StatusAccepted, job)
	case action == "onboard-node" && r.Method == http.MethodPost:
		var payload deployNodePayload
		if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if payload.CentralURL == "" {
			payload.CentralURL = defaultCentralURL(r)
		}
		job, err := s.createOnboardNodeJob(ctx, serverID, payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.onboard_queued",
			Message:  "node onboarding queued",
			ServerID: serverID,
			NodeID:   job.NodeID,
			JobID:    job.JobID,
			Metadata: map[string]any{"image": job.Request.Image, "deploy_dir": job.Request.DeployDir, "central_url": job.Request.CentralURL},
		})
		writeJSON(w, http.StatusAccepted, job)
	case action == "restart-node" && r.Method == http.MethodPost:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		job, err := s.createNodeOperationJob(ctx, serverID, jobTypeRestartNode, nodeOperationPayload{})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.restart_queued",
			Message:  "node restart queued",
			ServerID: serverID,
			NodeID:   job.NodeID,
			JobID:    job.JobID,
		})
		writeJSON(w, http.StatusAccepted, job)
	case action == "upgrade-node" && r.Method == http.MethodPost:
		var payload nodeOperationPayload
		if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		job, err := s.createNodeOperationJob(ctx, serverID, jobTypeUpgradeNode, payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.recordEvent(dbEvent{
			Type:     "server.upgrade_queued",
			Message:  "node upgrade queued",
			ServerID: serverID,
			NodeID:   job.NodeID,
			JobID:    job.JobID,
			Metadata: map[string]any{"image": job.Request.Image},
		})
		writeJSON(w, http.StatusAccepted, job)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	jobs, err := s.store.Jobs(ctx, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs": jobs,
		"now":  time.Now().UTC(),
	})
}

func (s *adminServer) handleJobAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	jobID, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/jobs/"))
	if err != nil || strings.TrimSpace(jobID) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid job id"))
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	job, err := s.store.GetJob(ctx, strings.TrimSpace(jobID))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *adminServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	events, err := s.store.Events(ctx, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"now":    time.Now().UTC(),
	})
}

func (s *adminServer) recordEvent(event dbEvent) {
	if s == nil || s.store == nil {
		return
	}
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = newID("evt")
	}
	if strings.TrimSpace(event.Actor) == "" {
		event.Actor = "admin"
	}
	if err := s.store.SaveEvent(context.Background(), event); err != nil {
		log.Printf("[admin] save event %s failed: %v", event.Type, err)
	}
}

func (s *adminServer) handleRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	name, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/rules/"))
	if err != nil || name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid rule name"))
		return
	}
	if err := validateRuleName(name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	switch r.Method {
	case http.MethodGet:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		ruleDoc, err := s.store.GetRule(ctx, name)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, ruleDoc)
	case http.MethodPut:
		var payload dbRule
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		payload.Name = name
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.UpsertRule(ctx, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if s.applier != nil && s.rulesDir != "" {
			if err := writeRuleFile(s.rulesDir, payload); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteRule(ctx, name); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if s.applier != nil && s.rulesDir != "" {
			_ = os.Remove(filepath.Join(s.rulesDir, name+".rule"))
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *adminServer) startAdminWorkers(ctx context.Context) {
	reconcileInterval := envDuration(domainReconcileIntervalEnv, defaultDomainReconcilePeriod)
	certInterval := envDuration(certificateRenewIntervalEnv, defaultCertRenewPeriod)
	rulesHealthInterval := envDuration(rulesHealthIntervalEnv, defaultRulesHealthPeriod)
	nodeProxyHealthInterval := envDuration(nodeProxyHealthIntervalEnv, defaultNodeProxyHealthPeriod)
	if reconcileInterval > 0 {
		go s.domainReconcileLoop(ctx, reconcileInterval)
	}
	if certInterval > 0 {
		go s.certificateRenewLoop(ctx, certInterval)
	}
	if rulesHealthInterval > 0 {
		go s.rulesHealthLoop(ctx, rulesHealthInterval)
	}
	if nodeProxyHealthInterval > 0 {
		go s.nodeProxyHealthLoop(ctx, nodeProxyHealthInterval)
	}
}

func (s *adminServer) domainReconcileLoop(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := s.reconcileDomainFailover(ctx); err != nil {
				log.Printf("[admin] domain failover reconcile failed: %v", err)
			}
			timer.Reset(interval)
		}
	}
}

func (s *adminServer) rulesHealthLoop(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			target := firstNonEmpty(os.Getenv(rulesHealthTargetEnv), defaultRulesHealthTarget)
			timeoutValue := firstNonEmpty(os.Getenv(rulesHealthTimeoutEnv), defaultRulesHealthTimeout)
			if _, err := s.checkAndSaveRulesHealth(ctx, target, timeoutValue); err != nil {
				log.Printf("[admin] rules health check failed: %v", err)
			}
			timer.Reset(interval)
		}
	}
}

func (s *adminServer) nodeProxyHealthLoop(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			target := firstNonEmpty(os.Getenv(nodeProxyHealthTargetEnv), defaultNodeProxyHealthTarget)
			timeoutValue := firstNonEmpty(os.Getenv(nodeProxyHealthTimeoutEnv), defaultNodeProxyHealthTimeout)
			if err := s.checkAndSaveNodeProxyHealth(ctx, target, timeoutValue); err != nil {
				log.Printf("[admin] node proxy health check failed: %v", err)
			}
			timer.Reset(interval)
		}
	}
}

type NodeProxyProbe struct {
	Status     string    `json:"status"`
	CheckedAt  time.Time `json:"checked_at"`
	ExitIP     string    `json:"exit_ip,omitempty"`
	Org        string    `json:"org,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Error      string    `json:"error,omitempty"`
}

func (s *adminServer) checkAndSaveNodeProxyHealth(ctx context.Context, target, timeoutValue string) error {
	storeCtx, cancelStore := withTimeout(ctx)
	defer cancelStore()
	nodes, err := s.store.Nodes(storeCtx)
	if err != nil {
		return err
	}
	users, err := s.store.Users(storeCtx)
	if err != nil {
		return err
	}
	servers, err := s.store.Servers(storeCtx)
	if err != nil {
		return err
	}
	user, ok := firstProbeUser(users, time.Now().UTC())
	if !ok {
		return fmt.Errorf("no enabled user is available for node proxy health checks")
	}
	serverByNode := make(map[string]dbServer, len(servers))
	for _, server := range servers {
		if strings.TrimSpace(server.NodeID) != "" {
			serverByNode[server.NodeID] = server
		}
	}
	for _, node := range nodes {
		if !nodeHeartbeatFresh(node, time.Now().UTC()) || publicIPString(node.PublicIP) == "" {
			continue
		}
		server := serverByNode[node.NodeID]
		probe := probeNodeProxy(ctx, node, server, user, target, timeoutValue)
		saveCtx, cancelSave := withTimeout(context.Background())
		if err := s.store.UpdateNodeProxyProbe(saveCtx, node.NodeID, probe); err != nil {
			cancelSave()
			return err
		}
		cancelSave()
	}
	return nil
}

func firstProbeUser(users []dbUser, now time.Time) (dbUser, bool) {
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	for _, user := range users {
		if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
			continue
		}
		if user.Enabled != nil && !*user.Enabled {
			continue
		}
		if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
			continue
		}
		return user, true
	}
	return dbUser{}, false
}

func probeNodeProxy(ctx context.Context, node NodeHeartbeat, server dbServer, user dbUser, target, timeoutValue string) NodeProxyProbe {
	target = firstNonEmpty(target, os.Getenv(nodeProxyHealthTargetEnv), defaultNodeProxyHealthTarget)
	timeout := 8 * time.Second
	if parsed, err := time.ParseDuration(firstNonEmpty(timeoutValue, os.Getenv(nodeProxyHealthTimeoutEnv), defaultNodeProxyHealthTimeout)); err == nil && parsed > 0 {
		timeout = parsed
	}
	checkedAt := time.Now().UTC()
	result := NodeProxyProbe{
		Status:    "error",
		CheckedAt: checkedAt,
	}
	if !looksLikeHTTPURL(target) {
		target = "https://" + target
	}
	parsedTarget, err := url.Parse(target)
	if err != nil || parsedTarget.Scheme == "" || parsedTarget.Host == "" {
		result.Error = fmt.Sprintf("invalid probe url %q", target)
		return result
	}
	host := publicIPString(node.PublicIP)
	if host == "" {
		result.Error = "node public_ip is not public"
		return result
	}
	proxyURL := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, nodeProxyProbePort(server)),
		User:   url.UserPassword(user.Username, user.Password),
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(&proxyURL),
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          1,
		IdleConnTimeout:       timeout,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, parsedTarget.String(), nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "glider-node-proxy-health/"+version)
	start := time.Now()
	resp, err := client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = resp.Status
		return result
	}
	var info ipInfoPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Status = "ok"
	result.ExitIP = info.IP
	result.Org = info.Org
	result.Error = ""
	return result
}

func nodeProxyProbePort(server dbServer) string {
	for _, mapping := range server.ProxyPorts {
		containerPort := containerPortFromMapping(mapping)
		if containerPort == "8443" || containerPort == "" && strings.TrimSpace(mapping) == "8443" {
			if hostPort := hostPortFromMapping(mapping); hostPort != "" {
				return hostPort
			}
		}
	}
	for _, mapping := range server.ProxyPorts {
		if hostPort := hostPortFromMapping(mapping); hostPort != "" && hostPort != "443" {
			return hostPort
		}
	}
	return "8443"
}

func containerPortFromMapping(mapping string) string {
	mapping = strings.TrimSpace(strings.Trim(mapping, `"'`))
	if mapping == "" {
		return ""
	}
	if strings.Contains(mapping, "/") {
		mapping = strings.SplitN(mapping, "/", 2)[0]
	}
	parts := strings.Split(mapping, ":")
	if len(parts) == 0 {
		return ""
	}
	candidate := strings.Trim(parts[len(parts)-1], "[] ")
	if _, err := strconv.Atoi(candidate); err == nil {
		return candidate
	}
	return ""
}

func (s *adminServer) certificateRenewLoop(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := s.renewDueCertificates(ctx); err != nil {
				log.Printf("[admin] certificate renew reconcile failed: %v", err)
			}
			timer.Reset(interval)
		}
	}
}

func (s *adminServer) reconcileDomainFailover(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	settings, err := s.effectiveCloudflareSettings(cctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(settings.APIToken) == "" {
		return nil
	}
	domains, err := s.store.Domains(cctx)
	if err != nil {
		return err
	}
	nodes, err := s.store.Nodes(cctx)
	if err != nil {
		return err
	}
	nodeMap := make(map[string]NodeHeartbeat, len(nodes))
	for _, node := range nodes {
		nodeMap[node.NodeID] = node
	}
	for _, d := range domains {
		if !d.Enabled || !d.FailoverEnabled || len(d.NodeIDs) == 0 {
			continue
		}
		decision := evaluateDomainFailover(d, nodeMap, time.Now().UTC())
		if decision.StateChanged {
			if err := s.store.UpdateDomainFailoverState(context.Background(), d.Domain, decision.State); err != nil {
				log.Printf("[admin] save failover state for %s failed: %v", d.Domain, err)
			}
		}
		next, ok := decision.Target, decision.ShouldSwitch
		if !ok {
			continue
		}
		d.ActiveNodeID = next.NodeID
		cfConfig, err := syncCloudflareDNSWithToken(cctx, d, next, settings.APIToken)
		if updateErr := s.store.UpdateDomainCloudflare(context.Background(), d.Domain, cfConfig); updateErr != nil && err == nil {
			err = updateErr
		}
		if err == nil {
			err = s.store.SwitchDomainActiveNode(context.Background(), d.Domain, next.NodeID, decision.State)
		}
		if err != nil {
			log.Printf("[admin] failover %s to %s failed: %v", d.Domain, next.NodeID, err)
			s.recordEvent(dbEvent{
				Type:     "domain.failover_failed",
				Severity: "error",
				Message:  "domain failover failed",
				Domain:   d.Domain,
				NodeID:   next.NodeID,
				Metadata: map[string]any{"error": err.Error(), "from_node_id": decision.State.LastFromNodeID, "to_node_id": next.NodeID},
			})
			continue
		}
		s.recordEvent(dbEvent{
			Type:    "domain.failover_switched",
			Message: "domain failover switched active node",
			Domain:  d.Domain,
			NodeID:  next.NodeID,
			Metadata: map[string]any{
				"from_node_id":   decision.State.LastFromNodeID,
				"to_node_id":     next.NodeID,
				"reason":         decision.Reason,
				"cooldown_until": decision.State.CooldownUntil,
				"record_name":    cfConfig.RecordName,
				"record_type":    cfConfig.RecordType,
				"target":         next.PublicIP,
			},
		})
		log.Printf("[admin] failed over %s to node %s", d.Domain, next.NodeID)
	}
	return nil
}

func (s *adminServer) renewDueCertificates(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	settings, err := s.effectiveCloudflareSettings(cctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(settings.APIToken) == "" || strings.TrimSpace(settings.ACMEEmail) == "" {
		return nil
	}
	domains, err := s.store.Domains(cctx)
	if err != nil {
		return err
	}
	for _, d := range domains {
		if !d.Enabled || !certificateRenewDue(d) {
			continue
		}
		plan, err := certificatePlanWithSettings(cctx, d, settings.ACMEEmail, settings.ACMEDirectoryURL, settings)
		if err != nil {
			failed := certificateFailure(d.Certificate, err)
			_ = s.store.UpdateDomainCertificate(context.Background(), d.Domain, failed)
			log.Printf("[admin] plan cert renewal for %s failed: %v", d.Domain, err)
			continue
		}
		cert, err := issueCertificateWithCloudflareTokenZone(cctx, d, plan.Email, plan.DirectoryURL, settings.APIToken, plan.ZoneID)
		if err != nil {
			failed := certificateFailure(d.Certificate, err)
			_ = s.store.UpdateDomainCertificate(context.Background(), d.Domain, failed)
			log.Printf("[admin] renew cert for %s failed: %v", d.Domain, err)
			continue
		}
		if err := s.store.UpdateDomainCertificate(context.Background(), d.Domain, cert); err != nil {
			log.Printf("[admin] save renewed cert for %s failed: %v", d.Domain, err)
			continue
		}
		log.Printf("[admin] renewed cert for %s version %s", d.Domain, cert.Version)
	}
	return nil
}

func isNodeHealthy(node NodeHeartbeat) bool {
	return nodeHealthyAt(node, time.Now())
}

func nodeHealthyAt(node NodeHeartbeat, now time.Time) bool {
	if node.NodeID == "" || node.Error != "" {
		return false
	}
	if node.UpdatedAt.IsZero() {
		return false
	}
	if now.Sub(node.UpdatedAt) > 90*time.Second {
		return false
	}
	if strings.EqualFold(node.ProxyStatus, "error") && node.ProxyCheckedAt != nil && now.Sub(*node.ProxyCheckedAt) <= 3*time.Minute {
		return false
	}
	return true
}

func nodeHeartbeatFresh(node NodeHeartbeat, now time.Time) bool {
	if node.NodeID == "" || node.Error != "" || node.UpdatedAt.IsZero() {
		return false
	}
	return now.Sub(node.UpdatedAt) <= 90*time.Second
}

func failoverTarget(d dbDomain, nodes map[string]NodeHeartbeat) (NodeHeartbeat, bool) {
	if !d.Enabled || !d.FailoverEnabled || len(d.NodeIDs) == 0 {
		return NodeHeartbeat{}, false
	}
	active := nodes[d.ActiveNodeID]
	if isNodeHealthy(active) {
		return NodeHeartbeat{}, false
	}
	next, ok := firstHealthyAssignedNode(d, nodes)
	if !ok || next.NodeID == d.ActiveNodeID {
		return NodeHeartbeat{}, false
	}
	return next, true
}

type failoverDecision struct {
	ShouldSwitch bool
	Target       NodeHeartbeat
	State        domainFailoverState
	StateChanged bool
	Reason       string
}

func evaluateDomainFailover(d dbDomain, nodes map[string]NodeHeartbeat, now time.Time) failoverDecision {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state := d.FailoverState
	state.LastCheckAt = &now
	policy := failoverPolicyWithDefaultsForDomain(d)
	decision := failoverDecision{State: state}
	if !d.Enabled || !d.FailoverEnabled || len(d.NodeIDs) == 0 {
		return decision
	}
	active := nodes[d.ActiveNodeID]
	if nodeHealthyAt(active, now) {
		if state.ActiveFailureCount != 0 || strings.TrimSpace(state.LastError) != "" {
			state.ActiveFailureCount = 0
			state.LastError = ""
			decision.State = state
			decision.StateChanged = true
		}
		if policy.AutoFailback && !policy.ManualLock && strings.TrimSpace(policy.PrimaryNodeID) != "" && d.ActiveNodeID != policy.PrimaryNodeID {
			if state.CooldownUntil != nil && state.CooldownUntil.After(now) {
				state.LastError = "cooldown active"
				decision.State = state
				decision.Reason = state.LastError
				decision.StateChanged = true
				return decision
			}
			primary := nodes[policy.PrimaryNodeID]
			if nodeHealthyAt(primary, now) && nodeReadyForDomainAt(primary, d, now) {
				cooldownUntil := now.Add(time.Duration(policy.CooldownSeconds) * time.Second)
				state.LastFromNodeID = d.ActiveNodeID
				state.LastToNodeID = primary.NodeID
				state.LastSwitchAt = &now
				state.CooldownUntil = &cooldownUntil
				state.ActiveFailureCount = 0
				state.LastError = ""
				state.LastReason = "primary node recovered"
				decision.ShouldSwitch = true
				decision.Target = primary
				decision.State = state
				decision.StateChanged = true
				decision.Reason = state.LastReason
			}
		}
		return decision
	}
	state.ActiveFailureCount++
	state.LastFailureAt = &now
	state.LastReason = activeFailureReasonAt(d.ActiveNodeID, active, now)
	decision.StateChanged = true

	if policy.ManualLock {
		state.LastError = "manual lock enabled"
		decision.State = state
		decision.Reason = state.LastError
		return decision
	}
	if state.CooldownUntil != nil && state.CooldownUntil.After(now) {
		state.LastError = "cooldown active"
		decision.State = state
		decision.Reason = state.LastError
		return decision
	}
	if state.ActiveFailureCount < policy.FailThreshold {
		state.LastError = fmt.Sprintf("waiting for failure threshold %d/%d", state.ActiveFailureCount, policy.FailThreshold)
		decision.State = state
		decision.Reason = state.LastError
		return decision
	}
	next, ok := firstHealthyAssignedNodeAt(d, nodes, now)
	if !ok || next.NodeID == d.ActiveNodeID {
		state.LastError = "no healthy failover candidate"
		decision.State = state
		decision.Reason = state.LastError
		return decision
	}
	cooldownUntil := now.Add(time.Duration(policy.CooldownSeconds) * time.Second)
	state.LastFromNodeID = d.ActiveNodeID
	state.LastToNodeID = next.NodeID
	state.LastSwitchAt = &now
	state.CooldownUntil = &cooldownUntil
	state.ActiveFailureCount = 0
	state.LastError = ""
	state.LastReason = "active node unhealthy"
	decision.ShouldSwitch = true
	decision.Target = next
	decision.State = state
	decision.Reason = state.LastReason
	return decision
}

func failoverPolicyWithDefaultsForDomain(d dbDomain) domainFailoverPolicy {
	policy := failoverPolicyWithDefaults(d.FailoverPolicy)
	policy.PrimaryNodeID = strings.TrimSpace(policy.PrimaryNodeID)
	if policy.PrimaryNodeID == "" && len(d.NodeIDs) > 0 {
		policy.PrimaryNodeID = d.NodeIDs[0]
	}
	return policy
}

func failoverPolicyWithDefaults(policy domainFailoverPolicy) domainFailoverPolicy {
	if policy.FailThreshold <= 0 {
		policy.FailThreshold = 3
	}
	if policy.CooldownSeconds <= 0 {
		policy.CooldownSeconds = 300
	}
	policy.PrimaryNodeID = strings.TrimSpace(policy.PrimaryNodeID)
	return policy
}

func activeFailureReason(activeNodeID string, active NodeHeartbeat) string {
	return activeFailureReasonAt(activeNodeID, active, time.Now().UTC())
}

func activeFailureReasonAt(activeNodeID string, active NodeHeartbeat, now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(activeNodeID) == "" {
		return "active node not selected"
	}
	if strings.TrimSpace(active.NodeID) == "" {
		return "active node heartbeat missing"
	}
	if strings.TrimSpace(active.Error) != "" {
		return "active node error: " + active.Error
	}
	if strings.EqualFold(active.ProxyStatus, "error") && active.ProxyCheckedAt != nil && now.Sub(*active.ProxyCheckedAt) <= 3*time.Minute {
		if strings.TrimSpace(active.ProxyError) != "" {
			return "active node proxy error: " + active.ProxyError
		}
		return "active node proxy error"
	}
	return "active node heartbeat stale"
}

func firstHealthyAssignedNode(d dbDomain, nodes map[string]NodeHeartbeat) (NodeHeartbeat, bool) {
	return firstHealthyAssignedNodeAt(d, nodes, time.Now().UTC())
}

func firstHealthyAssignedNodeAt(d dbDomain, nodes map[string]NodeHeartbeat, now time.Time) (NodeHeartbeat, bool) {
	for _, nodeID := range d.NodeIDs {
		node := nodes[nodeID]
		if nodeHealthyAt(node, now) && nodeReadyForDomainAt(node, d, now) {
			return node, true
		}
	}
	return NodeHeartbeat{}, false
}

func nodeReadyForDomain(node NodeHeartbeat, d dbDomain) bool {
	return nodeReadyForDomainAt(node, d, time.Now().UTC())
}

func nodeReadyForDomainAt(node NodeHeartbeat, d dbDomain, now time.Time) bool {
	version := strings.TrimSpace(d.Certificate.Version)
	if version == "" {
		return true
	}
	return nodeHasDomainCertificateVersionAt(node, d.Domain, version, now)
}

func nodeHasDomainCertificateVersion(node NodeHeartbeat, domain, version string) bool {
	return nodeHasDomainCertificateVersionAt(node, domain, version, time.Now().UTC())
}

func nodeHasDomainCertificateVersionAt(node NodeHeartbeat, domain, version string, now time.Time) bool {
	domain, err := normalizeDomainName(domain)
	if err != nil {
		return false
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	for _, cert := range node.CertDomains {
		certDomain, err := normalizeDomainName(cert.Domain)
		if err != nil {
			continue
		}
		if certDomain == domain && strings.TrimSpace(cert.Version) == version && nodeCertStateValidAt(cert, now) {
			return true
		}
	}
	return false
}

func nodeCertStateValidAt(cert NodeCertState, now time.Time) bool {
	if cert.ExpiresAt == nil {
		return false
	}
	return cert.ExpiresAt.After(now)
}

func certificateRenewDue(d dbDomain) bool {
	now := time.Now().UTC()
	if d.Certificate.ExpiresAt == nil || d.Certificate.FullchainPEM == "" || d.Certificate.PrivateKeyPEM == "" {
		return true
	}
	if !d.Certificate.ExpiresAt.After(now) {
		return true
	}
	days := renewBeforeDays(d)
	return d.Certificate.ExpiresAt.Sub(now) <= time.Duration(days)*24*time.Hour
}

func certificateRenewStatus(d dbDomain, now time.Time) string {
	if strings.TrimSpace(d.Certificate.LastError) != "" {
		return "error"
	}
	if d.Certificate.ExpiresAt == nil || d.Certificate.FullchainPEM == "" || d.Certificate.PrivateKeyPEM == "" {
		return "missing"
	}
	if !d.Certificate.ExpiresAt.After(now) {
		return "expired"
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	days := renewBeforeDays(d)
	if d.Certificate.ExpiresAt.Sub(now) <= time.Duration(days)*24*time.Hour {
		return "due"
	}
	return "valid"
}

func certificateRenewInDays(d dbDomain, now time.Time) int {
	if d.Certificate.ExpiresAt == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	days := renewBeforeDays(d)
	renewAt := d.Certificate.ExpiresAt.Add(-time.Duration(days) * 24 * time.Hour)
	hours := renewAt.Sub(now).Hours()
	if hours <= 0 {
		return 0
	}
	return int(math.Ceil(hours / 24))
}

func renewBeforeDays(d dbDomain) int {
	if d.RenewBeforeDays > 0 {
		return d.RenewBeforeDays
	}
	return 30
}

func certificateDaysRemaining(d dbDomain, now time.Time) int {
	if d.Certificate.ExpiresAt == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	hours := d.Certificate.ExpiresAt.Sub(now).Hours()
	if hours <= 0 {
		return 0
	}
	return int(math.Ceil(hours / 24))
}

type rulesHealthResponse struct {
	CheckedAt time.Time       `json:"checked_at"`
	Target    string          `json:"target"`
	Timeout   string          `json:"timeout,omitempty"`
	Results   []checkResponse `json:"results"`
}

func (s *adminServer) handleRulesHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}

	if r.Method == http.MethodGet && parseBool(r.URL.Query().Get("latest")) {
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		health, err := s.store.LatestRulesHealth(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if health == nil {
			writeJSON(w, http.StatusOK, rulesHealthResponse{
				CheckedAt: time.Time{},
				Target:    firstNonEmpty(os.Getenv(rulesHealthTargetEnv), defaultRulesHealthTarget),
				Timeout:   firstNonEmpty(os.Getenv(rulesHealthTimeoutEnv), defaultRulesHealthTimeout),
				Results:   []checkResponse{},
			})
			return
		}
		writeJSON(w, http.StatusOK, health)
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("target"))
	timeoutValue := strings.TrimSpace(r.URL.Query().Get("timeout"))
	if r.Method == http.MethodPost {
		var payload struct {
			Target  string `json:"target"`
			Timeout string `json:"timeout"`
		}
		if err := decodeJSON(r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if payload.Target != "" {
			target = payload.Target
		}
		if payload.Timeout != "" {
			timeoutValue = payload.Timeout
		}
	}
	if target == "" {
		target = firstNonEmpty(os.Getenv(rulesHealthTargetEnv), defaultRulesHealthTarget)
	}
	if timeoutValue == "" {
		timeoutValue = firstNonEmpty(os.Getenv(rulesHealthTimeoutEnv), defaultRulesHealthTimeout)
	}

	health, err := s.checkAndSaveRulesHealth(r.Context(), target, timeoutValue)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (s *adminServer) checkAndSaveRulesHealth(ctx context.Context, target, timeoutValue string) (rulesHealthResponse, error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	health, err := s.checkRulesHealth(ctx, target, timeoutValue)
	if err != nil {
		return health, err
	}
	saveCtx, cancel := withTimeout(context.Background())
	defer cancel()
	if err := s.store.SaveRulesHealth(saveCtx, health); err != nil {
		return health, err
	}
	return health, nil
}

func (s *adminServer) checkRulesHealth(ctx context.Context, target, timeoutValue string) (rulesHealthResponse, error) {
	target = firstNonEmpty(target, os.Getenv(rulesHealthTargetEnv), defaultRulesHealthTarget)
	timeoutValue = firstNonEmpty(timeoutValue, os.Getenv(rulesHealthTimeoutEnv), defaultRulesHealthTimeout)
	perRuleTimeout := 8 * time.Second
	if parsed, err := time.ParseDuration(timeoutValue); err == nil && parsed > 0 {
		perRuleTimeout = parsed
	}

	storeCtx, cancelStore := withTimeout(ctx)
	defer cancelStore()
	rules, err := s.store.Rules(storeCtx)
	if err != nil {
		return rulesHealthResponse{}, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })

	results := make([]checkResponse, 0, len(rules))
	checkBudget := time.Duration(len(rules)+1) * (perRuleTimeout + time.Second)
	checkCtx, cancelChecks := context.WithTimeout(ctx, checkBudget)
	defer cancelChecks()
	for _, ruleDoc := range rules {
		if strings.TrimSpace(ruleDoc.Name) == "" {
			continue
		}
		result, err := s.runCheck(checkCtx, checkRequest{
			Type:    "rule",
			Name:    ruleDoc.Name,
			Target:  target,
			Timeout: timeoutValue,
			Probe:   "ipinfo",
		})
		if err != nil {
			result = checkResponse{
				Status:  "error",
				Type:    "rule",
				Name:    ruleDoc.Name,
				Target:  target,
				Network: "tcp",
				Probe:   "ipinfo",
				Error:   err.Error(),
			}
		}
		results = append(results, result)
	}

	return rulesHealthResponse{
		CheckedAt: time.Now().UTC(),
		Target:    target,
		Timeout:   timeoutValue,
		Results:   results,
	}, nil
}

func (s *adminServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	ctx, cancel := withTimeout(r.Context())
	defer cancel()
	if s.applier == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("proxy reload unavailable in admin mode"))
		return
	}
	if err := s.reload(ctx); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type checkRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Target  string `json:"target"`
	Network string `json:"network"`
	Timeout string `json:"timeout"`
	Probe   string `json:"probe"`
}

type checkResponse struct {
	Status     string         `json:"status"`
	Type       string         `json:"type"`
	Name       string         `json:"name,omitempty"`
	Target     string         `json:"target"`
	Network    string         `json:"network"`
	Probe      string         `json:"probe,omitempty"`
	URL        string         `json:"url,omitempty"`
	HTTPStatus int            `json:"http_status,omitempty"`
	Dialer     string         `json:"dialer,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	IPInfo     *ipInfoPayload `json:"ip_info,omitempty"`
	Error      string         `json:"error,omitempty"`
}

func (s *adminServer) handleCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(w, r) {
		return
	}
	var req checkRequest
	switch r.Method {
	case http.MethodGet:
		req = checkRequest{
			Type:    r.URL.Query().Get("type"),
			Name:    r.URL.Query().Get("name"),
			Target:  r.URL.Query().Get("target"),
			Network: r.URL.Query().Get("network"),
			Timeout: r.URL.Query().Get("timeout"),
			Probe:   r.URL.Query().Get("probe"),
		}
	case http.MethodPost:
		if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	resp, err := s.runCheck(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *adminServer) runCheck(ctx context.Context, req checkRequest) (checkResponse, error) {
	if s.pxySw == nil || s.pxySw.Current() == nil {
		return checkResponse{}, fmt.Errorf("connectivity check requires a running proxy; unavailable in admin-only mode")
	}
	if strings.EqualFold(strings.TrimSpace(req.Probe), "ipinfo") || looksLikeHTTPURL(req.Target) {
		return s.runHTTPProbe(ctx, req)
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = "default"
	}
	req.Network = strings.ToLower(strings.TrimSpace(req.Network))
	if req.Network == "" {
		req.Network = "tcp"
	}
	if req.Network != "tcp" {
		return checkResponse{}, fmt.Errorf("unsupported network %q", req.Network)
	}
	req.Target = normalizeCheckTarget(req.Target)
	if req.Target == "" {
		return checkResponse{}, fmt.Errorf("target required")
	}
	if _, _, err := net.SplitHostPort(req.Target); err != nil {
		return checkResponse{}, fmt.Errorf("invalid target %q: %w", req.Target, err)
	}
	timeout := 5 * time.Second
	if req.Timeout != "" {
		parsed, err := time.ParseDuration(req.Timeout)
		if err != nil || parsed <= 0 {
			return checkResponse{}, fmt.Errorf("invalid timeout %q", req.Timeout)
		}
		timeout = parsed
	}

	var (
		conn   net.Conn
		dialer proxy.Dialer
		err    error
	)
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, dialer, err = s.dialForCheck(req, req.Network, req.Target)
	}()

	select {
	case <-ctx.Done():
		return checkResponse{}, ctx.Err()
	case <-time.After(timeout):
		return checkResponse{
			Status:     "error",
			Type:       req.Type,
			Name:       req.Name,
			Target:     req.Target,
			Network:    req.Network,
			DurationMS: time.Since(start).Milliseconds(),
			Error:      "timeout",
		}, nil
	case <-done:
	}
	if conn != nil {
		_ = conn.Close()
	}
	resp := checkResponse{
		Status:     "ok",
		Type:       req.Type,
		Name:       req.Name,
		Target:     req.Target,
		Network:    req.Network,
		DurationMS: time.Since(start).Milliseconds(),
	}
	if dialer != nil {
		resp.Dialer = dialer.Addr()
	}
	if err != nil {
		resp.Status = "error"
		resp.Error = err.Error()
	}
	return resp, nil
}

type ipInfoPayload struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Loc      string `json:"loc,omitempty"`
	Org      string `json:"org,omitempty"`
	Postal   string `json:"postal,omitempty"`
	Timezone string `json:"timezone,omitempty"`
	Readme   string `json:"readme,omitempty"`
}

func (s *adminServer) runHTTPProbe(ctx context.Context, req checkRequest) (checkResponse, error) {
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = "default"
	}
	req.Network = "tcp"
	req.Probe = strings.ToLower(strings.TrimSpace(req.Probe))
	if req.Probe == "" {
		req.Probe = "ipinfo"
	}

	targetURL := strings.TrimSpace(req.Target)
	if targetURL == "" && req.Probe == "ipinfo" {
		targetURL = "https://ipinfo.io/json"
	}
	if targetURL == "" {
		return checkResponse{}, fmt.Errorf("target required")
	}
	if !looksLikeHTTPURL(targetURL) {
		targetURL = "https://" + targetURL
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return checkResponse{}, fmt.Errorf("invalid probe url %q", targetURL)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return checkResponse{}, fmt.Errorf("unsupported probe scheme %q", parsedURL.Scheme)
	}

	timeout := 8 * time.Second
	if req.Timeout != "" {
		parsed, err := time.ParseDuration(req.Timeout)
		if err != nil || parsed <= 0 {
			return checkResponse{}, fmt.Errorf("invalid timeout %q", req.Timeout)
		}
		timeout = parsed
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var usedDialer proxy.Dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, dialer, err := s.dialForCheck(req, network, addr)
			if err == nil {
				usedDialer = dialer
			}
			return conn, err
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          1,
		IdleConnTimeout:       timeout,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	httpReq, err := http.NewRequestWithContext(probeCtx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return checkResponse{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "glider-admin-check/"+version)

	start := time.Now()
	resp, err := client.Do(httpReq)
	result := checkResponse{
		Status:     "ok",
		Type:       req.Type,
		Name:       req.Name,
		Target:     parsedURL.Host,
		Network:    "tcp",
		Probe:      req.Probe,
		URL:        parsedURL.String(),
		DurationMS: time.Since(start).Milliseconds(),
	}
	if usedDialer != nil {
		result.Dialer = usedDialer.Addr()
	}
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Status = "error"
		result.Error = resp.Status
		return result, nil
	}
	var info ipInfoPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result, nil
	}
	result.IPInfo = &info
	return result, nil
}

func (s *adminServer) dialForCheck(req checkRequest, network, target string) (net.Conn, proxy.Dialer, error) {
	switch req.Type {
	case "default":
		return s.pxySw.Dial(network, target)
	case "rule":
		if strings.TrimSpace(req.Name) == "" {
			return nil, nil, fmt.Errorf("name required for rule check")
		}
		return s.dialRuleByName(req.Name, network, target)
	case "user":
		if strings.TrimSpace(req.Name) == "" {
			return nil, nil, fmt.Errorf("name required for user check")
		}
		return s.pxySw.DialWithUser(req.Name, network, target)
	default:
		return nil, nil, fmt.Errorf("unsupported check type %q", req.Type)
	}
}

func (s *adminServer) dialRuleByName(name, network, target string) (net.Conn, proxy.Dialer, error) {
	ruleConf := s.findLoadedRule(name)
	if ruleConf == nil {
		return nil, nil, fmt.Errorf("rule %q is not loaded", name)
	}
	strategy := ruleConf.Strategy
	group := rule.NewFwdrGroup(ruleConf.RulePath, ruleConf.Forward, &strategy)
	return group.Dial(network, target)
}

func (s *adminServer) findLoadedRule(name string) *rule.Config {
	if s.conf == nil {
		return nil
	}
	for _, ruleConf := range s.conf.rules {
		if strings.TrimSuffix(filepath.Base(ruleConf.RulePath), filepath.Ext(ruleConf.RulePath)) == name {
			return ruleConf
		}
	}
	return nil
}

func looksLikeHTTPURL(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

func normalizeCheckTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			if u.Host != "" {
				return u.Host
			}
			return u.Path
		}
	}
	return target
}

func (s *adminServer) reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	snap, err := LoadSnapshotFromStore(ctx, s.store)
	if err != nil {
		return err
	}
	if err := s.applier.Apply(ctx, snap); err != nil {
		return err
	}
	s.lastReload = time.Now()
	return nil
}

func withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 5*time.Second)
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{
		"error": err.Error(),
	})
}

const adminHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Glider Control Plane</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --panel-2: #f9fafb;
      --text: #17202a;
      --muted: #657282;
      --line: #dfe5ec;
      --accent: #1f7a8c;
      --accent-2: #0f766e;
      --danger: #b42318;
      --warn: #b45309;
      --ok: #15803d;
      --shadow: 0 10px 28px rgba(15, 23, 42, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
    }
    button, input, select, textarea { font: inherit; }
    button {
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      min-height: 34px;
      padding: 0 12px;
      border-radius: 6px;
      cursor: pointer;
    }
    button:hover { border-color: #b8c2cc; background: #f8fafc; }
    button:disabled { opacity: .62; cursor: wait; }
    button.primary { border-color: var(--accent); background: var(--accent); color: #fff; }
    button.primary:hover { background: #166678; }
    button.danger { color: var(--danger); border-color: #f0b8b3; }
    button.ghost { background: transparent; }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 8px 10px;
      outline: none;
    }
    input:focus, select:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(31, 122, 140, .12); }
    textarea { min-height: 230px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; line-height: 1.45; }
    label { color: var(--muted); font-size: 12px; }
    .app { min-height: 100vh; display: grid; grid-template-columns: 250px 1fr; }
    .sidebar { background: #18212c; color: #dce6f2; padding: 22px 18px; }
    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 26px; }
    .brand-mark { width: 34px; height: 34px; border-radius: 8px; background: #2dd4bf; display: grid; place-items: center; color: #102026; font-weight: 800; }
    .brand-title { font-size: 17px; font-weight: 700; }
    .brand-sub { font-size: 12px; color: #9fb0c3; margin-top: 2px; }
    .nav button { width: 100%; justify-content: flex-start; text-align: left; background: transparent; color: #cbd5e1; border-color: transparent; margin-bottom: 6px; }
    .nav button.active { background: rgba(45, 212, 191, .16); color: #fff; border-color: rgba(45, 212, 191, .24); }
    .side-card { margin-top: 22px; border: 1px solid rgba(203, 213, 225, .14); border-radius: 8px; padding: 12px; background: rgba(255, 255, 255, .04); }
    .side-card input { margin-top: 8px; background: #111827; color: #fff; border-color: #334155; }
    .side-actions { display: flex; gap: 8px; margin-top: 10px; }
    .side-actions button { color: #e2e8f0; background: #243142; border-color: #334155; }
    .main { min-width: 0; }
    header { height: 78px; display: flex; align-items: center; justify-content: space-between; padding: 0 28px; border-bottom: 1px solid var(--line); background: rgba(255, 255, 255, .82); backdrop-filter: blur(10px); position: sticky; top: 0; z-index: 2; }
    h1 { font-size: 22px; margin: 0; letter-spacing: 0; }
    .header-meta { color: var(--muted); font-size: 13px; margin-top: 4px; }
    .toolbar { display: flex; align-items: center; gap: 10px; }
    .content { padding: 24px 28px 34px; }
    .stats { display: grid; grid-template-columns: repeat(7, minmax(120px, 1fr)); gap: 14px; margin-bottom: 18px; }
    .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; box-shadow: var(--shadow); }
    .stat-label { color: var(--muted); font-size: 12px; }
    .stat-value { font-size: 24px; font-weight: 750; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: minmax(280px, 380px) minmax(420px, 1fr); gap: 18px; align-items: start; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); min-width: 0; }
    .panel + .panel { margin-top: 18px; }
    .panel-head { padding: 14px 16px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .panel-title { font-size: 15px; font-weight: 740; }
    .panel-body { padding: 16px; }
    .list { max-height: 560px; overflow: auto; }
    .item { width: 100%; border-bottom: 1px solid var(--line); padding: 12px 14px; display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: center; }
    .item:last-child { border-bottom: 0; }
    .item:hover { background: var(--panel-2); }
    .item-main { min-width: 0; cursor: pointer; }
    .item-title { font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .item-sub { color: var(--muted); font-size: 12px; margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .item-actions { display: flex; gap: 6px; align-items: center; }
    .item-actions button { min-height: 30px; padding: 0 9px; font-size: 12px; }
    .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .form-grid .wide { grid-column: 1 / -1; }
    .checkbox-row { display: flex; align-items: center; gap: 8px; height: 36px; }
    .checkbox-row input { width: auto; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; align-items: center; }
    .pill { display: inline-flex; align-items: center; min-height: 22px; padding: 0 8px; border-radius: 999px; font-size: 12px; border: 1px solid var(--line); color: var(--muted); background: #fff; white-space: nowrap; }
    .pill.ok { color: var(--ok); border-color: #bbf7d0; background: #f0fdf4; }
    .pill.err { color: var(--danger); border-color: #fecaca; background: #fff1f2; }
    .pill.warn { color: var(--warn); border-color: #fed7aa; background: #fff7ed; }
    .tabs { display: none; }
    .tabs.active { display: block; }
    .check-grid { display: grid; grid-template-columns: 160px 1fr 1fr 120px; gap: 12px; align-items: end; }
    .result { margin-top: 14px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel-2); padding: 12px; min-height: 58px; color: var(--muted); white-space: pre-wrap; }
    .toast { min-width: 220px; color: var(--muted); font-size: 13px; }
    .empty { padding: 20px; color: var(--muted); }
    .search-row { padding: 12px 14px; border-bottom: 1px solid var(--line); background: var(--panel-2); }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; font-weight: 650; background: var(--panel-2); }
    td { font-size: 13px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .muted { color: var(--muted); }
    .compact { font-size: 12px; color: var(--muted); }
    .inline-check { display: inline-flex; align-items: center; gap: 8px; color: var(--muted); }
    .inline-check input { width: auto; }
    .node-select { border: 1px solid var(--line); border-radius: 6px; background: #fff; padding: 8px 10px; min-height: 98px; max-height: 170px; overflow: auto; }
    .node-select label { display: flex; gap: 8px; align-items: center; color: var(--text); font-size: 13px; padding: 3px 0; }
    .node-select input { width: auto; }
    @media (max-width: 980px) {
      .app { grid-template-columns: 1fr; }
      .sidebar { position: static; }
      header { height: auto; padding: 18px; align-items: flex-start; gap: 14px; flex-direction: column; }
      .content { padding: 18px; }
      .stats, .grid, .check-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">G</div>
        <div>
          <div class="brand-title">Glider</div>
          <div class="brand-sub">Control Plane</div>
        </div>
      </div>
      <nav class="nav">
        <button id="tabBtnOverview" class="active" onclick="showTab('overview')">Overview</button>
        <button id="tabBtnUsers" onclick="showTab('users')">Users</button>
        <button id="tabBtnRules" onclick="showTab('rules')">Rules</button>
	        <button id="tabBtnChecks" onclick="showTab('checks')">Connectivity</button>
	        <button id="tabBtnNodes" onclick="showTab('nodes')">Nodes</button>
	        <button id="tabBtnServers" onclick="showTab('servers')">Servers</button>
	        <button id="tabBtnCerts" onclick="showTab('certs')">Domains</button>
      </nav>
      <div class="side-card">
        <label for="adminToken">Admin token</label>
        <input id="adminToken" type="password" autocomplete="current-password" placeholder="Bearer token">
        <div class="side-actions">
          <button id="saveTokenBtn" type="button" onclick="saveToken()">Save</button>
          <button type="button" onclick="clearToken()">Clear</button>
        </div>
      </div>
    </aside>

    <main class="main">
      <header>
        <div>
          <h1 id="pageTitle">Overview</h1>
          <div class="header-meta" id="pageSubtitle">Centralized users, routing rules, nodes, and live checks.</div>
        </div>
        <div class="toolbar">
          <span id="authStatus" class="toast"></span>
          <button onclick="refreshAll()">Refresh</button>
          <button class="primary" onclick="reloadConfig()">Reload</button>
          <span id="reloadStatus" class="pill">idle</span>
        </div>
      </header>

      <div class="content">
        <section id="tabOverview" class="tabs active">
          <div class="stats">
            <div class="stat"><div class="stat-label">Users</div><div class="stat-value" id="statUsers">0</div></div>
            <div class="stat"><div class="stat-label">Active users</div><div class="stat-value" id="statActiveUsers">0</div></div>
            <div class="stat"><div class="stat-label">Rules</div><div class="stat-value" id="statRules">0</div></div>
            <div class="stat"><div class="stat-label">Healthy rules</div><div class="stat-value" id="statHealthyRules">-</div></div>
            <div class="stat"><div class="stat-label">Nodes online</div><div class="stat-value" id="statNodesOnline">0</div></div>
            <div class="stat"><div class="stat-label">Config version</div><div class="stat-value mono" id="statConfigVersion">-</div></div>
            <div class="stat"><div class="stat-label">Nodes synced</div><div class="stat-value" id="statNodesSynced">-</div></div>
          </div>
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Quick IP Info Check</div><span class="pill">ipinfo.io</span></div>
            <div class="panel-body">
              <div class="check-grid">
                <div><label>Route type</label><select id="quickCheckType"><option value="default">Default route</option><option value="rule">Rule route</option><option value="user">User route</option></select></div>
                <div><label>Name</label><input id="quickCheckName" placeholder="rule or username"></div>
                <div><label>Target URL</label><input id="quickCheckTarget" value="https://ipinfo.io/json"></div>
                <div><label>Timeout</label><input id="quickCheckTimeout" value="8s"></div>
              </div>
              <div class="actions"><button class="primary" onclick="runQuickCheck()">Run Check</button></div>
              <div id="quickCheckResult" class="result">No check has run yet.</div>
            </div>
          </div>
        </section>

        <section id="tabUsers" class="tabs">
          <div class="grid">
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Users</div><span id="usersCount" class="pill">0</span></div>
              <div class="search-row"><input id="userSearch" placeholder="Search users, rules, status" oninput="renderUsers()"></div>
              <div id="usersList" class="list"></div>
            </div>
            <div class="panel">
              <div class="panel-head"><div class="panel-title">User Editor</div><span id="selectedUserStatus" class="pill">new</span></div>
              <div class="panel-body">
                <div class="form-grid">
                  <div><label>Username</label><input id="userName" placeholder="username"></div>
                  <div><label>Password</label><input id="userPass" placeholder="password"></div>
                  <div><label>Rule</label><select id="userRule"></select></div>
                  <div><label>Expires at</label><input id="userExpires" type="datetime-local"></div>
                  <div class="checkbox-row"><input id="userEnabled" type="checkbox" checked><label for="userEnabled">Enabled</label></div>
                </div>
                <div class="actions">
                  <button class="primary" onclick="saveUser()">Save User</button>
                  <button class="danger" onclick="deleteUser()">Delete User</button>
                  <button onclick="checkSelectedUser()">Check IP Info</button>
                </div>
                <div id="userCheckResult" class="result">Select or save a user, then run a route check.</div>
              </div>
            </div>
          </div>
        </section>

        <section id="tabRules" class="tabs">
          <div class="grid">
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Rules</div><span id="rulesCount" class="pill">0</span></div>
              <div class="search-row"><input id="ruleSearch" placeholder="Search rules or forward content" oninput="renderRules()"></div>
              <div id="rulesList" class="list"></div>
            </div>
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Rule Editor</div><span id="selectedRuleStatus" class="pill">new</span></div>
              <div class="panel-body">
                <div class="form-grid">
                  <div class="wide"><label>Rule name</label><input id="ruleName" placeholder="rule name without .rule"></div>
                  <div class="wide"><label>Rule content</label><textarea id="ruleContent" placeholder="forward=direct://&#10;domain=example.com"></textarea></div>
                </div>
                <div class="actions">
                  <button class="primary" onclick="saveRule()">Save Rule</button>
                  <button class="danger" onclick="deleteRule()">Delete Rule</button>
                  <button onclick="checkSelectedRule()">Check IP Info</button>
                </div>
                <div id="ruleCheckResult" class="result">Select or save a rule, then run a route check.</div>
              </div>
            </div>
          </div>
        </section>

        <section id="tabChecks" class="tabs">
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Connectivity Lab</div><span class="pill">route exit IP</span></div>
            <div class="panel-body">
              <div class="check-grid">
                <div><label>Type</label><select id="checkType"><option value="default">Default</option><option value="rule">Rule</option><option value="user">User</option></select></div>
                <div><label>Name</label><input id="checkName" placeholder="rule name or username"></div>
                <div><label>Target URL</label><input id="checkTarget" value="https://ipinfo.io/json"></div>
                <div><label>Timeout</label><input id="checkTimeout" value="8s"></div>
              </div>
              <div class="actions"><button class="primary" onclick="runCheckFromForm()">Run Check</button></div>
              <div id="checkResult" class="result">Checks run through the currently loaded local proxy runtime.</div>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Rules Health</div><span id="rulesHealthStatus" class="pill">idle</span></div>
            <div class="panel-body">
              <div class="check-grid">
                <div><label>Target URL</label><input id="healthTarget" value="https://ipinfo.io/json"></div>
                <div><label>Timeout</label><input id="healthTimeout" value="8s"></div>
                <div><label>Interval seconds</label><input id="healthInterval" type="number" min="15" value="60"></div>
                <div><label>&nbsp;</label><span class="inline-check"><input id="healthAuto" type="checkbox" onchange="toggleHealthAuto()"> auto</span></div>
              </div>
              <div class="actions"><button class="primary" onclick="runRulesHealth()">Check All Rules</button></div>
              <div id="rulesHealthTable" class="table-wrap result">No health check has run yet.</div>
            </div>
          </div>
        </section>

	        <section id="tabNodes" class="tabs">
	          <div class="panel">
	            <div class="panel-head"><div class="panel-title">Nodes</div><span id="nodesCount" class="pill">0</span></div>
	            <div class="search-row"><input id="nodeSearch" placeholder="Search nodes, hosts, IPs, versions, errors" oninput="renderNodes()"></div>
	            <div class="panel-body">
	              <div id="nodesTable" class="table-wrap">No nodes have reported yet.</div>
	            </div>
	          </div>
	        </section>

	        <section id="tabServers" class="tabs">
	          <div class="grid">
	            <div class="panel">
	              <div class="panel-head"><div class="panel-title">Servers</div><span id="serversCount" class="pill">0</span></div>
	              <div class="search-row"><input id="serverSearch" placeholder="Search servers, hosts, nodes" oninput="renderServers()"></div>
	              <div id="serversList" class="list"></div>
	            </div>
	            <div class="panel">
	              <div class="panel-head"><div class="panel-title">Server Provisioning</div><span id="selectedServerStatus" class="pill">new</span></div>
	              <div class="panel-body">
	                <div class="form-grid">
	                  <div><label>Server ID</label><input id="serverID" placeholder="zgo"></div>
	                  <div><label>Node ID</label><input id="serverNodeID" placeholder="zgo"></div>
	                  <div><label>Name</label><input id="serverName" placeholder="friendly name"></div>
	                  <div><label>Host</label><input id="serverHost" placeholder="203.0.113.10"></div>
	                  <div><label>SSH port</label><input id="serverSSHPort" type="number" min="1" value="22"></div>
	                  <div><label>SSH user</label><input id="serverSSHUser" value="root"></div>
	                  <div><label>Auth type</label><select id="serverAuthType"><option value="auto">Auto</option><option value="password">Password</option><option value="private_key">Private key</option></select></div>
	                  <div><label>Deploy dir</label><input id="serverDeployDir" value="/root/data/docker_data/glider"></div>
	                  <div class="wide"><label>Image</label><input id="serverImage" value="ghcr.io/ferryboatseranade/glider:latest"></div>
	                  <div><label>Proxy ports</label><input id="serverProxyPorts" value="443:443,8443:8443"></div>
	                  <div><label>Traffic iface</label><input id="serverTrafficIface" value="eth0"></div>
	                  <div><label>Password</label><input id="serverPassword" type="password" autocomplete="new-password" placeholder="leave blank to keep"></div>
	                  <div><label>Key passphrase</label><input id="serverPassphrase" type="password" autocomplete="new-password" placeholder="optional"></div>
	                  <div class="wide"><label>Private key</label><textarea id="serverPrivateKey" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
	                  <div><label>Central URL</label><input id="deployCentralURL" placeholder="http://15.204.95.51:8444"></div>
	                  <div><label>Node token</label><input id="deployNodeToken" type="password" autocomplete="new-password" placeholder="manual deploy only"></div>
	                  <div><label>Sync interval</label><input id="deploySyncInterval" value="30s"></div>
	                  <div><label>Wait heartbeat seconds</label><input id="deployWaitHeartbeat" type="number" min="15" value="120"></div>
	                  <div><label>Upgrade image</label><input id="upgradeImage" placeholder="ghcr.io/ferryboatseranade/glider:v..."></div>
	                  <div class="checkbox-row"><input id="deployInstallDocker" type="checkbox" checked><label for="deployInstallDocker">Install Docker if missing</label></div>
	                </div>
	                <div class="actions">
	                  <button class="primary" onclick="saveServer()">Save Server</button>
	                  <button onclick="testServerSSH()">Test SSH</button>
	                  <button onclick="preflightServerNode()">Preflight</button>
	                  <button class="primary" onclick="onboardServerNode()">Onboard Node</button>
	                  <button onclick="deployServerNode()">Deploy Node</button>
	                  <button onclick="restartServerNode()">Restart Node</button>
	                  <button onclick="upgradeServerNode()">Upgrade Node</button>
	                  <button class="danger" onclick="deleteServer()">Delete</button>
	                </div>
	                <div id="serverResult" class="result">Save a server, test SSH, then deploy node mode.</div>
	              </div>
	            </div>
	          </div>
	          <div class="panel">
	            <div class="panel-head"><div class="panel-title">Provisioning Jobs</div><span id="jobsCount" class="pill">0</span></div>
	            <div class="panel-body">
	              <div id="jobsTable" class="table-wrap">No jobs yet.</div>
	            </div>
	          </div>
	          <div class="panel">
	            <div class="panel-head"><div class="panel-title">Recent Events</div><span id="eventsCount" class="pill">0</span></div>
	            <div class="panel-body">
	              <div id="eventsTable" class="table-wrap">No events yet.</div>
	            </div>
	          </div>
	        </section>

	        <section id="tabCerts" class="tabs">
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Cloudflare Settings</div><span id="cfTokenStatus" class="pill">not configured</span></div>
            <div class="panel-body">
              <div class="form-grid">
                <div><label>API token</label><input id="cfAPIToken" type="password" autocomplete="new-password" placeholder="new API token or leave blank"></div>
                <div><label>Account ID</label><input id="cfAccountID" placeholder="account token only"></div>
                <div><label>ACME email</label><input id="cfACMEEmail" placeholder="admin@example.com"></div>
                <div class="wide"><label>ACME directory</label><input id="cfACMEDirectory" placeholder="Let's Encrypt production"></div>
                <div><label>Zone test domain</label><input id="cfVerifyDomain" placeholder="proxy.example.com"></div>
                <div class="checkbox-row"><input id="cfDNSEditTest" type="checkbox"><label for="cfDNSEditTest">DNS edit test</label></div>
              </div>
              <div class="actions">
                <button class="primary" onclick="saveCloudflareSettings()">Save Settings</button>
                <button onclick="verifyCloudflareToken()">Verify Token</button>
                <button class="danger" onclick="clearCloudflareToken()">Clear Token</button>
              </div>
              <div id="cfSettingsResult" class="result">Cloudflare token is required for DNS sync, failover, and ACME DNS-01.</div>
            </div>
          </div>
          <div class="grid">
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Domains</div><span id="domainsCount" class="pill">0</span></div>
              <div class="search-row"><input id="domainSearch" placeholder="Search domains, nodes, DNS status" oninput="renderDomains()"></div>
              <div id="domainsList" class="list"></div>
            </div>
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Domain Editor</div><span id="selectedDomainStatus" class="pill">new</span></div>
              <div class="panel-body">
                <div class="form-grid">
                  <div><label>Domain</label><input id="domainName" placeholder="proxy.example.com"></div>
                  <div><label>Active node</label><select id="domainActiveNode"></select></div>
                  <div class="wide"><label>Assigned nodes</label><div id="domainNodeList" class="node-select"></div></div>
                  <div><label>Cloudflare zone ID</label><input id="domainZoneID" placeholder="optional"></div>
                  <div><label>Record name</label><input id="domainRecordName" placeholder="proxy.example.com"></div>
                  <div><label>Record type</label><select id="domainRecordType"><option value="">Auto</option><option value="A">A</option><option value="AAAA">AAAA</option></select></div>
                  <div><label>TTL</label><input id="domainTTL" type="number" min="1" value="1"></div>
                  <div><label>Renew before days</label><input id="domainRenewBefore" type="number" min="1" value="30"></div>
                  <div><label>Fail threshold</label><input id="domainFailThreshold" type="number" min="1" value="3"></div>
                  <div><label>Cooldown seconds</label><input id="domainCooldownSeconds" type="number" min="1" value="300"></div>
                  <div><label>Primary node</label><select id="domainPrimaryNode"></select></div>
                  <div class="checkbox-row"><input id="domainEnabled" type="checkbox" checked><label for="domainEnabled">Enabled</label></div>
                  <div class="checkbox-row"><input id="domainProxied" type="checkbox"><label for="domainProxied">Cloudflare proxied</label></div>
                  <div class="checkbox-row"><input id="domainFailover" type="checkbox"><label for="domainFailover">Heartbeat failover</label></div>
                  <div class="checkbox-row"><input id="domainManualLock" type="checkbox"><label for="domainManualLock">Manual lock active node</label></div>
                  <div class="checkbox-row"><input id="domainAutoFailback" type="checkbox"><label for="domainAutoFailback">Auto failback</label></div>
                  <div><label>ACME email</label><input id="domainACMEEmail" placeholder="admin@example.com"></div>
                  <div><label>ACME directory</label><input id="domainACMEDirectory" placeholder="Let's Encrypt production"></div>
                  <div class="wide"><label>Import fullchain PEM</label><textarea id="domainImportFullchain" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>
                  <div class="wide"><label>Import private key PEM</label><textarea id="domainImportKey" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>
                </div>
                <div class="actions">
                  <button class="primary" onclick="saveDomain()">Save Domain</button>
                  <button onclick="previewDomainDNS()">Preview DNS</button>
                  <button onclick="syncDomainDNS()">Sync DNS</button>
                  <button onclick="previewDomainCert()">Preview Cert</button>
                  <button onclick="issueDomainCert()">Issue Cert</button>
                  <button onclick="importDomainCert()">Import Cert</button>
                  <button class="danger" onclick="deleteDomain()">Delete</button>
                </div>
                <div id="domainResult" class="result">Select or save a domain. Cloudflare and ACME credentials stay on the admin server.</div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  </div>

<script>
let adminToken = loadStoredAdminToken();
let usersCache = [];
let rulesCache = [];
let nodesCache = [];
let domainsCache = [];
let serversCache = [];
let jobsCache = [];
let eventsCache = [];
let configStatus = {};
let cloudflareSettings = null;
let rulesHealthCache = null;
let lastCheck = null;
let healthTimer = null;

const titles = {
  overview: ['Overview', 'Centralized users, routing rules, nodes, and live checks.'],
  users: ['Users', 'Manage dynamic credentials and user-bound routes.'],
  rules: ['Rules', 'Edit forwarding rules stored in MongoDB.'],
  checks: ['Connectivity', 'Probe route exit IPs and rule health.'],
  nodes: ['Nodes', 'Heartbeat, config version, traffic, and node errors.'],
  servers: ['Servers', 'SSH inventory, remote provisioning, and node deployment jobs.'],
  certs: ['Domains', 'Cloudflare DNS, node assignment, and certificate bundles.']
};

function $(id) { return document.getElementById(id); }

function showTab(name) {
  ['overview','users','rules','checks','nodes','servers','certs'].forEach(tab => {
    $('tab' + cap(tab)).classList.toggle('active', tab === name);
    $('tabBtn' + cap(tab)).classList.toggle('active', tab === name);
  });
  $('pageTitle').textContent = titles[name][0];
  $('pageSubtitle').textContent = titles[name][1];
  if (name === 'nodes') {
    loadConfigStatus();
    loadNodes();
  }
  if (name === 'servers') {
    loadServers();
    loadJobs();
    loadEvents();
  }
  if (name === 'certs') {
    loadCloudflareSettings();
    loadDomains();
  }
}

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

function setStatus(message, tone) {
  const el = $('authStatus');
  el.textContent = message || '';
  el.style.color = tone === 'err' ? 'var(--danger)' : tone === 'warn' ? 'var(--warn)' : 'var(--muted)';
}

function withAuthHeaders(headers) {
  const out = Object.assign({}, headers || {});
  if (adminToken) out['X-Admin-Token'] = adminToken;
  return out;
}

async function fetchJSON(url, options) {
  const opts = options || {};
  opts.headers = withAuthHeaders(opts.headers);
  const res = await fetch(url, opts);
  let data = {};
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function isoToLocalInput(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  if (isNaN(date.getTime())) return '';
  const tzOffset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - tzOffset).toISOString().slice(0, 16);
}

function localInputToISO(value) {
  if (!value) return '';
  const date = new Date(value);
  if (isNaN(date.getTime())) return '';
  return date.toISOString();
}

function userStatus(u) {
  if (u.enabled === false) return 'disabled';
  if (u.expires_at) {
    const date = new Date(u.expires_at);
    if (!isNaN(date.getTime())) {
      if (date.getTime() <= Date.now()) return 'expired';
      return 'expires ' + date.toLocaleString();
    }
  }
  return 'active';
}

function statusPill(status) {
  const cls = status === 'active' || status === 'ok' || status === 'online' || status === 'synced' ? 'ok' : status === 'disabled' || status === 'stale' || status === 'unknown' ? 'warn' : status === 'expired' || status === 'error' || status === 'offline' ? 'err' : '';
  return '<span class="pill ' + cls + '">' + escapeHTML(status) + '</span>';
}

function escapeHTML(value) {
  return String(value || '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function escapeJS(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

function normalizeAdminToken(value) {
  let token = String(value || '').trim();
  if (token.indexOf('GLIDER_ADMIN_TOKEN=') === 0) token = token.slice('GLIDER_ADMIN_TOKEN='.length).trim();
  if (token.toLowerCase().indexOf('bearer ') === 0) token = token.slice(7).trim();
  if ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"))) {
    token = token.slice(1, -1).trim();
  }
  return token;
}

function loadStoredAdminToken() {
  try {
    return localStorage.getItem('gliderAdminToken') || '';
  } catch (e) {
    return '';
  }
}

function persistAdminToken(token) {
  try {
    if (token) localStorage.setItem('gliderAdminToken', token);
    else localStorage.removeItem('gliderAdminToken');
    return true;
  } catch (e) {
    return false;
  }
}

async function verifyAdminToken(token) {
  const res = await fetch('/api/auth/check', {
    method: 'POST',
    headers: token ? {'X-Admin-Token': token} : {},
    cache: 'no-store'
  });
  let data = {};
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function saveToken() {
  const previous = adminToken;
  const token = normalizeAdminToken($('adminToken').value);
  $('adminToken').value = token;
  const btn = $('saveTokenBtn');
  if (btn) btn.disabled = true;
  setStatus(token ? 'Checking token via /api/auth/check...' : 'Clearing token...');
  try {
    if (token) await verifyAdminToken(token);
    adminToken = token;
    const persisted = persistAdminToken(token);
    setStatus(token ? (persisted ? 'Token saved' : 'Token works for this page; browser storage is unavailable') : 'Token cleared', persisted ? '' : 'warn');
    if (token) await refreshAll({ preserveStatus: true });
  } catch (e) {
    adminToken = previous;
    $('adminToken').value = previous;
    setStatus('Token not saved: ' + e.message, 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}

function clearToken() {
  adminToken = '';
  $('adminToken').value = '';
  persistAdminToken('');
  setStatus('Token cleared');
}

async function refreshAll(opts) {
  const options = opts || {};
  await Promise.all([loadConfigStatus(options), loadRules(options), loadUsers(options), loadNodes(options), loadServers(options), loadJobs(options), loadEvents(options), loadDomains(options), loadCloudflareSettings(options), loadLatestRulesHealth()]);
  renderStats();
}

function maybeClearStatus(options) {
  if (!options || !options.preserveStatus) setStatus('');
}

async function loadConfigStatus(options) {
  try {
    configStatus = await fetchJSON('/api/config/status');
    renderStats();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadRules(options) {
  try {
    rulesCache = await fetchJSON('/api/rules');
    renderRules();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadUsers(options) {
  try {
    usersCache = await fetchJSON('/api/users');
    renderUsers();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadNodes(options) {
  try {
    const data = await fetchJSON('/api/nodes');
    nodesCache = data.nodes || [];
    renderNodes(data.now);
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadDomains(options) {
  try {
    const data = await fetchJSON('/api/domains');
    domainsCache = data.domains || [];
    renderDomains();
    renderDomainNodeControls();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadServers(options) {
  try {
    const data = await fetchJSON('/api/servers');
    serversCache = data.servers || [];
    renderServers();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadJobs(options) {
  try {
    const data = await fetchJSON('/api/jobs?limit=50');
    jobsCache = data.jobs || [];
    renderJobs();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadEvents(options) {
  try {
    const data = await fetchJSON('/api/events?limit=100');
    eventsCache = data.events || [];
    renderEvents();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

async function loadCloudflareSettings(options) {
  try {
    cloudflareSettings = await fetchJSON('/api/settings/cloudflare');
    renderCloudflareSettings();
    maybeClearStatus(options);
  } catch (e) {
    setStatus(e.message, 'err');
  }
}

function renderCloudflareSettings() {
  const s = cloudflareSettings || {};
  if (!$('cfTokenStatus')) return;
  $('cfTokenStatus').textContent = s.configured ? 'configured' : 'not configured';
  $('cfTokenStatus').className = 'pill ' + (s.configured ? 'ok' : 'warn');
  $('cfAccountID').value = s.account_id || '';
  $('cfACMEEmail').value = s.acme_email || '';
  $('cfACMEDirectory').value = s.acme_directory_url || '';
  $('cfAPIToken').value = '';
  const lines = [
    'token: ' + (s.configured ? escapeHTML(s.masked_token || 'configured') : 'not configured'),
    'source: ' + escapeHTML(s.source || '-'),
    'token owner: ' + (s.account_id ? 'account token' : 'user token'),
    'account id: ' + escapeHTML(s.account_id || '-'),
    'acme email: ' + escapeHTML(s.acme_email || '-'),
    'acme directory: ' + escapeHTML(s.acme_directory_url || "Let's Encrypt production"),
    'updated: ' + escapeHTML(formatDate(s.updated_at))
  ];
  $('cfSettingsResult').innerHTML = lines.join('\n');
}

function renderStats() {
  const active = usersCache.filter(u => userStatus(u) === 'active').length;
  const online = nodesCache.filter(n => nodeStatus(n) === 'online').length;
  const healthy = rulesHealthCache ? rulesHealthCache.results.filter(r => r.status === 'ok').length + '/' + rulesHealthCache.results.length : '-';
  const centralVersion = configStatus.config_version || '';
  const synced = centralVersion ? nodesCache.filter(n => n.config_version === centralVersion).length + '/' + nodesCache.length : '-';
  $('statUsers').textContent = usersCache.length;
  $('statActiveUsers').textContent = active;
  $('statRules').textContent = rulesCache.length;
  $('statHealthyRules').textContent = healthy;
  $('statNodesOnline').textContent = online;
  $('statConfigVersion').textContent = shortHash(centralVersion);
  $('statNodesSynced').textContent = synced;
  $('usersCount').textContent = visibleUsers().length + '/' + usersCache.length;
  $('rulesCount').textContent = visibleRules().length + '/' + rulesCache.length;
  $('nodesCount').textContent = visibleNodes().length + '/' + nodesCache.length;
  if ($('serversCount')) $('serversCount').textContent = visibleServers().length + '/' + serversCache.length;
  if ($('jobsCount')) $('jobsCount').textContent = jobsCache.length;
  if ($('eventsCount')) $('eventsCount').textContent = eventsCache.length;
  if ($('domainsCount')) $('domainsCount').textContent = visibleDomains().length + '/' + domainsCache.length;
}

function visibleRules() {
  const q = (($('ruleSearch') && $('ruleSearch').value) || '').toLowerCase().trim();
  if (!q) return rulesCache;
  return rulesCache.filter(r => [r.name, r.content].join(' ').toLowerCase().includes(q));
}

function visibleUsers() {
  const q = (($('userSearch') && $('userSearch').value) || '').toLowerCase().trim();
  if (!q) return usersCache;
  return usersCache.filter(u => [u.username, u.rule, userStatus(u)].join(' ').toLowerCase().includes(q));
}

function visibleDomains() {
  const q = (($('domainSearch') && $('domainSearch').value) || '').toLowerCase().trim();
  if (!q) return domainsCache;
  return domainsCache.filter(d => [d.domain, d.active_node_id, (d.node_ids || []).join(' '), domainStatus(d), dnsStatus(d), certStatus(d), certRenewStatus(d), domainCertSyncStatus(d), domainFailoverStatus(d)].join(' ').toLowerCase().includes(q));
}

function visibleServers() {
  const q = (($('serverSearch') && $('serverSearch').value) || '').toLowerCase().trim();
  if (!q) return serversCache;
  return serversCache.filter(s => [s.server_id, s.name, s.node_id, s.host, s.status, s.image].join(' ').toLowerCase().includes(q));
}

function visibleNodes() {
  const q = (($('nodeSearch') && $('nodeSearch').value) || '').toLowerCase().trim();
  if (!q) return nodesCache;
  return nodesCache.filter(n => [
    n.node_id,
    n.hostname,
    n.public_ip,
    n.glider_version,
    n.config_version,
    n.cert_version,
    n.error,
    n.cert_error,
    n.proxy_status,
    n.proxy_exit_ip,
    n.proxy_org,
    n.proxy_error,
    n.auth_mode,
    nodeStatus(n),
    configSyncStatus(n)
  ].join(' ').toLowerCase().includes(q));
}

function renderRules() {
  const list = $('rulesList');
  const sel = $('userRule');
  const visible = visibleRules();
  list.innerHTML = '';
  sel.innerHTML = '<option value="">(default)</option>';
  if (!visible.length) list.innerHTML = '<div class="empty">No matching rules.</div>';
  visible.forEach(r => {
    const item = document.createElement('div');
    item.className = 'item';
    item.innerHTML = '<div class="item-main"><div class="item-title">' + escapeHTML(r.name) + '</div><div class="item-sub">updated ' + formatDate(r.updated_at) + '</div></div><div class="item-actions"><button>IP Info</button></div>';
    item.querySelector('.item-main').onclick = () => selectRule(r.name);
    item.querySelector('button').onclick = () => runCheck({ type: 'rule', name: r.name, target: ipInfoTarget(), timeout: $('checkTimeout').value || '8s', resultId: 'ruleCheckResult', probe: 'ipinfo' });
    list.appendChild(item);
  });
  rulesCache.forEach(r => {
    const opt = document.createElement('option');
    opt.value = r.name;
    opt.textContent = r.name;
    sel.appendChild(opt);
  });
  renderStats();
}

function renderUsers() {
  const list = $('usersList');
  const visible = visibleUsers();
  list.innerHTML = '';
  if (!visible.length) list.innerHTML = '<div class="empty">No matching users.</div>';
  visible.forEach(u => {
    const status = userStatus(u);
    const item = document.createElement('div');
    item.className = 'item';
    item.innerHTML = '<div class="item-main"><div class="item-title">' + escapeHTML(u.username) + '</div><div class="item-sub">' + escapeHTML(u.rule || '(default)') + ' · ' + escapeHTML(status) + '</div></div><div class="item-actions">' + statusPill(status) + '<button>IP Info</button></div>';
    item.querySelector('.item-main').onclick = () => selectUser(u);
    item.querySelector('button').onclick = () => runCheck({ type: 'user', name: u.username, target: ipInfoTarget(), timeout: $('checkTimeout').value || '8s', resultId: 'userCheckResult', probe: 'ipinfo' });
    list.appendChild(item);
  });
  renderStats();
}

function renderNodes(nowValue) {
  const wrap = $('nodesTable');
  const visible = visibleNodes();
  if (!visible.length) {
    wrap.innerHTML = '<div class="empty">' + (nodesCache.length ? 'No matching nodes.' : 'No nodes have reported yet.') + '</div>';
    renderStats();
    return;
  }
  wrap.innerHTML = '<table><thead><tr><th>Node</th><th>Status</th><th>Public IP</th><th>Token</th><th>Versions</th><th>Traffic</th><th>Top Users</th><th>Top Rules</th><th>Top Dialers</th><th>Uptime</th><th>Last heartbeat</th><th>Error</th><th>Actions</th></tr></thead><tbody>' + visible.map(n => {
    const status = nodeStatus(n);
    const configSync = configSyncStatus(n);
    return '<tr>' +
      '<td><strong>' + escapeHTML(n.node_id) + '</strong><div class="compact">' + escapeHTML(n.hostname || '-') + '</div></td>' +
      '<td>' + statusPill(status) + '</td>' +
      '<td class="mono">' + escapeHTML(n.public_ip || '-') + proxyProbeSummary(n) + '</td>' +
      '<td>' + statusPill(n.has_token ? 'dedicated' : 'shared') + '<div class="compact">last auth ' + escapeHTML(n.auth_mode || '-') + '</div>' + (n.token_set_at ? '<div class="compact">' + escapeHTML(formatDate(n.token_set_at)) + '</div>' : '') + '</td>' +
      '<td class="mono">config ' + escapeHTML(shortHash(n.config_version)) + ' ' + statusPill(configSync) + '<div class="compact mono">central ' + escapeHTML(shortHash(configStatus.config_version)) + '</div><div class="compact mono">cert ' + escapeHTML(shortHash(n.cert_version)) + '</div></td>' +
      '<td>' + escapeHTML(formatBytes((n.rx_bytes || 0) + (n.tx_bytes || 0))) + '<div class="compact">rx ' + escapeHTML(formatBytes(n.rx_bytes || 0)) + ' / tx ' + escapeHTML(formatBytes(n.tx_bytes || 0)) + '</div></td>' +
      '<td>' + trafficSummary((n.traffic || {}).users) + '</td>' +
      '<td>' + trafficSummary((n.traffic || {}).rules) + '</td>' +
      '<td>' + trafficSummary((n.traffic || {}).dialers) + '</td>' +
      '<td>' + escapeHTML(formatDuration(n.uptime || 0)) + '</td>' +
      '<td>' + escapeHTML(formatDate(n.updated_at)) + '</td>' +
      '<td>' + escapeHTML(n.error || '-') + (n.cert_error ? '<div class="compact">cert ' + escapeHTML(n.cert_error) + '</div>' : '') + '</td>' +
      '<td><button data-node-action="set-token" data-node-id="' + escapeHTML(n.node_id) + '">Set Token</button><button data-node-action="clear-token" data-node-id="' + escapeHTML(n.node_id) + '">Clear Token</button><button class="danger" data-node-action="delete" data-node-id="' + escapeHTML(n.node_id) + '">Delete</button></td>' +
      '</tr>';
  }).join('') + '</tbody></table>';
  document.querySelectorAll('[data-node-action]').forEach(btn => {
    const nodeID = btn.getAttribute('data-node-id') || '';
    const action = btn.getAttribute('data-node-action') || '';
    btn.onclick = () => {
      if (action === 'set-token') return setNodeToken(nodeID);
      if (action === 'clear-token') return clearNodeToken(nodeID);
      if (action === 'delete') return deleteNode(nodeID);
    };
  });
  renderStats();
}

function renderServers() {
  const list = $('serversList');
  if (!list) return;
  const visible = visibleServers();
  list.innerHTML = '';
  if (!visible.length) list.innerHTML = '<div class="empty">No matching servers.</div>';
  visible.forEach(s => {
    const item = document.createElement('div');
    item.className = 'item';
    const status = s.status || 'saved';
    item.innerHTML = '<div class="item-main"><div class="item-title">' + escapeHTML(s.server_id) + '</div><div class="item-sub">' + escapeHTML(s.host || '-') + ' · node ' + escapeHTML(s.node_id || '-') + ' · ' + escapeHTML(status) + '</div></div><div class="item-actions">' + statusPill(serverStatusTone(status)) + '<button>Deploy</button></div>';
    item.querySelector('.item-main').onclick = () => selectServer(s.server_id);
    item.querySelector('button').onclick = () => {
      selectServerIntoForm(s);
      deployServerNode();
    };
    list.appendChild(item);
  });
  renderStats();
}

function serverStatusTone(status) {
  status = String(status || '').toLowerCase();
  if (status === 'ssh_ok' || status === 'preflight_ok' || status === 'deployed' || status === 'onboarded' || status === 'restarted' || status === 'upgraded') return 'ok';
  if (status === 'heartbeat_pending') return 'warn';
  if (status === 'unreachable' || status === 'preflight_failed' || status === 'error') return 'error';
  return status || 'saved';
}

function proxyProbeSummary(n) {
  const status = n.proxy_status || '';
  if (!status) return '';
  const cls = status === 'ok' ? 'ok' : 'err';
  const lines = ['<div class="compact">' + statusPill(status) + ' proxy ' + escapeHTML(formatDate(n.proxy_checked_at)) + '</div>'];
  if (n.proxy_exit_ip || n.proxy_org) lines.push('<div class="compact mono">exit ' + escapeHTML(n.proxy_exit_ip || '-') + ' ' + escapeHTML(n.proxy_org || '') + '</div>');
  if (n.proxy_error) lines.push('<div class="compact">' + escapeHTML(n.proxy_error) + '</div>');
  return lines.join('');
}

function renderJobs() {
  const wrap = $('jobsTable');
  if (!wrap) return;
  if (!jobsCache.length) {
    wrap.innerHTML = '<div class="empty">No jobs yet.</div>';
    renderStats();
    return;
  }
  wrap.innerHTML = '<table><thead><tr><th>Job</th><th>Status</th><th>Target</th><th>Created</th><th>Finished</th><th>Error</th><th>Logs</th></tr></thead><tbody>' + jobsCache.map(job => {
    const logs = (job.logs || []).slice(-4).map(l => '<div class="compact">' + escapeHTML(formatDate(l.at)) + ' ' + escapeHTML(l.message) + '</div>').join('');
    const steps = jobStepsSummary(job);
    return '<tr>' +
      '<td><strong>' + escapeHTML(job.type || '-') + '</strong><div class="compact mono">' + escapeHTML(job.job_id || '-') + '</div></td>' +
      '<td>' + statusPill(job.status || 'unknown') + '</td>' +
      '<td>server ' + escapeHTML(job.server_id || '-') + '<div class="compact">node ' + escapeHTML(job.node_id || '-') + '</div></td>' +
      '<td>' + escapeHTML(formatDate(job.created_at)) + '</td>' +
      '<td>' + escapeHTML(formatDate(job.finished_at)) + '</td>' +
      '<td>' + escapeHTML(job.error || '-') + '</td>' +
      '<td>' + steps + (logs || '<span class="compact">-</span>') + '</td>' +
      '</tr>';
  }).join('') + '</tbody></table>';
  renderStats();
}

function jobStepsSummary(job) {
  const steps = (job && job.steps) || [];
  if (!steps.length) return '';
  return '<div class="job-steps">' + steps.map(step => {
    const status = step.status || 'unknown';
    const when = step.finished_at || step.started_at;
    const err = step.error ? '<div class="compact">' + escapeHTML(step.error) + '</div>' : '';
    return '<div class="compact">' + statusPill(status) + ' <span class="mono">' + escapeHTML(step.name || '-') + '</span> ' + escapeHTML(formatDate(when)) + err + '</div>';
  }).join('') + '</div>';
}

function renderEvents() {
  const wrap = $('eventsTable');
  if (!wrap) return;
  if (!eventsCache.length) {
    wrap.innerHTML = '<div class="empty">No events yet.</div>';
    renderStats();
    return;
  }
  wrap.innerHTML = '<table><thead><tr><th>Time</th><th>Event</th><th>Target</th><th>Message</th><th>Metadata</th></tr></thead><tbody>' + eventsCache.map(event => {
    return '<tr>' +
      '<td>' + escapeHTML(formatDate(event.created_at)) + '</td>' +
      '<td>' + statusPill(event.severity || 'info') + '<div class="compact mono">' + escapeHTML(event.type || '-') + '</div></td>' +
      '<td>server ' + escapeHTML(event.server_id || '-') + '<div class="compact">node ' + escapeHTML(event.node_id || '-') + '</div><div class="compact">domain ' + escapeHTML(event.domain || '-') + '</div></td>' +
      '<td>' + escapeHTML(event.message || '-') + '<div class="compact mono">' + escapeHTML(event.job_id || '') + '</div></td>' +
      '<td class="compact mono">' + escapeHTML(eventMetadata(event.metadata)) + '</td>' +
      '</tr>';
  }).join('') + '</tbody></table>';
  renderStats();
}

function eventMetadata(metadata) {
  if (!metadata) return '-';
  try {
    return JSON.stringify(metadata);
  } catch (e) {
    return String(metadata);
  }
}

async function selectServer(serverID) {
  const s = await fetchJSON('/api/servers/' + encodeURIComponent(serverID));
  selectServerIntoForm(s);
  showTab('servers');
}

function selectServerIntoForm(s) {
  s = s || {};
  $('serverID').value = s.server_id || '';
  $('serverNodeID').value = s.node_id || s.server_id || '';
  $('serverName').value = s.name || '';
  $('serverHost').value = s.host || '';
  $('serverSSHPort').value = s.ssh_port || 22;
  $('serverSSHUser').value = s.ssh_user || 'root';
  $('serverAuthType').value = s.auth_type || 'auto';
  $('serverDeployDir').value = s.deploy_dir || '/root/data/docker_data/glider';
  $('serverImage').value = s.image || 'ghcr.io/ferryboatseranade/glider:latest';
  $('upgradeImage').value = s.image || '';
  $('serverProxyPorts').value = (s.proxy_ports || ['443:443','8443:8443']).join(',');
  $('serverTrafficIface').value = s.traffic_iface || 'eth0';
  if (!$('deployCentralURL').value) $('deployCentralURL').value = defaultCentralURL();
  $('serverPassword').value = '';
  $('serverPrivateKey').value = '';
  $('serverPassphrase').value = '';
  $('selectedServerStatus').textContent = s.status || 'selected';
  renderServerResult(s);
}

function renderServerResult(s) {
  s = s || {};
  const lines = [
    'server: ' + escapeHTML(s.server_id || '-'),
    'host: ' + escapeHTML(s.host || '-') + ':' + escapeHTML(s.ssh_port || 22),
    'ssh user: ' + escapeHTML(s.ssh_user || 'root'),
    'node id: ' + escapeHTML(s.node_id || '-'),
    'deploy dir: ' + escapeHTML(s.deploy_dir || '-'),
    'image: ' + escapeHTML(s.image || '-'),
    'credentials: password ' + (s.has_password ? 'yes' : 'no') + ', private key ' + (s.has_private_key ? 'yes' : 'no'),
    'status: ' + escapeHTML(s.status || '-'),
    'last ssh test: ' + escapeHTML(formatDate(s.last_test_at)),
    'last deploy: ' + escapeHTML(formatDate(s.last_deploy_at)),
    'last deploy job: ' + escapeHTML(s.last_deploy_job || '-')
  ];
  if (s.last_error) lines.push('error: ' + escapeHTML(s.last_error));
  $('serverResult').innerHTML = lines.join('\n');
}

function serverPayload() {
  const payload = {
    server_id: $('serverID').value.trim(),
    node_id: $('serverNodeID').value.trim(),
    name: $('serverName').value.trim(),
    host: $('serverHost').value.trim(),
    ssh_port: Number($('serverSSHPort').value || 22),
    ssh_user: $('serverSSHUser').value.trim() || 'root',
    auth_type: $('serverAuthType').value || 'auto',
    deploy_dir: $('serverDeployDir').value.trim() || '/root/data/docker_data/glider',
    image: $('serverImage').value.trim() || 'ghcr.io/ferryboatseranade/glider:latest',
    proxy_ports: splitCSV($('serverProxyPorts').value),
    traffic_iface: $('serverTrafficIface').value.trim() || 'eth0'
  };
  const password = $('serverPassword').value;
  const privateKey = $('serverPrivateKey').value;
  const passphrase = $('serverPassphrase').value;
  if (password) payload.password = password;
  if (privateKey) payload.private_key = privateKey;
  if (passphrase) payload.passphrase = passphrase;
  return payload;
}

async function saveServer() {
  const payload = serverPayload();
  const saved = await fetchJSON('/api/servers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  $('selectedServerStatus').textContent = 'saved';
  selectServerIntoForm(saved);
  await loadServers();
}

async function deleteServer() {
  const serverID = $('serverID').value.trim();
  if (!serverID) return;
  if (!confirm('Delete server ' + serverID + '?')) return;
  await fetchJSON('/api/servers/' + encodeURIComponent(serverID), { method: 'DELETE' });
  clearServerForm();
  await loadServers();
}

function clearServerForm() {
  ['serverID','serverNodeID','serverName','serverHost','serverPassword','serverPrivateKey','serverPassphrase','deployNodeToken','upgradeImage'].forEach(id => { $(id).value = ''; });
  $('deployCentralURL').value = defaultCentralURL();
  $('serverSSHPort').value = 22;
  $('serverSSHUser').value = 'root';
  $('serverAuthType').value = 'auto';
  $('serverDeployDir').value = '/root/data/docker_data/glider';
  $('serverImage').value = 'ghcr.io/ferryboatseranade/glider:latest';
  $('serverProxyPorts').value = '443:443,8443:8443';
  $('serverTrafficIface').value = 'eth0';
  $('deploySyncInterval').value = '30s';
  $('deployWaitHeartbeat').value = 120;
  $('deployInstallDocker').checked = true;
  $('selectedServerStatus').textContent = 'new';
  $('serverResult').textContent = 'Save a server, test SSH, then deploy node mode.';
}

async function testServerSSH() {
  const saved = await fetchJSON('/api/servers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(serverPayload()) });
  selectServerIntoForm(saved);
  $('serverResult').textContent = 'Queued SSH test...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(saved.server_id) + '/test-ssh', { method: 'POST' });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs()]);
}

async function deployServerNode() {
  const saved = await fetchJSON('/api/servers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(serverPayload()) });
  const nodeToken = $('deployNodeToken').value.trim();
  if (!nodeToken) {
    $('serverResult').textContent = 'Node token is required for deployment.';
    return;
  }
  const payload = {
    central_url: $('deployCentralURL').value.trim(),
    node_token: nodeToken,
    image: $('serverImage').value.trim(),
    deploy_dir: $('serverDeployDir').value.trim(),
    proxy_ports: splitCSV($('serverProxyPorts').value),
    sync_interval: $('deploySyncInterval').value.trim() || '30s',
    install_docker: $('deployInstallDocker').checked,
    wait_heartbeat_seconds: Number($('deployWaitHeartbeat').value || 120)
  };
  $('serverResult').textContent = 'Queued node deployment...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(saved.server_id) + '/deploy-node', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs(), loadNodes()]);
}

async function onboardServerNode() {
  const saved = await fetchJSON('/api/servers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(serverPayload()) });
  selectServerIntoForm(saved);
  const payload = {
    central_url: $('deployCentralURL').value.trim() || defaultCentralURL(),
    image: $('serverImage').value.trim(),
    deploy_dir: $('serverDeployDir').value.trim(),
    proxy_ports: splitCSV($('serverProxyPorts').value),
    sync_interval: $('deploySyncInterval').value.trim() || '30s',
    install_docker: $('deployInstallDocker').checked,
    wait_heartbeat_seconds: Number($('deployWaitHeartbeat').value || 120)
  };
  $('serverResult').textContent = 'Queued node onboarding...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(saved.server_id) + '/onboard-node', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs(), loadEvents(), loadNodes()]);
}

async function preflightServerNode() {
  const saved = await fetchJSON('/api/servers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(serverPayload()) });
  selectServerIntoForm(saved);
  $('serverResult').textContent = 'Queued node preflight...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(saved.server_id) + '/preflight-node', { method: 'POST' });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs(), loadEvents(), loadNodes()]);
}

async function restartServerNode() {
  const serverID = $('serverID').value.trim();
  if (!serverID) return;
  $('serverResult').textContent = 'Queued node restart...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(serverID) + '/restart-node', { method: 'POST' });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs(), loadEvents(), loadNodes()]);
}

async function upgradeServerNode() {
  const serverID = $('serverID').value.trim();
  if (!serverID) return;
  const image = $('upgradeImage').value.trim() || $('serverImage').value.trim();
  if (!image) {
    $('serverResult').textContent = 'Upgrade image is required.';
    return;
  }
  $('serverResult').textContent = 'Queued node upgrade...';
  const job = await fetchJSON('/api/servers/' + encodeURIComponent(serverID) + '/upgrade-node', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ image })
  });
  await pollJob(job.job_id, 'serverResult');
  await Promise.all([loadServers(), loadJobs(), loadEvents(), loadNodes()]);
}

async function pollJob(jobID, resultID) {
  const el = $(resultID);
  for (let i = 0; i < 120; i++) {
    const job = await fetchJSON('/api/jobs/' + encodeURIComponent(jobID));
    el.innerHTML = renderJobDetail(job);
    await Promise.all([loadJobs({ preserveStatus: true }), loadEvents({ preserveStatus: true })]);
    if (job.status === 'succeeded' || job.status === 'failed') return job;
    await sleep(2000);
  }
  return null;
}

function renderJobDetail(job) {
  const lines = [
    'job: ' + escapeHTML(job.job_id || '-'),
    'type: ' + escapeHTML(job.type || '-'),
    'status: ' + escapeHTML(job.status || '-'),
    'server: ' + escapeHTML(job.server_id || '-'),
    'node: ' + escapeHTML(job.node_id || '-')
  ];
  if (job.error) lines.push('error: ' + escapeHTML(job.error));
  if ((job.steps || []).length) {
    lines.push('steps:');
    (job.steps || []).forEach(step => {
      const err = step.error ? ' error=' + escapeHTML(step.error) : '';
      lines.push('  ' + escapeHTML(step.status || 'unknown') + ' ' + escapeHTML(step.name || '-') + ' ' + escapeHTML(formatDate(step.finished_at || step.started_at)) + err);
    });
  }
  (job.logs || []).forEach(log => lines.push(formatDate(log.at) + ' ' + escapeHTML(log.message)));
  return lines.join('\n');
}

function splitCSV(value) {
  return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function configSyncStatus(n) {
  const central = configStatus.config_version || '';
  if (!central || !n.config_version) return 'unknown';
  return n.config_version === central ? 'synced' : 'stale';
}

function trafficSummary(items) {
  items = (items || []).slice().sort((a, b) => ((b.rx_bytes || 0) + (b.tx_bytes || 0)) - ((a.rx_bytes || 0) + (a.tx_bytes || 0))).slice(0, 3);
  if (!items.length) return '<span class="compact">-</span>';
  return items.map(i => '<div class="compact"><span class="mono">' + escapeHTML(i.name || '-') + '</span> ' + escapeHTML(formatBytes((i.rx_bytes || 0) + (i.tx_bytes || 0))) + '</div>').join('');
}

async function deleteNode(nodeID) {
  if (!nodeID) return;
  if (!confirm('Delete node ' + nodeID + '? It will reappear on the next heartbeat if still running.')) return;
  await fetchJSON('/api/nodes/' + encodeURIComponent(nodeID), { method: 'DELETE' });
  await loadNodes();
  renderDomainNodeControls();
}

async function setNodeToken(nodeID) {
  if (!nodeID) return;
  const token = prompt('New token for node ' + nodeID + ' (at least 16 characters)');
  if (token === null) return;
  const trimmed = token.trim();
  if (!trimmed) return;
  await fetchJSON('/api/nodes/' + encodeURIComponent(nodeID) + '/token', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ token: trimmed }) });
  await loadNodes();
}

async function clearNodeToken(nodeID) {
  if (!nodeID) return;
  if (!confirm('Clear dedicated token for node ' + nodeID + '? It will fall back to the shared node token.')) return;
  await fetchJSON('/api/nodes/' + encodeURIComponent(nodeID) + '/token', { method: 'DELETE' });
  await loadNodes();
}

function renderDomains() {
  const list = $('domainsList');
  if (!list) return;
  const visible = visibleDomains();
  list.innerHTML = '';
  if (!visible.length) list.innerHTML = '<div class="empty">No matching domains.</div>';
  visible.forEach(d => {
    const item = document.createElement('div');
    item.className = 'item';
    item.innerHTML = '<div class="item-main"><div class="item-title">' + escapeHTML(d.domain) + '</div><div class="item-sub">' + escapeHTML(d.active_node_id || '-') + ' · ' + escapeHTML(dnsStatus(d)) + ' · ' + escapeHTML(certStatus(d)) + ' · ' + escapeHTML(certRenewStatus(d)) + ' · ' + escapeHTML(domainCertSyncStatus(d)) + ' · ' + escapeHTML(domainFailoverStatus(d)) + '</div></div><div class="item-actions">' + statusPill(domainStatus(d)) + '<button>DNS</button></div>';
    item.querySelector('.item-main').onclick = () => selectDomain(d.domain);
    item.querySelector('button').onclick = () => {
      selectDomainIntoForm(d);
      syncDomainDNS();
    };
    list.appendChild(item);
  });
  renderStats();
}

function renderDomainNodeControls() {
  const active = $('domainActiveNode');
  const primary = $('domainPrimaryNode');
  const list = $('domainNodeList');
  if (!active || !list) return;
  const selectedActive = active.value;
  const selectedPrimary = primary ? primary.value : '';
  const selectedNodes = selectedDomainNodes();
  active.innerHTML = '<option value="">Select node</option>';
  if (primary) primary.innerHTML = '<option value="">First assigned node</option>';
  list.innerHTML = '';
  nodesCache.forEach(n => {
    const opt = document.createElement('option');
    opt.value = n.node_id;
    opt.textContent = n.node_id + (n.public_ip ? ' · ' + n.public_ip : '');
    active.appendChild(opt);
    if (primary) {
      const primaryOpt = document.createElement('option');
      primaryOpt.value = n.node_id;
      primaryOpt.textContent = n.node_id + (n.public_ip ? ' · ' + n.public_ip : '');
      primary.appendChild(primaryOpt);
    }

    const label = document.createElement('label');
    label.innerHTML = '<input type="checkbox" value="' + escapeHTML(n.node_id) + '"> <span>' + escapeHTML(n.node_id) + ' <span class="compact">' + escapeHTML(n.public_ip || '') + '</span></span>';
    const input = label.querySelector('input');
    input.checked = selectedNodes.includes(n.node_id);
    list.appendChild(label);
  });
  if (selectedActive) active.value = selectedActive;
  if (primary && selectedPrimary) primary.value = selectedPrimary;
}

function selectedDomainNodes() {
  const list = $('domainNodeList');
  if (!list) return [];
  return Array.from(list.querySelectorAll('input[type=checkbox]:checked')).map(i => i.value);
}

function domainStatus(d) {
  if (d.runtime && d.runtime.status) return d.runtime.status;
  if (!d.enabled) return 'disabled';
  if (d.certificate && d.certificate.last_error) return 'error';
  if (d.cloudflare && d.cloudflare.last_error) return 'error';
  return 'active';
}

function dnsStatus(d) {
  if (d.runtime && d.runtime.dns_status) return d.runtime.dns_status;
  const cf = d.cloudflare || {};
  if (cf.last_error) return 'dns error';
  if (cf.last_synced_at) return 'dns synced';
  return 'dns pending';
}

function certStatus(d) {
  if (d.runtime && d.runtime.cert_status) return d.runtime.cert_status;
  const cert = d.certificate || {};
  if (cert.last_error) return 'cert error';
  if (!cert.version) return 'cert missing';
  if (cert.expires_at) {
    const exp = new Date(cert.expires_at).getTime();
    if (!isNaN(exp) && exp <= Date.now()) return 'cert expired';
  }
  return 'cert issued';
}

function certRenewStatus(d) {
  if (d.runtime && d.runtime.cert_renew_status) {
    if (d.runtime.cert_renew_status === 'valid' && d.runtime.cert_renew_in_days > 0) return 'renew in ' + d.runtime.cert_renew_in_days + 'd';
    if (d.runtime.cert_renew_status === 'due') return 'renew due';
    if (d.runtime.cert_renew_status === 'expired') return 'renew expired';
    if (d.runtime.cert_renew_status === 'missing') return 'renew due';
    if (d.runtime.cert_renew_status === 'error') return 'renew blocked';
    return 'renew ' + d.runtime.cert_renew_status;
  }
  const cert = d.certificate || {};
  if (cert.last_error) return 'renew blocked';
  if (!cert.version || !cert.expires_at) return 'renew due';
  const exp = new Date(cert.expires_at).getTime();
  if (isNaN(exp)) return 'renew unknown';
  const now = Date.now();
  if (exp <= now) return 'renew expired';
  const renewBeforeDays = Number(d.renew_before_days || 30);
  const renewAt = exp - renewBeforeDays * 24 * 60 * 60 * 1000;
  if (renewAt <= now) return 'renew due';
  return 'renew in ' + Math.ceil((renewAt - now) / (24 * 60 * 60 * 1000)) + 'd';
}

function certDaysRemaining(d) {
  if (d.runtime && typeof d.runtime.cert_days_remaining === 'number') return String(d.runtime.cert_days_remaining);
  const cert = (d && d.certificate) || {};
  if (!cert.expires_at) return '-';
  const exp = new Date(cert.expires_at).getTime();
  if (isNaN(exp)) return '-';
  const days = Math.ceil((exp - Date.now()) / (24 * 60 * 60 * 1000));
  return String(Math.max(0, days));
}

function domainCertSyncStatus(d) {
  if (d.runtime && d.runtime.cert_sync_status) return d.runtime.cert_sync_status;
  const nodes = d.node_ids || [];
  if (!nodes.length) return 'cert nodes none';
  const cert = d.certificate || {};
  if (!cert.version) return 'cert not issued';
  const synced = nodes.filter(nodeID => nodeHasDomainCert(findNode(nodeID), d.domain, cert.version)).length;
  return 'cert synced ' + synced + '/' + nodes.length;
}

function domainFailoverStatus(d) {
  if (d.runtime && d.runtime.failover_status) return d.runtime.failover_status;
  if (!d.enabled || !d.failover_enabled) return 'failover disabled';
  const nodes = d.node_ids || [];
  if (nodes.length < 2) return 'failover needs nodes';
  return 'failover unknown';
}

function nodeHasDomainCert(node, domain, version) {
  if (!node || !domain || !version) return false;
  const target = String(domain).toLowerCase().replace(/\.$/, '');
  const targetVersion = String(version);
  return (node.cert_domains || []).some(cert => {
    const certDomain = String(cert.domain || '').toLowerCase().replace(/\.$/, '');
    return certDomain === target && cert.version === targetVersion;
  });
}

async function selectDomain(domain) {
  const d = await fetchJSON('/api/domains/' + encodeURIComponent(domain));
  selectDomainIntoForm(d);
  showTab('certs');
}

function selectDomainIntoForm(d) {
  d = d || {};
  const cf = d.cloudflare || {};
  const policy = d.failover_policy || {};
  $('domainName').value = d.domain || '';
  $('domainEnabled').checked = d.enabled !== false;
  $('domainFailover').checked = !!d.failover_enabled;
  $('domainManualLock').checked = !!policy.manual_lock;
  $('domainAutoFailback').checked = !!policy.auto_failback;
  $('domainFailThreshold').value = policy.fail_threshold || 3;
  $('domainCooldownSeconds').value = policy.cooldown_seconds || 300;
  $('domainPrimaryNode').value = policy.primary_node_id || '';
  $('domainActiveNode').value = d.active_node_id || '';
  $('domainZoneID').value = cf.zone_id || '';
  $('domainRecordName').value = cf.record_name || d.domain || '';
  $('domainRecordType').value = cf.record_type || '';
  $('domainTTL').value = cf.ttl || 1;
  $('domainProxied').checked = !!cf.proxied;
  $('domainRenewBefore').value = d.renew_before_days || 30;
  $('domainImportFullchain').value = '';
  $('domainImportKey').value = '';
  renderDomainNodeControls();
  const assigned = d.node_ids || [];
  Array.from($('domainNodeList').querySelectorAll('input[type=checkbox]')).forEach(input => {
    input.checked = assigned.includes(input.value);
  });
  $('selectedDomainStatus').textContent = domainStatus(d);
  renderDomainResult(d);
}

function renderDomainResult(d) {
  const cf = (d && d.cloudflare) || {};
  const cert = (d && d.certificate) || {};
  const lines = [
    'domain: ' + escapeHTML((d && d.domain) || '-'),
    'assigned nodes: ' + escapeHTML(((d && d.node_ids) || []).join(', ') || '-'),
    'active node: ' + escapeHTML((d && d.active_node_id) || '-'),
    'dns: ' + escapeHTML(cf.record_type || '-') + ' ' + escapeHTML(cf.record_name || '-') + ' -> ' + escapeHTML((findNode((d && d.active_node_id) || '') || {}).public_ip || '-'),
    'cloudflare zone: ' + escapeHTML(cf.zone_name || cf.zone_id || '-'),
    'cloudflare record: ' + escapeHTML(cf.record_id || '-'),
    'dns synced: ' + escapeHTML(formatDate(cf.last_synced_at)),
    'cert version: ' + escapeHTML(shortHash(cert.version)),
    'cert expires: ' + escapeHTML(formatDate(cert.expires_at)),
    'cert days remaining: ' + escapeHTML(certDaysRemaining(d)),
    'cert renewal: ' + escapeHTML(certRenewStatus(d)),
    'renew before days: ' + escapeHTML((d && d.renew_before_days) || 30),
    'node cert sync: ' + escapeHTML(domainCertSyncStatus(d)),
    'failover: ' + escapeHTML(domainFailoverStatus(d)),
    'failover failures: ' + escapeHTML(failoverFailureSummary(d)),
    'failover cooldown until: ' + escapeHTML(formatDate(((d && d.runtime) || {}).failover_cooldown_until)),
    'manual lock: ' + (((d && d.failover_policy) || {}).manual_lock ? 'yes' : 'no'),
    'primary node: ' + escapeHTML(((d && d.failover_policy) || {}).primary_node_id || (((d && d.node_ids) || [])[0] || '-')),
    'auto failback: ' + (((d && d.failover_policy) || {}).auto_failback ? 'yes' : 'no'),
    'failover ready nodes: ' + escapeHTML(((d && d.runtime) || {}).failover_ready_nodes || 0)
  ];
  if (d && d.runtime && d.runtime.failover_blocked_reason) lines.push('failover blocked: ' + escapeHTML(d.runtime.failover_blocked_reason));
  if (cf.last_error) lines.push('dns error: ' + escapeHTML(cf.last_error));
  if (cert.last_error) lines.push('cert error: ' + escapeHTML(cert.last_error));
  $('domainResult').innerHTML = lines.join('\n');
}

function findNode(nodeID) {
  return nodesCache.find(n => n.node_id === nodeID);
}

function failoverFailureSummary(d) {
  const runtime = (d && d.runtime) || {};
  const policy = (d && d.failover_policy) || {};
  return String(runtime.failover_failures || 0) + '/' + String(runtime.failover_threshold || policy.fail_threshold || 3);
}

async function saveDomain() {
  const domain = $('domainName').value.trim();
  const nodeIDs = selectedDomainNodes();
  const activeNode = $('domainActiveNode').value || nodeIDs[0] || '';
  const payload = {
    domain,
    enabled: $('domainEnabled').checked,
    node_ids: nodeIDs,
    active_node_id: activeNode,
    failover_enabled: $('domainFailover').checked,
    failover_policy: {
      fail_threshold: Number($('domainFailThreshold').value || 3),
      cooldown_seconds: Number($('domainCooldownSeconds').value || 300),
      manual_lock: $('domainManualLock').checked,
      auto_failback: $('domainAutoFailback').checked,
      primary_node_id: $('domainPrimaryNode').value || ''
    },
    renew_before_days: Number($('domainRenewBefore').value || 30),
    dns_provider: 'cloudflare',
    cloudflare: {
      zone_id: $('domainZoneID').value.trim(),
      record_name: $('domainRecordName').value.trim() || domain,
      record_type: $('domainRecordType').value,
      ttl: Number($('domainTTL').value || 1),
      proxied: $('domainProxied').checked
    }
  };
  await fetchJSON('/api/domains', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  $('selectedDomainStatus').textContent = 'saved';
  await loadDomains();
}

function renderDNSPlan(plan, prefix) {
  plan = plan || {};
  const lines = [
    (prefix || 'DNS plan'),
    'action: ' + escapeHTML(plan.action || '-'),
    'domain: ' + escapeHTML(plan.domain || '-'),
    'node: ' + escapeHTML(plan.node_id || '-') + ' (' + escapeHTML(plan.node_public_ip || '-') + ')',
    'zone: ' + escapeHTML(plan.zone_name || '-') + ' (' + escapeHTML(plan.zone_id || '-') + ')',
    'record: ' + escapeHTML(plan.record_type || '-') + ' ' + escapeHTML(plan.record_name || '-'),
    'target: ' + escapeHTML(plan.target_content || '-'),
    'ttl: ' + escapeHTML(plan.ttl || '-'),
    'proxied: ' + (plan.proxied ? 'yes' : 'no')
  ];
  if (plan.existing_id || plan.existing_content) {
    lines.push('existing record: ' + escapeHTML(plan.existing_id || '-') + ' -> ' + escapeHTML(plan.existing_content || '-'));
    lines.push('existing ttl/proxied: ' + escapeHTML(plan.existing_ttl || '-') + ' / ' + (plan.existing_proxied ? 'yes' : 'no'));
  }
  return lines.join('\n');
}

function renderCertPlan(plan, prefix) {
  plan = plan || {};
  const lines = [
    (prefix || 'Certificate plan'),
    'action: ' + escapeHTML(plan.action || '-'),
    'domain: ' + escapeHTML(plan.domain || '-'),
    'zone: ' + escapeHTML(plan.zone_name || '-') + ' (' + escapeHTML(plan.zone_id || '-') + ')',
    'challenge: ' + escapeHTML(plan.challenge_record || '-'),
    'acme email: ' + escapeHTML(plan.email || '-'),
    'acme directory: ' + escapeHTML(plan.directory_url || '-'),
    'current cert: ' + escapeHTML(shortHash(plan.current_version || '')),
    'expires: ' + escapeHTML(formatDate(plan.expires_at)),
    'days remaining: ' + escapeHTML(plan.days_remaining || 0),
    'renew: ' + escapeHTML(plan.renew_status || '-') + ' / in ' + escapeHTML(plan.renew_in_days || 0) + 'd',
    'renew before days: ' + escapeHTML(plan.renew_before_days || 30),
    'assigned nodes: ' + escapeHTML((plan.node_ids || []).join(', ') || '-')
  ];
  return lines.join('\n');
}

async function previewDomainDNS() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  await saveDomain();
  $('domainResult').textContent = 'Building Cloudflare DNS plan...';
  const data = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/dns-plan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ node_id: $('domainActiveNode').value })
  });
  $('domainResult').innerHTML = renderDNSPlan(data.plan, 'DNS preview');
}

async function previewDomainCert() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  await saveDomain();
  $('domainResult').textContent = 'Building certificate plan...';
  const data = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/cert-plan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ email: $('domainACMEEmail').value.trim(), directory_url: $('domainACMEDirectory').value.trim() })
  });
  $('domainResult').innerHTML = renderCertPlan(data.plan, 'Certificate preview');
}

async function saveCloudflareSettings() {
  const payload = {
    account_id: $('cfAccountID').value.trim(),
    acme_email: $('cfACMEEmail').value.trim(),
    acme_directory_url: $('cfACMEDirectory').value.trim()
  };
  const token = $('cfAPIToken').value.trim();
  if (token) payload.api_token = token;
  $('cfSettingsResult').textContent = 'Saving Cloudflare settings...';
  cloudflareSettings = await fetchJSON('/api/settings/cloudflare', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  renderCloudflareSettings();
}

async function verifyCloudflareToken() {
  $('cfSettingsResult').textContent = 'Verifying Cloudflare token...';
  try {
    const payload = {
      domain: ($('cfVerifyDomain') && $('cfVerifyDomain').value.trim()) || '',
      dns_edit_test: !!(($('cfDNSEditTest') && $('cfDNSEditTest').checked))
    };
    const data = await fetchJSON('/api/settings/cloudflare/verify', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const lines = [
      'verify: ok',
      'scope: ' + escapeHTML(data.scope || '-'),
      'status: ' + escapeHTML(data.status || '-'),
      'token id: ' + escapeHTML(data.id || '-'),
      'not before: ' + escapeHTML(formatDate(data.not_before)),
      'expires: ' + escapeHTML(formatDate(data.expires_on))
    ];
    if (data.zone) {
      lines.push('zone: ' + escapeHTML(data.zone.zone_name || '-') + ' (' + escapeHTML(data.zone.zone_id || '-') + ')');
      lines.push('zone read: ' + (data.zone.zone_read_ok ? 'ok' : '-'));
      lines.push('dns edit: ' + (data.zone.dns_edit_ok ? 'ok' : (payload.dns_edit_test ? 'failed' : 'not tested')));
      if (data.zone.test_record) lines.push('test record: ' + escapeHTML(data.zone.test_record));
    }
    $('cfSettingsResult').innerHTML = lines.join('\n');
  } catch (e) {
    $('cfSettingsResult').innerHTML = '<span class="pill err">verify failed</span> ' + escapeHTML(e.message);
  }
}

async function clearCloudflareToken() {
  $('cfSettingsResult').textContent = 'Clearing Cloudflare token...';
  cloudflareSettings = await fetchJSON('/api/settings/cloudflare', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      clear_token: true,
      account_id: $('cfAccountID').value.trim(),
      acme_email: $('cfACMEEmail').value.trim(),
      acme_directory_url: $('cfACMEDirectory').value.trim()
    })
  });
  renderCloudflareSettings();
}

async function deleteDomain() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  await fetchJSON('/api/domains/' + encodeURIComponent(domain), { method: 'DELETE' });
  clearDomainForm();
  await loadDomains();
}

function clearDomainForm() {
  ['domainName','domainZoneID','domainRecordName','domainACMEEmail','domainACMEDirectory','domainImportFullchain','domainImportKey'].forEach(id => { $(id).value = ''; });
  $('domainRecordType').value = '';
  $('domainTTL').value = 1;
  $('domainRenewBefore').value = 30;
  $('domainFailThreshold').value = 3;
  $('domainCooldownSeconds').value = 300;
  $('domainPrimaryNode').value = '';
  $('domainEnabled').checked = true;
  $('domainProxied').checked = false;
  $('domainFailover').checked = false;
  $('domainManualLock').checked = false;
  $('domainAutoFailback').checked = false;
  $('domainActiveNode').value = '';
  Array.from($('domainNodeList').querySelectorAll('input[type=checkbox]')).forEach(i => { i.checked = false; });
  $('selectedDomainStatus').textContent = 'new';
  $('domainResult').textContent = 'Select or save a domain. Cloudflare and ACME credentials stay on the admin server.';
}

async function syncDomainDNS() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  await saveDomain();
  $('domainResult').textContent = 'Syncing Cloudflare DNS...';
  const data = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/sync-dns', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ node_id: $('domainActiveNode').value })
  });
  $('domainResult').innerHTML = renderDNSPlan(data.plan, 'DNS synced') + '\nactive node: ' + escapeHTML(data.active_node || '-');
  await loadDomains();
}

async function issueDomainCert() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  await saveDomain();
  $('domainResult').textContent = 'Issuing certificate with ACME DNS-01...';
  const data = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/issue-cert', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ email: $('domainACMEEmail').value.trim(), directory_url: $('domainACMEDirectory').value.trim() })
  });
  const issued = 'Certificate issued\nversion: ' + escapeHTML(shortHash(data.cert_version)) + '\nexpires: ' + escapeHTML(formatDate(data.expires_at));
  $('domainResult').innerHTML = data.plan ? renderCertPlan(data.plan, issued) : issued;
  await loadDomains();
}

async function importDomainCert() {
  const domain = $('domainName').value.trim();
  if (!domain) return;
  const fullchain = $('domainImportFullchain').value.trim();
  const key = $('domainImportKey').value.trim();
  if (!fullchain || !key) {
    $('domainResult').textContent = 'Fullchain PEM and private key PEM are required.';
    return;
  }
  await saveDomain();
  $('domainResult').textContent = 'Importing certificate...';
  const data = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/import-cert', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ fullchain_pem: fullchain, private_key_pem: key })
  });
  $('domainImportFullchain').value = '';
  $('domainImportKey').value = '';
  $('domainResult').innerHTML = 'Certificate imported\nversion: ' + escapeHTML(shortHash(data.cert_version)) + '\nexpires: ' + escapeHTML(formatDate(data.expires_at));
  await loadDomains();
}

function nodeStatus(n) {
  if (n.error) return 'error';
  const updated = new Date(n.updated_at || 0).getTime();
  if (!updated || isNaN(updated)) return 'offline';
  const age = Date.now() - updated;
  if (age <= 90 * 1000) return 'online';
  if (age <= 5 * 60 * 1000) return 'stale';
  return 'offline';
}

function formatDate(iso) {
  if (!iso) return 'unknown';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'unknown';
  return d.toLocaleString();
}

function formatDuration(seconds) {
  seconds = Number(seconds || 0);
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return d + 'd ' + h + 'h';
  if (h) return h + 'h ' + m + 'm';
  return m + 'm';
}

function formatBytes(bytes) {
  bytes = Number(bytes || 0);
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return (i === 0 ? bytes.toFixed(0) : bytes.toFixed(1)) + ' ' + units[i];
}

function shortHash(value) {
  if (!value) return '-';
  return value.length > 12 ? value.slice(0, 12) : value;
}

function defaultCentralURL() {
  return window.location.origin || '';
}

async function selectRule(name) {
  const rule = await fetchJSON('/api/rules/' + encodeURIComponent(name));
  $('ruleName').value = rule.name;
  $('ruleContent').value = rule.content || '';
  $('selectedRuleStatus').textContent = 'selected';
  showTab('rules');
}

function selectUser(u) {
  $('userName').value = u.username;
  $('userPass').value = u.password || '';
  $('userRule').value = u.rule || '';
  $('userEnabled').checked = u.enabled !== false;
  $('userExpires').value = isoToLocalInput(u.expires_at);
  $('selectedUserStatus').textContent = userStatus(u);
  showTab('users');
}

async function saveRule() {
  const name = $('ruleName').value.trim();
  const content = $('ruleContent').value;
  await fetchJSON('/api/rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name, content }) });
  $('selectedRuleStatus').textContent = 'saved';
  await loadRules();
}

async function deleteRule() {
  const name = $('ruleName').value.trim();
  if (!name) return;
  await fetchJSON('/api/rules/' + encodeURIComponent(name), { method: 'DELETE' });
  $('ruleName').value = '';
  $('ruleContent').value = '';
  $('selectedRuleStatus').textContent = 'new';
  await loadRules();
}

async function saveUser() {
  const username = $('userName').value.trim();
  const password = $('userPass').value;
  const rule = $('userRule').value;
  const enabled = $('userEnabled').checked;
  const expiresAt = localInputToISO($('userExpires').value);
  const payload = { username, password, rule, enabled };
  if (expiresAt) payload.expires_at = expiresAt;
  await fetchJSON('/api/users', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  $('selectedUserStatus').textContent = 'saved';
  await loadUsers();
}

async function deleteUser() {
  const username = $('userName').value.trim();
  if (!username) return;
  await fetchJSON('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
  $('userName').value = '';
  $('userPass').value = '';
  $('userRule').value = '';
  $('userEnabled').checked = true;
  $('userExpires').value = '';
  $('selectedUserStatus').textContent = 'new';
  await loadUsers();
}

async function reloadConfig() {
  const el = $('reloadStatus');
  el.textContent = 'running';
  el.className = 'pill warn';
  try {
    await fetchJSON('/api/reload', { method: 'POST' });
    el.textContent = 'ok';
    el.className = 'pill ok';
  } catch (e) {
    el.textContent = 'error';
    el.className = 'pill err';
    setStatus(e.message, 'err');
  }
}

function ipInfoTarget() {
  return $('checkTarget').value.trim() || $('quickCheckTarget').value.trim() || 'https://ipinfo.io/json';
}

function checkSelectedUser() {
  const name = $('userName').value.trim();
  runCheck({ type: 'user', name, target: ipInfoTarget(), timeout: $('checkTimeout').value || '8s', resultId: 'userCheckResult', probe: 'ipinfo' });
}

function checkSelectedRule() {
  const name = $('ruleName').value.trim();
  runCheck({ type: 'rule', name, target: ipInfoTarget(), timeout: $('checkTimeout').value || '8s', resultId: 'ruleCheckResult', probe: 'ipinfo' });
}

function runQuickCheck() {
  runCheck({ type: $('quickCheckType').value, name: $('quickCheckName').value.trim(), target: $('quickCheckTarget').value.trim(), timeout: $('quickCheckTimeout').value.trim(), resultId: 'quickCheckResult', probe: 'ipinfo' });
}

function runCheckFromForm() {
  runCheck({ type: $('checkType').value, name: $('checkName').value.trim(), target: $('checkTarget').value.trim(), timeout: $('checkTimeout').value.trim(), resultId: 'checkResult', probe: 'ipinfo' });
}

async function runCheck(opts) {
  const el = $(opts.resultId || 'checkResult');
  el.textContent = 'Checking...';
  try {
    const payload = { type: opts.type || 'default', name: opts.name || '', target: opts.target || ipInfoTarget(), network: 'tcp', timeout: opts.timeout || '8s', probe: opts.probe || 'ipinfo' };
    const data = await fetchJSON('/api/check', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    lastCheck = data;
    renderStats();
    el.innerHTML = renderCheckResult(data);
  } catch (e) {
    lastCheck = { status: 'error' };
    renderStats();
    el.innerHTML = '<span class="pill err">error</span> ' + escapeHTML(e.message);
  }
}

function renderCheckResult(data) {
  const cls = data.status === 'ok' ? 'ok' : 'err';
  const info = data.ip_info || {};
  const lines = [
    '<span class="pill ' + cls + '">' + escapeHTML(data.status) + '</span>',
    'route: ' + escapeHTML(data.type || 'default') + (data.name ? ' / ' + escapeHTML(data.name) : ''),
    'url: ' + escapeHTML(data.url || data.target),
    'dialer: ' + escapeHTML(data.dialer || '-'),
    'duration: ' + escapeHTML(data.duration_ms) + ' ms'
  ];
  if (data.http_status) lines.push('http: ' + escapeHTML(data.http_status));
  if (info.ip) lines.push('ip: ' + escapeHTML(info.ip));
  if (info.org) lines.push('org: ' + escapeHTML(info.org));
  if (info.city || info.region || info.country) lines.push('location: ' + escapeHTML([info.city, info.region, info.country].filter(Boolean).join(', ')));
  if (info.timezone) lines.push('timezone: ' + escapeHTML(info.timezone));
  if (data.error) lines.push('error: ' + escapeHTML(data.error));
  return lines.join('\n');
}

async function runRulesHealth() {
  const el = $('rulesHealthStatus');
  el.textContent = 'running';
  el.className = 'pill warn';
  $('rulesHealthTable').textContent = 'Checking all rules...';
  try {
    const payload = { target: $('healthTarget').value.trim() || 'https://ipinfo.io/json', timeout: $('healthTimeout').value.trim() || '8s' };
    rulesHealthCache = await fetchJSON('/api/rules/health', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    renderRulesHealth();
    el.textContent = 'ok';
    el.className = 'pill ok';
  } catch (e) {
    el.textContent = 'error';
    el.className = 'pill err';
    $('rulesHealthTable').innerHTML = '<span class="pill err">error</span> ' + escapeHTML(e.message);
  }
  renderStats();
}

async function loadLatestRulesHealth() {
  try {
    rulesHealthCache = await fetchJSON('/api/rules/health?latest=1');
    renderRulesHealth();
    if (rulesHealthCache && rulesHealthCache.checked_at) {
      $('rulesHealthStatus').textContent = 'latest';
      $('rulesHealthStatus').className = 'pill ok';
    }
  } catch (e) {
    $('rulesHealthStatus').textContent = 'unavailable';
    $('rulesHealthStatus').className = 'pill warn';
  }
  renderStats();
}

function renderRulesHealth() {
  const wrap = $('rulesHealthTable');
  const results = (rulesHealthCache && rulesHealthCache.results) || [];
  if (!results.length) {
    const checked = rulesHealthCache && rulesHealthCache.checked_at;
    wrap.innerHTML = '<div class="empty">' + (checked ? 'No rule health results.' : 'No saved rule health check yet.') + '</div>';
    return;
  }
  wrap.innerHTML = '<table><thead><tr><th>Rule</th><th>Status</th><th>Exit IP</th><th>Org</th><th>Location</th><th>Dialer</th><th>Latency</th><th>Error</th></tr></thead><tbody>' + results.map(r => {
    const info = r.ip_info || {};
    return '<tr>' +
      '<td><strong>' + escapeHTML(r.name || '-') + '</strong></td>' +
      '<td>' + statusPill(r.status || 'unknown') + '</td>' +
      '<td class="mono">' + escapeHTML(info.ip || '-') + '</td>' +
      '<td>' + escapeHTML(info.org || '-') + '</td>' +
      '<td>' + escapeHTML([info.city, info.region, info.country].filter(Boolean).join(', ') || '-') + '</td>' +
      '<td class="mono">' + escapeHTML(r.dialer || '-') + '</td>' +
      '<td>' + escapeHTML(r.duration_ms || 0) + ' ms</td>' +
      '<td>' + escapeHTML(r.error || '-') + '</td>' +
      '</tr>';
  }).join('') + '</tbody></table><div class="compact">checked ' + escapeHTML(formatDate(rulesHealthCache.checked_at)) + ' target ' + escapeHTML(rulesHealthCache.target || '-') + '</div>';
}

function toggleHealthAuto() {
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
  }
  if ($('healthAuto').checked) {
    const seconds = Math.max(15, Number($('healthInterval').value || 60));
    healthTimer = setInterval(runRulesHealth, seconds * 1000);
    runRulesHealth();
  }
}

$('adminToken').value = adminToken;
$('deployCentralURL').value = defaultCentralURL();
$('adminToken').addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    e.preventDefault();
    saveToken();
  }
});
refreshAll();
</script>
</body>
</html>`
