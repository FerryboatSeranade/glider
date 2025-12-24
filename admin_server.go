package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

const (
	mongoURLEnv   = "GLIDER_MONGO_URI"
	mongoDBEnv    = "GLIDER_MONGO_DB"
	adminTokenEnv = "GLIDER_ADMIN_TOKEN"
)

type adminServer struct {
	addr     string
	store    *mongoStore
	rulesDir string
	conf     *Config
	pxySw    *proxy.Switcher
	token    string

	reloadMu   sync.Mutex
	lastReload time.Time
}

func startAdminServer(conf *Config, pxySw *proxy.Switcher) {
	if conf.Admin == "" {
		return
	}

	uri := strings.TrimSpace(os.Getenv(mongoURLEnv))
	if uri == "" {
		log.F("[admin] %s not set, admin disabled", mongoURLEnv)
		return
	}
	dbName := strings.TrimSpace(os.Getenv(mongoDBEnv))
	if dbName == "" {
		dbName = "glider"
	}
	token := strings.TrimSpace(os.Getenv(adminTokenEnv))
	if token == "" {
		log.F("[admin] %s not set, admin auth disabled", adminTokenEnv)
	}

	if conf.RulesDir == "" {
		log.F("[admin] rules-dir is empty, admin disabled")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := newMongoStore(ctx, uri, dbName)
	if err != nil {
		log.F("[admin] mongo connect error: %v", err)
		return
	}

	srv := &adminServer{
		addr:     conf.Admin,
		store:    store,
		rulesDir: conf.RulesDir,
		conf:     conf,
		pxySw:    pxySw,
		token:    token,
	}
	ctxInit, cancelInit := withTimeout(context.Background())
	defer cancelInit()
	if err := srv.reload(ctxInit); err != nil {
		log.F("[admin] initial reload failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/users", srv.handleUsers)
	mux.HandleFunc("/api/users/", srv.handleUser)
	mux.HandleFunc("/api/rules", srv.handleRules)
	mux.HandleFunc("/api/rules/", srv.handleRule)
	mux.HandleFunc("/api/reload", srv.handleReload)

	server := &http.Server{
		Addr:              srv.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.F("[admin] listening on %s", srv.addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.F("[admin] server error: %v", err)
		}
	}()
}

func (s *adminServer) requireToken(w http.ResponseWriter, r *http.Request) bool {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(adminHTML))
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
		if err := writeRuleFile(s.rulesDir, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
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
		if err := writeRuleFile(s.rulesDir, payload); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		ctx, cancel := withTimeout(r.Context())
		defer cancel()
		if err := s.store.DeleteRule(ctx, name); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = os.Remove(filepath.Join(s.rulesDir, name+".rule"))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
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
	if err := s.reload(ctx); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *adminServer) reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	rules, err := s.store.Rules(ctx)
	if err != nil {
		return err
	}
	if err := writeRuleFiles(s.rulesDir, rules); err != nil {
		return err
	}

	users, err := s.store.Users(ctx)
	if err != nil {
		return err
	}
	userMap, ruleUsers := buildUserMaps(users)

	newConf := *s.conf
	newConf.rules = nil
	if err := loadRules(&newConf); err != nil {
		return err
	}

	missing := applyRuleUsers(newConf.rules, ruleUsers)
	if len(missing) > 0 {
		return fmt.Errorf("missing rule(s): %s", strings.Join(missing, ", "))
	}

	newProxy := rule.NewProxy(newConf.Forwards, &newConf.Strategy, newConf.rules)
	newProxy.Check()

	s.pxySw.Set(newProxy)
	proxy.DefaultUserStore.Set(userMap)
	s.conf.rules = newConf.rules
	s.lastReload = time.Now()
	return nil
}

func buildUserMaps(users []dbUser) (map[string]proxy.UserEntry, map[string][]string) {
	userMap := make(map[string]proxy.UserEntry)
	ruleUsers := make(map[string][]string)
	now := time.Now()
	for _, u := range users {
		if u.Username == "" {
			continue
		}
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		entry := proxy.UserEntry{
			Password:  u.Password,
			Enabled:   enabled,
			ExpiresAt: normalizeExpiry(u.ExpiresAt),
		}
		userMap[u.Username] = entry
		if u.Rule != "" && userActive(entry, now) {
			ruleUsers[u.Rule] = append(ruleUsers[u.Rule], u.Username)
		}
	}
	return userMap, ruleUsers
}

func userActive(entry proxy.UserEntry, now time.Time) bool {
	if !entry.Enabled {
		return false
	}
	if entry.ExpiresAt == nil || entry.ExpiresAt.IsZero() {
		return true
	}
	return now.Before(*entry.ExpiresAt)
}

func normalizeExpiry(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	tt := *t
	return &tt
}

func applyRuleUsers(rules []*rule.Config, ruleUsers map[string][]string) []string {
	nameToRule := make(map[string]*rule.Config)
	for _, r := range rules {
		r.User = nil
		name := strings.TrimSuffix(filepath.Base(r.RulePath), filepath.Ext(r.RulePath))
		nameToRule[name] = r
	}

	var missing []string
	for name, users := range ruleUsers {
		ruleConf, ok := nameToRule[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		ruleConf.User = append(ruleConf.User, users...)
	}
	return missing
}

func writeRuleFiles(dir string, rules []dbRule) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, r := range rules {
		if err := writeRuleFile(dir, r); err != nil {
			return err
		}
	}
	return nil
}

func writeRuleFile(dir string, ruleDoc dbRule) error {
	if err := validateRuleName(ruleDoc.Name); err != nil {
		return err
	}
	path := filepath.Join(dir, ruleDoc.Name+".rule")
	return os.WriteFile(path, []byte(ruleDoc.Content), 0o644)
}

var ruleNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func validateRuleName(name string) error {
	if name == "" {
		return fmt.Errorf("rule name required")
	}
	if !ruleNameRe.MatchString(name) {
		return fmt.Errorf("invalid rule name")
	}
	return nil
}

func withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 5*time.Second)
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
  <title>Glider Admin</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h2 { margin-top: 24px; }
    input, select, textarea { width: 100%; max-width: 520px; margin: 4px 0; }
    textarea { height: 180px; }
    button { margin: 6px 4px 6px 0; }
    .row { margin-bottom: 12px; }
    .list { margin-top: 8px; }
    .item { border-bottom: 1px solid #ddd; padding: 6px 0; }
  </style>
</head>
<body>
  <h1>Glider Admin</h1>
  <div class="row">
    <input id="adminToken" type="password" placeholder="admin token">
    <button onclick="saveToken()">Set Token</button>
    <span id="authStatus"></span>
  </div>
  <button onclick="reloadConfig()">Reload</button>
  <span id="reloadStatus"></span>

  <h2>Users</h2>
  <div class="row">
    <input id="userName" placeholder="username">
    <input id="userPass" placeholder="password">
    <label><input id="userEnabled" type="checkbox" checked> enabled</label>
    <input id="userExpires" type="datetime-local" placeholder="expires at">
    <select id="userRule"></select>
    <button onclick="saveUser()">Save User</button>
    <button onclick="deleteUser()">Delete User</button>
  </div>
  <div id="usersList" class="list"></div>

  <h2>Rules</h2>
  <div class="row">
    <input id="ruleName" placeholder="rule name (no .rule)">
    <textarea id="ruleContent" placeholder="rule content"></textarea>
    <button onclick="saveRule()">Save Rule</button>
    <button onclick="deleteRule()">Delete Rule</button>
  </div>
  <div id="rulesList" class="list"></div>

<script>
let adminToken = localStorage.getItem('gliderAdminToken') || '';

function setStatus(message) {
  const el = document.getElementById('authStatus');
  if (el) el.textContent = message || '';
}

function withAuthHeaders(headers) {
  const out = Object.assign({}, headers || {});
  if (adminToken) out['X-Admin-Token'] = adminToken;
  return out;
}

function isoToLocalInput(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  if (isNaN(date.getTime())) return '';
  const tzOffset = date.getTimezoneOffset() * 60000;
  const local = new Date(date.getTime() - tzOffset);
  return local.toISOString().slice(0, 16);
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

async function fetchJSON(url, options) {
  const opts = options || {};
  opts.headers = withAuthHeaders(opts.headers);
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function loadRules() {
  try {
    const rules = await fetchJSON('/api/rules');
    const list = document.getElementById('rulesList');
    list.innerHTML = '';
    const sel = document.getElementById('userRule');
    sel.innerHTML = '<option value="">(default)</option>';
    rules.forEach(r => {
      const item = document.createElement('div');
      item.className = 'item';
      item.textContent = r.name;
      item.onclick = () => selectRule(r.name);
      list.appendChild(item);
      const opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = r.name;
      sel.appendChild(opt);
    });
    setStatus('');
  } catch (e) {
    setStatus(e.message);
  }
}

async function loadUsers() {
  try {
    const users = await fetchJSON('/api/users');
    const list = document.getElementById('usersList');
    list.innerHTML = '';
    users.forEach(u => {
      const item = document.createElement('div');
      item.className = 'item';
      item.textContent = u.username + ' -> ' + (u.rule || '(default)') + ' (' + userStatus(u) + ')';
      item.onclick = () => selectUser(u);
      list.appendChild(item);
    });
    setStatus('');
  } catch (e) {
    setStatus(e.message);
  }
}

async function selectRule(name) {
  const rule = await fetchJSON('/api/rules/' + encodeURIComponent(name));
  document.getElementById('ruleName').value = rule.name;
  document.getElementById('ruleContent').value = rule.content || '';
}

function selectUser(u) {
  document.getElementById('userName').value = u.username;
  document.getElementById('userPass').value = u.password || '';
  document.getElementById('userRule').value = u.rule || '';
  document.getElementById('userEnabled').checked = u.enabled !== false;
  document.getElementById('userExpires').value = isoToLocalInput(u.expires_at);
}

function saveToken() {
  adminToken = document.getElementById('adminToken').value.trim();
  localStorage.setItem('gliderAdminToken', adminToken);
  setStatus(adminToken ? 'token set' : 'token cleared');
}

async function saveRule() {
  const name = document.getElementById('ruleName').value.trim();
  const content = document.getElementById('ruleContent').value;
  await fetchJSON('/api/rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name, content }) });
  await loadRules();
}

async function deleteRule() {
  const name = document.getElementById('ruleName').value.trim();
  if (!name) return;
  await fetchJSON('/api/rules/' + encodeURIComponent(name), { method: 'DELETE' });
  document.getElementById('ruleName').value = '';
  document.getElementById('ruleContent').value = '';
  await loadRules();
}

async function saveUser() {
  const username = document.getElementById('userName').value.trim();
  const password = document.getElementById('userPass').value;
  const rule = document.getElementById('userRule').value;
  const enabled = document.getElementById('userEnabled').checked;
  const expiresRaw = document.getElementById('userExpires').value;
  const expiresAt = localInputToISO(expiresRaw);
  const payload = { username, password, rule, enabled };
  if (expiresAt) payload.expires_at = expiresAt;
  await fetchJSON('/api/users', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  await loadUsers();
}

async function deleteUser() {
  const username = document.getElementById('userName').value.trim();
  if (!username) return;
  await fetchJSON('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
  document.getElementById('userName').value = '';
  document.getElementById('userPass').value = '';
  document.getElementById('userRule').value = '';
  document.getElementById('userEnabled').checked = true;
  document.getElementById('userExpires').value = '';
  await loadUsers();
}

async function reloadConfig() {
  const el = document.getElementById('reloadStatus');
  el.textContent = '...';
  try {
    await fetchJSON('/api/reload', { method: 'POST' });
    el.textContent = 'ok';
  } catch (e) {
    el.textContent = 'error: ' + e.message;
  }
}

loadRules();
loadUsers();
document.getElementById('adminToken').value = adminToken;
</script>
</body>
</html>`
