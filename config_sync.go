package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

type ConfigSnapshot struct {
	ConfigVersion string    `json:"config_version"`
	Users         []dbUser  `json:"users"`
	Rules         []dbRule  `json:"rules"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ConfigApplier struct {
	conf     *Config
	pxySw    *proxy.Switcher
	rulesDir string

	mu      sync.Mutex
	version string
}

func NewConfigApplier(conf *Config, pxySw *proxy.Switcher) *ConfigApplier {
	return &ConfigApplier{
		conf:     conf,
		pxySw:    pxySw,
		rulesDir: conf.RulesDir,
	}
}

func (a *ConfigApplier) Version() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.version
}

func (a *ConfigApplier) SetVersion(version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version = version
}

func (a *ConfigApplier) Apply(ctx context.Context, snap ConfigSnapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.rulesDir == "" {
		return fmt.Errorf("rules-dir is empty")
	}
	if snap.ConfigVersion != "" && snap.ConfigVersion == a.version {
		return nil
	}

	stagingDir, err := writeRuleFilesStaged(a.rulesDir, snap.Rules)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)

	newConf := *a.conf
	newConf.rules = nil
	newConf.RulesDir = stagingDir
	if err := loadRules(&newConf); err != nil {
		return err
	}

	userMap, ruleUsers := buildUserMaps(snap.Users)
	missing := applyRuleUsers(newConf.rules, ruleUsers)
	if len(missing) > 0 {
		return fmt.Errorf("missing rule(s): %s", strings.Join(missing, ", "))
	}

	newProxy := rule.NewProxy(newConf.Forwards, &newConf.Strategy, newConf.rules)
	newProxy.Check()

	if err := replaceDir(stagingDir, a.rulesDir); err != nil {
		if copyErr := syncRuleDir(stagingDir, a.rulesDir); copyErr != nil {
			return fmt.Errorf("replace rules dir: %v; sync files: %v", err, copyErr)
		}
	}
	if err := ensureDirMode(a.rulesDir, 0o755); err != nil {
		return err
	}
	newConf.RulesDir = a.rulesDir
	if err := rewriteRulePaths(newConf.rules, stagingDir, a.rulesDir); err != nil {
		return err
	}

	a.pxySw.Set(newProxy)
	proxy.DefaultUserStore.Set(userMap)
	a.conf.rules = newConf.rules
	a.version = snap.ConfigVersion
	return nil
}

func LoadSnapshotFromStore(ctx context.Context, store *mongoStore) (ConfigSnapshot, error) {
	rules, err := store.Rules(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	users, err := store.Users(ctx)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	version, updatedAt := configVersion(users, rules)
	return ConfigSnapshot{
		ConfigVersion: version,
		Users:         users,
		Rules:         rules,
		UpdatedAt:     updatedAt,
	}, nil
}

func configVersion(users []dbUser, rules []dbRule) (string, time.Time) {
	var latest time.Time
	h := sha256.New()
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	for _, u := range users {
		if u.UpdatedAt.After(latest) {
			latest = u.UpdatedAt
		}
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		expires := ""
		if u.ExpiresAt != nil {
			expires = u.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(h, "u:%s:%s:%s:%t:%s:%s\n", u.Username, u.Password, u.Rule, enabled, expires, u.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	for _, r := range rules {
		if r.UpdatedAt.After(latest) {
			latest = r.UpdatedAt
		}
		fmt.Fprintf(h, "r:%s:%s:%s\n", r.Name, r.Content, r.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	if latest.IsZero() {
		latest = time.Unix(0, 0).UTC()
	}
	return hex.EncodeToString(h.Sum(nil)), latest.UTC()
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
	stagingDir, err := writeRuleFilesStaged(dir, rules)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)
	if err := replaceDir(stagingDir, dir); err != nil {
		if copyErr := syncRuleDir(stagingDir, dir); copyErr != nil {
			return fmt.Errorf("replace rules dir: %v; sync files: %v", err, copyErr)
		}
	}
	return nil
}

func writeRuleFilesStaged(dir string, rules []dbRule) (string, error) {
	parent := filepath.Dir(dir)
	base := filepath.Base(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	stagingDir, err := os.MkdirTemp(parent, "."+base+".tmp-*")
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		if err := writeRuleFile(stagingDir, r); err != nil {
			_ = os.RemoveAll(stagingDir)
			return "", err
		}
	}
	return stagingDir, nil
}

func writeRuleFile(dir string, ruleDoc dbRule) error {
	if err := validateRuleName(ruleDoc.Name); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, ruleDoc.Name+".rule")
	return os.WriteFile(path, []byte(ruleDoc.Content), 0o644)
}

func replaceDir(src, dst string) error {
	backup := dst + ".bak"
	_ = os.RemoveAll(backup)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if _, statErr := os.Stat(backup); statErr == nil {
			_ = os.Rename(backup, dst)
		}
		return err
	}
	_ = os.RemoveAll(backup)
	return nil
}

func syncRuleDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	srcEntries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	newNames := make(map[string]struct{})
	tempPaths := make(map[string]string)
	defer func() {
		for _, tmpPath := range tempPaths {
			_ = os.Remove(tmpPath)
		}
	}()
	for _, entry := range srcEntries {
		if entry.IsDir() {
			continue
		}
		newNames[entry.Name()] = struct{}{}
		b, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dst, "."+entry.Name()+".tmp-*")
		if err != nil {
			return err
		}
		if _, err := tmp.Write(b); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return err
		}
		if err := tmp.Chmod(0o644); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return err
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmp.Name())
			return err
		}
		tempPaths[entry.Name()] = tmp.Name()
	}
	for name, tmpPath := range tempPaths {
		if err := os.Rename(tmpPath, filepath.Join(dst, name)); err != nil {
			return err
		}
		delete(tempPaths, name)
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".rule") {
			continue
		}
		if _, ok := newNames[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dst, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func ensureDirMode(dir string, mode os.FileMode) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return os.Chmod(dir, mode)
}

func rewriteRulePaths(rules []*rule.Config, oldDir, newDir string) error {
	oldAbs, err := filepath.Abs(oldDir)
	if err != nil {
		return err
	}
	newAbs, err := filepath.Abs(newDir)
	if err != nil {
		return err
	}
	for _, r := range rules {
		ruleAbs, err := filepath.Abs(r.RulePath)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(oldAbs, ruleAbs)
		if err != nil {
			return err
		}
		r.RulePath = filepath.Join(newAbs, rel)
	}
	return nil
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
