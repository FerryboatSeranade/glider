package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

func testConfig(t *testing.T, dir string) (*Config, *ConfigApplier) {
	t.Helper()
	conf := &Config{
		Forwards: []string{"direct://"},
		Strategy: rule.Strategy{
			Strategy:      "rr",
			Check:         "disable",
			CheckInterval: 30,
			CheckTimeout:  10,
			DialTimeout:   3,
			RelayTimeout:  0,
		},
		RulesDir: filepath.Join(dir, "rules.d"),
	}
	sw := proxy.NewSwitcher(rule.NewProxy(conf.Forwards, &conf.Strategy, nil))
	return conf, NewConfigApplier(conf, sw)
}

func testSnapshot(version string, users []dbUser, rules []dbRule) ConfigSnapshot {
	return ConfigSnapshot{
		ConfigVersion: version,
		Users:         users,
		Rules:         rules,
		UpdatedAt:     time.Now().UTC(),
	}
}

func TestConfigApplierAppliesSnapshotAndWritesRules(t *testing.T) {
	conf, applier := testConfig(t, t.TempDir())
	enabled := true
	snap := testSnapshot("v1", []dbUser{{
		Username: "alice",
		Password: "secret",
		Rule:     "office",
		Enabled:  &enabled,
	}}, []dbRule{{
		Name:    "office",
		Content: "domain=example.com\n",
	}})

	if err := applier.Apply(context.Background(), snap); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if applier.Version() != "v1" {
		t.Fatalf("version = %q, want v1", applier.Version())
	}
	if !proxy.DefaultUserStore.Validate("alice", "secret") {
		t.Fatalf("dynamic user was not installed")
	}
	b, err := os.ReadFile(filepath.Join(conf.RulesDir, "office.rule"))
	if err != nil {
		t.Fatalf("rule file not written: %v", err)
	}
	if string(b) != "domain=example.com\n" {
		t.Fatalf("rule content = %q", string(b))
	}
}

func TestConfigApplierKeepsOldConfigWhenReloadFails(t *testing.T) {
	conf, applier := testConfig(t, t.TempDir())
	ok := testSnapshot("v1", nil, []dbRule{{
		Name:    "office",
		Content: "domain=example.com\n",
	}})
	if err := applier.Apply(context.Background(), ok); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	rulePath := filepath.Join(conf.RulesDir, "office.rule")
	if b, err := os.ReadFile(rulePath); err != nil || string(b) != "domain=example.com\n" {
		t.Fatalf("initial rule file = %q, err = %v", string(b), err)
	}

	bad := testSnapshot("v2", []dbUser{{
		Username: "bob",
		Password: "secret",
		Rule:     "missing-rule",
	}}, []dbRule{{
		Name:    "office",
		Content: "domain=changed.example\n",
	}})
	if err := applier.Apply(context.Background(), bad); err == nil {
		t.Fatalf("Apply() succeeded, want missing rule error")
	}
	if applier.Version() != "v1" {
		t.Fatalf("version changed to %q after failed apply", applier.Version())
	}
	if proxy.DefaultUserStore.Validate("bob", "secret") {
		t.Fatalf("failed config installed user bob")
	}
	b, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("rule file missing after failed apply: %v", err)
	}
	if string(b) != "domain=example.com\n" {
		t.Fatalf("rule file changed after failed apply: %q", string(b))
	}
}

func TestConfigVersionIsStableForSameContent(t *testing.T) {
	now := time.Now().UTC()
	users := []dbUser{{Username: "b", Password: "2", UpdatedAt: now}, {Username: "a", Password: "1", UpdatedAt: now}}
	rules := []dbRule{{Name: "z", Content: "domain=z\n", UpdatedAt: now}, {Name: "m", Content: "domain=m\n", UpdatedAt: now}}
	v1, u1 := configVersion(users, rules)
	v2, u2 := configVersion([]dbUser{users[1], users[0]}, []dbRule{rules[1], rules[0]})
	if v1 == "" || v1 != v2 {
		t.Fatalf("versions not stable: %q %q", v1, v2)
	}
	if !u1.Equal(now) || !u2.Equal(now) {
		t.Fatalf("updated_at mismatch: %s %s want %s", u1, u2, now)
	}
}

func TestSyncRuleDirReplacesRuleFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "new.rule"), []byte("domain=new.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "old.rule"), []byte("domain=old.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := syncRuleDir(src, dst); err != nil {
		t.Fatalf("syncRuleDir() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "old.rule")); !os.IsNotExist(err) {
		t.Fatalf("old.rule still exists or stat failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "new.rule"))
	if err != nil {
		t.Fatalf("new.rule not written: %v", err)
	}
	if string(b) != "domain=new.example\n" {
		t.Fatalf("new.rule = %q", string(b))
	}
}
