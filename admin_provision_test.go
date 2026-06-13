package main

import (
	"strings"
	"testing"
	"time"
)

func TestRenderNodeProvisionFiles(t *testing.T) {
	env := renderNodeEnv("zgo", "http://central.example:8444", "node-secret-123456", "30s", "/etc/glider-cache", "/etc/glider-certs", "eth0")
	for _, needle := range []string{
		"GLIDER_MODE=node",
		"GLIDER_NODE_ID=zgo",
		"GLIDER_CENTRAL_URL=http://central.example:8444",
		"GLIDER_NODE_TOKEN=node-secret-123456",
		"GLIDER_SYNC_INTERVAL=30s",
	} {
		if !strings.Contains(env, needle) {
			t.Fatalf("env missing %q:\n%s", needle, env)
		}
	}

	compose := renderNodeCompose("ghcr.io/ferryboatseranade/glider:v1", []string{"443:443", "8443:8443"})
	for _, needle := range []string{
		"image: ghcr.io/ferryboatseranade/glider:v1",
		`- "443:443"`,
		`- "8443:8443"`,
		"./cache:/etc/glider-cache",
		"./certs:/etc/glider-certs",
	} {
		if !strings.Contains(compose, needle) {
			t.Fatalf("compose missing %q:\n%s", needle, compose)
		}
	}

	conf := renderNodeGliderConf("/etc/glider-certs")
	if !strings.Contains(conf, "mode=node") || !strings.Contains(conf, "certDir=/etc/glider-certs") || !strings.Contains(conf, "rules-dir=/etc/rules.d") {
		t.Fatalf("unexpected glider.conf:\n%s", conf)
	}
}

func TestReplaceComposeImage(t *testing.T) {
	compose := "services:\n  glider-node:\n    image: old/image:v1\n    restart: unless-stopped\n"
	updated, err := replaceComposeImage(compose, "ghcr.io/ferryboatseranade/glider:v2")
	if err != nil {
		t.Fatalf("replaceComposeImage() error = %v", err)
	}
	if !strings.Contains(updated, "    image: ghcr.io/ferryboatseranade/glider:v2") {
		t.Fatalf("image was not replaced:\n%s", updated)
	}
	if _, err := replaceComposeImage("services:\n  glider-node:\n", "image:v1"); err == nil {
		t.Fatalf("replaceComposeImage() succeeded without image line")
	}
}

func TestHostPortFromMapping(t *testing.T) {
	cases := map[string]string{
		"443:443":             "443",
		"127.0.0.1:8443:8443": "8443",
		"[::1]:9443:443/tcp":  "9443",
		"8443":                "8443",
		"bad":                 "",
	}
	for input, want := range cases {
		if got := hostPortFromMapping(input); got != want {
			t.Fatalf("hostPortFromMapping(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestServerUpdateDefaultsAndRedactsSecrets(t *testing.T) {
	t.Setenv(settingsKeyEnv, "0123456789abcdef0123456789abcdef")
	password := "root-password"
	privateKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----"
	payload := serverUpsertPayload{
		ServerID:   "zgo",
		Host:       "38.49.59.207",
		Password:   &password,
		PrivateKey: &privateKey,
	}
	server, secrets := serverFromPayload(payload)
	set, _, err := serverUpdateDocument(server, secrets, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("serverUpdateDocument() error = %v", err)
	}
	if set["node_id"] != "zgo" || set["ssh_port"] != 22 || set["deploy_dir"] != "/root/data/docker_data/glider" {
		t.Fatalf("defaults not applied: %#v", set)
	}
	if set["password"] == password || set["private_key"] == privateKey {
		t.Fatalf("secrets should be encoded before storage: %#v", set)
	}
	if !strings.HasPrefix(set["password"].(string), encryptedSecretV1) || !strings.HasPrefix(set["private_key"].(string), encryptedSecretV1) {
		t.Fatalf("secrets should use encrypted storage prefix: %#v", set)
	}

	redacted := redactServerSecrets(dbServer{Password: password, PrivateKey: privateKey, Passphrase: "phrase"})
	if !redacted.HasPassword || !redacted.HasPrivateKey || !redacted.HasPassphrase {
		t.Fatalf("secret flags not set: %#v", redacted)
	}
	if redacted.Password != "" || redacted.PrivateKey != "" || redacted.Passphrase != "" {
		t.Fatalf("secrets leaked in redacted server: %#v", redacted)
	}
}

func TestServerAuthTypeAliases(t *testing.T) {
	t.Setenv(settingsKeyEnv, "0123456789abcdef0123456789abcdef")
	for _, authType := range []string{"key", "private-key", "privatekey", "ssh_key", "ssh-key", "private_key"} {
		server, secrets := serverFromPayload(serverUpsertPayload{
			ServerID:   "zgo",
			Host:       "38.49.59.207",
			AuthType:   authType,
			PrivateKey: stringPtr("test-key"),
		})
		set, _, err := serverUpdateDocument(server, secrets, time.Unix(100, 0).UTC())
		if err != nil {
			t.Fatalf("serverUpdateDocument(%q) error = %v", authType, err)
		}
		if got := set["auth_type"]; got != "private_key" {
			t.Fatalf("auth_type %q normalized to %#v, want private_key", authType, got)
		}
	}
}

func stringPtr(value string) *string {
	return &value
}
