#!/usr/bin/env python3
from __future__ import annotations

import http.server
import json
import pathlib
import subprocess
import sys
import threading
import unittest


SCRIPT = pathlib.Path(__file__).with_name("domain_onboarding_check.py")


class MockAdmin(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), MockAdminHandler)
        self.settings = {
            "configured": True,
            "source": "database",
            "masked_token": "old********oken",
            "account_id": "acct-existing",
            "acme_email": "ops@example.com",
            "acme_directory_url": "https://acme.example/directory",
        }
        self.domain_exists = True
        self.saved_settings_payloads: list[dict] = []


class MockAdminHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    @property
    def admin(self) -> MockAdmin:
        return self.server  # type: ignore[return-value]

    def send_json(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        n = int(self.headers.get("content-length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/api/config/status":
            return self.send_json(200, {"config_version": "abcdef123456", "users_count": 1, "rules_count": 2})
        if self.path == "/api/nodes":
            return self.send_json(200, {"nodes": [{"node_id": "zgo", "public_ip": "38.49.59.207", "config_version": "abcdef123456", "cert_version": "certv"}]})
        if self.path == "/api/settings/cloudflare":
            return self.send_json(200, self.admin.settings)
        if self.path == "/api/domains/proxy.example.com" and self.admin.domain_exists:
            return self.send_json(200, {"domain": "proxy.example.com", "runtime": {"status": "active", "dns_status": "dns pending", "cert_status": "cert missing", "cert_sync_status": "cert not issued"}})
        return self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/settings/cloudflare":
            payload = self.read_json()
            self.admin.saved_settings_payloads.append(payload)
            self.admin.settings = {
                "configured": True,
                "source": "database",
                "masked_token": "new********oken",
                "account_id": payload.get("account_id", ""),
                "acme_email": payload.get("acme_email", ""),
                "acme_directory_url": payload.get("acme_directory_url", ""),
            }
            return self.send_json(200, self.admin.settings)
        if self.path == "/api/settings/cloudflare/verify":
            return self.send_json(200, {"status": "active", "scope": "account", "zone": {"zone_name": "example.com", "zone_read_ok": True, "dns_edit_ok": False}})
        if self.path == "/api/domains/proxy.example.com/dns-plan":
            return self.send_json(200, {"status": "ok", "plan": {"action": "create", "record_type": "A", "record_name": "proxy.example.com", "target": "38.49.59.207"}})
        if self.path == "/api/domains/proxy.example.com/cert-plan":
            return self.send_json(200, {"status": "ok", "plan": {"action": "issue", "challenge_record": "_acme-challenge.proxy.example.com", "renew_status": "missing"}})
        return self.send_json(404, {"error": "not found"})


class OnboardingCheckTest(unittest.TestCase):
    def run_script(self, admin: MockAdmin, *extra: str) -> subprocess.CompletedProcess[str]:
        url = f"http://127.0.0.1:{admin.server_address[1]}"
        cmd = [
            sys.executable,
            str(SCRIPT),
            "--admin-url",
            url,
            "--admin-token",
            "admin-token",
            "--domain",
            "proxy.example.com",
            "--node-id",
            "zgo",
            *extra,
        ]
        return subprocess.run(cmd, text=True, capture_output=True, timeout=20)

    def with_admin(self):
        admin = MockAdmin()
        thread = threading.Thread(target=admin.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(admin.shutdown)
        self.addCleanup(admin.server_close)
        return admin

    def test_save_cloudflare_settings_preserves_existing_non_secret_fields(self):
        admin = self.with_admin()
        secret = "cf-secret-token-should-not-print"

        result = self.run_script(admin, "--save-cloudflare-settings", "--cloudflare-token", secret)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(admin.saved_settings_payloads[-1], {
            "api_token": secret,
            "account_id": "acct-existing",
            "acme_email": "ops@example.com",
            "acme_directory_url": "https://acme.example/directory",
        })
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_save_cloudflare_settings_overrides_and_clears_explicit_fields(self):
        admin = self.with_admin()

        result = self.run_script(
            admin,
            "--save-cloudflare-settings",
            "--cloudflare-token",
            "new-token",
            "--cloudflare-account-id",
            "acct-new",
            "--clear-acme-email",
            "--acme-directory",
            "https://acme-v02.api.letsencrypt.org/directory",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(admin.saved_settings_payloads[-1], {
            "api_token": "new-token",
            "account_id": "acct-new",
            "acme_email": "",
            "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
        })

    def test_unconfigured_cloudflare_fails_before_domain_writes(self):
        admin = self.with_admin()
        admin.settings = {"configured": False}

        result = self.run_script(admin)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Cloudflare settings are not configured", result.stderr)
        self.assertEqual(admin.saved_settings_payloads, [])


if __name__ == "__main__":
    unittest.main()
