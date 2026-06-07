#!/usr/bin/env python3
"""Validate a Glider domain/node/Cloudflare onboarding path.

The default mode is read-mostly: it verifies Admin auth, node heartbeat,
Cloudflare settings/token, saves the domain assignment, and runs DNS/cert
preview APIs. Use --sync-dns or --issue-cert for write operations.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def request(base: str, token: str, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    url = base.rstrip("/") + path
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data) if data else {}
    except urllib.error.HTTPError as err:
        data = err.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"error": data}
        return err.code, parsed


def require_ok(label: str, status: int, body: dict) -> dict:
    if 200 <= status < 300:
        print(f"[ok] {label}")
        return body
    print(f"[error] {label}: HTTP {status}", file=sys.stderr)
    print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(1)


def short(value: str | None) -> str:
    value = value or ""
    return value[:12] if len(value) > 12 else value or "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-url", required=True, help="Central Admin URL, for example http://1.2.3.4:8444")
    parser.add_argument("--admin-token", required=True, help="GLIDER_ADMIN_TOKEN")
    parser.add_argument("--domain", required=True, help="Domain to onboard, for example proxy.example.com")
    parser.add_argument("--node-id", required=True, help="Target node id, for example zgo")
    parser.add_argument("--acme-email", default="", help="Override ACME email for cert preview/issue")
    parser.add_argument("--acme-directory", default="", help="Override ACME directory URL")
    parser.add_argument("--record-type", default="", choices=["", "A", "AAAA"], help="DNS record type; empty means Auto")
    parser.add_argument("--ttl", type=int, default=1, help="Cloudflare TTL, 1 means automatic")
    parser.add_argument("--proxied", action="store_true", help="Set Cloudflare proxied=true")
    parser.add_argument("--failover", action="store_true", help="Enable domain failover")
    parser.add_argument("--renew-before-days", type=int, default=30)
    parser.add_argument("--sync-dns", action="store_true", help="Actually update Cloudflare DNS")
    parser.add_argument("--issue-cert", action="store_true", help="Actually issue/renew the ACME certificate")
    args = parser.parse_args()

    cfg = require_ok("admin config status", *request(args.admin_url, args.admin_token, "GET", "/api/config/status"))
    print(f"  config_version={short(cfg.get('config_version'))} users={cfg.get('users_count')} rules={cfg.get('rules_count')}")

    nodes_body = require_ok("node heartbeat list", *request(args.admin_url, args.admin_token, "GET", "/api/nodes"))
    nodes = {node.get("node_id"): node for node in nodes_body.get("nodes", [])}
    node = nodes.get(args.node_id)
    if not node:
        print(f"[error] node {args.node_id!r} has not reported to Admin", file=sys.stderr)
        return 1
    print(f"  node={args.node_id} public_ip={node.get('public_ip') or '-'} config={short(node.get('config_version'))} cert={short(node.get('cert_version'))}")

    cf = require_ok("cloudflare settings", *request(args.admin_url, args.admin_token, "GET", "/api/settings/cloudflare"))
    if not cf.get("configured"):
        print("[error] Cloudflare settings are not configured in Admin", file=sys.stderr)
        return 1
    print(f"  cloudflare_source={cf.get('source') or '-'} account_id={'yes' if cf.get('account_id') else 'no'}")

    verify_payload = {"domain": args.domain, "dns_edit_test": False}
    verify = require_ok("cloudflare token zone check", *request(args.admin_url, args.admin_token, "POST", "/api/settings/cloudflare/verify", verify_payload))
    zone = verify.get("zone") or {}
    print(f"  scope={verify.get('scope') or '-'} zone={zone.get('zone_name') or '-'} zone_read={zone.get('zone_read_ok')}")

    domain_payload = {
        "domain": args.domain,
        "enabled": True,
        "node_ids": [args.node_id],
        "active_node_id": args.node_id,
        "failover_enabled": args.failover,
        "renew_before_days": args.renew_before_days,
        "dns_provider": "cloudflare",
        "cloudflare": {
            "record_type": args.record_type,
            "record_name": args.domain,
            "ttl": args.ttl,
            "proxied": args.proxied,
        },
    }
    require_ok("save domain assignment", *request(args.admin_url, args.admin_token, "POST", "/api/domains", domain_payload))

    encoded = urllib.parse.quote(args.domain, safe="")
    dns_plan = require_ok("dns preview", *request(args.admin_url, args.admin_token, "POST", f"/api/domains/{encoded}/dns-plan", {"node_id": args.node_id}))
    plan = dns_plan.get("plan") or {}
    print(f"  dns_action={plan.get('action') or '-'} {plan.get('record_type') or '-'} {plan.get('record_name') or '-'} -> {plan.get('target') or '-'}")

    cert_payload = {"email": args.acme_email, "directory_url": args.acme_directory}
    cert_plan = require_ok("certificate preview", *request(args.admin_url, args.admin_token, "POST", f"/api/domains/{encoded}/cert-plan", cert_payload))
    cplan = cert_plan.get("plan") or {}
    print(f"  cert_action={cplan.get('action') or '-'} challenge={cplan.get('challenge_record') or '-'} renew={cplan.get('renew_status') or '-'}")

    if args.issue_cert:
        issued = require_ok("issue certificate", *request(args.admin_url, args.admin_token, "POST", f"/api/domains/{encoded}/issue-cert", cert_payload))
        print(f"  cert_version={short(issued.get('cert_version'))} expires_at={issued.get('expires_at') or '-'}")

    if args.sync_dns:
        synced = require_ok("sync cloudflare dns", *request(args.admin_url, args.admin_token, "POST", f"/api/domains/{encoded}/sync-dns", {"node_id": args.node_id}))
        splan = synced.get("plan") or {}
        print(f"  synced_active_node={synced.get('active_node') or '-'} action={splan.get('action') or '-'}")

    domains = require_ok("domain runtime status", *request(args.admin_url, args.admin_token, "GET", f"/api/domains/{encoded}"))
    runtime = domains.get("runtime") or {}
    print(f"  runtime={runtime.get('status') or '-'} dns={runtime.get('dns_status') or '-'} cert={runtime.get('cert_status') or '-'} sync={runtime.get('cert_sync_status') or '-'}")

    print("[ok] onboarding check complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
