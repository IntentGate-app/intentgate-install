#!/usr/bin/env python3
"""acceptance-smoke.py: product acceptance / security smoke checks against a RUNNING install.

Part of the release bundle, so the clean-room run uses nothing from developer repositories.

    python3 release/acceptance-smoke.py --manifest release-manifest.json --form compose [--project intentgate]
    python3 release/acceptance-smoke.py --manifest release-manifest.json --form helm --namespace intentgate

Checks (each prints SMOKE|<id>|PASS|FAIL|<detail>; any FAIL makes SECURITY_SMOKE=RED, exit 1):
  health       every service with a health endpoint answers 200
  revisions    every self-reporting service reports exactly its manifest commit
  auth         admin/data surfaces refuse unauthenticated calls (401/403, or a redirect to sign-in)
  defaults     no published default secret, no mock auth, no demo tenant token in the running env
  headers      the console sends nosniff + frame protection and does not advertise its framework
  exposure     (compose) published ports bind to loopback only; TLS is the operator's reverse proxy
Nothing here prints a secret value.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

NODE_FETCH = r"""
const [u, m] = [process.argv[1], process.argv[2] || 'GET'];
fetch(u, {method: m, redirect: 'manual', headers: {'content-type': 'application/json'}, body: m === 'POST' ? '{}' : undefined})
  .then(async r => { const h = {}; r.headers.forEach((v, k) => h[k] = v); let b = ''; try { b = (await r.text()).slice(0, 4000) } catch (e) {}
                     process.stdout.write(JSON.stringify({status: r.status, headers: h, body: b})) })
  .catch(e => process.stdout.write(JSON.stringify({status: 0, error: String(e)})));
"""


class Probe:
    def __init__(self, a: argparse.Namespace):
        self.a = a

    def _exec(self, service: str, argv: list[str]) -> str:
        if self.a.form == "compose":
            cmd = ["docker", "compose", "-p", self.a.project, "exec", "-T", service, *argv]
        else:
            cmd = ["kubectl", "-n", self.a.namespace, "exec", f"deploy/{service}", "--", *argv]
        return subprocess.run(cmd, capture_output=True, text=True).stdout

    def http(self, via: str, url: str, method: str = "GET") -> dict:
        """HTTP from inside the product network, executed in a product container that has node."""
        raw = self._exec(via, ["node", "-e", NODE_FETCH, url, method])
        try:
            return json.loads(raw)
        except Exception:
            return {"status": 0, "error": raw[:200]}

    def env_names(self, service: str) -> dict:
        if self.a.form == "compose":
            ids = subprocess.run(["docker", "compose", "-p", self.a.project, "ps", "-q", service], capture_output=True, text=True).stdout.split()
            if not ids:
                return {}
            env = json.loads(subprocess.run(["docker", "inspect", ids[0], "--format", "{{json .Config.Env}}"], capture_output=True, text=True).stdout or "[]")
            return dict(e.split("=", 1) for e in env if "=" in e)
        j = json.loads(subprocess.run(["kubectl", "-n", self.a.namespace, "get", f"deploy/{service}", "-o", "json"], capture_output=True, text=True).stdout or "{}")
        cs = j.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])
        return {e["name"]: e.get("value", "<secretRef>") for e in cs[0].get("env", [])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--form", choices=["compose", "helm"], required=True)
    ap.add_argument("--project", default="intentgate")
    ap.add_argument("--namespace", default="intentgate")
    a = ap.parse_args()
    m = json.load(open(a.manifest))
    comps = {c["name"]: c for c in m["components"]}
    svc = {n: c["runtime"]["service"] for n, c in comps.items()}
    port = {n: c["runtime"]["port"] for n, c in comps.items()}
    p = Probe(a)
    via = svc["console-pro"]  # a product container with node, inside the product network
    results: list[tuple[str, bool, str]] = []

    def url(n: str, path: str) -> str:
        return f"http://{svc[n]}:{port[n]}{path}"

    # health
    for n, path in (("platform-gateway", "/health"), ("governance-worker", "/readyz"), ("gateway", "/healthz"), ("console-pro", "/api/version")):
        if n in comps:
            r = p.http(via, url(n, path))
            results.append((f"health:{n}", r.get("status") == 200, f"GET {path} -> {r.get('status')}"))
    # revisions
    for n, c in comps.items():
        rs = c["runtime"]["revision_source"]
        if rs["kind"] != "http-json":
            results.append((f"revision:{n}", False if c["kind"] == "first-party" else True,
                            f"{rs['kind']}: the service cannot report its own commit" if c["kind"] == "first-party" else "third-party, digest only"))
            continue
        r = p.http(via, url(n, rs["path"]))
        try:
            got = json.loads(r.get("body") or "{}").get(rs["field"])
        except Exception:
            got = None
        results.append((f"revision:{n}", got == c["source"]["commit"], f"{rs['path']}#{rs['field']}={got} manifest={c['source']['commit']}"))
    # auth required
    def refused(r: dict) -> bool:
        s = r.get("status", 0)
        loc = r.get("headers", {}).get("location", "")
        return s in (401, 403) or (300 <= s < 400 and "/auth/signin" in loc)
    for n, path, method in (("console-pro", "/", "GET"), ("console-pro", "/api/agents", "GET"),
                            ("gateway", "/v1/admin/audit", "GET"), ("gateway", "/v1/mcp", "POST"),
                            ("platform-gateway", "/api/v1/discovery/observations", "POST")):
        if n in comps:
            r = p.http(via, url(n, path), method)
            results.append((f"auth:{n}{path}", refused(r), f"{method} {path} unauthenticated -> {r.get('status')} {r.get('headers', {}).get('location', '')[:60]}"))
    # defaults
    ce, ge = p.env_names(svc["console-pro"]), p.env_names(svc["gateway"])
    results.append(("defaults:console-auth", ce.get("AUTH_PROVIDER") == "oidc" and "INTENTGATE_ALLOW_MOCK_AUTH" not in ce, "AUTH_PROVIDER must be oidc; mock opt-out absent"))
    results.append(("defaults:gateway-demo-tenant", "INTENTGATE_TENANT_ADMINS" not in ge, "no demo tenant-admin token in the gateway env"))
    published = {"lab-deception-token", "intentgate", "dev", "changeme"}
    bad = [k for env in (ce, ge) for k, v in env.items() if v in published and k.endswith(("TOKEN", "SECRET", "PASSWORD", "KEY"))]
    results.append(("defaults:published-secrets", not bad, f"keys with a published default value: {bad or 'none'}"))
    # headers
    r = p.http(via, url("console-pro", "/auth/signin"))
    h = {k.lower(): v for k, v in r.get("headers", {}).items()}
    frame = "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "")
    results.append(("headers:nosniff", h.get("x-content-type-options", "").lower() == "nosniff", f"x-content-type-options={h.get('x-content-type-options')}"))
    results.append(("headers:frame-protection", frame, f"x-frame-options={h.get('x-frame-options')} csp-frame-ancestors={'frame-ancestors' in h.get('content-security-policy', '')}"))
    results.append(("headers:no-powered-by", "x-powered-by" not in h, f"x-powered-by={h.get('x-powered-by')}"))
    # exposure
    if a.form == "compose":
        out = subprocess.run(["docker", "compose", "-p", a.project, "ps", "--format", "{{.Service}} {{.Publishers}}"], capture_output=True, text=True).stdout
        wide = [line for line in out.splitlines() if "0.0.0.0" in line or ":::" in line]
        results.append(("exposure:loopback-only", not wide, f"published on all interfaces: {wide or 'none'}"))
    ok = all(x for _, x, _ in results)
    for name, x, d in results:
        print(f"SMOKE|{name}|{'PASS' if x else 'FAIL'}|{d}")
    print(f"SECURITY_SMOKE={'GREEN' if ok else 'RED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
