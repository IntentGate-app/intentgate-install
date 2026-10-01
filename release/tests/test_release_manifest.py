#!/usr/bin/env python3
"""Anti-vacuity tests for release/release-manifest.py.

A GOOD fixture (every component ACCEPTED with a tagged anchor, digest, signed IGBA/1 record, SBOM and a
DSSE attestation signed by a throw-away ECDSA key the test pins as its own trust anchor) must PASS
build -> sign -> verify -> verify-bundle -> verify-install. Each deliberately BROKEN fixture must FAIL.
The tool is exercised as a black box (subprocess), exactly as CI and the installer call it.

All keys are generated per run in a temporary directory. No private key is ever committed.

    python3 -m unittest release/tests/test_release_manifest.py -v      (or: pytest release/tests)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.dirname(HERE)
ROOT = os.path.dirname(REL)
TOOL = os.path.join(REL, "release-manifest.py")
CONTRACT = os.path.join(REL, "config-contract.json")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402


def run(*args: str, cwd: str | None = None) -> tuple[int, str]:
    r = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout + r.stderr


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def D(n: int) -> str:
    return "sha256:" + format(n, "x") * 64 if n < 16 else "sha256:" + sha(str(n).encode())


def C(n: int) -> str:
    return sha(f"commit{n}".encode())[:40]


SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
COMPONENTS = [("console-pro", "ghcr.io/intentgate-app/intentgate-console-pro", 3000),
              ("platform-gateway", "ghcr.io/intentgate-app/intentgate-platform-gateway", 4000),
              ("governance-worker", "ghcr.io/intentgate-app/intentgate-platform-governance-worker", 4100),
              ("gateway", "ghcr.io/intentgate-app/intentgate-gateway", 8080),
              ("extractor", "ghcr.io/intentgate-app/intentgate-extractor", 8090)]


class Fixture:
    """A self-contained release tree: release/ (tool inputs, evidence, trust) + bundle static files."""

    def __init__(self, digests: dict | None = None) -> None:
        self.digests = digests or {}
        self.dir = tempfile.mkdtemp(prefix="igrm-")
        self.rel = os.path.join(self.dir, "release")
        for sub in ("inputs", "evidence", "trust"):
            os.makedirs(os.path.join(self.rel, sub))
        shutil.copy(CONTRACT, os.path.join(self.rel, "config-contract.json"))
        shutil.copy(TOOL, os.path.join(self.rel, "release-manifest.py"))
        shutil.copy(os.path.join(REL, "release-manifest.schema.json"), os.path.join(self.rel, "release-manifest.schema.json"))
        for f in ("install.sh", "README.md"):
            open(os.path.join(self.dir, f), "w").write(f"fixture {f}\n")
        # release signing key (ECDSA P-256, the production algorithm) pinned by this fixture's anchor
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.ec_key_other = ec.generate_private_key(ec.SECP256R1())
        point = self.ec_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        fp = sha(SPKI_PREFIX + point)
        json.dump({"key_set_version": "IGRK/1", "keys": [{"key_id": "test-release-key", "algorithm": "ECDSA_P256_SHA256",
                   "public_key_hex": point.hex(), "fingerprint_sha256": fp, "status": "ACTIVE"}]},
                  open(os.path.join(self.rel, "trust", "release-key-set.json"), "w"))
        json.dump({"anchor_version": "IGRK-ANCHOR/1", "fingerprints": [{"key_id": "test-release-key", "fingerprint_sha256": fp}]},
                  open(os.path.join(self.rel, "trust", "release-trust-anchor.json"), "w"))
        # ed25519 TEST key for the detached test signature path
        self.ed = ed25519.Ed25519PrivateKey.generate()
        self.ed_other = ed25519.Ed25519PrivateKey.generate()
        for name, k in (("test.key", self.ed), ("other.key", self.ed_other)):
            open(os.path.join(self.dir, name), "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            open(os.path.join(self.dir, name + ".pub"), "wb").write(k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.inputs = self._good_inputs()
        # owner direction 2026-09-30: releasable only with an independent review gate result for exactly these commits
        self.inputs["independent_review"] = {
            "INDEPENDENT_REVIEW": "GREEN", "DETERMINISTIC_GATES": "GREEN", "RELEASE_ELIGIBLE": "YES",
            "candidate_id": "C-fixture", "bundle_sha256": "0" * 64,
            "candidate_heads": {c["source"]["repository"].rsplit("/", 1)[-1]: c["source"]["commit"]
                                for c in self.inputs["components"] if c.get("kind") != "third-party"}}
        self.bundle_files = {"static": ["install.sh", "README.md", "release/release-manifest.py", "release/config-contract.json"],
                             "rendered": ["docker-compose.yml", ".env.example"], "generated_at_install": [".env"]}

    def p(self, *a: str) -> str:
        return os.path.join(self.dir, *a)

    def _attestation(self, name: str, digest: str, key=None) -> str:
        stmt = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": name, "digest": {"sha256": digest.split(":", 1)[1]}}], "predicate": {}}
        payload = json.dumps(stmt).encode()
        pt = "application/vnd.in-toto+json"
        pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt.encode(), len(payload), payload)
        sig = (key or self.ec_key).sign(pae, ec.ECDSA(hashes.SHA256()))
        return json.dumps({"payloadType": pt, "payload": base64.b64encode(payload).decode(),
                           "signatures": [{"keyid": "test-release-key", "sig": base64.b64encode(sig).decode()}]})

    def _good_inputs(self) -> dict:
        comps = []
        for i, (name, repo, port) in enumerate(COMPONENTS):
            digest, commit = self.digests.get(name, D(i + 1)), C(i + 1)
            ev = os.path.join(self.rel, "evidence", name)
            os.makedirs(ev)
            json.dump({"record_version": "IGBA/1",
                       "artifact": {"digest": digest, "registry_ref": repo, "self_report": "STAMPED"},
                       "source": {"revision": commit, "repository": "https://example.invalid/" + name, "tree_state": "CLEAN"},
                       "builder": {"run_id": str(100 + i)}, "signing": {"state": "SIGNED"},
                       "acceptance_eligibility": {"state": "ELIGIBLE"}}, open(os.path.join(ev, "build-attribution.json"), "w"))
            json.dump({"bomFormat": "CycloneDX", "components": []}, open(os.path.join(ev, "sbom.json"), "w"))
            open(os.path.join(ev, "attestation.signed.json"), "w").write(self._attestation(repo, digest))
            comps.append({
                "name": name, "kind": "first-party", "role": name, "component_class": "runtime",
                "source": {"repository": "https://example.invalid/" + name, "commit": commit, "ref": None},
                "status": "ACCEPTED", "status_evidence": "fixture",
                "accepted_anchor": {"kind": "tag", "tag": f"LKG-FIXTURE-{name}", "commit": commit, "evidence": "fixture"},
                "image": {"repository": repo, "digest": digest},
                "attribution": f"evidence/{name}/build-attribution.json",
                "sbom": f"evidence/{name}/sbom.json",
                "provenance_attestation": f"evidence/{name}/attestation.signed.json",
                "runtime": {"service": name, "port": port, "health": {"kind": "none"},
                            "revision_source": {"kind": "http-json", "port": port, "path": "/v", "field": "commit"},
                            "depends_on": ["postgres"], "replicas": 1,
                            **({"publish": {"bind_key": "CONSOLE_BIND", "host_port": 3000}} if name == "console-pro" else {})},
                "schema_owner": {"ddl_mechanism": "versioned", "migration_level": "0042"} if name != "extractor" else None,
            })
        comps.append({"name": "postgres", "kind": "third-party", "role": "db", "component_class": "runtime",
                      "source": {"repository": "https://hub.docker.com/_/postgres", "commit": None, "ref": None},
                      "status": "THIRD_PARTY", "status_evidence": "fixture", "registry_verified": True, "accepted_anchor": None,
                      "image": {"repository": "docker.io/library/postgres", "digest": self.digests.get("postgres", D(9))},
                      "attribution": None, "sbom": None, "provenance_attestation": None,
                      "runtime": {"service": "postgres", "port": 5432,
                                  "health": {"kind": "exec", "compose_test": ["CMD-SHELL", "pg_isready"]},
                                  "revision_source": {"kind": "digest-only"}, "depends_on": [], "replicas": 1,
                                  "volume": {"name": "intentgate-db", "mount": "/var/lib/postgresql/data"}},
                      "schema_owner": None})
        comps.append(self._sdk())
        return {"inputs_version": "igrm-inputs/1", "release_id": "intentgate-2026.01.01-rc1", "created_at": "2026-01-01T00:00:00Z",
                "open_owner_decisions": [], "components": comps,
                "schema": {"database": "intentgate", "fingerprint_algorithm": "lkg-lab-state/1 DB_SCHEMA",
                           "expected_fingerprint": "0123456789abcdef0123456789abcdef", "expected_fingerprint_evidence": "fixture",
                           "migration_manifest": {"levels": ["0042"]}}}

    SDK_ARTIFACTS = [{"filename": "intentgate-0.3.0-py3-none-any.whl", "sha256": sha(b"wheel")},
                     {"filename": "intentgate-0.3.0.tar.gz", "sha256": sha(b"sdist")}]

    def _sdk_attestation(self, shas: list, key=None) -> str:
        stmt = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": "intentgate", "digest": {"sha256": h}} for h in shas], "predicate": {}}
        payload = json.dumps(stmt).encode()
        pt = "application/vnd.in-toto+json"
        pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt.encode(), len(payload), payload)
        sig = (key or self.ec_key).sign(pae, ec.ECDSA(hashes.SHA256()))
        return json.dumps({"payloadType": pt, "payload": base64.b64encode(payload).decode(),
                           "signatures": [{"keyid": "test-release-key", "sig": base64.b64encode(sig).decode()}]})

    def _sdk(self) -> dict:
        """A fully evidenced DISTRIBUTABLE (positive control): accepted anchor, version tag at the commit, governed
        artifact digests, signed build record, SBOM, attestation over exactly the artifacts. No image, no runtime."""
        commit = C(42)
        ev = os.path.join(self.rel, "evidence", "sdk-python")
        os.makedirs(ev)
        digests = ["sha256:" + a["sha256"] for a in self.SDK_ARTIFACTS]
        json.dump({"record_version": "IGBA/1", "artifact": {"digests": digests, "registry_ref": "pypi:intentgate"},
                   "source": {"revision": commit, "tree_state": "CLEAN"}, "builder": {"run_id": "200"},
                   "signing": {"state": "SIGNED"}, "acceptance_eligibility": {"state": "ELIGIBLE"}},
                  open(os.path.join(ev, "build-attribution.json"), "w"))
        json.dump({"bomFormat": "CycloneDX", "components": []}, open(os.path.join(ev, "sbom.json"), "w"))
        open(os.path.join(ev, "attestation.signed.json"), "w").write(self._sdk_attestation([a["sha256"] for a in self.SDK_ARTIFACTS]))
        return {"name": "sdk-python", "kind": "first-party", "role": "client SDK", "component_class": "distributable",
                "source": {"repository": "https://example.invalid/intentgate-sdk-python", "commit": commit, "ref": None},
                "status": "ACCEPTED", "status_evidence": "fixture",
                "accepted_anchor": {"kind": "tag", "tag": "LKG-FIXTURE-sdk-python", "commit": commit, "evidence": "fixture"},
                "image": None, "runtime": None, "schema_owner": None,
                "distributable": {"ecosystem": "pypi", "package_name": "intentgate", "version": "0.3.0", "version_tag": "v0.3.0",
                                  "version_tag_commit": commit, "artifacts": copy.deepcopy(self.SDK_ARTIFACTS),
                                  "artifact_digest_kind": "governed-build", "artifact_digest_source": "fixture"},
                "attribution": "evidence/sdk-python/build-attribution.json", "sbom": "evidence/sdk-python/sbom.json",
                "provenance_attestation": "evidence/sdk-python/attestation.signed.json"}

    def comp(self, inputs: dict, name: str) -> dict:
        return next(c for c in inputs["components"] if c["name"] == name)

    def build(self, inputs: dict | None = None, out: str = "release-manifest.json") -> tuple[int, str]:
        ip = os.path.join(self.rel, "inputs", "in.json")
        json.dump(inputs or self.inputs, open(ip, "w"), indent=2)
        bf = self.p("bundle-files.json")
        json.dump(self.bundle_files, open(bf, "w"))
        return run("build", "--inputs", ip, "--contract", os.path.join(self.rel, "config-contract.json"),
                   "--bundle-files", bf, "--bundle-root", self.dir, "--out", self.p(out))

    def render(self, manifest: str = "release-manifest.json") -> None:
        c = os.path.join(self.rel, "config-contract.json")
        assert run("render-compose", "--manifest", self.p(manifest), "--contract", c, "--out", self.p("docker-compose.yml"))[0] == 0
        assert run("render-env-example", "--contract", c, "--out", self.p(".env.example"))[0] == 0

    def sign_ec(self, manifest: str, key=None, out: str = "release-manifest.json.sig") -> None:
        sig = (key or self.ec_key).sign(open(self.p(manifest), "rb").read(), ec.ECDSA(hashes.SHA256()))
        open(self.p(out), "wb").write(base64.b64encode(sig) + b"\n")

    def trust(self) -> list[str]:
        return ["--key-set", os.path.join(self.rel, "trust", "release-key-set.json"),
                "--trust-anchor", os.path.join(self.rel, "trust", "release-trust-anchor.json")]

    def good_env(self) -> str:
        env = self.p(".env")
        open(env, "w").write("\n".join([
            "AUTH_OIDC_ISSUER=https://login.example.invalid/tenant/v2.0", "AUTH_OIDC_CLIENT_ID=client",
            "AUTH_OIDC_CLIENT_SECRET=secret-value", "AUTH_ROLE_CLAIM=groups", "AUTH_ROLE_MAPPING=ig-admins:admin",
            "CONSOLE_PRO_PUBLIC_URL=https://console.example.invalid", "INTENTGATE_PUBLIC_GATEWAY_URL=https://gw.example.invalid",
            "INTENTGATE_PLATFORM_GATEWAY_TENANT=tenant-a"]) + "\n")
        rc, o = run("config-generate", "--contract", os.path.join(self.rel, "config-contract.json"), "--env", env)
        assert rc == 0, o
        return env

    def facts(self, manifest: dict) -> dict:
        files = {}
        for d, _, fs in os.walk(self.dir):
            for f in fs:
                rp = os.path.relpath(os.path.join(d, f), self.dir)
                if rp.split(os.sep)[0] in ("release-manifest.json", "release-manifest.json.sig", "install.sh", "README.md",
                                           "docker-compose.yml", ".env.example", ".env") or rp in manifest["bundle"]["static"]:
                    files[rp] = sha(open(os.path.join(d, f), "rb").read())
        cf = os.path.join(self.dir, "cfacts.json")
        run("config-validate", "--contract", os.path.join(self.rel, "config-contract.json"), "--env", self.p(".env"), "--facts-out", cf)
        rt = [c for c in manifest["components"] if c["component_class"] == "runtime"]
        return {"facts_version": "igif/1", "install_form": "compose", "release_id": manifest["release_id"],
                "containers": [{"service": c["runtime"]["service"], "image_digest": c["image"]["digest"]} for c in rt],
                "revisions": {c["runtime"]["service"]: {"source": "http", "value": c["source"]["commit"]}
                              for c in rt if c["kind"] == "first-party"},
                "env_names": {c["runtime"]["service"]: ["PATH", "PORT"] for c in rt},
                "schema_fingerprint": manifest["schema"]["expected_fingerprint"],
                "config": json.load(open(cf)),
                "inventory": {"files": files, "nested_repositories": []}}

    def verify_install(self, facts: dict) -> tuple[int, str]:
        fp = self.p("facts.json")
        json.dump(facts, open(fp, "w"))
        return run("verify-install", "--manifest", self.p("release-manifest.json"), "--sig", self.p("release-manifest.json.sig"),
                   *self.trust(), "--contract", os.path.join(self.rel, "config-contract.json"), "--facts", fp)

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


class GoodFixture(unittest.TestCase):
    """The positive control. If this fails, every negative result below is meaningless."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.f = Fixture()
        rc, o = cls.f.build()
        assert rc == 0, o
        cls.f.render()
        cls.f.sign_ec("release-manifest.json")
        cls.f.good_env()
        cls.m = json.load(open(cls.f.p("release-manifest.json")))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.f.cleanup()

    def test_01_good_manifest_is_releasable(self) -> None:
        self.assertTrue(self.m["releasable"], self.m["releasable_blockers"])
        self.assertEqual(self.m["releasable_blockers"], [])
        for c in self.m["components"]:
            if c["provenance_attestation"]:
                self.assertEqual(c["provenance_attestation"]["signature"], "VERIFIED")

    def test_02_good_signature_verifies_and_is_releasable(self) -> None:
        rc, o = run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                    *self.f.trust(), "--require-releasable")
        self.assertEqual(rc, 0, o)
        self.assertIn("MANIFEST_VERIFY=PASS", o)

    def test_03_good_bundle_verifies(self) -> None:
        # the fixture dir also holds test keys/inputs: verify a clean copy of just the bundle
        b = tempfile.mkdtemp()
        try:
            for rel in list(self.m["bundle"]["static"]) + self.m["bundle"]["rendered"] + ["release-manifest.json", "release-manifest.json.sig", ".env"]:
                os.makedirs(os.path.dirname(os.path.join(b, rel)) or b, exist_ok=True)
                shutil.copy(self.f.p(rel), os.path.join(b, rel))
            rc, o = run("verify-bundle", "--manifest", os.path.join(b, "release-manifest.json"), "--bundle-dir", b)
            self.assertEqual(rc, 0, o)
        finally:
            shutil.rmtree(b)

    def test_04_good_install_chain_is_green(self) -> None:
        rc, o = self.f.verify_install(self.f.facts(self.m))
        self.assertEqual(rc, 0, o)
        self.assertIn("PROVENANCE_CHAIN=GREEN", o)
        self.assertNotIn("|FAIL|", o)

    def test_05_good_config_validates(self) -> None:
        rc, o = run("config-validate", "--contract", CONTRACT, "--env", self.f.p(".env"))
        self.assertEqual(rc, 0, o)
        self.assertNotIn("secret-value", o)  # values are never printed

    def test_06_compose_is_digest_only_and_matches_helm(self) -> None:
        compose = open(self.f.p("docker-compose.yml")).read()
        self.assertNotIn("latest", compose)
        rc, refs = run("image-refs", "--kind", "compose", "--file", self.f.p("docker-compose.yml"))
        self.assertEqual(rc, 0)
        crefs = dict(line.split("=", 1) for line in refs.split())
        self.assertEqual(len(crefs), 6)
        for r in crefs.values():
            self.assertRegex(r, r"@sha256:[0-9a-f]{64}$")
        rc, vals = run("render-helm-values", "--manifest", self.f.p("release-manifest.json"), "--contract", CONTRACT)
        self.assertEqual(rc, 0, vals)
        # parity: Helm values name the same repository@digest per component as compose
        hrefs, comp = {}, None
        for line in vals.splitlines():
            s = line.strip()
            if line.startswith("  ") and not line.startswith("   ") and s.endswith(":") and s[:-1] in {c["name"] for c in self.m["components"]}:
                comp = s[:-1]
            if s.startswith("repository:"):
                repo = json.loads(s.split(":", 1)[1])
            if s.startswith("digest:") and comp:
                hrefs[self.m_service(comp)] = f"{repo}@{json.loads(s.split(':', 1)[1])}"
        self.assertEqual(hrefs, crefs)

    def m_service(self, comp: str) -> str:
        return next(c["runtime"]["service"] for c in self.m["components"] if c["name"] == comp)

    def test_07_rebuild_is_deterministic(self) -> None:
        rc, o = self.f.build(out="again.json")
        self.assertEqual(rc, 0, o)
        self.assertEqual(open(self.f.p("again.json"), "rb").read(), open(self.f.p("release-manifest.json"), "rb").read())

    def test_08_compose_render_is_accepted_by_docker_compose(self) -> None:
        if not shutil.which("docker"):
            self.skipTest("docker not available")
        r = subprocess.run(["docker", "compose", "-f", self.f.p("docker-compose.yml"), "--env-file", self.f.p(".env"), "config", "-q"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_09_ed25519_test_key_path(self) -> None:
        sig = self.f.p("ed.sig")
        rc, o = run("sign", "--manifest", self.f.p("release-manifest.json"), "--test-private-key", self.f.p("test.key"), "--sig-out", sig)
        self.assertEqual(rc, 0, o)
        rc, o = run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", sig, "--test-public-key", self.f.p("test.key.pub"), "--allow-test-key")
        self.assertEqual(rc, 0, o)


class BrokenFixtures(unittest.TestCase):
    """Every deliberately broken fixture must be refused."""

    def setUp(self) -> None:
        self.f = Fixture()

    def tearDown(self) -> None:
        self.f.cleanup()

    def good(self) -> dict:
        rc, o = self.f.build()
        self.assertEqual(rc, 0, o)
        self.f.render()
        self.f.sign_ec("release-manifest.json")
        self.f.good_env()
        return json.load(open(self.f.p("release-manifest.json")))

    def assertFails(self, rc: int, o: str, code: str) -> None:
        self.assertNotEqual(rc, 0, o)
        self.assertIn(code, o)

    # --- identity: tags, latest ---------------------------------------------------------------
    def test_tag_instead_of_digest(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "console-pro")["image"]["digest"] = "1.6.3"
        self.assertFails(*self.f.build(i), "IMAGE_NOT_DIGEST")

    def test_tag_in_repository_field(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "gateway")["image"]["repository"] = "ghcr.io/intentgate-app/intentgate-gateway:1.6.2"
        self.assertFails(*self.f.build(i), "IMAGE_REPOSITORY")

    def test_tag_field_on_image(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "gateway")["image"]["tag"] = "main"
        self.assertFails(*self.f.build(i), "IMAGE_FIELDS")

    def test_latest_in_repository(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "extractor")["image"]["repository"] = "ghcr.io/intentgate-app/intentgate-extractor:latest"
        self.assertFails(*self.f.build(i), "IMAGE_REPOSITORY")

    def test_latest_anywhere_in_manifest(self) -> None:
        self.good()
        m = json.load(open(self.f.p("release-manifest.json")))
        m["components"][0]["role"] = "console ${INTENTGATE_VERSION:-latest}"
        json.dump(m, open(self.f.p("release-manifest.json"), "w"))
        self.assertFails(*run("lint", "--manifest", self.f.p("release-manifest.json")), "MUTABLE_REFERENCE")

    # --- evidence -------------------------------------------------------------------------------
    def test_missing_attribution_is_not_releasable(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "console-pro")["attribution"] = None
        rc, o = self.f.build(i)
        self.assertEqual(rc, 0, o)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertFalse(m["releasable"])
        self.assertIn("NO_ATTRIBUTION", [b["code"] for b in m["releasable_blockers"]])
        self.f.sign_ec("release-manifest.json")
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              *self.f.trust(), "--require-releasable"), "NOT_RELEASABLE")

    def test_attribution_for_another_digest(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "platform-gateway")["image"]["digest"] = D(7)
        self.assertFails(*self.f.build(i), "ATTRIBUTION_DIGEST_MISMATCH")

    def test_wrong_commit_component(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        c = self.f.comp(i, "gateway")
        c["source"]["commit"] = C(99)
        c["accepted_anchor"]["commit"] = C(99)
        self.assertFails(*self.f.build(i), "ATTRIBUTION_COMMIT_MISMATCH")

    def test_attestation_subject_mismatch(self) -> None:
        open(os.path.join(self.f.rel, "evidence", "gateway", "attestation.signed.json"), "w").write(
            self.f._attestation("x", D(12)))
        self.assertFails(*self.f.build(), "ATTESTATION_SUBJECT_MISMATCH")

    def test_attestation_signed_by_untrusted_key(self) -> None:
        open(os.path.join(self.f.rel, "evidence", "gateway", "attestation.signed.json"), "w").write(
            self.f._attestation("x", D(4), key=self.f.ec_key_other))
        rc, o = self.f.build()
        self.assertEqual(rc, 0, o)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertIn(("gateway", "ATTESTATION_NOT_VERIFIED"), [(b["component"], b["code"]) for b in m["releasable_blockers"]])

    # --- acceptance cannot be invented ----------------------------------------------------------
    def test_provisional_component_is_not_releasable(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "platform-gateway")["status"] = "PROVISIONAL"
        rc, o = self.f.build(i)
        self.assertEqual(rc, 0, o)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertFalse(m["releasable"])

    def test_provisional_component_marked_releasable_by_hand(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "platform-gateway")["status"] = "PROVISIONAL"
        self.f.build(i)
        m = json.load(open(self.f.p("release-manifest.json")))
        m["releasable"], m["releasable_blockers"] = True, []
        json.dump(m, open(self.f.p("release-manifest.json"), "w"))
        self.f.sign_ec("release-manifest.json")  # even correctly signed, a hand-set flag is refused
        rc, o = run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"), *self.f.trust())
        self.assertFails(rc, o, "RELEASABLE_BLOCKERS_NOT_COMPUTED")
        self.assertIn("RELEASABLE_FLAG_NOT_COMPUTED", o)

    def test_accepted_without_matching_anchor(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "gateway")["accepted_anchor"]["commit"] = C(50)
        self.assertFails(*self.f.build(i), "ACCEPTANCE_INVENTED")

    def test_untagged_anchor_is_not_releasable(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "console-pro")["accepted_anchor"]["tag"] = None
        self.f.build(i)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertIn("ANCHOR_NOT_TAGGED", [b["code"] for b in m["releasable_blockers"]])

    def test_unmeasured_schema_is_not_releasable(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        i["schema"]["expected_fingerprint"] = None
        self.f.build(i)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertIn("SCHEMA_FINGERPRINT_UNMEASURED", [b["code"] for b in m["releasable_blockers"]])

    def test_missing_required_component(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        i["components"] = [c for c in i["components"] if c["name"] != "governance-worker"]
        self.f.build(i)
        m = json.load(open(self.f.p("release-manifest.json")))
        self.assertIn(("governance-worker", "REQUIRED_COMPONENT_MISSING"), [(b["component"], b["code"]) for b in m["releasable_blockers"]])

    # --- signatures -----------------------------------------------------------------------------
    def test_unsigned(self) -> None:
        self.good()
        os.remove(self.f.p("release-manifest.json.sig"))
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              *self.f.trust()), "UNSIGNED")

    def test_tampered_manifest(self) -> None:
        self.good()
        data = open(self.f.p("release-manifest.json"), "rb").read().replace(b'"replicas": 1', b'"replicas": 2', 1)
        open(self.f.p("release-manifest.json"), "wb").write(data)
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              *self.f.trust()), "SIGNATURE_INVALID")

    def test_wrong_key(self) -> None:
        self.good()
        self.f.sign_ec("release-manifest.json", key=self.f.ec_key_other)
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              *self.f.trust()), "SIGNATURE_INVALID")

    def test_key_not_pinned_by_trust_anchor(self) -> None:
        self.good()
        ap = os.path.join(self.f.rel, "trust", "release-trust-anchor.json")
        a = json.load(open(ap))
        a["fingerprints"][0]["fingerprint_sha256"] = "0" * 64
        json.dump(a, open(ap, "w"))
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              *self.f.trust()), "NO_TRUSTED_KEY")

    def test_substituted_trust_root_refused_by_out_of_band_pin(self) -> None:
        """An attacker who controls the bundle replaces key set + anchor and re-signs. The bundled anchor
        is circular and accepts it; the out-of-band pinned fingerprint (what install.sh uses) refuses it."""
        self.good()
        point = lambda k: k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        genuine_fp = sha(SPKI_PREFIX + point(self.f.ec_key))
        rc, o = run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                    "--key-set", os.path.join(self.f.rel, "trust", "release-key-set.json"), "--pinned-fingerprint", genuine_fp)
        self.assertEqual(rc, 0, o)  # positive control for the pinned mode
        atk = ec.generate_private_key(ec.SECP256R1())
        afp = sha(SPKI_PREFIX + point(atk))
        json.dump({"keys": [{"key_id": "attacker", "algorithm": "ECDSA_P256_SHA256", "public_key_hex": point(atk).hex(),
                             "fingerprint_sha256": afp, "status": "ACTIVE"}]}, open(os.path.join(self.f.rel, "trust", "release-key-set.json"), "w"))
        json.dump({"fingerprints": [{"key_id": "attacker", "fingerprint_sha256": afp}]}, open(os.path.join(self.f.rel, "trust", "release-trust-anchor.json"), "w"))
        self.f.sign_ec("release-manifest.json", key=atk)
        rc, o = run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"), *self.f.trust())
        self.assertEqual(rc, 0, "the bundled anchor is circular by construction; this documents why install.sh never uses it")
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                              "--key-set", os.path.join(self.f.rel, "trust", "release-key-set.json"), "--pinned-fingerprint", genuine_fp),
                         "NO_TRUSTED_KEY")

    def test_installer_requires_out_of_band_fingerprint(self) -> None:
        d = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(ROOT, "install.sh"), d)
            open(os.path.join(d, "release-manifest.json"), "w").write("{}")
            open(os.path.join(d, "release-manifest.json.sig"), "w").write("x")
            env = {k: v for k, v in os.environ.items() if k != "INTENTGATE_RELEASE_KEY_FINGERPRINT"}
            r = subprocess.run(["bash", os.path.join(d, "install.sh")], capture_output=True, text=True, env=env)
            self.assertNotEqual(r.returncode, 0)
            if "Docker" in r.stderr and "INTENTGATE_RELEASE_KEY_FINGERPRINT" not in r.stderr:
                self.skipTest("docker prerequisite not met before the fingerprint step")
            self.assertIn("INTENTGATE_RELEASE_KEY_FINGERPRINT", r.stderr)
        finally:
            shutil.rmtree(d)

    def test_test_key_requires_explicit_opt_in(self) -> None:
        self.good()
        run("sign", "--manifest", self.f.p("release-manifest.json"), "--test-private-key", self.f.p("test.key"), "--sig-out", self.f.p("t.sig"))
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("t.sig"),
                              "--test-public-key", self.f.p("test.key.pub")), "TEST_KEY_REFUSED")

    def test_wrong_test_key(self) -> None:
        self.good()
        run("sign", "--manifest", self.f.p("release-manifest.json"), "--test-private-key", self.f.p("other.key"), "--sig-out", self.f.p("t.sig"))
        self.assertFails(*run("verify", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("t.sig"),
                              "--test-public-key", self.f.p("test.key.pub"), "--allow-test-key"), "SIGNATURE_INVALID")

    # --- install chain --------------------------------------------------------------------------
    def test_running_digest_differs(self) -> None:
        m = self.good()
        facts = self.f.facts(m)
        facts["containers"][2]["image_digest"] = D(13)
        self.assertFails(*self.f.verify_install(facts), "LINK|IMAGES_BY_DIGEST|FAIL")

    def test_running_container_not_in_manifest(self) -> None:
        m = self.good()
        facts = self.f.facts(m)
        facts["containers"].append({"service": "toolserver", "image_digest": D(14)})
        self.assertFails(*self.f.verify_install(facts), "LINK|IMAGES_BY_DIGEST|FAIL")

    def test_running_revision_differs(self) -> None:
        m = self.good()
        facts = self.f.facts(m)
        facts["revisions"]["gateway"]["value"] = C(77)
        self.assertFails(*self.f.verify_install(facts), "LINK|RUNNING_REVISIONS|FAIL")

    def test_schema_fingerprint_mismatch(self) -> None:
        m = self.good()
        facts = self.f.facts(m)
        facts["schema_fingerprint"] = "f" * 32
        self.assertFails(*self.f.verify_install(facts), "LINK|SCHEMA_FINGERPRINT|FAIL")

    def test_missing_config_key(self) -> None:
        m = self.good()
        env = self.f.p(".env")
        lines = [ln for ln in open(env).read().splitlines() if not ln.startswith("AUTH_OIDC_ISSUER=")]
        open(env, "w").write("\n".join(lines) + "\n")
        self.assertFails(*run("config-validate", "--contract", CONTRACT, "--env", env), "AUTH_OIDC_ISSUER: MISSING_REQUIRED")
        self.assertFails(*self.f.verify_install(self.f.facts(m)), "LINK|CONFIG_CONTRACT|FAIL")

    def test_published_default_secret_refused(self) -> None:
        self.good()
        env = self.f.p(".env")
        lines = [ln for ln in open(env).read().splitlines() if not ln.startswith("INTENTGATE_DECEPTION_TOKEN=")]
        open(env, "w").write("\n".join(lines + ["INTENTGATE_DECEPTION_TOKEN=lab-deception-token"]) + "\n")
        self.assertFails(*run("config-validate", "--contract", CONTRACT, "--env", env), "INTENTGATE_DECEPTION_TOKEN: FORBIDDEN_VALUE")

    def test_mutable_tag_key_refused(self) -> None:
        self.good()
        open(self.f.p(".env"), "a").write("IMAGE_TAG=1.6.2\n")
        self.assertFails(*run("config-validate", "--contract", CONTRACT, "--env", self.f.p(".env")), "IMAGE_TAG: FORBIDDEN_KEY")

    def test_mock_auth_refused(self) -> None:
        self.good()
        open(self.f.p(".env"), "a").write("AUTH_PROVIDER=mock\n")
        self.assertFails(*run("config-validate", "--contract", CONTRACT, "--env", self.f.p(".env")), "AUTH_PROVIDER: NOT_ALLOWED")

    def test_file_in_install_dir_not_in_bundle(self) -> None:
        m = self.good()
        facts = self.f.facts(m)
        facts["inventory"]["files"]["intentgate-install/docker-compose.yml"] = "0" * 64
        self.assertFails(*self.f.verify_install(facts), "LINK|BUNDLE_INVENTORY|FAIL")

    def test_nested_clone_in_bundle_dir(self) -> None:
        self.good()
        os.makedirs(self.f.p("intentgate-install", ".git"))
        open(self.f.p("intentgate-install", "install.sh"), "w").write("stale\n")
        rc, o = run("verify-bundle", "--manifest", self.f.p("release-manifest.json"), "--bundle-dir", self.f.dir)
        self.assertFails(rc, o, "NESTED_REPOSITORY")
        self.assertIn("FILE_NOT_IN_BUNDLE: intentgate-install/install.sh", o)

    def test_stale_archive_in_bundle_dir(self) -> None:
        self.good()
        open(self.f.p("intentgate-0.6.1.tgz"), "wb").write(b"\x1f\x8b")
        self.assertFails(*run("verify-bundle", "--manifest", self.f.p("release-manifest.json"), "--bundle-dir", self.f.dir),
                         "FILE_NOT_IN_BUNDLE: intentgate-0.6.1.tgz")

    def test_modified_static_file(self) -> None:
        self.good()
        open(self.f.p("install.sh"), "a").write("echo tampered\n")
        self.assertFails(*run("verify-bundle", "--manifest", self.f.p("release-manifest.json"), "--bundle-dir", self.f.dir),
                         "BUNDLE_FILE_MODIFIED: install.sh")

    def test_hand_edited_compose(self) -> None:
        self.good()
        p = self.f.p("docker-compose.yml")
        s = open(p).read()
        open(p, "w").write(s.replace("@sha256:" + "4" * 64, ":1.6.2", 1))
        self.assertFails(*run("verify-bundle", "--manifest", self.f.p("release-manifest.json"), "--bundle-dir", self.f.dir),
                         "RENDERED_DRIFT: docker-compose.yml")
        self.assertFails(*run("render-compose", "--manifest", self.f.p("release-manifest.json"), "--contract", CONTRACT, "--check", p),
                         "RENDER_DRIFT")

    def test_unresolved_digest_fails_closed_in_compose(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        c = self.f.comp(i, "extractor")
        c["image"]["digest"] = None
        c["attribution"] = c["sbom"] = c["provenance_attestation"] = None
        rc, o = self.f.build(i)
        self.assertEqual(rc, 0, o)
        self.f.render()
        text = open(self.f.p("docker-compose.yml")).read()
        self.assertIn("${INTENTGATE_UNRESOLVED_EXTRACTOR:?", text)
        if shutil.which("docker"):
            self.f.good_env()
            r = subprocess.run(["docker", "compose", "-f", self.f.p("docker-compose.yml"), "--env-file", self.f.p(".env"), "config", "-q"],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("no digest for extractor", r.stderr)


class ReleaseInputGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.d = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q", self.d], check=True)
        open(os.path.join(self.d, "docker-compose.yml"), "w").write('services:\n  a:\n    image: "r.example/a@sha256:' + "1" * 64 + '"\n')
        open(os.path.join(self.d, ".gitignore"), "w").write("nested/\n")
        subprocess.run(["git", "-C", self.d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", self.d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], check=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.d)

    def guard(self) -> tuple[int, str]:
        return run("guard-release-input", "--root", self.d)

    def commit(self, name: str, text: str) -> None:
        open(os.path.join(self.d, name), "w").write(text)
        subprocess.run(["git", "-C", self.d, "add", name], check=True)
        subprocess.run(["git", "-C", self.d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], check=True)

    def test_clean_tree_passes(self) -> None:
        rc, o = self.guard()
        self.assertEqual(rc, 0, o)

    def test_nested_ignored_clone(self) -> None:
        os.makedirs(os.path.join(self.d, "nested", ".git"))
        rc, o = self.guard()
        self.assertNotEqual(rc, 0)
        self.assertIn("NESTED_REPOSITORY", o)

    def test_committed_chart_archive(self) -> None:
        self.commit("intentgate-0.6.1.tgz", "x")
        rc, o = self.guard()
        self.assertNotEqual(rc, 0)
        self.assertIn("ARCHIVE_IN_RELEASE_INPUT: intentgate-0.6.1.tgz", o)

    def test_untracked_file(self) -> None:
        open(os.path.join(self.d, "stray.yml"), "w").write("x: 1\n")
        rc, o = self.guard()
        self.assertIn("UNTRACKED_FILE: stray.yml", o)

    def test_latest_default(self) -> None:
        self.commit("ha.yml", "services:\n  g:\n    image: ghcr.io/x/gateway:${INTENTGATE_VERSION:-latest}\n")
        rc, o = self.guard()
        self.assertNotEqual(rc, 0)
        self.assertIn("MUTABLE_REFERENCE: ha.yml", o)

    def test_map_form_image_key_is_not_a_reference(self) -> None:
        self.commit("values.yaml", 'components:\n  a:\n    image:\n      repository: "ghcr.io/x/a"\n      digest: "sha256:' + "1" * 64 + '"\n')
        rc, o = self.guard()
        self.assertEqual(rc, 0, o)

    def test_tagged_image(self) -> None:
        self.commit("c.yml", "services:\n  p:\n    image: postgres:16-alpine\n")
        rc, o = self.guard()
        self.assertIn("IMAGE_NOT_BY_DIGEST: c.yml:3: postgres:16-alpine", o)


class IndependentReviewGate(unittest.TestCase):
    """Owner direction 2026-09-30: a release manifest is never releasable without a GREEN independent review for
    exactly its component commits - missing, RED, or covering other commits all block."""

    def setUp(self) -> None:
        self.f = Fixture()

    def tearDown(self) -> None:
        self.f.cleanup()

    def codes(self, inputs: dict) -> set:
        rc, o = self.f.build(inputs)
        self.assertEqual(rc, 0, o)
        m = json.load(open(self.f.p("release-manifest.json")))
        return {b["code"] for b in m["releasable_blockers"]}

    def test_missing_review_blocks(self) -> None:
        i = json.loads(json.dumps(self.f.inputs)); i.pop("independent_review")
        self.assertIn("INDEPENDENT_REVIEW_MISSING", self.codes(i))

    def test_red_review_blocks(self) -> None:
        for k, v in (("INDEPENDENT_REVIEW", "RED"), ("DETERMINISTIC_GATES", "RED"), ("RELEASE_ELIGIBLE", "NO")):
            i = json.loads(json.dumps(self.f.inputs)); i["independent_review"][k] = v
            self.assertIn("INDEPENDENT_REVIEW_NOT_GREEN", self.codes(i))

    def test_review_of_other_commits_blocks(self) -> None:
        i = json.loads(json.dumps(self.f.inputs)); k = sorted(i["independent_review"]["candidate_heads"])[0]
        i["independent_review"]["candidate_heads"][k] = "f" * 40
        self.assertIn("INDEPENDENT_REVIEW_NOT_FOR_THIS_COMMIT", self.codes(i))


GATEWAY_REPO = os.environ.get("INTENTGATE_GATEWAY_REPO", os.path.join(os.path.dirname(ROOT), "gateway"))
GATEWAY_EVIDENCE_COMMIT = "3acd0c4da3aa7ee44c06e52e639abeaff865274b"


def load_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_manifest", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ProductBoundary(unittest.TestCase):
    """Owner decisions 2026-10-01: SDKs are DISTRIBUTABLE artifacts, runtime images are RUNTIME-required, and the
    extractor is IN (runtime) by dependency evidence. Misclassification, a missing runtime component, or a component
    outside the evidenced boundary is refused; a distributable never reaches Compose, Helm or a running install."""

    def setUp(self) -> None:
        self.f = Fixture()

    def tearDown(self) -> None:
        self.f.cleanup()

    def built(self, inputs: dict | None = None) -> dict:
        rc, o = self.f.build(inputs)
        self.assertEqual(rc, 0, o)
        return json.load(open(self.f.p("release-manifest.json")))

    def codes(self, inputs: dict) -> set:
        return {(b["component"], b["code"]) for b in self.built(inputs)["releasable_blockers"]}

    # --- positive control ------------------------------------------------------------------------
    def test_good_release_with_a_distributable_is_releasable(self) -> None:
        m = self.built()
        self.assertTrue(m["releasable"], m["releasable_blockers"])
        sdk = next(c for c in m["components"] if c["name"] == "sdk-python")
        self.assertEqual(sdk["component_class"], "distributable")
        self.assertIsNone(sdk["image"])
        self.assertIsNone(sdk["runtime"])
        self.assertEqual(sdk["provenance_attestation"]["signature"], "VERIFIED")
        self.assertEqual({c["component_class"] for c in m["components"] if c["name"] != "sdk-python"}, {"runtime"})

    # --- negative: misclassification -------------------------------------------------------------
    def test_sdk_misclassified_as_runtime_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        c = self.f.comp(i, "sdk-python")
        c.update(component_class="runtime", image={"repository": "ghcr.io/intentgate-app/intentgate-sdk-python", "digest": D(11)},
                 runtime={"service": "sdk-python", "port": 1, "health": {"kind": "none"}, "revision_source": {"kind": "digest-only"}})
        c.pop("distributable")
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("COMPONENT_CLASS_MISMATCH: sdk-python is declared runtime", o)

    def test_distributable_carrying_an_image_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "sdk-python")["image"] = {"repository": "ghcr.io/intentgate-app/intentgate-sdk-python", "digest": D(11)}
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("DISTRIBUTABLE_HAS_IMAGE", o)

    def test_extractor_misclassified_as_distributable_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "extractor")["component_class"] = "distributable"
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("COMPONENT_CLASS_MISMATCH: extractor is declared distributable", o)

    def test_missing_runtime_component_blocks(self) -> None:
        for name in ("extractor", "postgres"):
            i = copy.deepcopy(self.f.inputs)
            i["components"] = [c for c in i["components"] if c["name"] != name]
            self.assertIn((name, "REQUIRED_COMPONENT_MISSING"), self.codes(i))

    def test_sdk_is_optional_but_never_required(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        i["components"] = [c for c in i["components"] if c["name"] != "sdk-python"]
        self.assertTrue(self.built(i)["releasable"])

    def test_component_outside_the_evidenced_boundary_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        c = copy.deepcopy(self.f.comp(i, "gateway"))
        c["name"] = "portal"
        i["components"].append(c)
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("COMPONENT_OUTSIDE_BOUNDARY: portal", o)

    def test_class_missing_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        del self.f.comp(i, "gateway")["component_class"]
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("COMPONENT_CLASS_MISSING: gateway", o)

    def test_hand_edited_class_in_a_manifest_is_refused_by_lint(self) -> None:
        self.built()
        m = json.load(open(self.f.p("release-manifest.json")))
        next(c for c in m["components"] if c["name"] == "extractor")["component_class"] = "distributable"
        json.dump(m, open(self.f.p("release-manifest.json"), "w"))
        rc, o = run("lint", "--manifest", self.f.p("release-manifest.json"))
        self.assertNotEqual(rc, 0, o)
        self.assertIn("COMPONENT_CLASS_MISMATCH", o)

    # --- distributables are never installed, pulled or run ----------------------------------------
    def test_distributables_never_reach_compose_helm_or_the_install(self) -> None:
        m = self.built()
        self.f.render()
        compose = open(self.f.p("docker-compose.yml")).read()
        rc, vals = run("render-helm-values", "--manifest", self.f.p("release-manifest.json"), "--contract", CONTRACT)
        self.assertEqual(rc, 0, vals)
        for text in (compose, vals):
            self.assertNotIn("sdk-python", text)
            self.assertNotIn("intentgate-0.3.0", text)
        rc, refs = run("image-refs", "--kind", "compose", "--file", self.f.p("docker-compose.yml"))
        self.assertEqual(len(refs.split()), len([c for c in m["components"] if c["component_class"] == "runtime"]))
        self.f.sign_ec("release-manifest.json")
        self.f.good_env()
        facts = self.f.facts(m)
        facts["containers"].append({"service": "sdk-python", "image_digest": D(11)})
        rc, o = self.f.verify_install(facts)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("sdk-python: running but not in the manifest", o)

    # --- a distributable is releasable only as an exactly identified, attested package ------------
    def test_distributable_without_artifact_digest_blocks(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "sdk-python")["distributable"]["artifacts"] = []
        for k in ("attribution", "provenance_attestation"):
            self.f.comp(i, "sdk-python")[k] = None
        self.assertIn(("sdk-python", "NO_ARTIFACT_DIGEST"), self.codes(i))

    def test_locally_measured_artifact_digest_is_not_governed(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "sdk-python")["distributable"]["artifact_digest_kind"] = "local-reproducible-measurement"
        self.assertIn(("sdk-python", "ARTIFACT_DIGEST_NOT_GOVERNED"), self.codes(i))

    def test_version_tag_at_another_commit_blocks(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "sdk-python")["distributable"]["version_tag_commit"] = C(43)
        self.assertIn(("sdk-python", "VERSION_TAG_NOT_AT_COMMIT"), self.codes(i))

    def test_attribution_for_other_artifacts_is_refused(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        self.f.comp(i, "sdk-python")["distributable"]["artifacts"][0]["sha256"] = sha(b"another wheel")
        rc, o = self.f.build(i)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("ATTRIBUTION_DIGEST_MISMATCH: sdk-python", o)

    def test_attestation_over_other_artifacts_is_refused(self) -> None:
        open(os.path.join(self.f.rel, "evidence", "sdk-python", "attestation.signed.json"), "w").write(
            self.f._sdk_attestation([self.f.SDK_ARTIFACTS[0]["sha256"]]))
        rc, o = self.f.build()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("ATTESTATION_SUBJECT_MISMATCH", o)

    def test_dist_tag_is_never_a_version(self) -> None:
        for v in ("latest", "^0.3.0", "next"):
            i = copy.deepcopy(self.f.inputs)
            self.f.comp(i, "sdk-python")["distributable"]["version"] = v
            rc, o = self.f.build(i)
            self.assertNotEqual(rc, 0, o)
            self.assertIn("DISTRIBUTABLE_VERSION", o)

    # --- extractor verdict is encoded, and its evidence still holds in source -------------------------
    def test_extractor_verdict_is_encoded_in_the_generator(self) -> None:
        tool = load_tool()
        b = tool.PRODUCT_BOUNDARY["extractor"]
        self.assertEqual((b["class"], b["required"]), ("runtime", True))
        for cite in ("main.go:372", "main.go:548", "mcp.go:562", "mcp.go:2095-2098", "mcp.go:588", "INTENTGATE_REQUIRE_INTENT=true"):
            self.assertIn(cite, b["evidence"])
        self.assertIn("extractor", tool.REQUIRED_COMPONENTS)
        m = self.built()
        self.assertEqual(next(c for c in m["components"] if c["name"] == "extractor")["boundary_evidence"], b["evidence"])
        for n in ("sdk-python", "sdk-typescript"):
            self.assertEqual(tool.PRODUCT_BOUNDARY[n]["class"], "distributable")
            self.assertNotIn(n, tool.REQUIRED_COMPONENTS)

    def test_release_wiring_makes_the_extractor_runtime_required(self) -> None:
        w = json.load(open(CONTRACT))["wiring"]["gateway"]
        self.assertEqual(w["INTENTGATE_REQUIRE_INTENT"], {"literal": "true"})
        self.assertEqual(w["INTENTGATE_TASK_BINDING"], {"literal": "true"})
        self.assertEqual(w["INTENTGATE_EXTRACTOR_URL"], {"literal": "http://extractor:8090"})

    def test_extractor_dependency_evidence_still_holds_in_gateway_source(self) -> None:
        if subprocess.run(["git", "-C", GATEWAY_REPO, "cat-file", "-e", GATEWAY_EVIDENCE_COMMIT], capture_output=True).returncode != 0:
            self.skipTest(f"gateway repository with {GATEWAY_EVIDENCE_COMMIT[:7]} not available (set INTENTGATE_GATEWAY_REPO)")

        def line(path: str, n: int) -> str:
            return subprocess.run(["git", "-C", GATEWAY_REPO, "show", f"{GATEWAY_EVIDENCE_COMMIT}:{path}"], capture_output=True,
                                  text=True, check=True).stdout.splitlines()[n - 1]
        self.assertIn('envOr("INTENTGATE_EXTRACTOR_URL"', line("cmd/gateway/main.go", 372))
        self.assertIn("extractor.New(extractorURL", line("cmd/gateway/main.go", 548))
        self.assertIn("h.runIntentCheck(", line("internal/handlers/mcp.go", 562))
        self.assertIn("intResult.intent.AllowedTools", line("internal/handlers/mcp.go", 588))
        self.assertIn("errExtractorNotConfigured", line("internal/handlers/mcp.go", 2087))
        self.assertIn("h.cfg.Extractor.Extract(", line("internal/handlers/mcp.go", 2095))
        self.assertIn("Fail closed", line("internal/handlers/mcp.go", 2097))


class HumanImpersonationOverride(unittest.TestCase):
    """Owner decision 2026-10-01 (RELEASE-BLOCKING): no canonical release may expose GATEWAY_DEV_SUBJECT /
    INTENTGATE_PLATFORM_GATEWAY_SUBJECT, which attribute every automated bearer call to one (human) principal."""
    UUID = "00000000-0000-4000-8000-000000000001"  # a synthetic idp uuid; never a real person's

    def setUp(self) -> None:
        self.f = Fixture()

    def tearDown(self) -> None:
        self.f.cleanup()

    def contract(self, mutate) -> str:
        c = json.load(open(CONTRACT))
        mutate(c)
        p = os.path.join(self.f.rel, "config-contract.json")
        json.dump(c, open(p, "w"), indent=2)
        return p

    # --- positive controls -----------------------------------------------------------------------
    def test_canonical_contract_and_renders_carry_no_override(self) -> None:
        c = json.load(open(CONTRACT))
        self.assertEqual(load_tool().check_contract(c), [])
        self.assertNotIn("INTENTGATE_PLATFORM_GATEWAY_SUBJECT", {k["name"] for k in c["keys"]})
        self.assertNotIn("GATEWAY_DEV_SUBJECT", c["wiring"]["platform-gateway"])
        for f in ("docker-compose.yml", ".env.example"):
            text = open(os.path.join(ROOT, f)).read()
            self.assertNotIn("GATEWAY_DEV_SUBJECT", text, f)
            self.assertNotIn("INTENTGATE_PLATFORM_GATEWAY_SUBJECT", text, f)

    # --- negative: the contract ------------------------------------------------------------------
    def test_contract_wiring_the_override_is_refused(self) -> None:
        self.contract(lambda c: c["wiring"]["platform-gateway"].__setitem__("GATEWAY_DEV_SUBJECT", {"literal": self.UUID}))
        rc, o = self.f.build()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("HUMAN_IMPERSONATION_OVERRIDE: platform-gateway wires GATEWAY_DEV_SUBJECT", o)

    def test_contract_declaring_the_key_is_refused(self) -> None:
        def m(c):
            c["keys"].append({"name": "INTENTGATE_PLATFORM_GATEWAY_SUBJECT", "required": False, "secret": False, "generator": None,
                              "validator": {"kind": "any"}, "default": None, "forbidden_values": [], "scope": "product", "description": "x"})
            c["wiring"]["platform-gateway"]["X_SUBJECT"] = {"key": "INTENTGATE_PLATFORM_GATEWAY_SUBJECT"}
        self.contract(m)
        rc, o = self.f.build()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("contract declares key INTENTGATE_PLATFORM_GATEWAY_SUBJECT", o)
        self.assertIn("is fed from INTENTGATE_PLATFORM_GATEWAY_SUBJECT", o)

    def test_contract_dropping_the_forbidden_entries_is_refused(self) -> None:
        self.contract(lambda c: c.__setitem__("forbidden_keys", [k for k in c["forbidden_keys"] if "SUBJECT" not in k["name"]]))
        rc, o = self.f.build()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("does not list GATEWAY_DEV_SUBJECT in forbidden_keys", o)

    # --- negative: release configuration (compose .env / helm Secret source) -----------------------
    def test_release_config_setting_the_override_is_refused(self) -> None:
        for line in (f"INTENTGATE_PLATFORM_GATEWAY_SUBJECT={self.UUID}", "INTENTGATE_PLATFORM_GATEWAY_SUBJECT=",
                     f"GATEWAY_DEV_SUBJECT={self.UUID}", "GATEWAY_DEV_SUBJECT="):
            env = self.f.good_env()
            open(env, "a").write(line + "\n")
            for scope in ("compose", "helm"):
                rc, o = run("config-validate", "--contract", CONTRACT, "--env", env, "--scope", scope)
                self.assertNotEqual(rc, 0, f"{line} {scope}: {o}")
                self.assertIn(f"{line.split('=')[0]}: FORBIDDEN_KEY", o)
                self.assertNotIn(self.UUID, o)  # values are never printed
            os.remove(env)

    def test_refused_even_by_a_contract_that_forgot_it(self) -> None:
        p = self.contract(lambda c: c.__setitem__("forbidden_keys", [k for k in c["forbidden_keys"] if "SUBJECT" not in k["name"]]))
        env = self.f.good_env()
        open(env, "a").write(f"INTENTGATE_PLATFORM_GATEWAY_SUBJECT={self.UUID}\n")
        rc, o = run("config-validate", "--contract", p, "--env", env)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("INTENTGATE_PLATFORM_GATEWAY_SUBJECT: FORBIDDEN_KEY", o)

    # --- negative: a running install ---------------------------------------------------------------
    def test_running_component_with_the_override_fails_the_chain(self) -> None:
        rc, o = self.f.build()
        self.assertEqual(rc, 0, o)
        self.f.render()
        self.f.sign_ec("release-manifest.json")
        self.f.good_env()
        m = json.load(open(self.f.p("release-manifest.json")))
        facts = self.f.facts(m)
        rc, o = self.f.verify_install(facts)
        self.assertEqual(rc, 0, o)  # positive control
        self.assertIn("LINK|NO_IMPERSONATION_OVERRIDE|PASS", o)
        bad = copy.deepcopy(facts)
        bad["env_names"]["platform-gateway"].append("GATEWAY_DEV_SUBJECT")
        rc, o = self.f.verify_install(bad)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("LINK|NO_IMPERSONATION_OVERRIDE|FAIL|platform-gateway: GATEWAY_DEV_SUBJECT", o)
        unmeasured = copy.deepcopy(facts)
        del unmeasured["env_names"]
        rc, o = self.f.verify_install(unmeasured)
        self.assertIn("LINK|NO_IMPERSONATION_OVERRIDE|FAIL|running environment names not measured", o)
        bulk = copy.deepcopy(facts)
        bulk["env_names"]["platform-gateway"].append("<envFrom: unmeasurable bulk environment>")
        self.assertIn("LINK|NO_IMPERSONATION_OVERRIDE|FAIL", self.f.verify_install(bulk)[1])

    # --- negative: release input guard ---------------------------------------------------------------
    def test_guard_refuses_the_override_in_tracked_release_input(self) -> None:
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["git", "init", "-q", d], check=True)

            def commit(name: str, text: str) -> None:
                open(os.path.join(d, name), "w").write(text)
                subprocess.run(["git", "-C", d, "add", name], check=True)
                subprocess.run(["git", "-C", d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], check=True)
            commit("contract.json", json.dumps({"forbidden_keys": [{"name": "GATEWAY_DEV_SUBJECT"}, {"name": "INTENTGATE_PLATFORM_GATEWAY_SUBJECT"}]}, indent=2))
            rc, o = run("guard-release-input", "--root", d)
            self.assertEqual(rc, 0, o)  # naming the key as forbidden is not setting it
            commit("docker-compose.yml", 'services:\n  p:\n    environment:\n      GATEWAY_DEV_SUBJECT: "${INTENTGATE_PLATFORM_GATEWAY_SUBJECT:-}"\n')
            commit("values.yaml", 'env:\n  - name: "GATEWAY_DEV_SUBJECT"\n    secretKey: "X"\n')
            rc, o = run("guard-release-input", "--root", d)
            self.assertNotEqual(rc, 0, o)
            self.assertIn("HUMAN_IMPERSONATION_OVERRIDE: docker-compose.yml:4", o)
            self.assertIn("HUMAN_IMPERSONATION_OVERRIDE: values.yaml:2", o)
        finally:
            shutil.rmtree(d)


def oci_image(layout: str, name: str, ref_name: str | None = None) -> str:
    """Write a tiny synthetic single-platform OCI image into an image layout; returns its manifest digest."""
    os.makedirs(os.path.join(layout, "blobs", "sha256"), exist_ok=True)

    def blob(data: bytes) -> dict:
        h = sha(data)
        open(os.path.join(layout, "blobs", "sha256", h), "wb").write(data)
        return {"digest": "sha256:" + h, "size": len(data)}
    layer = blob(f"layer of {name}".encode())
    cfg = blob(json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": {"c": name}}}).encode())
    man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                      "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **cfg},
                      "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **layer}]}).encode()
    md = blob(man)
    ip = os.path.join(layout, "index.json")
    idx = json.load(open(ip)) if os.path.exists(ip) else {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []}
    d = {"mediaType": "application/vnd.oci.image.manifest.v1+json", **md}
    if ref_name:
        d["annotations"] = {"org.opencontainers.image.ref.name": ref_name}
    idx["manifests"].append(d)
    json.dump(idx, open(ip, "w"))
    open(os.path.join(layout, "oci-layout"), "w").write('{"imageLayoutVersion": "1.0.0"}')
    return md["digest"]


class ImageDistribution(unittest.TestCase):
    """Owner decision 2026-10-01 (D6): authenticated registry AND offline/air-gapped image bundle, both resolving the
    same signed manifest and identical digests; `latest` (or any tag) is valid in neither."""

    def setUp(self) -> None:
        self.src = tempfile.mkdtemp(prefix="oci-src-")
        names = [n for n, _, _ in COMPONENTS] + ["postgres"]
        self.sources, digests = {}, {}
        for n in names:
            layout = os.path.join(self.src, n)
            oci_image(layout, n + "-decoy", ref_name="latest")  # a tag in the SOURCE pointing at ANOTHER image
            digests[n] = oci_image(layout, n, ref_name="1.0")
            self.sources[n] = layout
        self.f = Fixture(digests=digests)
        rc, o = self.f.build()
        assert rc == 0, o
        self.f.render()
        self.f.sign_ec("release-manifest.json")
        self.m = json.load(open(self.f.p("release-manifest.json")))
        self.bundle = self.f.p("images")
        rc, o = self.assemble(self.bundle, tar=self.f.p("images.tar"))
        assert rc == 0, o

    def tearDown(self) -> None:
        self.f.cleanup()
        shutil.rmtree(self.src, ignore_errors=True)

    def assemble(self, out: str, tar: str | None = None, sources: dict | None = None) -> tuple[int, str]:
        args = ["assemble-image-bundle", "--manifest", self.f.p("release-manifest.json"), "--sig", self.f.p("release-manifest.json.sig"),
                "--out-dir", out]
        for k, v in (sources or self.sources).items():
            args += ["--source", f"{k}={v}"]
        return run(*args, *(["--tar", tar] if tar else []))

    def verify(self, bundle: str | None = None, *extra: str) -> tuple[int, str]:
        return run("verify-image-bundle", "--bundle", bundle or self.bundle, *self.f.trust(), *extra)

    def index(self) -> dict:
        return json.load(open(os.path.join(self.bundle, "index.json")))

    def write_index(self, idx: dict) -> None:
        json.dump(idx, open(os.path.join(self.bundle, "index.json"), "w"))

    def refs_file(self, lines: list) -> str:
        p = self.f.p("refs.txt")
        open(p, "w").write("\n".join(lines) + "\n")
        return p

    # --- positive controls -------------------------------------------------------------------------
    def test_offline_bundle_verifies_as_directory_and_tarball(self) -> None:
        rc, o = self.verify(None, "--manifest", self.f.p("release-manifest.json"))
        self.assertEqual(rc, 0, o)
        self.assertIn("IMAGE_BUNDLE=PASS", o)
        rc, o = self.verify(self.f.p("images.tar"), "--manifest", self.f.p("release-manifest.json"))
        self.assertEqual(rc, 0, o)
        for d in self.index()["manifests"]:
            self.assertNotIn("org.opencontainers.image.ref.name", d.get("annotations", {}))  # source tags never copied

    def test_tarball_is_deterministic(self) -> None:
        rc, o = self.assemble(self.f.p("images2"), tar=self.f.p("images2.tar"))
        self.assertEqual(rc, 0, o)
        self.assertEqual(open(self.f.p("images.tar"), "rb").read(), open(self.f.p("images2.tar"), "rb").read())

    def test_registry_and_offline_paths_resolve_identical_digests(self) -> None:
        rc, plan = run("pull-plan", "--manifest", self.f.p("release-manifest.json"))
        self.assertEqual(rc, 0, plan)
        registry = {line.split("=", 1)[0]: line.split("@", 1)[1] for line in plan.split()}
        offline = {d["annotations"]["io.intentgate.component"]: d["digest"] for d in self.index()["manifests"]}
        rc, crefs = run("image-refs", "--kind", "compose", "--file", self.f.p("docker-compose.yml"))
        compose = {line.split("=", 1)[0]: line.split("@", 1)[1] for line in crefs.split()}
        self.assertEqual(registry, offline)
        self.assertEqual(sorted(registry.values()), sorted(compose.values()))
        self.assertEqual(len(registry), 6)
        self.assertNotIn("sdk-python", registry)  # a distributable is never pulled
        rc, o = run("verify-image-refs", "--manifest", self.f.p("release-manifest.json"), "--refs", self.refs_file(crefs.split()))
        self.assertEqual(rc, 0, o)

    def test_mirror_rehomes_the_repository_never_the_digest(self) -> None:
        mirror = ["--mirror", "ghcr.io/intentgate-app=registry.customer.internal/intentgate", "--mirror", "docker.io/library=registry.customer.internal/library"]
        rc, plan = run("pull-plan", "--manifest", self.f.p("release-manifest.json"), *mirror)
        self.assertEqual(rc, 0, plan)
        self.assertTrue(all(r.split("=", 1)[1].startswith("registry.customer.internal/") for r in plan.split()), plan)
        rc, o = run("verify-image-refs", "--manifest", self.f.p("release-manifest.json"), "--refs", self.refs_file(plan.split()), *mirror)
        self.assertEqual(rc, 0, o)
        rc, o = run("verify-image-refs", "--manifest", self.f.p("release-manifest.json"), "--refs", self.refs_file(plan.split()))
        self.assertIn("REPOSITORY_MISMATCH", o)  # an undeclared mirror is refused
        rc, o = run("pull-plan", "--manifest", self.f.p("release-manifest.json"), "--mirror", "ghcr.io/intentgate-app=registry.internal/ig:latest")
        self.assertNotEqual(rc, 0, o)
        self.assertIn("MIRROR_FORMAT", o)

    # --- negative: registry path -------------------------------------------------------------------
    def test_registry_refs_refuse_tags_latest_other_digests_and_gaps(self) -> None:
        rc, plan = run("pull-plan", "--manifest", self.f.p("release-manifest.json"))
        good = plan.split()
        gw = next(x for x in good if x.startswith("gateway="))
        cases = {
            "TAG_REFERENCE": [x if x != gw else "gateway=ghcr.io/intentgate-app/intentgate-gateway:1.6.2" for x in good],
            "MUTABLE_REFERENCE": [x if x != gw else "gateway=ghcr.io/intentgate-app/intentgate-gateway:latest" for x in good],
            "DIGEST_MISMATCH": [x if x != gw else "gateway=ghcr.io/intentgate-app/intentgate-gateway@" + D(13) for x in good],
            "IMAGE_MISSING": [x for x in good if x != gw],
            "UNMANIFESTED_IMAGE": good + ["toolserver=ghcr.io/x/toolserver@" + D(14)],
        }
        for code, lines in cases.items():
            rc, o = run("verify-image-refs", "--manifest", self.f.p("release-manifest.json"), "--refs", self.refs_file(lines))
            self.assertNotEqual(rc, 0, f"{code}: {o}")
            self.assertIn(code, o)

    def test_unresolved_digest_has_no_pull_plan_and_no_bundle(self) -> None:
        i = copy.deepcopy(self.f.inputs)
        c = self.f.comp(i, "extractor")
        c["image"]["digest"] = None
        c["attribution"] = c["sbom"] = c["provenance_attestation"] = None
        self.f.build(i, out="unresolved.json")
        rc, o = run("pull-plan", "--manifest", self.f.p("unresolved.json"))
        self.assertNotEqual(rc, 0, o)
        self.assertIn("NOT_INSTALLABLE: the manifest has no digest for extractor", o)

    # --- negative: offline path ---------------------------------------------------------------------
    def test_tag_reference_in_bundle_index_is_refused(self) -> None:
        idx = self.index()
        idx["manifests"][0].setdefault("annotations", {})["org.opencontainers.image.ref.name"] = "1.6.2"
        self.write_index(idx)
        self.assertIn("TAG_REFERENCE", self.verify()[1])

    def test_latest_anywhere_in_bundle_index_is_refused(self) -> None:
        idx = self.index()
        idx["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = "latest"
        self.write_index(idx)
        rc, o = self.verify()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("MUTABLE_REFERENCE", o)

    def test_swapped_digest_is_refused(self) -> None:
        idx = self.index()
        a, b = idx["manifests"][0], idx["manifests"][1]
        a["digest"], b["digest"] = b["digest"], a["digest"]
        a["size"], b["size"] = b["size"], a["size"]
        self.write_index(idx)
        rc, o = self.verify()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("DIGEST_MISMATCH", o)

    def test_tampered_blob_is_refused(self) -> None:
        d = self.index()["manifests"][2]["digest"].split(":")[1]
        man = json.load(open(os.path.join(self.bundle, "blobs", "sha256", d)))
        layer = man["layers"][0]["digest"].split(":")[1]
        open(os.path.join(self.bundle, "blobs", "sha256", layer), "wb").write(b"evil layer")
        rc, o = self.verify()
        self.assertNotEqual(rc, 0, o)
        self.assertIn("BLOB_DIGEST_MISMATCH", o)

    def test_missing_blob_is_refused(self) -> None:
        d = self.index()["manifests"][1]["digest"].split(":")[1]
        os.remove(os.path.join(self.bundle, "blobs", "sha256", d))
        self.assertIn("BLOB_MISSING", self.verify()[1])

    def test_missing_and_unmanifested_images_are_refused(self) -> None:
        idx = self.index()
        idx["manifests"] = idx["manifests"][1:] + [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                    "digest": idx["manifests"][0]["digest"], "size": idx["manifests"][0]["size"],
                                                    "annotations": {"io.intentgate.component": "toolserver"}}]
        self.write_index(idx)
        rc, o = self.verify()
        self.assertIn("IMAGE_MISSING", o)
        self.assertIn("UNMANIFESTED_IMAGE", o)

    def test_stale_blob_and_foreign_file_are_refused(self) -> None:
        open(os.path.join(self.bundle, "blobs", "sha256", sha(b"stale")), "wb").write(b"stale")
        open(os.path.join(self.bundle, "notes.txt"), "w").write("x")
        rc, o = self.verify()
        self.assertIn("BLOB_NOT_REFERENCED", o)
        self.assertIn("FILE_NOT_IN_IMAGE_BUNDLE: notes.txt", o)

    def test_bundle_for_another_manifest_is_refused(self) -> None:
        other = self.f.p("other.json")
        m = dict(self.m)
        m["created_at"] = "2026-01-02T00:00:00Z"
        open(other, "w").write(json.dumps(m))
        rc, o = self.verify(None, "--manifest", other)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("MANIFEST_NOT_THE_RELEASE_MANIFEST", o)

    def test_unsigned_or_resigned_bundle_is_refused(self) -> None:
        self.f.sign_ec("release-manifest.json", key=self.f.ec_key_other, out="images/release-manifest.json.sig")
        self.assertIn("SIGNATURE_INVALID", self.verify()[1])
        os.remove(os.path.join(self.bundle, "release-manifest.json.sig"))
        self.assertIn("UNSIGNED", self.verify()[1])

    def test_assembler_selects_by_digest_never_by_tag(self) -> None:
        bad = dict(self.sources)
        decoy_only = os.path.join(self.src, "decoy-only")
        oci_image(decoy_only, "gateway-decoy", ref_name="latest")
        bad["gateway"] = decoy_only
        rc, o = self.assemble(self.f.p("images3"), sources=bad)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("DIGEST_NOT_IN_SOURCE: gateway", o)

    def test_tar_path_escape_is_refused(self) -> None:
        import io
        import tarfile
        p = self.f.p("evil.tar")
        with tarfile.open(p, "w") as t:
            ti = tarfile.TarInfo("../escape")
            ti.size = 1
            t.addfile(ti, io.BytesIO(b"x"))
        rc, o = self.verify(p)
        self.assertNotEqual(rc, 0, o)
        self.assertIn("TAR_PATH_ESCAPE", o)


class CanonicalRc0(unittest.TestCase):
    """The committed rc0 manifest is the current build of its inputs, and it is honestly RED."""

    def test_rc0_is_red_with_the_evidenced_blockers(self) -> None:
        mp = os.path.join(REL, "manifests", "intentgate-2026.09.30-rc0.release-manifest.json")
        if not os.path.exists(mp):
            self.skipTest("rc0 manifest not built yet")
        m = json.load(open(mp))
        rc, o = run("lint", "--manifest", mp)
        self.assertEqual(rc, 0, o)
        self.assertFalse(m["releasable"])
        got = {(b["component"], b["code"]) for b in m["releasable_blockers"]}
        for want in [("platform-gateway", "STATUS_PROVISIONAL"), ("governance-worker", "STATUS_PROVISIONAL"),
                     ("gateway", "STATUS_UNACCEPTED"), ("extractor", "STATUS_UNACCEPTED"), ("extractor", "NO_IMAGE_DIGEST"),
                     ("extractor", "SOURCE_COMMIT_UNKNOWN"), ("governance-worker", "NO_ATTRIBUTION"), ("gateway", "NO_ATTRIBUTION"),
                     ("console-pro", "ANCHOR_NOT_TAGGED"), ("postgres", "THIRD_PARTY_DIGEST_UNVERIFIED"),
                     ("*", "SCHEMA_FINGERPRINT_UNMEASURED"), ("*", "NO_MIGRATION_MANIFEST"), ("*", "INDEPENDENT_REVIEW_MISSING"),
                     ("sdk-python", "VERSION_TAG_NOT_AT_COMMIT"), ("sdk-typescript", "VERSION_TAG_NOT_AT_COMMIT"),
                     ("sdk-python", "ARTIFACT_DIGEST_NOT_GOVERNED"), ("sdk-typescript", "NO_ATTRIBUTION")]:
            self.assertIn(want, got)
        pg = next(c for c in m["components"] if c["name"] == "platform-gateway")
        self.assertEqual(pg["provenance_attestation"]["signature"], "VERIFIED")
        cls = {c["name"]: c["component_class"] for c in m["components"]}
        self.assertEqual(cls, {"postgres": "runtime", "extractor": "runtime", "platform-gateway": "runtime", "governance-worker": "runtime",
                               "gateway": "runtime", "console-pro": "runtime", "sdk-python": "distributable", "sdk-typescript": "distributable"})
        for c in m["components"]:
            if c["component_class"] == "distributable":
                self.assertIsNone(c["image"])
                self.assertEqual(len(c["distributable"]["artifacts"]) > 0, True)
        self.assertEqual({d["id"] for d in m["open_owner_decisions"]}, {"D1", "D3"})  # D5, D6 and the SDK/extractor part of D1 are ruled
        self.assertFalse(any(b["code"] == "OPEN_OWNER_DECISION" and b["detail"].startswith(("D5", "D6")) for b in m["releasable_blockers"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
