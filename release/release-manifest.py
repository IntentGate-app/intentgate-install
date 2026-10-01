#!/usr/bin/env python3
"""release-manifest.py: the canonical IntentGate release manifest (igrm/1) and its verifiers.

ONE PRODUCT, ONE MANIFEST. Compose and Helm are two delivery forms of one signed manifest.
This tool is the only thing that writes image references: `render-compose` and
`render-helm-values` derive every image from the manifest, by digest, and nothing else.
Hand-edited image references are refused by `guard-release-input` and by the renders' equality
checks in CI.

`releasable` IS COMPUTED, NEVER SET. `build` derives it from the evidence (component status,
accepted anchor, digest, IGBA/1 attribution, SBOM, provenance attestation, schema fingerprint,
migration level, open owner decisions). `lint`/`verify` recompute it and refuse any manifest
whose flag or blocker list differs from the recomputation, so an edited manifest cannot claim
to be releasable. A RED manifest is a valid manifest; a false GREEN is not.

Subcommands
  build                 inputs + evidence + contract + bundle files -> manifest (deterministic)
  lint                  structural + policy checks (no signature)
  sign                  TEST ONLY: detached ed25519 signature (production signing is cosign
                        sign-blob with the KMS release key, see .github/workflows/release.yml)
  verify                detached signature (production key set pinned by the trust anchor,
                        or an explicit test key) + lint [+ --require-releasable]
  verify-bundle         a bundle directory == manifest (static hashes, re-rendered files, no
                        file outside the bundle, no nested repository or archive)
  verify-install        manifest + facts of a running install -> PASS/FAIL per chain link
  render-compose        digest-pinned docker-compose.yml from the manifest
  render-helm-values    digest-only Helm values from the manifest
  render-env-example    .env.example from the configuration contract
  config-generate       fill generated secrets/derived/default keys into an env file
  config-validate       validate an env file against the contract (key NAMES only are printed)
  collect-facts         read the facts of a running compose or helm install
  capture-state         lkg-lab-state/1 lines for an install (for lkg-rollback-equivalence.sh state)
  guard-release-input   refuse stale/untracked artifacts, nested clones, archives, mutable refs
  image-refs            print component=repository@digest for a rendered compose or helm manifest
  pull-plan             registry path: repository@digest per runtime component (optional mirror re-homing)
  verify-image-refs     refuse resolved image refs that are tags, latest, other digests, unmanifested or missing
  assemble-image-bundle offline path: igib/1 OCI image layout selected BY DIGEST (+ signed manifest), optional tar
  verify-image-bundle   offline path: signature, bundled manifest == release manifest, index == manifest, blob sha256

Exit codes: 0 PASS, 1 FAIL (a verdict), 2 usage / missing input.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from typing import Any

MANIFEST_VERSION = "igrm/1"
FACTS_VERSION = "igif/1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FP32_RE = re.compile(r"^[0-9a-f]{32}$")
REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(\.[a-z0-9._-]+)*(:[0-9]+)?(/[a-z0-9._-]+)+$")
# A mutable reference: an explicit `latest`, a `${X:-latest}` default, or an image ref with a tag
# and no digest. Checked over whole files and over the manifest text.
MUTABLE_TEXT_RE = re.compile(r"(:-latest\}|:latest\b|\"latest\"|'latest')")
IMAGE_LINE_RE = re.compile(r"^[ \t]*(?:-[ \t]*)?image:[ \t]*[\"']?([^\"'\s#]+)", re.M)  # never crosses a line: `image:` as a map key is not a ref
UNRESOLVED_PREFIX = "${INTENTGATE_UNRESOLVED_"

STATUSES = {"ACCEPTED", "PROVISIONAL", "UNACCEPTED", "THIRD_PARTY"}

# THE PRODUCT BOUNDARY, from dependency evidence (never from repository names or packaging habits).
#   runtime        an image the installed product runs; Compose and Helm render it, by digest, and the install
#                  chain (IMAGES_BY_DIGEST, RUNNING_REVISIONS) measures it.
#   distributable  a package customers/integrations consume (PyPI / npm). Identity = package name + version +
#                  source commit + sha256 of the built artifact(s). It has NO image and NO runtime: the installer
#                  and the chart never require, pull or run it.
# A component that is not listed here is outside the evidenced boundary and is refused; a component declared in
# the other class is refused (owner decisions 2026-10-01; design/RELEASE-BOUNDARY-IDENTITY-REGISTRY-2026-10-01.md).
PRODUCT_BOUNDARY: dict[str, dict[str, Any]] = {
    "postgres": {"class": "runtime", "required": True,
                 "evidence": "shared product database: INTENTGATE_POSTGRES_URL is REQUIRED by gateway, platform-gateway, governance-worker, console-pro (config-contract.json wiring)"},
    "extractor": {"class": "runtime", "required": True,
                  "evidence": "IN (runtime), measured 2026-10-01 on gateway@3acd0c4: cmd/gateway/main.go:372 reads INTENTGATE_EXTRACTOR_URL, "
                              "main.go:548 extractor.New -> internal/extractor/client.go POST <url>/v1/extract; internal/handlers/mcp.go:562 runs the "
                              "intent stage on every north-south /v1/mcp tools/call, mcp.go:2080-2087 refuse when the header is missing or no extractor "
                              "is configured while INTENTGATE_REQUIRE_INTENT=true, mcp.go:2095-2098 fail closed when the extractor errors; mcp.go:588 "
                              "task binding (goal-drift) takes its declared plan from the extractor's allowed_tools. The release wiring sets "
                              "INTENTGATE_REQUIRE_INTENT=true, INTENTGATE_TASK_BINDING=true, INTENTGATE_EXTRACTOR_URL=http://extractor:8090 "
                              "(config-contract.json), as the Lab does (lab@f6a5507 compose.yml:137-158). Callers: sdk-python client.py:275-276 and "
                              "sdk-typescript client.ts:282-283 send X-Intent-Prompt; console-pro@416efb1 lib/lab-demo.ts:114."},
    "platform-gateway": {"class": "runtime", "required": True,
                         "evidence": "console-pro INTENTGATE_PLATFORM_GATEWAY_URL and gateway INTENTGATE_DISCOVERY_*_URL target it (config-contract.json wiring)"},
    "governance-worker": {"class": "runtime", "required": True,
                          "evidence": "governed run substrate; consumes GOVERNANCE_DATABASE_URL (config-contract.json wiring)"},
    "gateway": {"class": "runtime", "required": True,
                "evidence": "the policy enforcement point; console-pro INTENTGATE_GATEWAY_URL=http://gateway:8080 (config-contract.json wiring)"},
    "console-pro": {"class": "runtime", "required": True,
                    "evidence": "operator console; the only operator sign-in surface (AUTH_OIDC_* REQUIRED, config-contract.json)"},
    "sdk-python": {"class": "distributable", "required": False,
                   "evidence": "PyPI package 'intentgate' (pyproject.toml). No runtime component imports it: console-pro@416efb1, platform@97178b8, "
                               "gateway@3acd0c4 carry no dependency on it; lab uses it only in test workflows (lab@f6a5507 .github/workflows/lab-self-proofs.yml:153)"},
    "sdk-typescript": {"class": "distributable", "required": False,
                       "evidence": "npm package '@intentgate-app/intentgate' (package.json). No runtime component depends on it: console-pro@416efb1 package.json, "
                                   "platform@97178b8 package.json files carry no dependency on it; lab uses it only in test workflows (lab@f6a5507 lab-self-proofs.yml:161)"},
}
COMPONENT_CLASSES = {"runtime", "distributable"}
REQUIRED_COMPONENTS = [n for n, b in PRODUCT_BOUNDARY.items() if b["required"]]
COMPONENT_ORDER = ["postgres", "extractor", "platform-gateway", "governance-worker", "gateway", "console-pro"]
DISTRIBUTABLE_ECOSYSTEMS = {"pypi", "npm"}
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# HUMAN IMPERSONATION OVERRIDES (owner decision 2026-10-01, RELEASE-BLOCKING). The platform gateway's dev authenticator
# takes principal.subject from GATEWAY_DEV_SUBJECT (platform 3ea2b27, `process.env.GATEWAY_DEV_SUBJECT ?? 'dev-principal'`);
# set to a human's idp URN uuid it attributes EVERY bearer (automated) call to that human. No canonical release may wire,
# accept or run with either name, whatever the value (an EMPTY value is not nullish: subject would become ""). These names
# are fixed here, not only in the contract, so a contract that drops them from its forbidden list is still refused.
HUMAN_IMPERSONATION_ENV = {
    "GATEWAY_DEV_SUBJECT": "platform dev-authenticator subject override: attributes every automated bearer call to one principal (e.g. a human's idp URN)",
    "INTENTGATE_PLATFORM_GATEWAY_SUBJECT": "release config key that fed GATEWAY_DEV_SUBJECT (human-impersonation override for automated calls)",
}
IMPERSONATION_TEXT_RE = re.compile(r"\b(GATEWAY_DEV_SUBJECT|INTENTGATE_PLATFORM_GATEWAY_SUBJECT)\s*[:=]|name:[ \t]*[\"']?(GATEWAY_DEV_SUBJECT|INTENTGATE_PLATFORM_GATEWAY_SUBJECT)\b")


def runtime_components(m: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in m.get("components", []) if c.get("component_class") == "runtime"]


def check_contract(contract: dict[str, Any]) -> list[str]:
    """Refusals for a configuration contract that would expose a human-impersonation override."""
    e: list[str] = []
    forbidden = {f["name"] for f in contract.get("forbidden_keys", [])}
    for name, why in HUMAN_IMPERSONATION_ENV.items():
        if any(k["name"] == name for k in contract.get("keys", [])):
            e.append(f"HUMAN_IMPERSONATION_OVERRIDE: contract declares key {name} ({why})")
        if name not in forbidden:
            e.append(f"HUMAN_IMPERSONATION_OVERRIDE: contract does not list {name} in forbidden_keys")
    for comp, wiring in contract.get("wiring", {}).items():
        for env, src in wiring.items():
            if env in HUMAN_IMPERSONATION_ENV:
                e.append(f"HUMAN_IMPERSONATION_OVERRIDE: {comp} wires {env} ({HUMAN_IMPERSONATION_ENV[env]})")
            if isinstance(src, dict) and src.get("key") in HUMAN_IMPERSONATION_ENV:
                e.append(f"HUMAN_IMPERSONATION_OVERRIDE: {comp}.{env} is fed from {src['key']}")
    return e

HERE = os.path.dirname(os.path.abspath(__file__))


class Refusal(Exception):
    """A verdict: the input is refused. Printed as FAIL, exit 1."""


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------

def canonical_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: str) -> str:
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


def load_json(p: str) -> Any:
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def out(line: str) -> None:
    print(line, flush=True)


# ----------------------------------------------------------------------------------------------
# signatures (DSSE attestations of the release key set, and detached manifest signatures)
# ----------------------------------------------------------------------------------------------

SPKI_PREFIX_P256 = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    return hashes, serialization, ec, ed25519, InvalidSignature


def trusted_release_keys(key_set_path: str, anchor_path: str | None, pinned_fps: list[str] | None = None) -> list[dict[str, Any]]:
    """ACTIVE ECDSA P-256 keys whose SPKI fingerprint equals BOTH the key set's declaration and the
    consumer's pinned trust: an anchor file, or fingerprints passed explicitly (--pinned-fingerprint).

    A trust anchor that travels INSIDE the bundle it verifies is circular: whoever can replace the
    bundle can replace the anchor, re-hash it into the manifest and re-sign. Customer installs and the
    clean room therefore pin the fingerprint out of band (install.sh: INTENTGATE_RELEASE_KEY_FINGERPRINT)."""
    ks = load_json(key_set_path)
    if pinned_fps:
        pinned_any = {f.lower() for f in pinned_fps}
        pinned = None
    else:
        an = load_json(anchor_path)
        pinned = {(f["key_id"], f["fingerprint_sha256"]) for f in an.get("fingerprints", [])}
        pinned_any = set()
    keys = []
    for k in ks.get("keys", []):
        if k.get("status") != "ACTIVE" or k.get("algorithm") != "ECDSA_P256_SHA256":
            continue
        point = bytes.fromhex(k["public_key_hex"])
        fp = sha256_bytes(SPKI_PREFIX_P256 + point)
        if fp != k.get("fingerprint_sha256"):
            continue
        if (pinned is not None and (k["key_id"], fp) not in pinned) or (pinned is None and fp not in pinned_any):
            continue
        keys.append({"key_id": k["key_id"], "point": point, "fingerprint": fp})
    return keys


def ecdsa_verify(point: bytes, sig: bytes, msg: bytes) -> bool:
    c = _crypto()
    if c is None:
        raise Refusal("SIGNATURE_UNVERIFIABLE: python 'cryptography' is not installed (install it or use cosign verify-blob)")
    hashes, _, ec, _, InvalidSignature = c
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    try:
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def verify_attestation(att_path: str, image_digest: str | list[str], key_set: str, anchor: str) -> dict[str, Any]:
    """image_digest: the image digest, or (distributables) the list of artifact digests; the statement's subjects
    must be exactly that set."""
    want = sorted([image_digest] if isinstance(image_digest, str) else image_digest)
    env = load_json(att_path)
    payload = base64.b64decode(env["payload"])
    stmt = json.loads(payload)
    subjects = sorted("sha256:" + str(s.get("digest", {}).get("sha256")) for s in stmt.get("subject", []))
    subject_ok = bool(subjects) and subjects == want
    result = {"subject_digest": (subjects[0] if len(subjects) == 1 else ",".join(subjects)) if subjects else None,
              "predicate_type": stmt.get("predicateType"), "signature": "UNVERIFIED", "key_id": None}
    if not subject_ok:
        raise Refusal(f"ATTESTATION_SUBJECT_MISMATCH: {att_path} attests {result['subject_digest']}, manifest digest is {','.join(want)}")
    if _crypto() is None or not (os.path.exists(key_set) and os.path.exists(anchor)):
        return result
    pae = dsse_pae(env["payloadType"], payload)
    for s in env.get("signatures", []):
        for k in trusted_release_keys(key_set, anchor):
            if s.get("keyid") == k["key_id"] and ecdsa_verify(k["point"], base64.b64decode(s["sig"]), pae):
                result.update(signature="VERIFIED", key_id=k["key_id"])
                return result
    result["signature"] = "INVALID"
    return result


def verify_detached(manifest_bytes: bytes, sig_path: str | None, key_set: str | None, anchor: str | None,
                    test_public_key: str | None, allow_test_key: bool, pinned_fps: list[str] | None = None) -> str:
    """Returns the key id that verified, or raises Refusal. Never returns without a verification."""
    if not sig_path or not os.path.exists(sig_path) or os.path.getsize(sig_path) == 0:
        raise Refusal("UNSIGNED: no detached signature for the manifest")
    raw = open(sig_path, "rb").read().strip()
    try:
        sig = base64.b64decode(raw, validate=True)
    except Exception:
        raise Refusal("SIGNATURE_MALFORMED: the .sig file is not base64")
    if test_public_key:
        if not allow_test_key:
            raise Refusal("TEST_KEY_REFUSED: a test key was offered without --allow-test-key (never valid for a customer install)")
        c = _crypto()
        if c is None:
            raise Refusal("SIGNATURE_UNVERIFIABLE: python 'cryptography' is not installed")
        _, serialization, _, ed25519, InvalidSignature = c
        pub = serialization.load_pem_public_key(open(test_public_key, "rb").read())
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise Refusal("TEST_KEY_REFUSED: test keys are ed25519 only")
        try:
            pub.verify(sig, manifest_bytes)
        except InvalidSignature:
            raise Refusal("SIGNATURE_INVALID: the manifest does not verify against the test key (tampered or wrong key)")
        return "TEST-ONLY-ed25519"
    if not key_set or not (anchor or pinned_fps):
        raise Refusal("NO_TRUST_ROOT: --key-set and --trust-anchor or --pinned-fingerprint are required")
    keys = trusted_release_keys(key_set, anchor, pinned_fps)
    if not keys:
        raise Refusal("NO_TRUSTED_KEY: no ACTIVE key in the key set matches the pinned trust anchor")
    if _crypto() is None and shutil.which("cosign"):
        # Same trusted key (pinned by the anchor fingerprint), verified by cosign instead of python.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "m.json")
            open(mp, "wb").write(manifest_bytes)
            for k in keys:
                pem = os.path.join(td, "k.pem")
                der = SPKI_PREFIX_P256 + k["point"]
                open(pem, "w").write("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n")
                r = subprocess.run(["cosign", "verify-blob", "--key", pem, "--signature", sig_path,
                                    "--insecure-ignore-tlog=true", mp], capture_output=True, text=True)
                if r.returncode == 0:
                    return k["key_id"] + " (cosign)"
        raise Refusal("SIGNATURE_INVALID: cosign verify-blob refused the manifest against every trusted release key")
    for k in keys:
        if ecdsa_verify(k["point"], sig, manifest_bytes):
            return k["key_id"]
    raise Refusal("SIGNATURE_INVALID: the manifest does not verify against any trusted release key (tampered or wrong key)")


def sign_test(manifest: str, key_pem: str, sig_out: str) -> None:
    c = _crypto()
    if c is None:
        raise Refusal("python 'cryptography' is required to sign")
    _, serialization, _, ed25519, _ = c
    priv = serialization.load_pem_private_key(open(key_pem, "rb").read(), password=None)
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise Refusal("sign is TEST ONLY and accepts an ed25519 key only; production signs with cosign + KMS")
    sig = priv.sign(open(manifest, "rb").read())
    with open(sig_out, "wb") as f:
        f.write(base64.b64encode(sig) + b"\n")


# ----------------------------------------------------------------------------------------------
# build
# ----------------------------------------------------------------------------------------------

def _check_image(name: str, image: dict[str, Any]) -> None:
    if set(image) - {"repository", "digest"}:
        raise Refusal(f"IMAGE_FIELDS: {name}: image carries {sorted(set(image) - {'repository', 'digest'})}; identity is repository+digest only (no tags)")
    repo, dig = image.get("repository"), image.get("digest")
    if not isinstance(repo, str) or not REPO_RE.match(repo):
        raise Refusal(f"IMAGE_REPOSITORY: {name}: {repo!r} is not a bare repository (a tag or digest in the repository field is refused)")
    if dig is not None and (not isinstance(dig, str) or not DIGEST_RE.match(dig)):
        raise Refusal(f"IMAGE_NOT_DIGEST: {name}: {dig!r} is not sha256:<64 hex>; tags are never an identity")


def _load_attribution(base: str, rel: str, comp: dict[str, Any]) -> dict[str, Any]:
    p = os.path.join(base, rel)
    rec = load_json(p)
    if rec.get("record_version") != "IGBA/1":
        raise Refusal(f"ATTRIBUTION_FORMAT: {comp['name']}: {rel} is not IGBA/1")
    art, src = rec.get("artifact", {}), rec.get("source", {})
    if comp.get("component_class") == "distributable":
        d = comp["distributable"]
        want = sorted("sha256:" + a["sha256"] for a in d.get("artifacts", []))
        got = sorted(art.get("digests") or ([art["digest"]] if art.get("digest") else []))
        if got != want:
            raise Refusal(f"ATTRIBUTION_DIGEST_MISMATCH: {comp['name']}: record attests {got}, package artifacts are {want}")
        if art.get("registry_ref") != f"{d['ecosystem']}:{d['package_name']}":
            raise Refusal(f"ATTRIBUTION_REPOSITORY_MISMATCH: {comp['name']}: record names {art.get('registry_ref')}")
    else:
        img = comp["image"]
        if art.get("digest") != img.get("digest"):
            raise Refusal(f"ATTRIBUTION_DIGEST_MISMATCH: {comp['name']}: record attests {art.get('digest')}, component digest is {img.get('digest')}")
        if art.get("registry_ref") != img.get("repository"):
            raise Refusal(f"ATTRIBUTION_REPOSITORY_MISMATCH: {comp['name']}: record names {art.get('registry_ref')}")
    if src.get("revision") != comp["source"].get("commit"):
        raise Refusal(f"ATTRIBUTION_COMMIT_MISMATCH: {comp['name']}: record was built from {src.get('revision')}, component commit is {comp['source'].get('commit')}")
    return {"format": "IGBA/1", "path": rel, "sha256": sha256_file(p),
            "signing_state": rec.get("signing", {}).get("state"),
            "eligibility": rec.get("acceptance_eligibility", {}).get("state"),
            "self_report": art.get("self_report"), "tree_state": src.get("tree_state"),
            "builder_run_id": rec.get("builder", {}).get("run_id")}


def compute_blockers(m: dict[str, Any]) -> list[dict[str, str]]:
    b: list[dict[str, str]] = []

    def add(comp: str, code: str, detail: str) -> None:
        b.append({"component": comp, "code": code, "detail": detail})

    for d in m.get("open_owner_decisions", []):
        add("*", "OPEN_OWNER_DECISION", f"{d['id']}: {d['summary']}")
    # Owner direction 2026-09-30 (INDEPENDENT REVIEW GATE): release eligibility requires INDEPENDENT_REVIEW=GREEN and
    # every deterministic gate GREEN, as decided by lab review/irb.py gate for a candidate whose repository heads are
    # exactly the commits of this manifest's components. The result is produced by the review workflow, never set by hand.
    ir = m.get("independent_review")
    if not ir:
        add("*", "INDEPENDENT_REVIEW_MISSING", "no independent review gate result for this component set")
    else:
        if ir.get("INDEPENDENT_REVIEW") != "GREEN" or ir.get("DETERMINISTIC_GATES") != "GREEN" or ir.get("RELEASE_ELIGIBLE") != "YES":
            add("*", "INDEPENDENT_REVIEW_NOT_GREEN", f"review gate: INDEPENDENT_REVIEW={ir.get('INDEPENDENT_REVIEW')} "
                f"DETERMINISTIC_GATES={ir.get('DETERMINISTIC_GATES')} RELEASE_ELIGIBLE={ir.get('RELEASE_ELIGIBLE')}")
        heads = {str(k): str(v) for k, v in (ir.get("candidate_heads") or {}).items()}
        for c in m.get("components", []):
            if c.get("kind") == "third-party":
                continue
            repo = str(c.get("source", {}).get("repository") or c.get("source", {}).get("repo") or "").rstrip("/").rsplit("/", 1)[-1]
            repo = repo[:-4] if repo.endswith(".git") else repo
            norm = lambda x: re.sub(r"^intentgate-", "", str(x).rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
            match = next((v for k, v in heads.items() if norm(k) == norm(repo)), None)
            if match != c.get("source", {}).get("commit"):
                add(c["name"], "INDEPENDENT_REVIEW_NOT_FOR_THIS_COMMIT",
                    f"reviewed candidate {ir.get('candidate_id')} does not cover {repo}@{str(c.get('source', {}).get('commit'))[:12]}")
    names = [c["name"] for c in runtime_components(m)]
    for r in REQUIRED_COMPONENTS:
        if r not in names:
            add(r, "REQUIRED_COMPONENT_MISSING", f"the canonical product includes this {PRODUCT_BOUNDARY[r]['class']} component")
    sch = m.get("schema", {})
    if not sch.get("expected_fingerprint"):
        add("*", "SCHEMA_FINGERPRINT_UNMEASURED", "no clean-install schema fingerprint has been measured for this component set")
    if not sch.get("migration_manifest"):
        add("*", "NO_MIGRATION_MANIFEST", "no versioned migration manifest from zero / from the previous accepted release")
    for c in m.get("components", []):
        n = c["name"]
        img = c.get("image", {})
        if c.get("kind") == "third-party":
            if not img.get("digest"):
                add(n, "NO_IMAGE_DIGEST", "third-party image has no digest")
            if not c.get("registry_verified"):
                add(n, "THIRD_PARTY_DIGEST_UNVERIFIED", "digest was not verified to resolve in the upstream registry")
            continue
        st = c.get("status")
        if st != "ACCEPTED":
            add(n, f"STATUS_{st}", c.get("status_evidence", ""))
        if c.get("component_class") == "distributable":
            _distributable_blockers(c, add)
            continue
        src = c.get("source", {})
        if not src.get("commit"):
            add(n, "SOURCE_COMMIT_UNKNOWN", "no source commit is attributable to the image")
        a = c.get("accepted_anchor")
        if not a:
            add(n, "NO_ACCEPTED_ANCHOR", "no accepted anchor recovered from evidence")
        else:
            if not a.get("tag"):
                add(n, "ANCHOR_NOT_TAGGED", f"anchor {a.get('kind')} {str(a.get('commit'))[:12]} has no immutable tag")
            if a.get("commit") != src.get("commit"):
                add(n, "ANCHOR_COMMIT_MISMATCH", f"anchor {str(a.get('commit'))[:12]} != component {str(src.get('commit'))[:12]}")
        if not img.get("digest"):
            add(n, "NO_IMAGE_DIGEST", "no image digest")
        at = c.get("attribution")
        if not at:
            add(n, "NO_ATTRIBUTION", "no IGBA/1 build attribution record")
        else:
            if at.get("signing_state") != "SIGNED":
                add(n, "ATTRIBUTION_NOT_SIGNED", f"signing state {at.get('signing_state')}")
            if at.get("eligibility") != "ELIGIBLE":
                add(n, "ATTRIBUTION_NOT_ELIGIBLE", f"eligibility {at.get('eligibility')}")
        if not c.get("sbom"):
            add(n, "NO_SBOM", "no SBOM bound to the digest")
        pa = c.get("provenance_attestation")
        if not pa:
            add(n, "NO_PROVENANCE_ATTESTATION", "no signed provenance attestation bound to the digest")
        elif pa.get("signature") != "VERIFIED":
            add(n, "ATTESTATION_NOT_VERIFIED", f"attestation signature {pa.get('signature')}")
        if c.get("runtime", {}).get("revision_source", {}).get("kind") != "http-json":
            add(n, "RUNTIME_REVISION_NOT_SELF_REPORTED", "the running service cannot report its own commit")
        so = c.get("schema_owner")
        if so is not None and not so.get("migration_level"):
            add(n, "MIGRATION_UNVERSIONED", so.get("ddl_mechanism", ""))
    return b


def _distributable_blockers(c: dict[str, Any], add: Any) -> None:
    """A distributable (SDK) is releasable only as an exactly identified, attested package: source commit, accepted
    anchor at that commit, a version tag AT that commit (one version = one source), sha256 of every built artifact,
    a signed build record, an SBOM and a provenance attestation over exactly those artifacts."""
    n, src, d = c["name"], c.get("source", {}), c.get("distributable") or {}
    if not src.get("commit"):
        add(n, "SOURCE_COMMIT_UNKNOWN", "no source commit is attributable to the package")
    a = c.get("accepted_anchor")
    if not a:
        add(n, "NO_ACCEPTED_ANCHOR", "no accepted anchor recovered from evidence")
    else:
        if not a.get("tag"):
            add(n, "ANCHOR_NOT_TAGGED", f"anchor {a.get('kind')} {str(a.get('commit'))[:12]} has no immutable tag")
        if a.get("commit") != src.get("commit"):
            add(n, "ANCHOR_COMMIT_MISMATCH", f"anchor {str(a.get('commit'))[:12]} != component {str(src.get('commit'))[:12]}")
    if not d.get("artifacts"):
        add(n, "NO_ARTIFACT_DIGEST", "no sha256 of a built package artifact")
    elif d.get("artifact_digest_kind") != "governed-build":
        add(n, "ARTIFACT_DIGEST_NOT_GOVERNED", f"artifact digests are a {d.get('artifact_digest_kind')}, not the governed release build's output")
    if not d.get("version_tag"):
        add(n, "VERSION_NOT_TAGGED", f"version {d.get('version')} has no release tag")
    elif d.get("version_tag_commit") != src.get("commit"):
        add(n, "VERSION_TAG_NOT_AT_COMMIT", f"tag {d.get('version_tag')} is {str(d.get('version_tag_commit'))[:12]}, package source is "
            f"{str(src.get('commit'))[:12]}: version {d.get('version')} would name two different sources")
    at = c.get("attribution")
    if not at:
        add(n, "NO_ATTRIBUTION", "no signed build record for the package artifacts")
    else:
        if at.get("signing_state") != "SIGNED":
            add(n, "ATTRIBUTION_NOT_SIGNED", f"signing state {at.get('signing_state')}")
        if at.get("eligibility") != "ELIGIBLE":
            add(n, "ATTRIBUTION_NOT_ELIGIBLE", f"eligibility {at.get('eligibility')}")
    if not c.get("sbom"):
        add(n, "NO_SBOM", "no SBOM bound to the package artifacts")
    pa = c.get("provenance_attestation")
    if not pa:
        add(n, "NO_PROVENANCE_ATTESTATION", "no signed provenance attestation over the package artifacts")
    elif pa.get("signature") != "VERIFIED":
        add(n, "ATTESTATION_NOT_VERIFIED", f"attestation signature {pa.get('signature')}")


def _check_class(ci: dict[str, Any]) -> None:
    """Refuse a component outside the evidenced boundary, or declared in the wrong class, or carrying the other class's
    delivery fields. A distributable can never render into Compose/Helm because it can never carry an image."""
    n = ci.get("name")
    b = PRODUCT_BOUNDARY.get(n)
    if b is None:
        raise Refusal(f"COMPONENT_OUTSIDE_BOUNDARY: {n}: no dependency evidence classifies this component (PRODUCT_BOUNDARY)")
    cls = ci.get("component_class")
    if cls not in COMPONENT_CLASSES:
        raise Refusal(f"COMPONENT_CLASS_MISSING: {n}: component_class must be one of {sorted(COMPONENT_CLASSES)}")
    if cls != b["class"]:
        raise Refusal(f"COMPONENT_CLASS_MISMATCH: {n} is declared {cls}; the evidenced boundary classifies it {b['class']} ({b['evidence'][:160]})")
    if cls == "runtime":
        if not isinstance(ci.get("image"), dict) or not isinstance(ci.get("runtime"), dict):
            raise Refusal(f"RUNTIME_WITHOUT_IMAGE: {n}: a runtime component needs image and runtime")
        if ci.get("distributable") is not None:
            raise Refusal(f"RUNTIME_HAS_PACKAGE: {n}: a runtime component carries no distributable package block")
        return
    for f in ("image", "runtime", "schema_owner"):
        if ci.get(f) is not None:
            raise Refusal(f"DISTRIBUTABLE_HAS_{f.upper()}: {n}: a distributable is never installed, pulled or run by the installer or the chart")
    d = ci.get("distributable")
    if not isinstance(d, dict):
        raise Refusal(f"DISTRIBUTABLE_WITHOUT_PACKAGE: {n}: ecosystem, package_name, version and artifacts are required")
    if d.get("ecosystem") not in DISTRIBUTABLE_ECOSYSTEMS:
        raise Refusal(f"DISTRIBUTABLE_ECOSYSTEM: {n}: {d.get('ecosystem')!r}")
    if not isinstance(d.get("package_name"), str) or not d["package_name"]:
        raise Refusal(f"DISTRIBUTABLE_PACKAGE_NAME: {n}")
    if not isinstance(d.get("version"), str) or not VERSION_RE.match(d["version"]):
        raise Refusal(f"DISTRIBUTABLE_VERSION: {n}: {d.get('version')!r} is not an exact version (a dist-tag or range is never an identity)")
    for a in d.get("artifacts") or []:
        if not isinstance(a, dict) or not HEX64_RE.match(str(a.get("sha256"))) or not a.get("filename"):
            raise Refusal(f"DISTRIBUTABLE_ARTIFACT: {n}: every artifact is {{filename, sha256 (64 hex)}}")
    if d.get("version_tag_commit") is not None and not COMMIT_RE.match(str(d["version_tag_commit"])):
        raise Refusal(f"COMMIT_FORMAT: {n}: version_tag_commit must be 40 hex")


def build(args: argparse.Namespace) -> int:
    base = os.path.dirname(os.path.dirname(os.path.abspath(args.inputs)))  # release/
    inputs = load_json(args.inputs)
    contract_path = args.contract
    contract = load_json(contract_path)
    ce = check_contract(contract)
    if ce:
        raise Refusal("; ".join(ce))
    key_set = args.key_set or os.path.join(base, "trust", "release-key-set.json")
    anchor = args.trust_anchor or os.path.join(base, "trust", "release-trust-anchor.json")
    comps = []
    for ci in inputs["components"]:
        _check_class(ci)
        c = {k: ci.get(k) for k in ("name", "kind", "role", "component_class", "source", "status", "status_evidence",
                                   "accepted_anchor", "image", "runtime", "schema_owner")}
        c["boundary_evidence"] = PRODUCT_BOUNDARY[c["name"]]["evidence"]
        if c["component_class"] == "distributable":
            c["distributable"] = {k: ci["distributable"].get(k) for k in
                                  ("ecosystem", "package_name", "version", "version_tag", "version_tag_commit",
                                   "artifacts", "artifact_digest_kind", "artifact_digest_source")}
        if c["status"] not in STATUSES:
            raise Refusal(f"STATUS_UNKNOWN: {c['name']}: {c['status']!r}")
        if c["kind"] == "third-party":
            c["registry_verified"] = bool(ci.get("registry_verified"))
            if c["status"] != "THIRD_PARTY":
                raise Refusal(f"STATUS_KIND: {c['name']}: third-party components have status THIRD_PARTY")
        elif c["status"] == "THIRD_PARTY":
            raise Refusal(f"STATUS_KIND: {c['name']}: a first-party component cannot be THIRD_PARTY")
        if c["component_class"] == "runtime":
            _check_image(c["name"], c["image"])
        commit = c["source"].get("commit")
        if commit is not None and not COMMIT_RE.match(commit):
            raise Refusal(f"COMMIT_FORMAT: {c['name']}: {commit!r} is not a full 40-hex commit")
        a = c.get("accepted_anchor")
        if a:
            if not COMMIT_RE.match(a.get("commit") or ""):
                raise Refusal(f"ANCHOR_FORMAT: {c['name']}: anchor commit must be 40 hex")
            a = dict(a)
            if a.get("image_digest") is not None and not DIGEST_RE.match(a["image_digest"]):
                raise Refusal(f"IMAGE_NOT_DIGEST: {c['name']} anchor: {a['image_digest']!r}")
            if a.get("attribution"):
                ap = os.path.join(base, a["attribution"])
                rec = load_json(ap)
                if rec.get("artifact", {}).get("digest") != a.get("image_digest") or rec.get("source", {}).get("revision") != a["commit"]:
                    raise Refusal(f"ANCHOR_ATTRIBUTION_MISMATCH: {c['name']}: anchor record does not attest the anchor digest/commit")
                a["attribution_sha256"] = sha256_file(ap)
            c["accepted_anchor"] = a
        if c["status"] == "ACCEPTED" and (not a or a.get("commit") != commit):
            raise Refusal(f"ACCEPTANCE_INVENTED: {c['name']}: status ACCEPTED requires an accepted anchor at the component commit")
        c["attribution"] = _load_attribution(base, ci["attribution"], c) if ci.get("attribution") else None
        c["attribution_source"] = ci.get("attribution_source")
        if ci.get("image_digest_source"):
            c["image_digest_source"] = ci["image_digest_source"]
        if ci.get("sbom"):
            sp = os.path.join(base, ci["sbom"])
            sb = load_json(sp)
            c["sbom"] = {"path": ci["sbom"], "sha256": sha256_file(sp),
                         "format": sb.get("bomFormat") or sb.get("spdxVersion") or "unknown"}
        else:
            c["sbom"] = None
        if ci.get("provenance_attestation"):
            ap = os.path.join(base, ci["provenance_attestation"])
            subject = c["image"]["digest"] if c["component_class"] == "runtime" else \
                ["sha256:" + a["sha256"] for a in c["distributable"].get("artifacts") or []]
            v = verify_attestation(ap, subject, key_set, anchor)
            c["provenance_attestation"] = {"path": ci["provenance_attestation"], "sha256": sha256_file(ap), **v}
        else:
            c["provenance_attestation"] = None
        comps.append(c)

    # bundle: static files are hashed; rendered files are re-rendered by verifiers, never hashed here
    bf = load_json(args.bundle_files)
    root = os.path.abspath(args.bundle_root)
    static = {}
    for rel in sorted(bf["static"]):
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            raise Refusal(f"BUNDLE_FILE_MISSING: {rel}")
        static[rel] = sha256_file(p)
    s_in = inputs["schema"]
    if s_in.get("expected_fingerprint") is not None and not FP32_RE.match(s_in["expected_fingerprint"]):
        raise Refusal("SCHEMA_FINGERPRINT_FORMAT: expected_fingerprint is 32 hex (lkg-lab-state/1 DB_SCHEMA)")
    schema = dict(s_in)
    schema["owners"] = [{"component": c["name"], **c["schema_owner"]} for c in comps if c.get("schema_owner")]
    contract_rel = os.path.relpath(os.path.abspath(contract_path), root)
    m = {
        "manifest_version": MANIFEST_VERSION,
        "release_id": inputs["release_id"],
        "created_at": inputs["created_at"],
        "product": "IntentGate",
        "components": sorted(comps, key=lambda c: (COMPONENT_ORDER.index(c["name"]) if c["name"] in COMPONENT_ORDER else 99, c["name"])),
        "schema": schema,
        "config_contract": {"path": contract_rel, "sha256": sha256_file(contract_path),
                            "contract_version": contract["contract_version"],
                            "required_keys": sorted(k["name"] for k in contract["keys"] if k["required"])},
        "open_owner_decisions": inputs.get("open_owner_decisions", []),
        "owner_rulings": inputs.get("owner_rulings", []),
        "independent_review": inputs.get("independent_review"),
        "bundle": {"static": static, "rendered": sorted(bf["rendered"]),
                   "generated_at_install": sorted(bf["generated_at_install"])},
        "provenance": {"generator": "release/release-manifest.py", "generator_sha256": sha256_file(os.path.abspath(__file__)),
                       "inputs": os.path.relpath(os.path.abspath(args.inputs), os.path.dirname(base)),  # repo-relative: deterministic across hosts
                       "inputs_sha256": sha256_file(args.inputs)},
    }
    m["releasable_blockers"] = compute_blockers(m)
    m["releasable"] = not m["releasable_blockers"]
    lint_errors = lint_manifest(m)
    if lint_errors:
        raise Refusal("BUILD_PRODUCED_INVALID_MANIFEST: " + "; ".join(lint_errors))
    data = canonical_bytes(m)
    with open(args.out, "wb") as f:
        f.write(data)
    out(f"BUILT {m['release_id']} sha256={sha256_bytes(data)} releasable={str(m['releasable']).lower()} blockers={len(m['releasable_blockers'])}")
    for bl in m["releasable_blockers"]:
        out(f"  BLOCKER {bl['component']}: {bl['code']} - {bl['detail']}")
    return 0


# ----------------------------------------------------------------------------------------------
# lint
# ----------------------------------------------------------------------------------------------

def lint_manifest(m: dict[str, Any]) -> list[str]:
    e: list[str] = []
    if m.get("manifest_version") != MANIFEST_VERSION:
        e.append(f"MANIFEST_VERSION: {m.get('manifest_version')!r}")
    try:
        import jsonschema  # optional; the semantic checks below stand on their own
        sp = os.path.join(HERE, "release-manifest.schema.json")
        if os.path.exists(sp):
            for err in jsonschema.Draft202012Validator(load_json(sp)).iter_errors(m):
                e.append(f"SCHEMA: {'/'.join(str(x) for x in err.absolute_path)}: {err.message}")
    except ImportError:
        pass
    text = json.dumps(m)
    if MUTABLE_TEXT_RE.search(text):
        e.append("MUTABLE_REFERENCE: the manifest contains 'latest'")
    names = set()
    for c in m.get("components", []):
        n = c.get("name")
        if n in names:
            e.append(f"DUPLICATE_COMPONENT: {n}")
        names.add(n)
        try:
            _check_class(c)
            if c.get("component_class") == "runtime":
                _check_image(n, c.get("image", {}))
        except Refusal as r:
            e.append(str(r))
        st = c.get("status")
        if st not in STATUSES:
            e.append(f"STATUS_UNKNOWN: {n}: {st!r}")
        a = c.get("accepted_anchor")
        if st == "ACCEPTED" and (not a or a.get("commit") != c.get("source", {}).get("commit")):
            e.append(f"ACCEPTANCE_INVENTED: {n}: ACCEPTED without an accepted anchor at the component commit")
        at = c.get("attribution")
        if at and not re.match(r"^[0-9a-f]{64}$", at.get("sha256", "")):
            e.append(f"ATTRIBUTION_DIGEST: {n}")
    fp = m.get("schema", {}).get("expected_fingerprint")
    if fp is not None and not FP32_RE.match(fp):
        e.append("SCHEMA_FINGERPRINT_FORMAT")
    recomputed = compute_blockers(m)
    if recomputed != m.get("releasable_blockers"):
        e.append("RELEASABLE_BLOCKERS_NOT_COMPUTED: the blocker list differs from the recomputation (hand-edited?)")
    if m.get("releasable") is not (not recomputed):
        e.append(f"RELEASABLE_FLAG_NOT_COMPUTED: manifest says releasable={m.get('releasable')}, recomputation says {not recomputed}")
    return e


def cmd_lint(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m)
    for x in errs:
        out(f"FAIL {x}")
    if errs:
        out("MANIFEST_LINT=FAIL")
        return 1
    out(f"MANIFEST_LINT=PASS {m['release_id']} releasable={str(m['releasable']).lower()}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    data = open(args.manifest, "rb").read()
    kid = verify_detached(data, args.sig, args.key_set, args.trust_anchor, args.test_public_key, args.allow_test_key, args.pinned_fingerprint)
    out(f"SIGNATURE=VERIFIED key={kid} manifest_sha256={sha256_bytes(data)}")
    m = json.loads(data)
    errs = lint_manifest(m)
    if errs:
        for x in errs:
            out(f"FAIL {x}")
        raise Refusal("MANIFEST_LINT=FAIL")
    out(f"MANIFEST_LINT=PASS releasable={str(m['releasable']).lower()} blockers={len(m['releasable_blockers'])}")
    if args.require_releasable and not m["releasable"]:
        for b in m["releasable_blockers"]:
            out(f"  BLOCKER {b['component']}: {b['code']}")
        raise Refusal(f"NOT_RELEASABLE: {m['release_id']} has {len(m['releasable_blockers'])} blocker(s)")
    out("MANIFEST_VERIFY=PASS")
    return 0


# ----------------------------------------------------------------------------------------------
# rendering (the ONLY writer of image references)
# ----------------------------------------------------------------------------------------------

def _q(s: Any) -> str:
    if isinstance(s, bool):
        return "true" if s else "false"
    if isinstance(s, int):
        return str(s)
    return json.dumps(str(s))


def image_ref(c: dict[str, Any]) -> str:
    img = c["image"]
    if img.get("digest"):
        return f"{img['repository']}@{img['digest']}"
    var = "INTENTGATE_UNRESOLVED_" + re.sub(r"[^A-Z0-9]", "_", c["name"].upper())
    return "${" + var + ":?release manifest has no digest for " + c["name"] + ": this release is not installable}"


def _contract_keys(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {k["name"]: k for k in contract["keys"]}


def _compose_env_value(src: dict[str, Any], keys: dict[str, dict[str, Any]]) -> str:
    if "literal" in src:
        return src["literal"]
    k = keys[src["key"]]
    if k["required"]:
        return "${" + k["name"] + ":?" + k["name"] + " is required by config-contract.json}"
    if k.get("default") is not None:
        return "${" + k["name"] + ":-" + k["default"] + "}"
    return "${" + k["name"] + ":-}"


def manifest_sha(path: str) -> str:
    return sha256_file(path)


def render_compose(m: dict[str, Any], contract: dict[str, Any], msha: str) -> str:
    keys = _contract_keys(contract)
    L = ["# GENERATED by release/release-manifest.py render-compose. DO NOT EDIT: CI re-renders and compares.",
         f"# release {m['release_id']} manifest sha256 {msha}",
         f"# releasable: {str(m['releasable']).lower()} ({len(m['releasable_blockers'])} blocker(s); see the manifest)",
         "# Every image is pinned by digest from the signed manifest; there is no tag fallback.",
         "",
         "name: intentgate",
         "",
         "services:"]
    comps = {c["name"]: c for c in runtime_components(m)}  # distributables are never rendered
    volumes = []
    for name in [n for n in COMPONENT_ORDER if n in comps]:
        c = comps[name]
        rt = c["runtime"]
        svc = rt["service"]
        L.append(f"  {svc}:")
        L.append(f"    image: {_q(image_ref(c))}")
        L.append("    pull_policy: missing")
        L.append("    restart: unless-stopped")
        L.append("    labels:")
        L.append(f"      app.intentgate.release: {_q(m['release_id'])}")
        L.append(f"      app.intentgate.component: {_q(name)}")
        deps = rt.get("depends_on") or []
        if deps:
            L.append("    depends_on:")
            for d in deps:
                dc = comps.get(d)
                healthy = dc is not None and dc["runtime"].get("health", {}).get("compose_test")
                L.append(f"      {comps[d]['runtime']['service'] if d in comps else d}:")
                L.append(f"        condition: {'service_healthy' if healthy else 'service_started'}")
        wiring = contract["wiring"].get(name, {})
        if wiring:
            L.append("    environment:")
            for env in sorted(wiring):
                L.append(f"      {env}: {_q(_compose_env_value(wiring[env], keys))}")
        vol = rt.get("volume")
        if vol:
            L.append("    volumes:")
            L.append(f"      - {_q(vol['name'] + ':' + vol['mount'])}")
            volumes.append(vol["name"])
        pub = rt.get("publish")
        if pub:
            bk = keys[pub["bind_key"]]
            L.append("    ports:")
            L.append(f"      - {_q('${' + bk['name'] + ':-' + bk['default'] + '}:' + str(pub['host_port']) + ':' + str(rt['port']))}")
        test = rt.get("health", {}).get("compose_test")
        if test:
            L.append("    healthcheck:")
            L.append("      test: [" + ", ".join(_q(t) for t in test) + "]")
            L.append("      interval: 10s")
            L.append("      timeout: 5s")
            L.append("      retries: 30")
            L.append("      start_period: 20s")
        L.append("    networks: [internal]")
    L.append("")
    L.append("networks:")
    L.append("  internal: {}")
    if volumes:
        L.append("")
        L.append("volumes:")
        for v in volumes:
            L.append(f"  {v}: {{}}")
    return "\n".join(L) + "\n"


def _yaml(obj: Any, ind: int = 0) -> list[str]:
    """Minimal deterministic YAML emitter (JSON-quoted scalars). No PyYAML dependency."""
    p = "  " * ind
    lines: list[str] = []
    if isinstance(obj, dict):
        if not obj:
            return [p + "{}"]
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{p}{k}:")
                lines.extend(_yaml(v, ind + 1))
            elif isinstance(v, dict):
                lines.append(f"{p}{k}: {{}}")
            elif isinstance(v, list):
                lines.append(f"{p}{k}: []")
            else:
                lines.append(f"{p}{k}: {_scalar(v)}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, dict) and v:
                sub = _yaml(v, ind + 1)
                lines.append(p + "- " + sub[0].lstrip())
                lines.extend(sub[1:])
            else:
                lines.append(f"{p}- {_scalar(v)}")
    return lines


def _scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(str(v))


def helm_values(m: dict[str, Any], contract: dict[str, Any], msha: str) -> dict[str, Any]:
    keys = _contract_keys(contract)
    comps = {c["name"]: c for c in runtime_components(m)}  # distributables are never rendered
    vals: dict[str, Any] = {
        "release": {"id": m["release_id"], "manifestSha256": msha, "releasable": m["releasable"],
                    "blockers": len(m["releasable_blockers"])},
        "configSecretName": "intentgate-config",
        "imagePullSecrets": [],
        "componentOrder": [n for n in COMPONENT_ORDER if n in comps],
        "components": {},
    }
    for name in vals["componentOrder"]:
        c = comps[name]
        rt = c["runtime"]
        env = []
        for e in sorted(contract["wiring"].get(name, {})):
            src = contract["wiring"][name][e]
            if "literal" in src:
                env.append({"name": e, "value": src["literal"]})
            else:
                k = keys[src["key"]]
                env.append({"name": e, "secretKey": k["name"], "optional": not k["required"]})
        h = rt.get("health", {})
        probe = {"kind": h.get("kind", "none")}
        if h.get("kind") == "http":
            probe["path"] = h["path"]
        if h.get("kind") == "exec":
            probe["command"] = ["pg_isready", "-U", "intentgate", "-d", "intentgate", "-h", "127.0.0.1"]
        vals["components"][name] = {
            "serviceName": rt["service"],
            "image": {"repository": c["image"]["repository"], "digest": c["image"]["digest"] or "",
                      "unresolved": "" if c["image"]["digest"] else f"release manifest {m['release_id']} has no digest for {name}"},
            "port": rt["port"],
            "replicas": rt.get("replicas", 1),
            "probe": probe,
            "persistence": {"enabled": bool(rt.get("volume")), "mountPath": (rt.get("volume") or {}).get("mount", ""), "size": "10Gi"},
            "env": env,
        }
    return vals


def render_helm_values(m: dict[str, Any], contract: dict[str, Any], msha: str) -> str:
    head = ["# GENERATED by release/release-manifest.py render-helm-values. DO NOT EDIT: CI re-renders and compares.",
            f"# release {m['release_id']} manifest sha256 {msha}",
            "# Images are digest-only; a component without a digest makes `helm template` fail with its reason."]
    return "\n".join(head + _yaml(helm_values(m, contract, msha))) + "\n"


def render_env_example(contract: dict[str, Any]) -> str:
    L = ["# GENERATED from release/config-contract.json by release-manifest.py render-env-example. DO NOT EDIT.",
         "# The installer fills every GENERATED key and refuses to start while a REQUIRED key is empty.",
         "# Images are NOT configured here: they come only from the signed release manifest, by digest.", ""]
    for k in contract["keys"]:
        tag = []
        tag.append("REQUIRED" if k["required"] else "optional")
        if k["secret"]:
            tag.append("secret")
        if k["generator"]:
            tag.append("GENERATED" if k["generator"].startswith("random") else "DERIVED")
        if k["scope"] != "product":
            tag.append(f"{k['scope']} only")
        L.append(f"# {k['name']} [{', '.join(tag)}] {k['description']}".rstrip())
        val = k["default"] if (k["default"] is not None and not k["secret"]) else ""
        L.append(f"{k['name']}={val}")
    return "\n".join(L) + "\n"


def cmd_render(args: argparse.Namespace, kind: str) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m)
    if errs:
        raise Refusal("refusing to render from an invalid manifest: " + "; ".join(errs))
    contract = load_json(args.contract)
    if sha256_file(args.contract) != m["config_contract"]["sha256"]:
        raise Refusal("CONFIG_CONTRACT_MISMATCH: the contract file is not the one the manifest binds")
    ce = check_contract(contract)
    if ce:
        raise Refusal("refusing to render: " + "; ".join(ce))
    msha = manifest_sha(args.manifest)
    text = render_compose(m, contract, msha) if kind == "compose" else render_helm_values(m, contract, msha)
    return _emit(text, args)


def _emit(text: str, args: argparse.Namespace) -> int:
    if args.check:
        cur = open(args.check, encoding="utf-8").read() if os.path.exists(args.check) else None
        if cur != text:
            out(f"RENDER_DRIFT: {args.check} differs from the render of the manifest (hand-edited or stale)")
            return 1
        out(f"RENDER_MATCH: {args.check}")
        return 0
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


def cmd_render_env(args: argparse.Namespace) -> int:
    return _emit(render_env_example(load_json(args.contract)), args)


# ----------------------------------------------------------------------------------------------
# configuration contract
# ----------------------------------------------------------------------------------------------

def read_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    if not os.path.exists(path):
        return env
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        env[k.strip()] = v
    return env


def _validate_value(k: dict[str, Any], v: str) -> str | None:
    val = k["validator"]
    kind = val["kind"]
    if v in k.get("forbidden_values", []):
        return "FORBIDDEN_VALUE (a published default)"
    if kind == "any":
        return None
    if kind == "nonempty":
        return None if v else "EMPTY"
    if kind == "regex":
        return None if re.match(val["pattern"], v) else "FORMAT"
    if kind == "enum":
        return None if v in val["values"] else "NOT_ALLOWED"
    if kind == "min-length":
        return None if len(v) >= val["min"] else f"TOO_SHORT (<{val['min']})"
    if kind == "base64-bytes":
        for dec in (lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), lambda s: base64.b64decode(s + "=" * (-len(s) % 4))):
            try:
                raw = dec(v)
            except Exception:
                continue
            if len(raw) >= val.get("min_bytes", 0) and ("max_bytes" not in val or len(raw) <= val["max_bytes"]):
                return None
        return "NOT_BASE64_OF_REQUIRED_LENGTH"
    return f"UNKNOWN_VALIDATOR {kind}"


def validate_env(contract: dict[str, Any], env: dict[str, str], scope: str) -> tuple[list[str], list[str]]:
    """Returns (present_key_names, failures). Failures name keys and reasons, never values."""
    fails: list[str] = []
    keys = _contract_keys(contract)
    forbidden = {f["name"]: f["reason"] for f in contract.get("forbidden_keys", [])}
    for name, why in HUMAN_IMPERSONATION_ENV.items():  # fixed in the tool: present at all, even EMPTY, is refused
        forbidden.setdefault(name, why)
    for name in sorted(forbidden):
        if name in env:
            fails.append(f"{name}: FORBIDDEN_KEY ({forbidden[name]})")
    for name in env:
        if name not in keys and name not in forbidden:
            fails.append(f"{name}: UNKNOWN_KEY (not in config-contract.json)")
    for k in contract["keys"]:
        if k["scope"] not in ("product", scope):
            continue
        v = env.get(k["name"], "")
        if not v:
            if k["required"]:
                fails.append(f"{k['name']}: MISSING_REQUIRED")
            continue
        r = _validate_value(k, v)
        if r:
            fails.append(f"{k['name']}: {r}")
    return sorted(n for n, v in env.items() if v), fails


def generate_env(contract: dict[str, Any], path: str) -> list[str]:
    env = read_env(path)
    lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
    filled = []

    def setv(k: str, v: str) -> None:
        nonlocal lines
        env[k] = v
        filled.append(k)
        for i, line in enumerate(lines):
            if line.split("=", 1)[0].strip() == k and not line.lstrip().startswith("#"):
                lines[i] = f"{k}={v}"
                return
        lines.append(f"{k}={v}")

    for k in contract["keys"]:
        if env.get(k["name"]):
            continue
        g = k["generator"] or ""
        if g == "random-hex-32":
            setv(k["name"], secrets.token_hex(32))
        elif g == "random-base64url-32":
            setv(k["name"], base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))
        elif k["default"] is not None:
            setv(k["name"], k["default"])
    for k in contract["keys"]:  # derivations after randoms (they may reference them)
        g = k["generator"] or ""
        if g.startswith("derive:") and not env.get(k["name"]):
            tmpl = g[len("derive:"):]
            refs = re.findall(r"\$\{([A-Z0-9_]+)\}", tmpl)
            if all(env.get(r) for r in refs):
                setv(k["name"], re.sub(r"\$\{([A-Z0-9_]+)\}", lambda mm: env[mm.group(1)], tmpl))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return filled


def cmd_config_generate(args: argparse.Namespace) -> int:
    filled = generate_env(load_json(args.contract), args.env)
    out(f"CONFIG_GENERATED keys={len(filled)} ({', '.join(filled) if filled else 'none'}); values not printed")
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    contract = load_json(args.contract)
    present, fails = validate_env(contract, read_env(args.env), args.scope)
    if args.facts_out:
        with open(args.facts_out, "w") as f:
            json.dump({"present": present, "validation_failures": fails}, f, indent=2)
    for x in fails:
        out(f"FAIL {x}")
    out(f"CONFIG_CONTRACT={'PASS' if not fails else 'FAIL'} present={len(present)} failures={len(fails)}")
    return 0 if not fails else 1


# ----------------------------------------------------------------------------------------------
# bundle and release-input guards
# ----------------------------------------------------------------------------------------------

CONTROL_FILES = {"release-manifest.json", "release-manifest.json.sig", "CHECKSUMS"}


def _walk(root: str) -> tuple[list[str], list[str]]:
    files, nested = [], []
    for d, dirs, fs in os.walk(root):
        rel = os.path.relpath(d, root)
        if ".git" in dirs:
            if rel != ".":
                nested.append(os.path.join(rel, ".git"))
            dirs.remove(".git")
        for f in fs:
            files.append(os.path.normpath(os.path.join(rel, f)))
    return sorted(files), nested


def _generated_ok(path: str, patterns: list[str]) -> bool:
    import fnmatch
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def verify_bundle_dir(m: dict[str, Any], d: str, manifest_path: str, contract_path: str | None) -> list[str]:
    e: list[str] = []
    b = m["bundle"]
    files, nested = _walk(d)
    for n in nested:
        e.append(f"NESTED_REPOSITORY: {n} (a nested clone is never part of a release)")
    allowed = set(b["static"]) | set(b["rendered"]) | CONTROL_FILES
    for f in files:
        if f in allowed or _generated_ok(f, b["generated_at_install"]):
            continue
        e.append(f"FILE_NOT_IN_BUNDLE: {f}")
    for rel, h in b["static"].items():
        p = os.path.join(d, rel)
        if not os.path.isfile(p):
            e.append(f"BUNDLE_FILE_MISSING: {rel}")
        elif sha256_file(p) != h:
            e.append(f"BUNDLE_FILE_MODIFIED: {rel}")
    cpath = contract_path or os.path.join(d, m["config_contract"]["path"])
    if not os.path.isfile(cpath) or sha256_file(cpath) != m["config_contract"]["sha256"]:
        e.append("CONFIG_CONTRACT_MISMATCH")
        return e
    contract = load_json(cpath)
    e.extend(check_contract(contract))
    msha = sha256_file(manifest_path)
    expected = {"docker-compose.yml": render_compose(m, contract, msha),
                ".env.example": render_env_example(contract)}
    for rel in b["rendered"]:
        p = os.path.join(d, rel)
        want = expected.get(rel)
        if rel.endswith("values.release.yaml"):
            want = render_helm_values(m, contract, msha)
        if want is None:
            e.append(f"RENDERED_UNKNOWN: {rel}")
        elif not os.path.isfile(p):
            e.append(f"RENDERED_MISSING: {rel}")
        elif open(p, encoding="utf-8").read() != want:
            e.append(f"RENDERED_DRIFT: {rel} is not the render of this manifest")
    return e


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m) + verify_bundle_dir(m, args.bundle_dir, args.manifest, args.contract)
    for x in errs:
        out(f"FAIL {x}")
    out(f"BUNDLE_VERIFY={'PASS' if not errs else 'FAIL'}")
    return 0 if not errs else 1


def guard_release_input(root: str, bundle_files: str | None, exclude: list[str]) -> list[str]:
    e: list[str] = []
    root = os.path.abspath(root)

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", root, *a], check=True, capture_output=True, text=True).stdout

    tracked = [x for x in git("ls-files", "-z").split("\0") if x]
    _, nested = _walk(root)
    for n in nested:
        e.append(f"NESTED_REPOSITORY: {n}")
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        for f in fs:
            if re.search(r"\.(tgz|tar\.gz|tar|zip)$", f):
                e.append(f"ARCHIVE_IN_RELEASE_INPUT: {os.path.relpath(os.path.join(d, f), root)} (packaged artifacts are built, never committed or left in the tree)")
    status = git("status", "--porcelain", "--untracked-files=all", "--ignored")
    for line in status.splitlines():
        code, path = line[:2], line[3:]
        if code == "!!":
            e.append(f"IGNORED_FILE_IN_TREE: {path} (would ship with a folder copy; not release input)")
        elif code == "??":
            e.append(f"UNTRACKED_FILE: {path}")
        elif bundle_files and path in load_json(bundle_files).get("static", []):
            e.append(f"MODIFIED_BUNDLE_FILE: {path}")
    for rel in tracked:
        if any(rel == x or rel.startswith(x.rstrip("/") + "/") for x in exclude):
            continue
        p = os.path.join(root, rel)
        try:
            text = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for mm in MUTABLE_TEXT_RE.finditer(text):
            ln = text.count("\n", 0, mm.start()) + 1
            e.append(f"MUTABLE_REFERENCE: {rel}:{ln}: {mm.group(0)}")
        for mm in IMPERSONATION_TEXT_RE.finditer(text):
            ln = text.count("\n", 0, mm.start()) + 1
            e.append(f"HUMAN_IMPERSONATION_OVERRIDE: {rel}:{ln}: {(mm.group(1) or mm.group(2))} is set or wired")
        for mm in IMAGE_LINE_RE.finditer(text):
            ref = mm.group(1)
            if ref.startswith(UNRESOLVED_PREFIX) or "@sha256:" in ref:
                continue
            if "{{" in ref:  # a Helm template expression; the chart helper enforces digest-only
                continue
            ln = text.count("\n", 0, mm.start()) + 1
            e.append(f"IMAGE_NOT_BY_DIGEST: {rel}:{ln}: {ref}")
    return e


def cmd_guard(args: argparse.Namespace) -> int:
    errs = guard_release_input(args.root, args.bundle_files, args.exclude or [])
    for x in errs:
        out(f"FAIL {x}")
    out(f"RELEASE_INPUT_GUARD={'PASS' if not errs else 'FAIL'} findings={len(errs)}")
    return 0 if not errs else 1


# ----------------------------------------------------------------------------------------------
# verify-install: the provenance chain, link by link
# ----------------------------------------------------------------------------------------------

def verify_install(m: dict[str, Any], facts: dict[str, Any], manifest_path: str, contract: dict[str, Any] | None,
                   sig_kid: str | None) -> list[tuple[str, bool, str]]:
    links: list[tuple[str, bool, str]] = []
    links.append(("MANIFEST_SIGNATURE", sig_kid is not None, f"key={sig_kid}" if sig_kid else "not verified"))
    le = lint_manifest(m)
    links.append(("MANIFEST_LINT", not le, "; ".join(le) or "ok"))
    if facts.get("facts_version") != FACTS_VERSION:
        links.append(("FACTS_FORMAT", False, f"facts_version {facts.get('facts_version')!r}"))
        return links
    if facts.get("release_id") is not None and facts.get("release_id") != m["release_id"]:
        links.append(("RELEASE_ID", False, f"install labelled {facts['release_id']}, manifest is {m['release_id']}"))
    # bundle inventory: installed files == bundle static + rendered + declared generated files
    inv = facts.get("inventory")
    if inv is None:
        links.append(("BUNDLE_INVENTORY", False, "no installed-file inventory in facts"))
    else:
        b = m["bundle"]
        allowed = set(b["static"]) | set(b["rendered"]) | CONTROL_FILES
        bad = []
        for p, h in sorted(inv.get("files", {}).items()):
            if p in b["static"]:
                if h != b["static"][p]:
                    bad.append(f"{p} modified")
            elif p in allowed or _generated_ok(p, b["generated_at_install"]):
                continue
            else:
                bad.append(f"{p} not in bundle")
        for p in b["static"]:
            if p not in inv.get("files", {}):
                bad.append(f"{p} missing")
        if contract is not None:
            msha = sha256_file(manifest_path)
            exp = {"docker-compose.yml": sha256_bytes(render_compose(m, contract, msha).encode()),
                   ".env.example": sha256_bytes(render_env_example(contract).encode())}
            for p, h in exp.items():
                if p in inv.get("files", {}) and inv["files"][p] != h:
                    bad.append(f"{p} is not the render of the manifest")
        for n in inv.get("nested_repositories", []):
            bad.append(f"nested repository {n}")
        links.append(("BUNDLE_INVENTORY", not bad, "; ".join(bad) or f"{len(inv.get('files', {}))} files == bundle + declared generated"))
    # images
    running = facts.get("containers", [])
    bad = []
    services = {c["runtime"]["service"]: c for c in runtime_components(m)}
    for c in runtime_components(m):
        svc = c["runtime"]["service"]
        want = c["image"]["digest"]
        inst = [r for r in running if r.get("service") == svc]
        if not want:
            bad.append(f"{c['name']}: manifest has no digest")
        elif not inst:
            bad.append(f"{c['name']}: not running")
        else:
            for r in inst:
                if r.get("image_digest") != want:
                    bad.append(f"{c['name']}: running {r.get('image_digest')} != manifest {want}")
    for r in running:
        if r.get("service") not in services:
            bad.append(f"{r.get('service')}: running but not in the manifest")
    links.append(("IMAGES_BY_DIGEST", not bad, "; ".join(bad) or f"{len(running)} containers match the manifest digests"))
    # revisions
    bad = []
    revs = facts.get("revisions", {})
    for c in runtime_components(m):
        if c["kind"] == "third-party":
            continue
        svc, want = c["runtime"]["service"], c["source"].get("commit")
        got = (revs.get(svc) or {}).get("value")
        if not want:
            bad.append(f"{c['name']}: manifest has no commit")
        elif got != want:
            bad.append(f"{c['name']}: reports {got!r} via {(revs.get(svc) or {}).get('source')}, manifest {want}")
    links.append(("RUNNING_REVISIONS", not bad, "; ".join(bad) or "every first-party service reports its manifest commit"))
    # schema
    want, got = m["schema"].get("expected_fingerprint"), facts.get("schema_fingerprint")
    if not want:
        links.append(("SCHEMA_FINGERPRINT", False, f"manifest has no expected fingerprint (UNMEASURED); install measured {got}"))
    else:
        links.append(("SCHEMA_FINGERPRINT", got == want, f"install {got} manifest {want}"))
    # no human-impersonation override in any running component's environment (names only; values are never read)
    en = facts.get("env_names")
    if en is None:
        links.append(("NO_IMPERSONATION_OVERRIDE", False, "running environment names not measured"))
    else:
        bad = [f"{svc}: {n}" for svc, names in sorted(en.items()) for n in names if n in HUMAN_IMPERSONATION_ENV or n.startswith("<envFrom")]
        missing = sorted(c["runtime"]["service"] for c in runtime_components(m) if c["runtime"]["service"] not in en)
        bad += [f"{svc}: environment not measured" for svc in missing]
        links.append(("NO_IMPERSONATION_OVERRIDE", not bad, "; ".join(bad) or "no running component carries GATEWAY_DEV_SUBJECT / INTENTGATE_PLATFORM_GATEWAY_SUBJECT"))
    # configuration
    cf = facts.get("config", {})
    missing = sorted(set(m["config_contract"]["required_keys"]) - set(cf.get("present", [])))
    bad = [f"missing {k}" for k in missing] + list(cf.get("validation_failures", []))
    links.append(("CONFIG_CONTRACT", not bad, "; ".join(bad) or "all required keys present and valid"))
    return links


def cmd_verify_install(args: argparse.Namespace) -> int:
    data = open(args.manifest, "rb").read()
    kid = None
    try:
        kid = verify_detached(data, args.sig, args.key_set, args.trust_anchor, args.test_public_key, args.allow_test_key, args.pinned_fingerprint)
    except Refusal as r:
        out(f"NOTE signature: {r}")
    m = json.loads(data)
    contract = load_json(args.contract) if args.contract else None
    links = verify_install(m, load_json(args.facts), args.manifest, contract, kid)
    ok = all(p for _, p, _ in links)
    for name, p, detail in links:
        out(f"LINK|{name}|{'PASS' if p else 'FAIL'}|{detail}")
    out(f"PROVENANCE_CHAIN={'GREEN' if ok else 'RED'}")
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------------
# facts and state from a running install (compose or helm)
# ----------------------------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise Refusal(f"COMMAND_FAILED: {' '.join(cmd[:3])}...: {r.stderr.strip()[:300]}")
    return r.stdout


PG_NORMALISE = ("pg_dump -U intentgate -d intentgate --schema-only 2>/dev/null | grep -v '^--' | grep -v '^SET ' "
                "| grep -v '^SELECT pg_catalog.set_config' | grep -Ev '^\\\\(un)?restrict ' | grep -v '^$' | sha256sum | cut -c1-32")


class Runtime:
    def __init__(self, form: str, project: str, namespace: str):
        self.form, self.project, self.ns = form, project, namespace

    def containers(self) -> list[dict[str, Any]]:
        res = []
        if self.form == "compose":
            ids = _run(["docker", "ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={self.project}"]).split()
            for cid in ids:
                j = json.loads(_run(["docker", "inspect", cid]))[0]
                lab = j["Config"].get("Labels") or {}
                ref = j["Config"]["Image"]
                dig = ref.split("@", 1)[1] if "@" in ref else None
                repo_digests = json.loads(_run(["docker", "image", "inspect", j["Image"], "--format", "{{json .RepoDigests}}"]) or "[]")
                if dig and not any(rd.endswith("@" + dig) for rd in repo_digests or []):
                    dig = f"UNVERIFIED({dig})"
                img_labels = json.loads(_run(["docker", "image", "inspect", j["Image"], "--format", "{{json .Config.Labels}}"]) or "null") or {}
                res.append({"service": lab.get("com.docker.compose.service"), "name": j["Name"].lstrip("/"),
                            "env_names": sorted({e.split("=", 1)[0] for e in (j["Config"].get("Env") or [])}),
                            "image_ref": ref, "image_digest": dig, "image_id": j["Image"],
                            "oci_revision": img_labels.get("org.opencontainers.image.revision"),
                            "state": j["State"]["Status"], "restarts": j.get("RestartCount", 0)})
        else:
            pods = json.loads(_run(["kubectl", "-n", self.ns, "get", "pods", "-o", "json"]))
            for p in pods["items"]:
                comp = p["metadata"].get("labels", {}).get("app.kubernetes.io/component")
                for cs in p.get("status", {}).get("containerStatuses", []):
                    spec_img = next((c["image"] for c in p["spec"]["containers"] if c["name"] == cs["name"]), "")
                    iid = cs.get("imageID", "")
                    dig = spec_img.split("@", 1)[1] if "@" in spec_img else None
                    if dig and not iid.endswith(dig):
                        dig = f"UNVERIFIED({dig})"
                    spec_c = next((c for c in p["spec"]["containers"] if c["name"] == cs["name"]), {})
                    names = {e["name"] for e in spec_c.get("env") or []}
                    if spec_c.get("envFrom"):
                        names.add("<envFrom: unmeasurable bulk environment>")
                    res.append({"service": comp, "name": p["metadata"]["name"], "env_names": sorted(names),
                                "image_ref": spec_img, "image_digest": dig,
                                "image_id": iid, "oci_revision": None,
                                "state": "running" if cs.get("ready") else "not-ready", "restarts": cs.get("restartCount", 0)})
        return res

    def exec(self, service: str, shell: str) -> str:
        if self.form == "compose":
            return _run(["docker", "compose", "-p", self.project, "exec", "-T", service, "sh", "-c", shell], check=False)
        return _run(["kubectl", "-n", self.ns, "exec", f"deploy/{service}", "--", "sh", "-c", shell], check=False) \
            if service != "postgres" else _run(["kubectl", "-n", self.ns, "exec", "statefulset/postgres", "--", "sh", "-c", shell], check=False)

    def http_json(self, service: str, port: int, path: str) -> Any:
        # read from INSIDE the network, through a probe image-independent route: node or wget in the target
        cmd = (f"(wget -qO- http://127.0.0.1:{port}{path} 2>/dev/null) || "
               f"(node -e \"require('http').get('http://127.0.0.1:{port}{path}',r=>{{let d='';r.on('data',c=>d+=c);r.on('end',()=>process.stdout.write(d))}})\" 2>/dev/null)")
        raw = self.exec(service, cmd)
        try:
            return json.loads(raw)
        except Exception:
            return None


def collect_facts(m: dict[str, Any], rt: Runtime, install_dir: str | None, contract: dict[str, Any] | None) -> dict[str, Any]:
    f: dict[str, Any] = {"facts_version": FACTS_VERSION, "install_form": rt.form, "release_id": None}
    cs = rt.containers()
    f["containers"] = [{k: c[k] for k in ("service", "name", "image_digest", "oci_revision", "state")} for c in cs]
    f["env_names"] = {}
    for c in cs:
        f["env_names"].setdefault(c["service"], [])
        f["env_names"][c["service"]] = sorted(set(f["env_names"][c["service"]]) | set(c["env_names"]))
    revs = {}
    for c in runtime_components(m):
        r = c["runtime"]["revision_source"]
        svc = c["runtime"]["service"]
        if r["kind"] == "http-json":
            j = rt.http_json(svc, r["port"], r["path"])
            revs[svc] = {"source": f"http:{r['path']}#{r['field']}", "value": (j or {}).get(r["field"]) if isinstance(j, dict) else None}
        elif r["kind"] == "oci-label":
            vals = {x.get("oci_revision") for x in cs if x["service"] == svc}
            revs[svc] = {"source": "oci-label (image metadata, bound by digest)", "value": vals.pop() if len(vals) == 1 else None}
    f["revisions"] = revs
    f["schema_fingerprint"] = rt.exec("postgres", PG_NORMALISE).strip() or None
    if install_dir:
        files, nested = _walk(install_dir)
        f["inventory"] = {"files": {p: sha256_file(os.path.join(install_dir, p)) for p in files}, "nested_repositories": nested}
        if contract is not None:
            present, fails = validate_env(contract, read_env(os.path.join(install_dir, ".env")), "compose" if rt.form == "compose" else "helm")
            f["config"] = {"present": present, "validation_failures": fails}
    return f


def cmd_collect_facts(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    rt = Runtime(args.form, args.project, args.namespace)
    contract = load_json(args.contract) if args.contract else None
    f = collect_facts(m, rt, args.install_dir, contract)
    if args.config_facts:
        f["config"] = load_json(args.config_facts)
    f["release_id"] = m["release_id"]
    with open(args.out, "w") as fh:
        json.dump(f, fh, indent=2, sort_keys=True)
    out(f"FACTS_WRITTEN {args.out} containers={len(f['containers'])}")
    return 0


def cmd_capture_state(args: argparse.Namespace) -> int:
    """lkg-lab-state/1 lines (the format lkg-rollback-equivalence.sh `state` compares). In a clean-room
    upgrade/rollback every container is recreated by construction, so started is '-' for all."""
    rt = Runtime(args.form, args.project, args.namespace)
    lines = ["STATE_SCHEMA|lkg-lab-state/1"]
    for c in sorted(rt.containers(), key=lambda x: x["name"]):
        lines.append(f"CONTAINER|{c['name']}|image={c['image_digest'] or c['image_id']}|rev={c['oci_revision'] or ''}|state={c['state']}|started=-|restarts={c['restarts']}")
    if args.install_dir:
        for p in sorted(_walk(args.install_dir)[0]):
            if p == ".env" or p.endswith((".env.example",)) or p.endswith(".yml") or p.endswith(".json"):
                lines.append(f"FILE|{p}|{sha256_file(os.path.join(args.install_dir, p))[:32]}")
    lines.append(f"DB_SCHEMA|{rt.exec('postgres', PG_NORMALISE).strip()}")
    tables = rt.exec("postgres", "psql -U intentgate -d intentgate -tA -c \"SELECT count(*) FROM information_schema.tables WHERE table_schema='public';\"").strip()
    lines.append(f"DB_TABLES|{tables}")
    lines.append("STATE_END|ok")
    text = "\n".join(lines) + "\n"
    if args.out:
        open(args.out, "w").write(text)
    else:
        sys.stdout.write(text)
    return 0


def cmd_image_refs(args: argparse.Namespace) -> int:
    """component=repository@digest for every image in a rendered compose file or `helm template` output."""
    text = open(args.file, encoding="utf-8").read()
    refs = []
    if args.kind == "compose":
        cur = None
        for line in text.splitlines():
            mm = re.match(r"^  ([a-z0-9-]+):\s*$", line)
            if mm:
                cur = mm.group(1)
            im = re.match(r"^\s+image:\s*\"?([^\"]+)\"?\s*$", line)
            if im and cur:
                refs.append(f"{cur}={im.group(1)}")
    else:
        comp = None
        for line in text.splitlines():
            mm = re.search(r"app\.kubernetes\.io/component:\s*\"?([a-z0-9-]+)\"?", line)
            if mm:
                comp = mm.group(1)
            im = re.match(r"^\s+(?:-\s+)?image:\s*\"?([^\"]+)\"?\s*$", line)
            if im and comp:
                refs.append(f"{comp}={im.group(1)}")
    for r in sorted(set(refs)):
        out(r)
    return 0


# ----------------------------------------------------------------------------------------------
# distribution: authenticated registry (pull plan) and offline / air-gapped image bundle (igib/1)
#
# Both paths resolve the SAME signed release manifest and the SAME digests. Neither has a tag:
#   registry  `pull-plan` lists repository@digest per runtime component (optionally re-homed to a customer mirror:
#             the repository prefix may change, the digest never does); `verify-image-refs` refuses any resolved
#             reference that is a tag, `latest`, another digest, unmanifested or missing.
#   offline   an OCI image layout (+ the signed manifest) whose index.json names each runtime component by digest
#             only (no org.opencontainers.image.ref.name tag); `verify-image-bundle` checks the signature, that the
#             bundled manifest is the release manifest, the index against the manifest, and every blob by sha256.
# ----------------------------------------------------------------------------------------------

IMAGE_BUNDLE_VERSION = "igib/1"
OCI_INDEX_MT = "application/vnd.oci.image.index.v1+json"
INDEX_MTS = {OCI_INDEX_MT, "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_MTS = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
ANN_COMPONENT, ANN_REPOSITORY = "io.intentgate.component", "io.intentgate.repository"
ANN_RELEASE, ANN_MANIFEST_SHA, ANN_BUNDLE = "io.intentgate.release", "io.intentgate.manifest-sha256", "io.intentgate.image-bundle"
ANN_REF_NAME = "org.opencontainers.image.ref.name"
IMAGE_BUNDLE_FILES = {"oci-layout", "index.json", "release-manifest.json", "release-manifest.json.sig"}


def _mirror(mirrors: list[str] | None) -> list[tuple[str, str]]:
    out_ = []
    for x in mirrors or []:
        if "=" not in x:
            raise Refusal(f"MIRROR_FORMAT: {x!r} (SRC_PREFIX=DST_PREFIX)")
        a, b = x.split("=", 1)
        if not REPO_RE.match(b.rstrip("/") + "/x") or MUTABLE_TEXT_RE.search(b) or ":" in b.split("/", 1)[-1] or "@" in b:
            raise Refusal(f"MIRROR_FORMAT: {b!r} is not a bare registry/repository prefix")
        out_.append((a.rstrip("/"), b.rstrip("/")))
    return out_


def _rehome(repo: str, mirrors: list[tuple[str, str]]) -> str:
    for a, b in mirrors:
        if repo == a or repo.startswith(a + "/"):
            return b + repo[len(a):]
    return repo


def pull_plan(m: dict[str, Any], mirrors: list[tuple[str, str]]) -> list[tuple[str, str]]:
    plan, missing = [], []
    for c in runtime_components(m):
        d = c["image"].get("digest")
        if not d:
            missing.append(c["name"])
            continue
        plan.append((c["name"], f"{_rehome(c['image']['repository'], mirrors)}@{d}"))
    if missing:
        raise Refusal(f"NOT_INSTALLABLE: the manifest has no digest for {', '.join(missing)}; there is no tag fallback")
    return plan


def verify_image_refs(m: dict[str, Any], refs: dict[str, str], mirrors: list[tuple[str, str]]) -> list[str]:
    e: list[str] = []
    want = {c["name"]: c for c in runtime_components(m)}
    for comp, ref in sorted(refs.items()):
        if re.search(r"(^|[:/])latest($|@)", ref) or MUTABLE_TEXT_RE.search(ref):
            e.append(f"MUTABLE_REFERENCE: {comp}={ref}")
            continue
        if "@" not in ref:
            e.append(f"TAG_REFERENCE: {comp}={ref} (a tag is never an identity)")
            continue
        repo, dig = ref.split("@", 1)
        if not REPO_RE.match(repo):
            e.append(f"TAG_REFERENCE: {comp}={ref} (a tag in the repository part)")
            continue
        c = want.get(comp)
        if c is None:
            e.append(f"UNMANIFESTED_IMAGE: {comp}={ref}")
            continue
        if dig != c["image"].get("digest"):
            e.append(f"DIGEST_MISMATCH: {comp}: {dig} != manifest {c['image'].get('digest')}")
        if repo not in {c["image"]["repository"], _rehome(c["image"]["repository"], mirrors)}:
            e.append(f"REPOSITORY_MISMATCH: {comp}: {repo} is neither {c['image']['repository']} nor its declared mirror")
    for comp in sorted(set(want) - set(refs)):
        e.append(f"IMAGE_MISSING: {comp}")
    return e


def _blob(layout: str, digest: str) -> str:
    return os.path.join(layout, "blobs", *digest.split(":", 1))


def _walk_blobs(layout: str, desc: dict[str, Any], seen: set[str], e: list[str], where: str) -> None:
    dig = desc.get("digest", "")
    if not DIGEST_RE.match(str(dig)):
        e.append(f"BLOB_DIGEST_FORMAT: {where}: {dig!r}")
        return
    p = _blob(layout, dig)
    if os.path.islink(p) or not os.path.isfile(p):
        e.append(f"BLOB_MISSING: {where}: {dig}")
        return
    data = open(p, "rb").read()
    if "sha256:" + sha256_bytes(data) != dig:
        e.append(f"BLOB_DIGEST_MISMATCH: {where}: content of {dig} does not hash to its name")
        return
    if desc.get("size") is not None and desc["size"] != len(data):
        e.append(f"BLOB_SIZE_MISMATCH: {where}: {dig}")
    if dig in seen:
        return
    seen.add(dig)
    mt = desc.get("mediaType")
    if mt in INDEX_MTS or mt in MANIFEST_MTS:
        try:
            doc = json.loads(data)
        except Exception:
            e.append(f"BLOB_NOT_JSON: {where}: {dig} is declared {mt}")
            return
        if mt in INDEX_MTS:
            for i, ch in enumerate(doc.get("manifests", [])):
                _walk_blobs(layout, ch, seen, e, f"{where}/manifests[{i}]")
        else:
            _walk_blobs(layout, doc.get("config", {}), seen, e, f"{where}/config")
            for i, ly in enumerate(doc.get("layers", [])):
                _walk_blobs(layout, ly, seen, e, f"{where}/layers[{i}]")


def verify_image_layout(m: dict[str, Any], msha: str, layout: str) -> list[str]:
    e: list[str] = []
    files, nested = _walk(layout)
    for n in nested:
        e.append(f"NESTED_REPOSITORY: {n}")
    for f in files:
        full = os.path.join(layout, f)
        if os.path.islink(full):
            e.append(f"SYMLINK_IN_IMAGE_BUNDLE: {f}")
        elif f not in IMAGE_BUNDLE_FILES and not re.match(r"^blobs/sha256/[0-9a-f]{64}$", f.replace(os.sep, "/")):
            e.append(f"FILE_NOT_IN_IMAGE_BUNDLE: {f}")
    try:
        if load_json(os.path.join(layout, "oci-layout")).get("imageLayoutVersion") != "1.0.0":
            e.append("OCI_LAYOUT_VERSION")
        idx_text = open(os.path.join(layout, "index.json"), encoding="utf-8").read()
        idx = json.loads(idx_text)
    except (FileNotFoundError, json.JSONDecodeError) as ex:
        return e + [f"OCI_LAYOUT_INVALID: {ex}"]
    if MUTABLE_TEXT_RE.search(idx_text):
        e.append("MUTABLE_REFERENCE: index.json contains 'latest'")
    if idx.get("schemaVersion") != 2 or idx.get("mediaType") != OCI_INDEX_MT:
        e.append("OCI_INDEX_FORMAT: index.json is not an OCI image index (schemaVersion 2)")
    ann = idx.get("annotations") or {}
    if ann.get(ANN_BUNDLE) != IMAGE_BUNDLE_VERSION:
        e.append(f"IMAGE_BUNDLE_VERSION: {ann.get(ANN_BUNDLE)!r}")
    if ann.get(ANN_RELEASE) != m["release_id"] or ann.get(ANN_MANIFEST_SHA) != msha:
        e.append("IMAGE_BUNDLE_NOT_FOR_THIS_MANIFEST: index annotations name another release or manifest")
    want = {c["name"]: c for c in runtime_components(m)}
    got: dict[str, str] = {}
    seen: set[str] = set()
    for i, d in enumerate(idx.get("manifests", [])):
        a = d.get("annotations") or {}
        comp = a.get(ANN_COMPONENT)
        where = f"index.manifests[{i}]({comp})"
        if ANN_REF_NAME in a:
            e.append(f"TAG_REFERENCE: {where} carries {ANN_REF_NAME}={a[ANN_REF_NAME]!r}; images are identified by digest only")
        if comp in got:
            e.append(f"DUPLICATE_IMAGE: {comp}")
        c = want.get(comp)
        if c is None:
            e.append(f"UNMANIFESTED_IMAGE: {where} {d.get('digest')}")
        else:
            if d.get("digest") != c["image"].get("digest"):
                e.append(f"DIGEST_MISMATCH: {comp}: bundle {d.get('digest')} != manifest {c['image'].get('digest')}")
            if a.get(ANN_REPOSITORY) != c["image"]["repository"]:
                e.append(f"REPOSITORY_MISMATCH: {comp}: bundle names {a.get(ANN_REPOSITORY)!r}")
        if d.get("mediaType") not in INDEX_MTS | MANIFEST_MTS:
            e.append(f"MEDIA_TYPE: {where}: {d.get('mediaType')!r}")
        got[comp] = d.get("digest")
        _walk_blobs(layout, d, seen, e, where)
    for comp, c in sorted(want.items()):
        if not c["image"].get("digest"):
            e.append(f"NOT_INSTALLABLE: {comp}: the manifest has no digest")
        elif comp not in got:
            e.append(f"IMAGE_MISSING: {comp}")
    blob_dir = os.path.join(layout, "blobs", "sha256")
    if os.path.isdir(blob_dir):
        for b in sorted(os.listdir(blob_dir)):
            if "sha256:" + b not in seen:
                e.append(f"BLOB_NOT_REFERENCED: sha256:{b} (stale or foreign content)")
    return e


def _safe_extract(tar_path: str, dest: str) -> None:
    import tarfile
    with tarfile.open(tar_path) as t:
        for mem in t.getmembers():
            n = os.path.normpath(mem.name)
            if n.startswith(("/", "..")) or os.path.isabs(n) or ".." in n.split(os.sep):
                raise Refusal(f"TAR_PATH_ESCAPE: {mem.name}")
            if not (mem.isfile() or mem.isdir()):
                raise Refusal(f"TAR_MEMBER_TYPE: {mem.name} is not a regular file or directory")
        t.extractall(dest, filter="data") if hasattr(tarfile, "data_filter") else t.extractall(dest)


def assemble_image_bundle(m: dict[str, Any], manifest_path: str, sig_path: str | None, sources: dict[str, str], out_dir: str) -> None:
    """Build an igib/1 layout from per-component OCI layouts (e.g. `skopeo copy --all docker://<repo>@<digest> oci:<dir>`).
    The image is selected from each source BY THE MANIFEST DIGEST; a source's tag names are ignored and never copied."""
    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise Refusal(f"REFUSED: {out_dir} is not empty")
    os.makedirs(os.path.join(out_dir, "blobs", "sha256"), exist_ok=True)
    plan = dict(pull_plan(m, []))
    msha = sha256_file(manifest_path)
    descs = []
    for comp in [c["name"] for c in runtime_components(m)]:
        src = sources.get(comp)
        if not src:
            raise Refusal(f"IMAGE_SOURCE_MISSING: {comp}")
        dig = plan[comp].rsplit("@", 1)[1]
        sidx = load_json(os.path.join(src, "index.json"))
        d = next((x for x in sidx.get("manifests", []) if x.get("digest") == dig), None)
        if d is None:
            raise Refusal(f"DIGEST_NOT_IN_SOURCE: {comp}: {src} holds no image {dig} (selection is by digest only)")
        seen: set[str] = set()
        err: list[str] = []
        _walk_blobs(src, d, seen, err, comp)
        if err:
            raise Refusal("; ".join(err))
        for b in seen:
            shutil.copyfile(_blob(src, b), _blob(out_dir, b))
        c = next(x for x in runtime_components(m) if x["name"] == comp)
        descs.append({"mediaType": d["mediaType"], "digest": dig, "size": d.get("size"),
                      "annotations": {ANN_COMPONENT: comp, ANN_REPOSITORY: c["image"]["repository"]}})
    open(os.path.join(out_dir, "oci-layout"), "w").write(json.dumps({"imageLayoutVersion": "1.0.0"}) + "\n")
    idx = {"schemaVersion": 2, "mediaType": OCI_INDEX_MT, "manifests": descs,
           "annotations": {ANN_BUNDLE: IMAGE_BUNDLE_VERSION, ANN_RELEASE: m["release_id"], ANN_MANIFEST_SHA: msha}}
    open(os.path.join(out_dir, "index.json"), "wb").write(canonical_bytes(idx))
    shutil.copyfile(manifest_path, os.path.join(out_dir, "release-manifest.json"))
    if sig_path:
        shutil.copyfile(sig_path, os.path.join(out_dir, "release-manifest.json.sig"))


def write_deterministic_tar(src_dir: str, tar_path: str) -> None:
    import tarfile
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as t:
        for f in _walk(src_dir)[0]:
            ti = t.gettarinfo(os.path.join(src_dir, f), arcname=f.replace(os.sep, "/"))
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = 0, 0, 0, "", "", 0o644
            with open(os.path.join(src_dir, f), "rb") as fh:
                t.addfile(ti, fh)


def cmd_pull_plan(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m)
    if errs:
        raise Refusal("refusing an invalid manifest: " + "; ".join(errs))
    for comp, ref in pull_plan(m, _mirror(args.mirror)):
        out(f"{comp}={ref}")
    return 0


def cmd_verify_image_refs(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m)
    refs: dict[str, str] = {}
    for line in open(args.refs, encoding="utf-8").read().split():
        if "=" not in line:
            errs.append(f"REF_FORMAT: {line!r}")
            continue
        k, v = line.split("=", 1)
        if k in refs and refs[k] != v:
            errs.append(f"CONFLICTING_REFS: {k}")
        refs[k] = v
    errs += verify_image_refs(m, refs, _mirror(args.mirror))
    for x in errs:
        out(f"FAIL {x}")
    out(f"IMAGE_REFS={'PASS' if not errs else 'FAIL'} refs={len(refs)}")
    return 0 if not errs else 1


def cmd_assemble_image_bundle(args: argparse.Namespace) -> int:
    m = load_json(args.manifest)
    errs = lint_manifest(m)
    if errs:
        raise Refusal("refusing an invalid manifest: " + "; ".join(errs))
    sources = {}
    for x in args.source or []:
        k, _, v = x.partition("=")
        sources[k] = v
    assemble_image_bundle(m, args.manifest, args.sig, sources, args.out_dir)
    e = verify_image_layout(m, sha256_file(args.manifest), args.out_dir)
    if e:
        raise Refusal("assembled bundle does not verify: " + "; ".join(e))
    if args.tar:
        write_deterministic_tar(args.out_dir, args.tar)
        out(f"IMAGE_BUNDLE_TAR {args.tar} sha256={sha256_file(args.tar)}")
    out(f"IMAGE_BUNDLE_ASSEMBLED {args.out_dir} images={len(runtime_components(m))}")
    return 0


def cmd_verify_image_bundle(args: argparse.Namespace) -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        layout = args.bundle
        if os.path.isfile(args.bundle):
            _safe_extract(args.bundle, td)
            layout = td
        mp = os.path.join(layout, "release-manifest.json")
        if not os.path.isfile(mp):
            raise Refusal("IMAGE_BUNDLE_NO_MANIFEST: the bundle carries no release-manifest.json")
        data = open(mp, "rb").read()
        kid = verify_detached(data, os.path.join(layout, "release-manifest.json.sig"), args.key_set, args.trust_anchor,
                              args.test_public_key, args.allow_test_key, args.pinned_fingerprint)
        out(f"SIGNATURE=VERIFIED key={kid}")
        errs: list[str] = []
        if args.manifest and open(args.manifest, "rb").read() != data:
            errs.append("MANIFEST_NOT_THE_RELEASE_MANIFEST: the bundled manifest is not byte-identical to the release manifest")
        m = json.loads(data)
        errs += lint_manifest(m)
        errs += verify_image_layout(m, sha256_bytes(data), layout)
        for x in errs:
            out(f"FAIL {x}")
        out(f"IMAGE_BUNDLE={'PASS' if not errs else 'FAIL'} {m.get('release_id')} images={len(runtime_components(m))}")
        return 0 if not errs else 1


# ----------------------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("build")
    b.add_argument("--inputs", required=True)
    b.add_argument("--contract", required=True)
    b.add_argument("--bundle-files", required=True)
    b.add_argument("--bundle-root", required=True)
    b.add_argument("--key-set")
    b.add_argument("--trust-anchor")
    b.add_argument("--out", required=True)
    x = sp.add_parser("lint")
    x.add_argument("--manifest", required=True)
    s = sp.add_parser("sign")
    s.add_argument("--manifest", required=True)
    s.add_argument("--test-private-key", required=True)
    s.add_argument("--sig-out", required=True)

    def sigargs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--sig")
        p.add_argument("--key-set")
        p.add_argument("--trust-anchor")
        p.add_argument("--test-public-key")
        p.add_argument("--allow-test-key", action="store_true")
        p.add_argument("--pinned-fingerprint", action="append",
                       help="SPKI sha256 of a trusted release key, obtained OUT OF BAND (repeatable); replaces --trust-anchor")

    v = sp.add_parser("verify")
    v.add_argument("--manifest", required=True)
    sigargs(v)
    v.add_argument("--require-releasable", action="store_true")
    vb = sp.add_parser("verify-bundle")
    vb.add_argument("--manifest", required=True)
    vb.add_argument("--bundle-dir", required=True)
    vb.add_argument("--contract")
    vi = sp.add_parser("verify-install")
    vi.add_argument("--manifest", required=True)
    vi.add_argument("--facts", required=True)
    vi.add_argument("--contract")
    sigargs(vi)
    for name in ("render-compose", "render-helm-values"):
        r = sp.add_parser(name)
        r.add_argument("--manifest", required=True)
        r.add_argument("--contract", required=True)
        r.add_argument("--out")
        r.add_argument("--check", help="compare with this file instead of writing (exit 1 on drift)")
    re_ = sp.add_parser("render-env-example")
    re_.add_argument("--contract", required=True)
    re_.add_argument("--out")
    re_.add_argument("--check")
    cg = sp.add_parser("config-generate")
    cg.add_argument("--contract", required=True)
    cg.add_argument("--env", required=True)
    cv = sp.add_parser("config-validate")
    cv.add_argument("--contract", required=True)
    cv.add_argument("--env", required=True)
    cv.add_argument("--scope", choices=["compose", "helm"], default="compose")
    cv.add_argument("--facts-out")
    cf = sp.add_parser("collect-facts")
    cf.add_argument("--manifest", required=True)
    cf.add_argument("--form", choices=["compose", "helm"], required=True)
    cf.add_argument("--project", default="intentgate")
    cf.add_argument("--namespace", default="intentgate")
    cf.add_argument("--install-dir")
    cf.add_argument("--contract")
    cf.add_argument("--config-facts")
    cf.add_argument("--out", required=True)
    cs = sp.add_parser("capture-state")
    cs.add_argument("--form", choices=["compose", "helm"], required=True)
    cs.add_argument("--project", default="intentgate")
    cs.add_argument("--namespace", default="intentgate")
    cs.add_argument("--install-dir")
    cs.add_argument("--out")
    g = sp.add_parser("guard-release-input")
    g.add_argument("--root", required=True)
    g.add_argument("--bundle-files")
    g.add_argument("--exclude", action="append")
    pp = sp.add_parser("pull-plan")
    pp.add_argument("--manifest", required=True)
    pp.add_argument("--mirror", action="append", help="SRC_PREFIX=DST_PREFIX: re-home repositories to a customer mirror (digest unchanged)")
    vr = sp.add_parser("verify-image-refs")
    vr.add_argument("--manifest", required=True)
    vr.add_argument("--refs", required=True, help="component=repository@digest lines (image-refs output, or a registry resolution)")
    vr.add_argument("--mirror", action="append")
    ab = sp.add_parser("assemble-image-bundle")
    ab.add_argument("--manifest", required=True)
    ab.add_argument("--sig")
    ab.add_argument("--source", action="append", help="component=<OCI image layout dir holding that component's digest>")
    ab.add_argument("--out-dir", required=True)
    ab.add_argument("--tar")
    vib = sp.add_parser("verify-image-bundle")
    vib.add_argument("--bundle", required=True, help="igib/1 OCI layout directory or tarball")
    vib.add_argument("--manifest", help="the release manifest the bundle must carry byte-identically")
    sigargs(vib)
    ir = sp.add_parser("image-refs")
    ir.add_argument("--kind", choices=["compose", "helm"], required=True)
    ir.add_argument("--file", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            return build(a)
        if a.cmd == "lint":
            return cmd_lint(a)
        if a.cmd == "sign":
            sign_test(a.manifest, a.test_private_key, a.sig_out)
            out(f"SIGNED (TEST KEY ONLY) {a.sig_out}")
            return 0
        if a.cmd == "verify":
            return cmd_verify(a)
        if a.cmd == "verify-bundle":
            return cmd_verify_bundle(a)
        if a.cmd == "verify-install":
            return cmd_verify_install(a)
        if a.cmd == "render-compose":
            return cmd_render(a, "compose")
        if a.cmd == "render-helm-values":
            return cmd_render(a, "helm")
        if a.cmd == "render-env-example":
            return cmd_render_env(a)
        if a.cmd == "config-generate":
            return cmd_config_generate(a)
        if a.cmd == "config-validate":
            return cmd_config_validate(a)
        if a.cmd == "collect-facts":
            return cmd_collect_facts(a)
        if a.cmd == "capture-state":
            return cmd_capture_state(a)
        if a.cmd == "guard-release-input":
            return cmd_guard(a)
        if a.cmd == "image-refs":
            return cmd_image_refs(a)
        if a.cmd == "pull-plan":
            return cmd_pull_plan(a)
        if a.cmd == "verify-image-refs":
            return cmd_verify_image_refs(a)
        if a.cmd == "assemble-image-bundle":
            return cmd_assemble_image_bundle(a)
        if a.cmd == "verify-image-bundle":
            return cmd_verify_image_bundle(a)
    except Refusal as r:
        out(f"FAIL {r}")
        return 1
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as ex:
        out(f"ERROR {type(ex).__name__}: {ex}")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
