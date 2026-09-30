#!/usr/bin/env bash
# assemble-bundle.sh — assemble the release bundle from TRACKED release inputs only.
#
#   release/assemble-bundle.sh <install-repo-root> <helm-chart-dir> <out-dir> [manifest.json [manifest.json.sig]]
#
# 1. Copies exactly the static files listed in release/bundle-files.json (install files from the
#    install checkout, chart files from the helm checkout at release/HELM_CHART_REF). A listed file
#    that is not tracked and clean in its repository is refused: untracked or stale content never
#    reaches a bundle.
# 2. Without a manifest argument it stops there (the caller builds the manifest over <out-dir>).
#    With one, it copies manifest (+ detached signature), renders docker-compose.yml, .env.example and
#    helm/intentgate/values.release.yaml FROM THE MANIFEST, verifies the bundle and writes CHECKSUMS.
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: $0 <install-root> <helm-chart-dir> <out-dir> [manifest.json [manifest.json.sig]]" >&2; exit 2; }
ROOT=$(cd "$1" && pwd); CHART=$(cd "$2" && pwd); OUT=$3; MAN=${4:-}; SIG=${5:-}
TOOL="$ROOT/release/release-manifest.py"
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
[ -z "$(ls -A "$OUT")" ] || [ -n "$MAN" ] || { echo "REFUSED: $OUT is not empty" >&2; exit 1; }

tracked_clean() {  # <repo-dir> <path-in-repo>
  git -C "$1" ls-files --error-unmatch -- "$2" >/dev/null 2>&1 || { echo "REFUSED: $2 is not tracked in $1" >&2; exit 1; }
  git -C "$1" diff --quiet HEAD -- "$2" || { echo "REFUSED: $2 has uncommitted changes in $1" >&2; exit 1; }
}

python3 - "$ROOT/release/bundle-files.json" <<'PY' > "$OUT/.static-list"
import json, sys
for p in json.load(open(sys.argv[1]))["static"]:
    print(p)
PY
while IFS= read -r rel; do
  case "$rel" in
    helm/intentgate/*) src_repo="$CHART"; src="${rel#helm/intentgate/}";;
    *)                 src_repo="$ROOT";  src="$rel";;
  esac
  tracked_clean "$src_repo" "$src"
  mkdir -p "$OUT/$(dirname "$rel")"
  cp -p "$src_repo/$src" "$OUT/$rel"
done < "$OUT/.static-list"
rm -f "$OUT/.static-list"
echo "ASSEMBLED static files into $OUT"

[ -n "$MAN" ] || exit 0
cp "$MAN" "$OUT/release-manifest.json"
[ -n "$SIG" ] && cp "$SIG" "$OUT/release-manifest.json.sig"
C="$OUT/release/config-contract.json"
python3 "$TOOL" render-compose     --manifest "$OUT/release-manifest.json" --contract "$C" --out "$OUT/docker-compose.yml"
python3 "$TOOL" render-env-example --contract "$C" --out "$OUT/.env.example"
python3 "$TOOL" render-helm-values --manifest "$OUT/release-manifest.json" --contract "$C" --out "$OUT/helm/intentgate/values.release.yaml"
python3 "$TOOL" verify-bundle --manifest "$OUT/release-manifest.json" --bundle-dir "$OUT"
SUMS=$(mktemp)
( cd "$OUT" && find . -type f ! -name CHECKSUMS -print0 | sort -z | xargs -0 sha256sum ) > "$SUMS"
mv "$SUMS" "$OUT/CHECKSUMS"
echo "BUNDLE_READY $OUT"
