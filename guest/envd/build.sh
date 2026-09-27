#!/usr/bin/env bash
# Reproducible static build of E2B's envd from the Go module proxy.
#
# Usage: guest/envd/build.sh [OUT_DIR]      (default: dist/guest)
#
# The build is bit-for-bit reproducible; the result is checked against the
# pinned hash in guest/envd/VERSION. Set ENVD_SKIP_HASH_CHECK=1 only when
# deliberately bumping the pinned revision.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
source <(grep -E '^[A-Z0-9_]+=' "$HERE/VERSION")
OUT_DIR="${1:-$ROOT/dist/guest}"
GOARCH="${GOARCH:-amd64}"
PROXY="${GOPROXY_URL:-https://proxy.golang.org}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/zip" "$WORK/src/packages" "$OUT_DIR"

# envd's go.mod replaces packages/shared with ../shared, so both modules are
# unpacked side by side at the same revision.
for m in envd shared; do
  curl -fsSL -o "$WORK/zip/$m.zip" \
    "$PROXY/github.com/e2b-dev/infra/packages/$m/@v/$ENVD_MODULE_VERSION.zip"
  (cd "$WORK/zip" && unzip -q "$m.zip")
  mv "$WORK/zip/github.com/e2b-dev/infra/packages/$m@$ENVD_MODULE_VERSION" "$WORK/src/packages/$m"
done
chmod -R u+w "$WORK/src"

COMMIT_SHORT="${ENVD_MODULE_VERSION##*-}"
COMMIT_SHORT="${COMMIT_SHORT:0:7}"
(
  cd "$WORK/src/packages/envd"
  # go.mod requires a newer Go than some hosts have; GOTOOLCHAIN=auto fetches
  # it from the module proxy and verifies it against sum.golang.org.
  GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
    go build -trimpath -buildvcs=false \
    -ldflags "-X=main.commitSHA=${COMMIT_SHORT} -s -w -buildid=" \
    -o "$OUT_DIR/envd" .
  cp LICENSE "$OUT_DIR/envd.LICENSE"
)

actual="$(sha256sum "$OUT_DIR/envd" | cut -d' ' -f1)"
if [[ "$GOARCH" == "amd64" && "${ENVD_SKIP_HASH_CHECK:-0}" != "1" && "$actual" != "$ENVD_SHA256_AMD64" ]]; then
  echo "envd hash mismatch: got $actual, pinned $ENVD_SHA256_AMD64" >&2
  exit 1
fi
version="$("$OUT_DIR/envd" -version)"
if [[ "$version" != "$ENVD_VERSION" ]]; then
  echo "envd reports version $version, expected $ENVD_VERSION" >&2
  exit 1
fi
echo "envd $version ($actual) -> $OUT_DIR/envd"
