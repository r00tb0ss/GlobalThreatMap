#!/usr/bin/env bash
# Build release archives (run on Linux from the source tree):
#   scripts/build-release.sh            -> dist/global-threat-intel-<v>.tar.gz          (online installer)
#                                          dist/global-threat-intel-<v>-offline.tar.gz  (bundled wheels + GeoIP)
#                                          dist/SHA256SUMS and a .sha256 next to each archive
# The offline bundle contains CPython 3.11-3.13 wheels for x86_64 and aarch64, so it installs with no
# internet access on Ubuntu 24.04+ (amd64/arm64) and Raspberry Pi OS 64-bit.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="$(tr -d ' \r\n' <"$SRC/VERSION")"
NAME="global-threat-intel-$VER"
OUT="$SRC/dist"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

stage() {   # stage DIR : copy the distributable tree
  local d="$1"
  mkdir -p "$d"
  ( cd "$SRC" && tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' -cf - \
      VERSION README.md install.sh update.sh uninstall.sh backup.sh restore.sh health-check.sh \
      backend frontend requirements services config scripts docs ) | tar -xf - -C "$d"
  # normalise: LF line endings for text, correct modes (sources may come from Windows)
  find "$d" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.service' -o -name '*.timer' -o -name '*.md' \
       -o -name '*.template' -o -name '*.lock' -o -name '*.in' -o -name 'gti' -o -name 'VERSION' -o -name '*.js' \
       -o -name '*.css' -o -name '*.html' \) -exec sed -i 's/\r$//' {} +
  find "$d" -type d -exec chmod 0755 {} +
  find "$d" -type f -exec chmod 0644 {} +
  chmod 0755 "$d"/*.sh "$d"/scripts/*.sh "$d"/scripts/gti
}

echo "== online package"
stage "$WORK/$NAME"
tar --owner=0 --group=0 --numeric-owner --sort=name -czf "$OUT/$NAME.tar.gz" -C "$WORK" "$NAME"

echo "== offline package"
# exactly the locked, hash-verified wheels for every supported Python/arch (never re-resolved)
for py in 311 312 313; do
  for arch in x86_64 aarch64; do
    "$PY" -m pip download -q --disable-pip-version-check --require-hashes --only-binary=:all: --no-deps \
      --platform "manylinux2014_$arch" --python-version "$py" --implementation cp \
      -r "$SRC/requirements/requirements.lock" -d "$WORK/$NAME/wheels/cp$py-$arch"
  done
done
mkdir -p "$WORK/$NAME/geoip"
cp "$SRC"/geoip/dbip-*-lite-*.mmdb.gz "$WORK/$NAME/geoip/" 2>/dev/null || echo "   (no GeoIP files in $SRC/geoip; offline bundle will download them at install)"
find "$WORK/$NAME/wheels" "$WORK/$NAME/geoip" -type f -exec chmod 0644 {} +
tar --owner=0 --group=0 --numeric-owner --sort=name -czf "$OUT/$NAME-offline.tar.gz" -C "$WORK" "$NAME"

cd "$OUT"
for f in "$NAME.tar.gz" "$NAME-offline.tar.gz"; do sha256sum "$f" >"$f.sha256"; done
sha256sum "$NAME.tar.gz" "$NAME-offline.tar.gz" >SHA256SUMS
ls -l "$OUT"
cat SHA256SUMS
