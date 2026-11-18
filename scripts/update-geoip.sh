#!/usr/bin/env bash
# Install/refresh the DB-IP Lite City + ASN databases (CC BY 4.0, no licence key) into the data dir.
#   update-geoip.sh --python <venv python> [--package <release dir with bundled geoip/*.mmdb.gz>]
# Prints one summary line on stdout. Exit 0 on success, 1 on failure (existing files are kept on failure).
# DB-IP does not publish checksums; downloads are verified by gzip integrity + opening them with the
# MaxMind reader and looking up a known address, before atomically replacing the old files.
set -euo pipefail
DEST="/var/lib/global-threat-intel/geoip"; PY=""; PKG=""
while (($#)); do case "$1" in --python) PY="$2"; shift ;; --package) PKG="$2"; shift ;; --dest) DEST="$2"; shift ;; *) echo "bad option $1" >&2; exit 2 ;; esac; shift; done
[[ -x "$PY" ]] || { echo "python not found"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
install -d -m 0750 "$DEST"

fetch() {   # fetch kind -> sets FILE
  local kind="$1" m f
  FILE=""
  if [[ -n "$PKG" ]] && f="$(ls -1 "$PKG"/geoip/dbip-"$kind"-lite-*.mmdb.gz 2>/dev/null | sort | tail -1)" && [[ -n "$f" ]]; then
    cp "$f" "$TMP/"; FILE="$TMP/$(basename "$f")"; SRC="bundled"; return 0
  fi
  for m in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do
    f="dbip-$kind-lite-$m.mmdb.gz"
    if curl -fsSL --max-time 300 --retry 2 --proto =https -o "$TMP/$f" "https://download.db-ip.com/free/$f"; then
      FILE="$TMP/$f"; SRC="download.db-ip.com"; return 0
    fi
  done
  return 1
}

for kind in city asn; do
  fetch "$kind" || { echo "download of DB-IP $kind database failed (no internet?)"; exit 1; }
  gzip -t "$FILE" || { echo "corrupt archive $(basename "$FILE")"; exit 1; }
  out="$TMP/$(basename "${FILE%.gz}")"
  gzip -dc "$FILE" >"$out"
  "$PY" -I - "$out" "$kind" <<'PY' || { echo "verification of $(basename "$out") failed"; exit 1; }
import sys, maxminddb
path, kind = sys.argv[1], sys.argv[2]
r = maxminddb.open_database(path).get("8.8.8.8") or {}
ok = (r.get("country", {}).get("iso_code") is not None) if kind == "city" else (r.get("autonomous_system_number") == 15169)
sys.exit(0 if ok else 1)
PY
  chmod 0644 "$out"
  # atomic replace, then remove older months of the same kind
  mv -f "$out" "$DEST/$(basename "$out")"
  find "$DEST" -maxdepth 1 -name "dbip-$kind-lite-*.mmdb" ! -name "$(basename "$out")" -delete
  NAMES+=("$(basename "$out")")
done
chown -R gti:gti "$DEST" 2>/dev/null || true
echo "${NAMES[*]} (${SRC})"
