#!/usr/bin/env bash
# Update to a new release:
#   sudo ./update.sh                         this package's version (run from the extracted new release)
#   sudo ./update.sh <release.tar.gz>        a downloaded release archive (verified with its .sha256 file)
#   sudo ./update.sh --check                 check GTI_UPDATE_URL (in gti.env) for a newer release
#   sudo ./update.sh --url <manifest.json>   download, verify and apply the release a manifest points to
# Always: backs up database + config, installs side by side, migrates, health-checks, rolls back on failure.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$HERE/scripts/lib.sh"
require_root
MODE=self; ARCHIVE=""; MANIFEST=""; YES=0
while (($#)); do
  case "$1" in
    --check) MODE=check ;;
    --url) MODE=url; MANIFEST="${2:?}"; shift ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "Unknown option $1" ;;
    *) MODE=archive; ARCHIVE="$1" ;;
  esac; shift
done
[[ -L "$CURRENT" ]] || die "No existing installation found. Use install.sh for a first install."
install -d -m 0750 "$LOG_DIR"
LOG_FILE="$LOG_DIR/update-$(date +%Y%m%d-%H%M%S).log"; : >"$LOG_FILE"; chmod 0640 "$LOG_FILE"
acquire_lock
OLD_REL="$(readlink -f "$CURRENT")"; OLD_VER="$(pkg_version "$OLD_REL")"
WORK="$(mktemp -d /var/tmp/gti-update.XXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

verify_archive() {   # verify_archive FILE [EXPECTED_SHA256]
  local f="$1" want="${2:-}"
  if [[ -z "$want" && -f "$f.sha256" ]]; then want="$(awk '{print $1}' "$f.sha256")"; fi
  [[ -n "$want" ]] || die "No checksum for $f (expected $f.sha256). Refusing an unverified update."
  local got; got="$(sha256sum "$f" | awk '{print $1}')"
  [[ "$got" == "$want" ]] || die "Checksum mismatch for $f: expected $want, got $got."
  log "checksum ok $got"
}

fetch_manifest() {   # sets M_VER M_URL M_SHA
  local url="$1" py; py="$OLD_REL/venv/bin/python"
  curl -fsSL --max-time 30 --proto =https -o "$WORK/manifest.json" "$url" || die "Could not download manifest $url"
  read -r M_VER M_URL M_SHA < <("$py" -I -c '
import json, re, sys
m = json.load(open(sys.argv[1]))
v, u, s = m["version"], m["url"], m["sha256"]
assert re.fullmatch(r"\d+\.\d+\.\d+", v) and u.startswith("https://") and re.fullmatch(r"[0-9a-f]{64}", s)
print(v, u, s)' "$WORK/manifest.json") || die "Manifest is malformed (needs version, https url, sha256)."
}

newer() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" && "$1" != "$2" ]]; }

case "$MODE" in
  check)
    url="$(conf_get GTI_UPDATE_URL)"
    [[ -n "$url" ]] || die "GTI_UPDATE_URL is not set in $CONF_FILE. Download a release and run: sudo ./update.sh <release.tar.gz>"
    fetch_manifest "$url"
    if newer "$M_VER" "$OLD_VER"; then echo "Update available: v$OLD_VER -> v$M_VER   (apply: sudo gti update --url $url)"; exit 0
    else echo "Up to date (v$OLD_VER)."; exit 0; fi ;;
  url)
    fetch_manifest "$MANIFEST"
    newer "$M_VER" "$OLD_VER" || { echo "Installed v$OLD_VER is not older than v$M_VER. Nothing to do."; exit 0; }
    curl -fSL --max-time 600 --proto =https -o "$WORK/release.tar.gz" "$M_URL" >>"$LOG_FILE" 2>&1 || die "Download failed: $M_URL"
    verify_archive "$WORK/release.tar.gz" "$M_SHA"
    ARCHIVE="$WORK/release.tar.gz" ;;
  archive)
    [[ -f "$ARCHIVE" ]] || die "No such file: $ARCHIVE"
    verify_archive "$ARCHIVE" ;;
esac

if [[ -n "$ARCHIVE" ]]; then
  mkdir -p "$WORK/pkg"
  # refuse archives with absolute paths or '..' before extracting anything
  if tar -tzf "$ARCHIVE" | grep -qE '(^/|(^|/)\.\.(/|$))'; then die "Archive contains unsafe paths."; fi
  tar -xzf "$ARCHIVE" -C "$WORK/pkg" --no-same-owner
  PKG="$(dirname "$(find "$WORK/pkg" -maxdepth 2 -name VERSION -type f | head -1)")"
  [[ -f "$PKG/VERSION" && -f "$PKG/scripts/lib.sh" ]] || die "Archive is not a Global Threat Intel release."
  # hand over to the NEW release's own update.sh so its logic (and migrations) are the ones used
  if [[ "$PKG" != "$HERE" ]]; then
    trap - EXIT
    exec 9>&-   # release lock; the new script takes it again
    args=(); ((YES)) && args+=(--yes)
    "$PKG/update.sh" "${args[@]}"; rc=$?
    rm -rf "$WORK"; exit $rc
  fi
fi

# ---------------- apply THIS package ($HERE) ----------------
NEW_VER="$(pkg_version "$HERE")"
STEP_TOTAL=8
printf '\n%sUpdating %s: v%s -> v%s%s\n\n' "$C_B" "$APP_TITLE" "$OLD_VER" "$NEW_VER" "$C_0"
if [[ "$NEW_VER" == "$OLD_VER" ]]; then
  echo "v$NEW_VER is already installed. To reinstall the application files use: sudo ./install.sh --repair"; exit 0
elif ! newer "$NEW_VER" "$OLD_VER"; then
  die "v$NEW_VER is older than the installed v$OLD_VER. Downgrades are not supported (restore a backup instead)."
fi

BACKUP=""; SWITCHED=0; PORT="$(conf_get GTI_PORT 8080)"
rollback() {
  local rc=$?
  trap - ERR; DIE_HOOK=""
  printf '\n%sUpdate failed at step %s: %s%s\n' "$C_ERR" "$STEP_NO" "$STEP_NAME" "$C_0" >&2
  log "FAILED step $STEP_NO ($STEP_NAME) rc=$rc; rolling back"
  if ((SWITCHED)); then
    systemctl stop "$SERVICE" >>"$LOG_FILE" 2>&1 || true
    switch_current "$OLD_REL"
    if [[ -n "$BACKUP" ]]; then
      local st; st="$(mktemp -d "$DATA_DIR/.rb.XXXX")"
      if ADMIN_RELEASE="$OLD_REL" admin_root verify-backup "$BACKUP" --extract-to "$st" >>"$LOG_FILE" 2>&1; then
        rm -f "$DATA_DIR/gti.db-wal" "$DATA_DIR/gti.db-shm"
        install -m 0600 -o "$SVC_USER" -g "$SVC_USER" "$st/gti.db" "$DATA_DIR/gti.db"
      fi
      rm -rf "$st"
    fi
    # the failed version may have exhausted systemd's restart allowance: clear it first
    start_service start >>"$LOG_FILE" 2>&1 || true
    if wait_healthy "$PORT" 60; then echo "Rolled back to v$OLD_VER; it is running and healthy." >&2
    else echo "Rolled back to v$OLD_VER but it is not healthy. Check: journalctl -u $SERVICE" >&2; fi
  else
    echo "The running version (v$OLD_VER) was not touched." >&2
  fi
  rm -rf "${RELEASES:?}/${NEW_VER:?}" "${RELEASES:?}"/.*.staging 2>/dev/null || true
  echo "Pre-update backup: ${BACKUP:-none}. Log: $LOG_FILE" >&2
  exit 1
}
trap rollback ERR
DIE_HOOK=rollback
trap 'printf "\nInterrupted.\n" >&2; rollback' INT TERM

step "Checking system compatibility"
detect_platform; check_platform
python_bin >/dev/null || die "Python 3.${MIN_PY_MINOR}-3.${MAX_PY_MINOR} required."
free_mb=$(df -Pm /opt | awk 'NR==2{print $4}'); ((free_mb > 600)) || die "Only ${free_mb} MB free on /opt."
step_ok "$OS_NAME, $DPKG_ARCH"

step "Backing up database and configuration"
BACKUP="$(make_backup pre-update)" || die "Backup failed; update aborted before any change."
ADMIN_RELEASE="$OLD_REL" admin_root verify-backup "$BACKUP" >>"$LOG_FILE" 2>&1 || die "Backup verification failed; update aborted."
step_ok "$BACKUP"

step "Installing new release side by side"
NEW_REL="$(install_release "$HERE")"
step_ok "$NEW_REL"

step "Stopping service"
run systemctl stop "$SERVICE"
step_ok

step "Applying database migrations"
SWITCHED=1
switch_current "$NEW_REL"
ADMIN_RELEASE="$NEW_REL" admin migrate >>"$LOG_FILE" 2>&1 || die "Migration failed."
step_ok "$(ADMIN_RELEASE="$NEW_REL" admin_root version)"

step "Updating services"
PROFILE="unchanged"; install_units "$NEW_REL" "512M"
step_ok

step "Starting and health-checking"
run start_service start || die "Service failed to start."
wait_healthy "$PORT" 90 || die "New version did not become healthy (crashed or no response within 90 s)."
ADMIN_RELEASE="$NEW_REL" admin health-db >>"$LOG_FILE" 2>&1 || die "Database health check failed."
step_ok

step "Cleaning up"
trap - ERR INT TERM; DIE_HOOK=""
# keep the new release and the one before it (manual rollback: point 'current' back and restore the backup)
mapfile -t old < <(ls -1dt "$RELEASES"/*/ 2>/dev/null | sed 's:/$::' | grep -vxF "$NEW_REL" | grep -vxF "$OLD_REL" || true)
for d in "${old[@]}"; do rm -rf "$d"; done
step_ok "previous release kept: $OLD_REL"
printf '\n%sUpdated to v%s.%s  Backup taken before the update: %s\n' "$C_OK" "$NEW_VER" "$C_0" "$BACKUP"
print_warnings
