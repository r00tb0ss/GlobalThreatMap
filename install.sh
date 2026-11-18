#!/usr/bin/env bash
# Global Threat Intelligence Platform - installer
#   sudo ./install.sh [--port N] [--local-only] [--offline] [--force] [--yes] [--repair]
# Supported: Ubuntu Server 24.04+ (x86-64, ARM64), Raspberry Pi OS 64-bit (bookworm+) on Pi 4 / Pi 5.
set -Eeuo pipefail
PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$PKG_DIR/scripts/lib.sh"

PORT=8080; HOST=0.0.0.0; OFFLINE=0; FORCE=0; REPAIR=0
usage() { sed -n '2,4p' "$0" | sed 's/^# \{0,1\}//'; cat <<EOF

Options:
  --port N        dashboard port (default 8080)
  --local-only    bind to 127.0.0.1 only (no LAN access)
  --offline       install only from files in this package (no internet needed)
  --force         continue on untested OS / low memory
  --yes           do not ask questions (non-interactive)
  --repair        reinstall the application files of an existing install of the same version
EOF
}
while (($#)); do
  case "$1" in
    --port) PORT="${2:?}"; shift ;;
    --local-only) HOST=127.0.0.1 ;;
    --offline) OFFLINE=1 ;;
    --force) FORCE=1 ;;
    --yes|-y) ;;   # accepted for scripting; the installer never prompts
    --repair) REPAIR=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "Unknown option: $1" ;;
  esac; shift
done
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1024 && PORT <= 65535)) || die "--port must be 1024-65535 (unprivileged)."
[[ -d "$PKG_DIR/wheels" ]] && OFFLINE_CAPABLE=1 || OFFLINE_CAPABLE=0

require_root
install -d -m 0750 "$LOG_DIR"
LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
: >"$LOG_FILE"; chmod 0640 "$LOG_FILE"
acquire_lock
VERSION="$(pkg_version "$PKG_DIR")"

# ---- rollback bookkeeping: only undo what THIS run created ----
CREATED_USER=0; CREATED_CONF=0; CREATED_DATA=0; CREATED_RELEASE=""; PREV_CURRENT=""; UNITS_INSTALLED=0; FRESH=1
on_error() {
  local rc=$?
  trap - ERR; DIE_HOOK=""
  printf '\n%sInstallation failed at step %s: %s%s\n' "$C_ERR" "$STEP_NO" "$STEP_NAME" "$C_0" >&2
  log "FAILED at step $STEP_NO ($STEP_NAME) rc=$rc"
  printf 'Rolling back changes made by this run...\n' >&2
  if ((FRESH)); then
    systemctl disable --now "${UNITS[@]}" >>"$LOG_FILE" 2>&1 || true
    if ((UNITS_INSTALLED)); then
      for u in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$u"; done
      rm -rf "/etc/systemd/system/${SERVICE}.d"; rm -f "$CLI"; systemctl daemon-reload || true
    fi
  elif [[ -n "$PREV_CURRENT" ]]; then
    switch_current "$PREV_CURRENT" || true
    systemctl restart "$SERVICE" >>"$LOG_FILE" 2>&1 || true
  fi
  [[ -n "$CREATED_RELEASE" && "$(readlink -f "$CURRENT" 2>/dev/null)" != "$CREATED_RELEASE" ]] && rm -rf "$CREATED_RELEASE"
  rm -rf "$RELEASES"/.*.staging 2>/dev/null || true
  ((CREATED_CONF)) && rm -f "$CONF_FILE" && rmdir "$CONF_DIR" 2>/dev/null
  ((CREATED_DATA)) && rm -rf "$DATA_DIR"
  ((CREATED_USER)) && userdel "$SVC_USER" >>"$LOG_FILE" 2>&1
  ((FRESH)) && { rmdir "$RELEASES" "$PREFIX" 2>/dev/null || true; }
  printf 'Nothing that existed before this run was removed. Full log: %s\n' "$LOG_FILE" >&2
  printf 'Fix the problem above and run the installer again; it is safe to re-run.\n' >&2
  exit 1
}
trap on_error ERR
DIE_HOOK=on_error
trap 'printf "\nInterrupted.\n" >&2; on_error' INT TERM

STEP_TOTAL=13
printf '\n%s%s Installer%s  v%s\n\n' "$C_B" "$APP_TITLE" "$C_0" "$VERSION"

# 1 ---------------------------------------------------------------------------
step "Detecting operating system"
detect_platform
check_platform
step_ok "$OS_NAME"

# 2 ---------------------------------------------------------------------------
step "Checking hardware"
choose_profile
hw="${KARCH}, ${MEM_MB} MB RAM, profile ${PROFILE}"
[[ -n "$PI_MODEL" ]] && hw="${PI_MODEL}, ${hw}"
if [[ -n "$PI_MODEL" && "$PI_MODEL" != *"Pi 4"* && "$PI_MODEL" != *"Pi 5"* && "$PI_MODEL" != *"Compute Module 4"* && "$PI_MODEL" != *"Compute Module 5"* ]]; then
  ((FORCE)) || die "$PI_MODEL is not supported (Raspberry Pi 4 or 5 required). Use --force to try anyway."
  warn "$PI_MODEL is not a supported Raspberry Pi model."
fi
if ((MEM_MB < 3500)); then step_warn "$hw - below the 4 GB recommendation; ingestion limits reduced"; else step_ok "$hw"; fi

# 3 ---------------------------------------------------------------------------
step "Checking storage"
need_mb=1500
for d in /opt /var; do
  free_mb=$(df -Pm "$d" | awk 'NR==2{print $4}')
  ((free_mb >= need_mb)) || die "Only ${free_mb} MB free on $d; at least ${need_mb} MB is required (4 GB+ recommended)."
done
free_var=$(df -Pm /var | awk 'NR==2{print $4}')
if [[ "$ROOT_DEV" == /dev/mmcblk* ]]; then
  step_warn "running from a microSD card (${free_var} MB free). An SSD is strongly recommended for continuous database writes"
elif ((free_var < 4096)); then
  step_warn "${free_var} MB free on /var; 4 GB+ recommended for history and backups"
else step_ok "${free_var} MB free"; fi

# 4 ---------------------------------------------------------------------------
step "Checking network and ports"
if ss -Hltn "( sport = :$PORT )" 2>/dev/null | grep -q .; then
  owner="$(ss -Hltnp "( sport = :$PORT )" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2 || true)"
  if [[ "$owner" == python* ]] && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then :
  else
    die "Port $PORT is already in use${owner:+ by $owner}. Choose another with --port N."
  fi
fi
NET_OK=1
curl -fsS --max-time 10 -o /dev/null https://pypi.org/simple/pip/ 2>>"$LOG_FILE" || NET_OK=0
if ss -Hltn "( sport = :$PORT )" 2>/dev/null | grep -q .; then port_msg="port $PORT used by this application"; else port_msg="port $PORT free"; fi
if ((NET_OK)); then step_ok "internet reachable, $port_msg"
elif ((OFFLINE_CAPABLE)); then OFFLINE=1; step_warn "no internet access; installing from the bundled offline files"
elif ((OFFLINE)); then die "--offline needs the offline bundle (this package has no wheels/ directory)."
else die "No internet access (pypi.org unreachable) and this is the online package. Use the -offline bundle or fix connectivity."; fi

# existing installation?
if [[ -L "$CURRENT" ]]; then
  FRESH=0
  PREV_CURRENT="$(readlink -f "$CURRENT")"
  installed_ver="$(pkg_version "$PREV_CURRENT" 2>/dev/null || echo unknown)"
  if [[ "$installed_ver" == "$VERSION" && $REPAIR == 0 ]]; then
    trap - ERR; DIE_HOOK=""
    info ""
    info "Version $VERSION is already installed. Nothing to do."
    info "  Check it:      sudo gti health"
    info "  Reinstall app: sudo ./install.sh --repair   (configuration and data are kept)"
    info "  Upgrade:       sudo ./update.sh <new-release.tar.gz>"
    exit 0
  fi
  if [[ "$installed_ver" != "$VERSION" ]]; then
    trap - ERR; DIE_HOOK=""
    info ""; info "Existing installation v$installed_ver found. Use update.sh to upgrade (it backs up and can roll back)."
    die "Refusing to overwrite an installation of a different version with install.sh."
  fi
fi

# 5 ---------------------------------------------------------------------------
step "Installing system packages"
pkgs=(python3 python3-venv ca-certificates curl gzip util-linux iproute2)
missing=()
for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p"); done
if ((${#missing[@]})); then
  ((OFFLINE)) && die "Offline install, but these system packages are missing: ${missing[*]}. Install them from your OS media first."
  export DEBIAN_FRONTEND=noninteractive
  run apt-get update || die "apt-get update failed (see $LOG_FILE)."
  run apt-get install -y --no-install-recommends "${missing[@]}" || die "Could not install: ${missing[*]} (see $LOG_FILE)."
fi
PY="$(python_bin)" || die "Python 3.${MIN_PY_MINOR}-3.${MAX_PY_MINOR} is required; found: $(python3 --version 2>&1)."
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "python3-venv/ensurepip is not usable for $PY."
step_ok "$("$PY" --version 2>&1)${missing:+, installed ${missing[*]}}"

# 6 ---------------------------------------------------------------------------
step "Creating service account and directories"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  run useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  CREATED_USER=1
fi
[[ -d "$DATA_DIR" ]] || CREATED_DATA=1
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$GEOIP_DIR"
install -d -m 0755 "$PREFIX" "$RELEASES"
install -d -m 0750 -o root -g root "$BACKUP_DIR"
# record packages this installer added, so uninstall can offer to remove exactly those
if ((${#missing[@]})); then printf '%s\n' "${missing[@]}" >>"$DATA_DIR/.installer-added-packages"; fi
step_ok "user $SVC_USER, $DATA_DIR"

# 7 ---------------------------------------------------------------------------
step "Installing application"
REL="$(install_release "$PKG_DIR")"
CREATED_RELEASE="$REL"
step_ok "$REL"

# 8 ---------------------------------------------------------------------------
step "Writing configuration"
install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
if [[ -f "$CONF_FILE" ]]; then
  step_ok "existing $CONF_FILE kept unchanged"
  PORT="$(conf_get GTI_PORT "$PORT")"; HOST="$(conf_get GTI_HOST "$HOST")"
else
  tmp="$(mktemp "$CONF_DIR/.gti.env.XXXX")"
  sed -e "s/@PROFILE@/$PROFILE/" -e "s/@MEM_MB@/$MEM_MB/" -e "s/@HOST@/$HOST/" -e "s/@PORT@/$PORT/" \
      -e "s/@CAP@/$CAP/" -e "s/@EVENTS@/$EVENTS/" "$REL/config/gti.env.template" >"$tmp"
  chown root:"$SVC_USER" "$tmp"; chmod 0640 "$tmp"; mv "$tmp" "$CONF_FILE"
  CREATED_CONF=1
  step_ok "$CONF_FILE (profile $PROFILE)"
fi

# 9 ---------------------------------------------------------------------------
step "Installing GeoIP/ASN databases"
geo_msg="$("$REL/scripts/update-geoip.sh" --package "$PKG_DIR" --python "$REL/venv/bin/python" 2>>"$LOG_FILE")" && geo_rc=0 || geo_rc=$?
if ((geo_rc == 0)); then step_ok "$geo_msg"
else step_warn "GeoIP databases unavailable ($geo_msg). The map cannot place IPs until 'sudo gti update-geoip' succeeds"; fi

# 10 --------------------------------------------------------------------------
step "Preparing database"
if [[ -f "$DATA_DIR/gti.db" ]]; then
  bk="$(ADMIN_RELEASE="$REL" make_backup pre-install)" || die "Could not back up the existing database; refusing to migrate it."
  info_msg="existing database kept, backup $bk"
else info_msg="new database"; fi
ADMIN_RELEASE="$REL" admin migrate >>"$LOG_FILE" 2>&1 || die "Database migration failed (see $LOG_FILE)."
step_ok "$info_msg"

# 11 --------------------------------------------------------------------------
step "Configuring services"
install_units "$REL" "$MEMMAX"
UNITS_INSTALLED=1
switch_current "$REL"
run systemctl enable "$SERVICE" "${APP_NAME}-backup.timer" "${APP_NAME}-geoip.timer"
run start_service restart || die "Service failed to start: see 'journalctl -u $SERVICE'."
run systemctl start "${APP_NAME}-backup.timer" "${APP_NAME}-geoip.timer"
mm="$(systemctl show "$SERVICE" -p MemoryMax --value 2>/dev/null)"
[[ "$mm" =~ ^[0-9]+$ ]] && mm="$((mm / 1048576))M"
step_ok "enabled at boot, MemoryMax=${mm:-$MEMMAX}"

# 12 --------------------------------------------------------------------------
step "Running health checks"
if ! wait_healthy "$PORT" 60; then
  journalctl -u "$SERVICE" -n 40 --no-pager >>"$LOG_FILE" 2>&1 || true
  die "The dashboard did not become healthy within 60 s. Service log copied to $LOG_FILE."
fi
admin health-db >>"$LOG_FILE" 2>&1 || die "Database health check failed (see $LOG_FILE)."
step_ok "http://127.0.0.1:$PORT/api/health ok"

# 13 --------------------------------------------------------------------------
step "Completing installation"
# keep newest 2 releases
trap - ERR; DIE_HOOK=""
mapfile -t old < <(ls -1dt "$RELEASES"/*/ 2>/dev/null | tail -n +3)
for d in "${old[@]}"; do if [[ "$(readlink -f "$d")" != "$(readlink -f "$CURRENT")" ]]; then rm -rf "$d"; fi; done
step_ok

printf '\n%sInstalled %s v%s%s\n\n' "$C_OK" "$APP_TITLE" "$VERSION" "$C_0"
printf 'Open the dashboard:\n'
if [[ "$HOST" == "127.0.0.1" ]]; then printf '  http://127.0.0.1:%s   (local only)\n' "$PORT"
else
  printf '  http://127.0.0.1:%s   (on this machine)\n' "$PORT"
  for ip in $(lan_ips); do printf '  http://%s:%s   (from your LAN)\n' "$ip" "$PORT"; done
fi
if [[ -f "$DATA_DIR/setup_token" ]]; then
  printf '\nFirst-time setup token (needed once to create the administrator account):\n  %s%s%s\n' "$C_B" "$(cat "$DATA_DIR/setup_token")" "$C_0"
  printf '  Show it again later with: sudo gti setup-token\n'
fi
cat <<EOF

Ports and services:
  ${PORT}/tcp   dashboard + API + WebSocket (/ws), bound to ${HOST}
  No database or cache server is installed: data lives in SQLite at ${DATA_DIR} (no network port).
  Outbound HTTPS (443) to the intelligence feeds and download.db-ip.com.

Firewall: nothing was changed.$(command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' && printf '\n  ufw is active. To allow your LAN: sudo ufw allow from 192.168.0.0/16 to any port %s proto tcp' "$PORT")

Useful commands: sudo gti status | sudo gti health | sudo gti backup | sudo gti logs
Install log: ${LOG_FILE}
EOF
print_warnings
