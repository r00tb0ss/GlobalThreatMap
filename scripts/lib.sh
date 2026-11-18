# shellcheck shell=bash
# shellcheck disable=SC2034  # variables here are used by the scripts that source this file
# Shared helpers for install.sh / update.sh / uninstall.sh / backup.sh / restore.sh / health-check.sh
# Sourced, never executed directly.

APP_NAME="global-threat-intel"
APP_TITLE="Global Threat Intelligence Platform"
PREFIX="/opt/${APP_NAME}"
RELEASES="${PREFIX}/releases"
CURRENT="${PREFIX}/current"
CONF_DIR="/etc/${APP_NAME}"
CONF_FILE="${CONF_DIR}/gti.env"
DATA_DIR="/var/lib/${APP_NAME}"
GEOIP_DIR="${DATA_DIR}/geoip"
BACKUP_DIR="/var/backups/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
SVC_USER="gti"
SERVICE="${APP_NAME}.service"
UNITS=("${APP_NAME}.service" "${APP_NAME}-backup.service" "${APP_NAME}-backup.timer"
       "${APP_NAME}-geoip.service" "${APP_NAME}-geoip.timer")
CLI="/usr/local/sbin/gti"
MIN_PY_MINOR=11
MAX_PY_MINOR=13

if [[ -t 1 ]]; then C_OK=$'\e[32m'; C_ERR=$'\e[31m'; C_WARN=$'\e[33m'; C_DIM=$'\e[2m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else C_OK=; C_ERR=; C_WARN=; C_DIM=; C_B=; C_0=; fi

LOG_FILE="${LOG_FILE:-/dev/null}"
STEP_NO=0
STEP_TOTAL=0
STEP_NAME=""
WARNINGS=()

log()  { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE"; }
info() { printf '%s\n' "$*"; log "INFO $*"; }
warn() { printf '%s  ! %s%s\n' "$C_WARN" "$*" "$C_0" >&2; log "WARN $*"; WARNINGS+=("$*"); }
# die: print, log, run the caller's rollback hook (top-level shell only, never inside $(...)), exit 1.
# Needed because `exit` does not fire the ERR trap, so plain die would skip rollback.
DIE_HOOK=""
die()  {
  printf '%sERROR: %s%s\n' "$C_ERR" "$*" "$C_0" >&2; log "ERROR $*"
  if [[ -n "$DIE_HOOK" ]] && ((BASH_SUBSHELL == 0)); then local h="$DIE_HOOK"; DIE_HOOK=""; "$h"; fi
  exit 1
}

# run a command, sending its output to the log file only
run() { log "RUN $*"; "$@" >>"$LOG_FILE" 2>&1; }

step() {   # step "Name" ; work happens ; step_ok
  STEP_NO=$((STEP_NO + 1)); STEP_NAME="$1"
  local label="[${STEP_NO}/${STEP_TOTAL}] $1"
  printf '%s' "$label"; printf '%*s' $((44 - ${#label} > 1 ? 44 - ${#label} : 1)) '' | tr ' ' '.'
  log "STEP ${STEP_NO}/${STEP_TOTAL} $1"
}
step_ok()   { printf ' %sOK%s%s\n' "$C_OK" "$C_0" "${1:+ ${C_DIM}($1)${C_0}}"; }
step_warn() { printf ' %sWARN%s %s\n' "$C_WARN" "$C_0" "$1"; WARNINGS+=("$1"); log "WARN $1"; }

require_root() { [[ $EUID -eq 0 ]] || die "Run with sudo: sudo $0 $*"; }

acquire_lock() {
  exec 9>/run/${APP_NAME}.lock
  flock -n 9 || die "Another install/update/uninstall is already running."
}

# ---- platform detection -------------------------------------------------------
detect_platform() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release; unsupported operating system."
  # read in a subshell: os-release defines VERSION, NAME, ID ... which must not clobber our variables
  # (regression: the installer printed the OS version as the application version)
  local osr
  mapfile -t osr < <( # shellcheck disable=SC1091
    . /etc/os-release; printf '%s\n' "${ID:-unknown}" "${VERSION_ID:-0}" "${PRETTY_NAME:-${ID:-unknown}}" "${ID_LIKE:-}")
  OS_ID="${osr[0]}"; OS_VER="${osr[1]}"; OS_NAME="${osr[2]}"; OS_LIKE="${osr[3]}"
  KARCH="$(uname -m)"
  DPKG_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
  PI_MODEL=""
  if [[ -r /proc/device-tree/model ]]; then PI_MODEL="$(tr -d '\0' </proc/device-tree/model)"; fi
  [[ "$PI_MODEL" == Raspberry\ Pi* ]] || PI_MODEL=""
  MEM_MB=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) / 1024 ))
  ROOT_DEV="$(findmnt -no SOURCE / 2>/dev/null || true)"
}

check_platform() {   # dies with a clear reason on unsupported platforms
  case "$DPKG_ARCH" in
    amd64|arm64) ;;
    armhf|armel|i386) die "32-bit userland ($DPKG_ARCH) is not supported. Install a 64-bit OS (Raspberry Pi OS 64-bit or Ubuntu Server ARM64)." ;;
    *) die "Unsupported CPU architecture: $KARCH / $DPKG_ARCH (supported: x86_64/amd64, aarch64/arm64)." ;;
  esac
  case "$OS_ID" in
    ubuntu)
      if dpkg --compare-versions "$OS_VER" lt 24.04; then die "Ubuntu $OS_VER is not supported (need 24.04 LTS or newer)."; fi ;;
    debian|raspbian)
      if dpkg --compare-versions "$OS_VER" lt 12; then die "Debian/Raspberry Pi OS $OS_VER is not supported (need 12 'bookworm' or newer, 64-bit)."; fi ;;
    *)
      if [[ " $OS_LIKE " == *" debian "* || " $OS_LIKE " == *" ubuntu "* ]]; then
        warn "$OS_NAME is Debian-like but untested. Continuing because --force was given." ; [[ ${FORCE:-0} == 1 ]] || die "Untested OS $OS_NAME. Re-run with --force to try anyway."
      else
        die "Unsupported operating system: $OS_NAME (supported: Ubuntu Server 24.04+, Raspberry Pi OS 64-bit bookworm+)."
      fi ;;
  esac
  command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die "systemd is not running; it is required to manage the services."
}

# memory profile -> sets PROFILE, CAP, MEMMAX, EVENTS
choose_profile() {
  if   (( MEM_MB < 1800 )); then
    [[ ${FORCE:-0} == 1 ]] || die "Only ${MEM_MB} MB RAM. At least 2 GB is required (4 GB recommended). Use --force to override."
    PROFILE="tiny";  CAP=5000;   MEMMAX="300M"; EVENTS=100
  elif (( MEM_MB < 3500 )); then PROFILE="2gb";  CAP=10000;  MEMMAX="400M"; EVENTS=100
  elif (( MEM_MB < 7000 )); then PROFILE="4gb";  CAP=20000;  MEMMAX="512M"; EVENTS=200
  elif (( MEM_MB < 14000 )); then PROFILE="8gb"; CAP=50000;  MEMMAX="1G";   EVENTS=300
  else                            PROFILE="16gb"; CAP=100000; MEMMAX="1536M"; EVENTS=500
  fi
}

python_bin() {   # prints path of a supported python3, or nothing
  local p
  for p in python3 python3.13 python3.12 python3.11; do
    if command -v "$p" >/dev/null 2>&1; then
      local minor; minor="$("$p" -c 'import sys;print(sys.version_info[1] if sys.version_info[0]==3 else 0)' 2>/dev/null || echo 0)"
      if (( minor >= MIN_PY_MINOR && minor <= MAX_PY_MINOR )); then command -v "$p"; return 0; fi
    fi
  done
  return 1
}

lan_ips() { hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' || true; }

conf_get() {   # conf_get KEY [default]
  local v=""
  [[ -r "$CONF_FILE" ]] && v="$(grep -E "^$1=" "$CONF_FILE" | tail -1 | cut -d= -f2- || true)"
  printf '%s' "${v:-${2:-}}"
}

wait_healthy() {   # wait_healthy PORT TIMEOUT_S ; fails fast if the service crash-loops
  local port="$1" t="${2:-60}" i r0 r
  r0="$(systemctl show "$SERVICE" -p NRestarts --value 2>/dev/null || echo 0)"
  for ((i = 0; i < t; i++)); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/api/health" 2>/dev/null | grep -q '"status":"ok"'; then return 0; fi
    r="$(systemctl show "$SERVICE" -p NRestarts --value 2>/dev/null || echo 0)"
    if systemctl is-failed --quiet "$SERVICE" || (( ${r:-0} - ${r0:-0} >= 3 )); then
      log "service is crash-looping (restarts: $r0 -> $r)"; return 1
    fi
    sleep 1
  done
  return 1
}

# start (or restart) the service after clearing a previous failed/start-limit state
start_service() {
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl "${1:-start}" "$SERVICE"
}

_ADMIN_PY='import sys; sys.path.insert(0, sys.argv.pop(1)); from gti.admin import main; main(sys.argv[1:])'

admin() {   # run gti.admin as the service user (files it creates are owned by gti)
  local rel="${ADMIN_RELEASE:-$CURRENT}"
  runuser -u "$SVC_USER" -- env GTI_DATA_DIR="$DATA_DIR" "$rel/venv/bin/python" -I -c "$_ADMIN_PY" "$rel/backend" "$@"
}

admin_root() {  # same, as root (backup needs to read the root-owned config file)
  local rel="${ADMIN_RELEASE:-$CURRENT}"
  env GTI_DATA_DIR="$DATA_DIR" "$rel/venv/bin/python" -I -c "$_ADMIN_PY" "$rel/backend" "$@"
}

make_backup() {  # make_backup LABEL -> prints archive path
  local label="$1" ts out
  ts="$(date +%Y%m%d-%H%M%S)"
  install -d -m 0750 -o root -g root "$BACKUP_DIR"
  out="${BACKUP_DIR}/gti-${label}-${ts}.tar.gz"
  admin_root backup "$out" --config "$CONF_FILE" >>"$LOG_FILE" 2>&1 || return 1
  printf '%s' "$out"
}

prune_backups() {  # keep newest N automatic backups
  local keep="${1:-7}"
  # shellcheck disable=SC2012
  ls -1t "$BACKUP_DIR"/gti-auto-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm -f --
}

# ---- release installation (shared by install.sh and update.sh) ---------------------
pkg_version() { tr -d ' \n\r' <"$1/VERSION"; }

# install_release PKG_DIR -> creates $RELEASES/<version> atomically (staging dir + rename)
install_release() {
  local pkg="$1" ver py pyminor wh stage dest
  ver="$(pkg_version "$pkg")"
  dest="$RELEASES/$ver"
  stage="$RELEASES/.${ver}.staging"
  py="$(python_bin)" || die "Python 3.${MIN_PY_MINOR}-3.${MAX_PY_MINOR} not found."
  pyminor="$("$py" -c 'import sys;print(sys.version_info[1])')"
  install -d -m 0755 "$RELEASES"
  rm -rf "$stage"
  install -d -m 0755 "$stage"
  local item
  for item in VERSION backend frontend requirements services config scripts docs install.sh update.sh uninstall.sh backup.sh restore.sh health-check.sh README.md; do
    [[ -e "$pkg/$item" ]] && cp -a "$pkg/$item" "$stage/"
  done
  rm -rf "$stage/backend/tests"
  find "$stage" -name '__pycache__' -type d -prune -exec rm -rf {} +
  run "$py" -m venv "$stage/venv" || die "Could not create Python virtual environment (is python3-venv installed?)"
  local pipargs=(--disable-pip-version-check --no-input --require-hashes --only-binary=:all: --no-cache-dir
                 -r "$stage/requirements/requirements.lock")
  wh="$pkg/wheels/cp3${pyminor}-$(uname -m)"
  if [[ -d "$wh" ]]; then
    pipargs+=(--no-index --find-links "$wh")
    log "installing Python packages from bundled wheelhouse $wh"
  elif [[ ${OFFLINE:-0} == 1 ]]; then
    die "Offline install requested but no bundled wheels for CPython 3.${pyminor} on $(uname -m) in $pkg/wheels."
  fi
  run "$stage/venv/bin/python" -m pip install "${pipargs[@]}" \
    || die "Python dependency installation failed (see $LOG_FILE). Check internet access to pypi.org."
  run "$stage/venv/bin/python" -I -c "import sys; sys.path.insert(0, '$stage/backend'); import gti.app, maxminddb, pydantic_core, websockets" \
    || die "Installed application failed its import self-test (see $LOG_FILE)."
  chown -R root:root "$stage"
  chmod -R u=rwX,go=rX "$stage"
  rm -rf "$dest"
  mv "$stage" "$dest"
  printf '%s' "$dest"
}

# switch the 'current' symlink atomically
switch_current() {
  ln -sfn "$1" "$PREFIX/.current.new"
  mv -T "$PREFIX/.current.new" "$CURRENT"
}

install_units() {   # install_units RELEASE_DIR MEMMAX
  local rel="$1" memmax="$2" u
  for u in "${UNITS[@]}"; do install -m 0644 "$rel/services/$u" "/etc/systemd/system/$u"; done
  install -d -m 0755 "/etc/systemd/system/${SERVICE}.d"
  [[ -f "/etc/systemd/system/${SERVICE}.d/10-resources.conf" ]] || cat >"/etc/systemd/system/${SERVICE}.d/10-resources.conf" <<EOF
# Written by install.sh for hardware profile ${PROFILE:-custom}. Safe to edit; preserved by updates.
[Service]
MemoryHigh=$(( $(numfmt --from=iec "$memmax") * 85 / 100 ))
MemoryMax=${memmax}
EOF
  install -m 0755 "$rel/scripts/gti" "$CLI"
  run systemctl daemon-reload
}

print_warnings() {
  if ((${#WARNINGS[@]})); then
    printf '\n%sWarnings:%s\n' "$C_WARN" "$C_0"
    local w; for w in "${WARNINGS[@]}"; do printf '  - %s\n' "$w"; done
  fi
}
