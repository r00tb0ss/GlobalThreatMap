#!/usr/bin/env bash
# Uninstall the Global Threat Intelligence Platform.
#   sudo ./uninstall.sh              standard: remove application + services; KEEP database, config, backups
#   sudo ./uninstall.sh --complete   also delete database, configuration, data, logs and the service account
#                                    (asks you to type DELETE; a final backup is offered first)
# Options: --yes (standard only: no question)   --remove-packages (also remove OS packages this installer added)
#          --confirm DELETE (non-interactive complete uninstall)   --no-final-backup
# Unrelated packages and user data are never touched.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$HERE/scripts/lib.sh"
require_root
COMPLETE=0; YES=0; RMPKG=0; CONFIRM=""; FINAL_BACKUP=1
while (($#)); do
  case "$1" in
    --complete) COMPLETE=1 ;; --yes|-y) YES=1 ;; --remove-packages) RMPKG=1 ;;
    --confirm) CONFIRM="${2:-}"; shift ;; --no-final-backup) FINAL_BACKUP=0 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option $1" ;;
  esac; shift
done
acquire_lock
# work from a copy of lib so removing /opt does not pull the script out from under us
echo
if ((COMPLETE)); then
  printf '%sCOMPLETE UNINSTALL%s will permanently delete:\n' "$C_ERR" "$C_0"
  printf '  %s (database, GeoIP files)\n  %s (configuration, API keys)\n  %s\n  %s\n  service account "%s"\n' \
    "$DATA_DIR" "$CONF_DIR" "$LOG_DIR" "$PREFIX" "$SVC_USER"
  ((FINAL_BACKUP)) && printf 'A final backup will be written to %s first (it is kept).\n' "$BACKUP_DIR"
  if [[ "$CONFIRM" != "DELETE" ]]; then
    read -r -p 'Type DELETE to continue: ' a
    [[ "$a" == "DELETE" ]] || { echo "Cancelled. Nothing was removed."; exit 1; }
  fi
else
  echo "Standard uninstall: removes the application and its services."
  echo "Kept: database ($DATA_DIR), configuration ($CONF_DIR), backups ($BACKUP_DIR)."
  if ((!YES)); then read -r -p "Continue? [y/N] " a; [[ "$a" == [yY]* ]] || { echo "Cancelled."; exit 1; }; fi
fi

if ((COMPLETE && FINAL_BACKUP)) && [[ -f "$DATA_DIR/gti.db" && -x "$CURRENT/venv/bin/python" ]]; then
  if fb="$(LOG_FILE=/dev/null make_backup final)"; then echo "Final backup: $fb"
  else echo "Final backup FAILED. Cancelling so no data is lost. Use --no-final-backup to skip it."; exit 1; fi
fi

echo "Stopping and removing services..."
systemctl disable --now "${UNITS[@]}" >/dev/null 2>&1 || true
for u in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$u"; done
rm -rf "/etc/systemd/system/${SERVICE}.d"
systemctl daemon-reload
systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
rm -f "$CLI" "/run/${APP_NAME}.lock.unused"
echo "Removing application files ($PREFIX)..."
added_pkgs=()
[[ -f "$DATA_DIR/.installer-added-packages" ]] && mapfile -t added_pkgs < <(sort -u "$DATA_DIR/.installer-added-packages")
rm -rf "$PREFIX"

if ((COMPLETE)); then
  echo "Deleting data, configuration and logs..."
  rm -rf "$DATA_DIR" "$CONF_DIR" "$LOG_DIR"
  if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" 2>/dev/null || true; fi
  getent group "$SVC_USER" >/dev/null && groupdel "$SVC_USER" 2>/dev/null || true
fi

if ((RMPKG)) && ((${#added_pkgs[@]})); then
  # only packages this installer added, and never python3 itself (other software depends on it)
  safe=(); for p in "${added_pkgs[@]}"; do [[ "$p" =~ ^(python3-venv|gzip)$ ]] && safe+=("$p"); done
  if ((${#safe[@]})); then echo "Removing packages added by the installer: ${safe[*]}"; apt-get remove -y "${safe[@]}" >/dev/null || true; fi
elif ((${#added_pkgs[@]})); then
  echo "Packages added by the installer were left installed: ${added_pkgs[*]} (use --remove-packages to remove python3-venv)."
fi

echo
if ((COMPLETE)); then echo "Complete uninstall finished. Backups (if any) remain in $BACKUP_DIR; delete that folder yourself if you want."
else echo "Uninstalled. Your data is preserved; reinstalling with install.sh will pick it up again."; fi
