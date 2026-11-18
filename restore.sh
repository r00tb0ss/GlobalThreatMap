#!/usr/bin/env bash
# Restore a backup:  sudo ./restore.sh <backup.tar.gz> [--with-config] [--yes]
#   The current database is backed up first (gti-pre-restore-*.tar.gz), so a restore can itself be undone.
#   --with-config also restores gti.env from the backup (default: keep the current configuration).
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$HERE/scripts/lib.sh"
require_root
FILE=""; WITH_CONF=0; YES=0
while (($#)); do case "$1" in --with-config) WITH_CONF=1 ;; --yes|-y) YES=1 ;; -h|--help) sed -n '2,4p' "$0"; exit 0 ;; -*) die "Unknown option $1" ;; *) FILE="$1" ;; esac; shift; done
[[ -n "$FILE" && -f "$FILE" ]] || die "Usage: sudo $0 <backup.tar.gz>   (backups are in $BACKUP_DIR)"
[[ -L "$CURRENT" ]] || die "Not installed. Install first, then restore."
LOG_FILE="$LOG_DIR/restore-$(date +%Y%m%d-%H%M%S).log"; install -d -m 0750 "$LOG_DIR"; : >"$LOG_FILE"
acquire_lock

echo "Verifying $FILE ..."
STAGE="$(mktemp -d "$DATA_DIR/.restore.XXXX")"
trap 'rm -rf "$STAGE"' EXIT
info_json="$(admin_root verify-backup "$FILE" --extract-to "$STAGE" 2>>"$LOG_FILE")" || die "Backup failed verification (see $LOG_FILE). Nothing was changed."
echo "  OK: $info_json"
if ((!YES)); then
  read -r -p "Replace the current database with this backup? [y/N] " a
  [[ "$a" == [yY]* ]] || { echo "Cancelled."; exit 1; }
fi
pre="$(make_backup pre-restore)" || die "Could not back up the current database; restore aborted."
echo "Current data saved to $pre"
systemctl stop "$SERVICE"
rm -f "$DATA_DIR/gti.db-wal" "$DATA_DIR/gti.db-shm"
install -m 0600 -o "$SVC_USER" -g "$SVC_USER" "$STAGE/gti.db" "$DATA_DIR/gti.db"
if ((WITH_CONF)) && [[ -f "$STAGE/gti.env" ]]; then
  install -m 0640 -o root -g "$SVC_USER" "$STAGE/gti.env" "$CONF_FILE"; echo "Configuration restored."
fi
admin migrate >>"$LOG_FILE" 2>&1 || die "Migration of the restored database failed; restore the previous state with: sudo $0 $pre"
start_service start
port="$(conf_get GTI_PORT 8080)"
if wait_healthy "$port" 60; then echo "Restore complete; service healthy."
else die "Service is not healthy after restore. Roll back with: sudo $0 $pre --yes"; fi
