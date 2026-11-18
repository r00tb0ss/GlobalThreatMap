#!/usr/bin/env bash
# Back up the database and configuration:  sudo ./backup.sh [--auto] [--out FILE]
#   --auto   label as an automatic backup and prune old ones (GTI_BACKUP_KEEP, default 7)
# Backups go to /var/backups/global-threat-intel (mode 0600, root only).
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$HERE/scripts/lib.sh"
require_root
AUTO=0; OUT=""
while (($#)); do case "$1" in --auto) AUTO=1 ;; --out) OUT="${2:?}"; shift ;; -h|--help) sed -n '2,4p' "$0"; exit 0 ;; *) die "Unknown option $1" ;; esac; shift; done
[[ -L "$CURRENT" ]] || die "Not installed (no $CURRENT)."
[[ -f "$DATA_DIR/gti.db" ]] || die "No database at $DATA_DIR/gti.db."
LOG_FILE="$LOG_DIR/backup.log"
install -d -m 0750 "$LOG_DIR"
free_mb=$(df -Pm "$BACKUP_DIR" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
db_mb=$(( $(stat -c %s "$DATA_DIR/gti.db") / 1048576 + 1 ))
(( free_mb > db_mb * 2 + 50 )) || die "Not enough free space for a backup (${free_mb} MB free, need ~$((db_mb * 2 + 50)) MB)."
if [[ -n "$OUT" ]]; then
  admin_root backup "$OUT" --config "$CONF_FILE" >>"$LOG_FILE" 2>&1 || die "Backup failed (see $LOG_FILE)."
  path="$OUT"
else
  path="$(make_backup "$( ((AUTO)) && echo auto || echo manual)")" || die "Backup failed (see $LOG_FILE)."
fi
admin_root verify-backup "$path" >>"$LOG_FILE" 2>&1 || die "Backup was written but failed verification: $path"
((AUTO)) && prune_backups "$(conf_get GTI_BACKUP_KEEP 7)"
log "backup ok $path"
echo "Backup written and verified: $path ($(du -h "$path" | cut -f1))"
