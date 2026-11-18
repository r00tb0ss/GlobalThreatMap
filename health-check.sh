#!/usr/bin/env bash
# Health check:  sudo ./health-check.sh [--full]     exit code 0 = healthy, 1 = problems found
#   --full  run a full SQLite integrity check (slower on large databases)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$HERE/scripts/lib.sh"
require_root
FULL=(); [[ "${1:-}" == "--full" ]] && FULL=(--full)
FAIL=0
ok()   { printf '  %sOK%s    %s\n' "$C_OK" "$C_0" "$*"; }
bad()  { printf '  %sFAIL%s  %s\n' "$C_ERR" "$C_0" "$*"; FAIL=1; }
note() { printf '  %sWARN%s  %s\n' "$C_WARN" "$C_0" "$*"; }

echo "Global Threat Intelligence Platform health"
[[ -L "$CURRENT" ]] && ok "installed: v$(pkg_version "$CURRENT") at $(readlink -f "$CURRENT")" || { bad "not installed"; exit 1; }
systemctl is-active --quiet "$SERVICE" && ok "service running" || bad "service not running (journalctl -u $SERVICE)"
systemctl is-enabled --quiet "$SERVICE" && ok "starts at boot" || bad "service not enabled at boot"
for t in "${APP_NAME}-backup.timer" "${APP_NAME}-geoip.timer"; do
  systemctl is-active --quiet "$t" && ok "$t active" || note "$t not active"
done
port="$(conf_get GTI_PORT 8080)"
if out="$(curl -fsS --max-time 5 "http://127.0.0.1:${port}/api/health" 2>&1)"; then ok "dashboard responds on port $port: $out"
else bad "dashboard not responding on port $port"; fi
if db="$(admin health-db --human "${FULL[@]}" 2>&1)"; then echo "$db"
else bad "database check failed: $db"; fi
ls "$GEOIP_DIR"/dbip-city-lite*.mmdb >/dev/null 2>&1 && ok "GeoIP database present" || note "GeoIP database missing (sudo gti update-geoip)"
free_mb=$(df -Pm "$DATA_DIR" | awk 'NR==2{print $4}')
if ((free_mb < 500)); then bad "only ${free_mb} MB free on $DATA_DIR"; elif ((free_mb < 2048)); then note "${free_mb} MB free on $DATA_DIR"; else ok "${free_mb} MB free on $DATA_DIR"; fi
mem="$(systemctl show "$SERVICE" -p MemoryCurrent --value 2>/dev/null)"; max="$(systemctl show "$SERVICE" -p MemoryMax --value 2>/dev/null)"
[[ "$mem" =~ ^[0-9]+$ ]] && ok "service memory $((mem / 1048576)) MB (limit $([[ "$max" =~ ^[0-9]+$ ]] && echo "$((max / 1048576)) MB" || echo "$max"))"
rx="$(systemctl show "$SERVICE" -p IPIngressBytes --value 2>/dev/null)"; up="$(systemctl show "$SERVICE" -p ActiveEnterTimestampMonotonic --value 2>/dev/null)"
if [[ "$rx" =~ ^[0-9]+$ && "$up" =~ ^[0-9]+$ && "$up" -gt 0 ]]; then
  secs=$(( ( $(awk '{print int($1*1000000)}' /proc/uptime) - up ) / 1000000 ))
  ((secs > 0)) && ok "downloaded $((rx / 1024)) KB since the service started ${secs}s ago (~$(( rx / secs * 86400 / 1048576 )) MB/day at this rate)"
fi
last="$(ls -1t "$BACKUP_DIR"/gti-*.tar.gz 2>/dev/null | head -1)"
[[ -n "$last" ]] && ok "latest backup: $last" || note "no backups yet (sudo gti backup)"
exit $FAIL
