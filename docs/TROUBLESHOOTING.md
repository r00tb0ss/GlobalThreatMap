# Troubleshooting

Start with `sudo gti health` and `sudo gti logs`.

| Symptom | Cause / fix |
|---|---|
| Installer: "32-bit userland (armhf)" | You run 32-bit Raspberry Pi OS. Reflash with the 64-bit image. |
| Installer: "Port 8080 is already in use" | `sudo ./install.sh --port 8090` |
| Installer: "No internet access" | Use the `-offline` package, or fix DNS/proxy. |
| Installer failed at a step | Read the named log in `/var/log/global-threat-intel/`. Fix, re-run `install.sh`: it is safe. |
| Can't open the dashboard from another device | Check the URL uses the Pi's LAN IP; check `ufw status`; check you did not install with `--local-only` (`GTI_HOST`). |
| Lost the setup token | `sudo gti setup-token` |
| Forgot the password | `sudo gti reset-password <user>` |
| Banner "Not current: ..." | That source failed or is stale. Open **Sources** to see the error. Data shown is the last good copy. |
| Map dots but no positions / "GeoIP database not installed" | `sudo gti update-geoip` (needs internet) |
| Local sensor shows nothing | Normal if nothing reaches this host. Enable UFW logging for blocks: `sudo ufw logging on`. |
| Local sensor "unavailable" | journalctl missing (non-systemd system); not supported. |
| GreyNoise source "error" | Their endpoint changed or is down. Other sources are unaffected. |
| Service keeps restarting | `journalctl -u global-threat-intel -n 100`. Out of memory? Raise `MemoryMax` in the drop-in or lower `GTI_MAX_INDICATORS_PER_SOURCE`. |
| Disk filling up | Lower retention in **Settings**; backups live in `/var/backups/global-threat-intel` (7 kept). |
| Update failed | It rolled back automatically; the message names the step and log. The pre-update backup path is printed. |
| "schema vN is newer than this application" | A newer release's database with an older app. Install the newer release or restore a matching backup. |
