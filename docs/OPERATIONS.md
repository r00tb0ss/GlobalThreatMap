# Operations

## Layout

| Path | Contents | Kept by standard uninstall |
|---|---|---|
| `/opt/global-threat-intel/releases/<v>/` | application + its virtualenv (last 2 kept) | no |
| `/opt/global-threat-intel/current` | symlink to the active release | no |
| `/etc/global-threat-intel/gti.env` | configuration (root:gti 0640) | **yes** |
| `/var/lib/global-threat-intel/` | `gti.db` (SQLite), `geoip/` | **yes** |
| `/var/backups/global-threat-intel/` | backups (root 0700, files 0600) | **yes** (also after complete uninstall) |
| `/var/log/global-threat-intel/` | install/update/restore logs | yes |
| `/usr/local/sbin/gti` | management command | no |

Services: `global-threat-intel.service` (dashboard + collectors), `global-threat-intel-backup.timer`
(daily, around 03:30), `global-threat-intel-geoip.timer` (monthly). All start at boot; the main service
restarts automatically after a crash (5 s delay, max 10 restarts per 5 minutes).

## Updating

```bash
tar -xzf global-threat-intel-<new>.tar.gz && cd global-threat-intel-<new>
sudo ./update.sh
```

or `sudo gti update /path/global-threat-intel-<new>.tar.gz` (the `.sha256` file must sit next to the archive).
With `GTI_UPDATE_URL` set to a release manifest (`{"version","url","sha256"}`), `sudo gti update --check` and
`sudo gti update --url <manifest>` work too.

The updater checks compatibility, makes and verifies a backup, installs the new release **next to** the old
one, stops the service, switches the `current` link, runs migrations, restarts and health-checks. On any
failure it switches back, restores the pre-update database, restarts the old version, and tells you.
Configuration, API keys, accounts, settings and all history are preserved. Downgrades are refused; use a
backup instead.

## Backup and restore

```bash
sudo gti backup                         # writes and verifies /var/backups/global-threat-intel/gti-manual-*.tar.gz
sudo gti restore <file>                 # current data is backed up first; --with-config also restores gti.env
```

Backups use SQLite's online backup API (consistent while running) and contain a manifest with SHA-256
checksums. Restore verifies the archive, checksums, SQLite integrity and schema compatibility **before**
touching anything.

## Uninstalling

```bash
sudo gti uninstall              # removes app + services; keeps data, config, backups
sudo gti uninstall --complete   # also deletes data, config, logs, the gti user (type DELETE; final backup first)
```

Add `--remove-packages` to remove `python3-venv` if the installer added it. Nothing else is removed.

## Configuration (`/etc/global-threat-intel/gti.env`)

| Key | Default | Meaning |
|---|---|---|
| `GTI_HOST` / `GTI_PORT` | 0.0.0.0 / 8080 | listen address/port |
| `GTI_MAX_INDICATORS_PER_SOURCE` | by RAM profile | cap per feed |
| `GTI_MAX_EVENTS_PER_RUN` | by profile | live "new listing" events per fetch |
| `GTI_RETENTION_DAYS` | 30 | default retention (also editable in Settings) |
| `GTI_FLOW_RETENTION_DAYS` | 3 | GreyNoise arcs retention (high volume) |
| `GTI_COOKIE_SECURE` | 0 | 1 behind HTTPS |
| `GTI_COLLECTORS` | 1 | 0 stops all collection |
| `GTI_BACKUP_KEEP` | 7 | automatic backups kept |
| `GTI_UPDATE_URL` | empty | release manifest URL for `gti update --check` |

Restart after editing: `sudo systemctl restart global-threat-intel`. Memory limits are in
`/etc/systemd/system/global-threat-intel.service.d/10-resources.conf` (kept across updates).
