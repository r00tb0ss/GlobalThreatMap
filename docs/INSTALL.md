# Installation

## Supported platforms

| Platform | Status |
|---|---|
| Ubuntu Server 24.04 LTS or newer, x86-64 | Supported. Installer tested (see TEST-REPORT.md) |
| Ubuntu Server 24.04 LTS or newer, ARM64 | Supported by design. ARM64 wheels are pinned by hash; **not yet tested on hardware** |
| Raspberry Pi OS 64-bit (Debian 12 "bookworm" or newer) | Supported by design. **Not yet tested on hardware** |
| Raspberry Pi 4 / Pi 5 | Supported by design. **Not yet tested on hardware** |
| 32-bit OS (armhf), Pi 3 or older, non-systemd systems | Refused by the installer with an explanation |

Python 3.11 to 3.13 from the OS is used (Ubuntu 24.04: 3.12, Pi OS bookworm: 3.11, trixie: 3.13).
Every Python package installs from a prebuilt wheel (`--only-binary`, `--require-hashes`), so no compiler
is needed and nothing is built on the Pi.

## Hardware

| | Minimum | Recommended |
|---|---|---|
| RAM | 2 GB (reduced limits) | 4 GB or more |
| Free disk | 1.5 GB on /opt and /var | 8 GB+ |
| Storage | microSD works | **USB 3 SSD (Pi 4) or NVMe/USB SSD (Pi 5)** |
| GPU | not used | not used |

The installer picks limits from the RAM it finds. You can change them later in
`/etc/global-threat-intel/gti.env`:

| RAM found | Profile | IPs kept per source | Service memory limit |
|---|---|---|---|
| < 3.5 GB | 2gb | 10,000 | 400 MB |
| 3.5 to 7 GB (Pi 4/5 4 GB) | 4gb | 20,000 | 512 MB |
| 7 to 14 GB (8 GB models) | 8gb | 50,000 | 1 GB |
| 14 GB+ (Pi 5 16 GB) | 16gb | 100,000 | 1.5 GB |

**Why an SSD:** the database is written every minute (GreyNoise arcs, local sensor) and every few hours in
bulk (feeds). SQLite runs in WAL mode with `synchronous=NORMAL` to keep writes low, but cheap microSD
cards wear out and stall under continuous writes. The installer warns when it detects a microSD root.

## Steps

```bash
git clone https://github.com/r00tb0ss/GlobalThreatMap.git
cd GlobalThreatMap
sudo ./install.sh
```

or, from a release archive (verify it first):

```bash
sha256sum -c global-threat-intel-1.2.0.tar.gz.sha256
tar -xzf global-threat-intel-1.2.0.tar.gz
cd global-threat-intel-1.2.0
sudo ./install.sh
```

What it does, in order: detect OS, check hardware (Pi model, RAM), check storage, check port and
internet, install `python3 python3-venv ca-certificates curl gzip util-linux iproute2` if missing,
create the `gti` system user and directories, install the application into
`/opt/global-threat-intel/releases/<version>` with its own virtualenv, write
`/etc/global-threat-intel/gti.env`, install the GeoIP databases, create or migrate the database
(backing up an existing one first), install and start the systemd services, run health checks, and print
the URL and setup token.

If any step fails, the installer names the step, rolls back what *that run* created, keeps everything that
existed before, and writes a full log to `/var/log/global-threat-intel/install-*.log`. Re-running it is safe.
Re-running it on an installed system of the same version does nothing; use `--repair` to reinstall the
application files (configuration and data are kept).

## First-time setup

1. Open the URL the installer printed, e.g. `http://192.168.1.50:8080`.
2. Enter the setup token (shown by the installer; again with `sudo gti setup-token`).
3. Choose an administrator username and a password of 12+ characters. There are no default credentials.
4. You land on **Sources**: the free feeds are already enabled. Add an AbuseIPDB key if you have one.
5. Optionally, under **Settings**, set this machine's location so locally observed attacks draw arcs to it,
   and choose the retention period.

## Ports and network

| Port | What | Bound to |
|---|---|---|
| 8080/tcp (configurable) | Dashboard, REST API and WebSocket (`/ws`), one port | 0.0.0.0 (LAN) or 127.0.0.1 with `--local-only` |

There is **no database or cache server**: no PostgreSQL port, no Redis port. Data lives in SQLite under
`/var/lib/global-threat-intel`. Outbound HTTPS (443) only, to: feodotracker.abuse.ch, lists.blocklist.de,
cinsscore.com, rules.emergingthreats.net, api.abuseipdb.com (if enabled), threat-map.greynoise.io,
threatmap-api.checkpoint.com, livethreatmap.radware.com (which currently redirects to ltm-prod-api.radware.com),
download.db-ip.com, your DNS resolver for reverse-DNS lookups when you open an IP, and pypi.org during install/update
(online package only). **Measured: about 200 MB/day of downloads** with every source on (6-minute sample,
see TEST-REPORT.md), most of it Radware (see DATA-SOURCES.md). `sudo gti health` shows the live rate.
Disable Radware on the Sources page on a metered connection.

The installer does **not** change the firewall. If `ufw` is active, allow your LAN only, for example:

```bash
sudo ufw allow from 192.168.0.0/16 to any port 8080 proto tcp
```

Do not forward the port on your router. For access from outside your network use a VPN (WireGuard/Tailscale),
or put an HTTPS reverse proxy in front and set `GTI_COOKIE_SECURE=1`.

## Raspberry Pi notes

- **Pi 4 and Pi 5 use the same procedure.** Use the 64-bit Raspberry Pi OS (Lite is fine).
- Pi 5: prefer an NVMe HAT or a USB 3 SSD. Pi 4: a USB 3 SSD in a blue USB port.
- No GPU, desktop or browser is needed on the Pi. Open the dashboard from another device on your LAN.
- The service is `Nice=5` with idle I/O for backups, so it yields to anything else running on the Pi.
