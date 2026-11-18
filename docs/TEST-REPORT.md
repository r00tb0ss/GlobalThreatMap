# Test report: Global Threat Intelligence Platform 1.2.0

Date: 2026-11-18. Tested application version: **1.2.0** (release archives in `dist/`, checksums in `dist/SHA256SUMS`).
1.1.0 added the Check Point and Radware arc sources; 1.2.0 adds the "What this IP is doing" panel, host details (reverse DNS, network blocks, neighbours), blocklist.de
service tags, optional AbuseIPDB per-IP lookups, exploit/CVE and AI-software labels, and easier dot selection.
The lifecycle tests below were run on 1.0.x; the upgrade paths 1.0.2 → 1.1.0 → 1.2.0 were then tested on the same
installation (sections "1.1.0" and "1.2.0").

## Overall result

**Ready, with known limitations.** The installer, updater, backup/restore and uninstaller were exercised end to end
on Ubuntu 24.04 x86-64 under systemd, including failure and recovery paths. **No Raspberry Pi or other ARM64 hardware
was available, so every ARM64 / Raspberry Pi result below is UNVERIFIED.** It is supported by design, but not tested.

## Test environment

| Item | Value |
|---|---|
| Host | Windows 11 PC, WSL 2 |
| Test OS | Ubuntu 24.04.3 LTS (x86_64, amd64), systemd as PID 1, Python 3.12.3 |
| Isolation | Two disposable WSL distros cloned from the base image: `gti-build` (build/lint) and `gti-test` (install tests). The user's own distro was not modified. |
| Host resources | 24 CPU threads, 16 GB RAM (the installer selected the 16gb profile; the 4 GB Pi profile was applied manually for measurements) |
| Dev/UI testing | Windows, Python 3.13, built-in browser |

WSL is not identical to a physical server: "reboot" was `wsl --terminate` followed by a cold start of the distro (systemd boots
fresh), and there is no real network interface or router in front of it.

## Platform compatibility

| Platform | Result |
|---|---|
| Ubuntu Server 24.04 x86-64 | **Verified** (WSL 2, see above) |
| Ubuntu Server 24.04 ARM64 | **Untested.** Lock contains hash-pinned aarch64 wheels for every package (pydantic-core, websockets, maxminddb native) |
| Raspberry Pi OS 64-bit (bookworm/trixie) | **Untested** |
| Raspberry Pi 4, 4 GB / 8 GB | **Untested** |
| Raspberry Pi 5, 4 GB / 8 GB / 16 GB | **Untested** |
| 32-bit / non-systemd / Ubuntu < 24.04 | Refusal logic present; refusal paths **not executed** on such systems |

What *was* verified for ARM64: `pip download --only-binary --platform manylinux2014_aarch64` resolved every dependency for
CPython 3.11, 3.12 and 3.13 (no source builds needed), and those wheels are bundled in the offline package.

## Automated tests: 88 passed, 0 failed (1.2.0)

Run on Windows/Python 3.13 and on Ubuntu/Python 3.12 against the hash-locked dependencies.
Coverage: feed parsers (valid/invalid/format change), IPv4/IPv6/mapped/private filtering, scoring known cases, auth
(setup token, policy, throttling, sessions, CSRF, origin checks), every API endpoint incl. invalid inputs, API keys never
returned, settings validation and persistence, ingestion dedup (no inflated counts), outage/stale/shrink guards, caps,
retention, scheduling/backoff, atomic rollback of a failed ingest, WebSocket auth/origin/delivery, local sensor parsing +
forged-log rejection, GreyNoise parsing/dedup/staleness, Check Point SSE parsing/merging/reconnect/error reporting,
Radware playback ingest-once/aggregation/unknown targets, country positions, gzip-bomb guard,
migrations v1→v5 preserving data, blocklist.de service tags (incl. partial list failure keeping
previous tags), AbuseIPDB lookups (key never returned or leaked in errors, 24 h cache, quota-exhausted fallback,
private/unknown IPs never sent out, disabled source makes no request), exploit CVE extraction, AI-software matching, feed activity wording for stored and live events, host details (reverse-DNS caching and timeout, /24 and ASN
neighbour counts, private/unknown IPs refused),, newer-schema refusal,
backup→restore round trip, tampered/path-traversal archives rejected, static MIME types, no inline scripts/innerHTML,
no third-party URLs, vendored-file integrity. `shellcheck -S warning` is clean on every script.

## Installer and lifecycle tests (gti-test distro)

| # | Test | Result |
|---|---|---|
| 1 | Fresh install, online package | **Pass**: 13/13 steps in 24 s; python3-venv installed automatically |
| 2 | Health check after install | **Pass**: service, timers, port, DB integrity, 6 sources collecting |
| 3 | Re-run installer on installed system | **Pass**: "already installed, nothing to do"; config/DB untouched |
| 4 | install.sh of a different version on top | **Pass**: refused, pointed to update.sh |
| 5 | Upgrade 1.0.0 → 1.0.1 → 1.0.2 with `gti update` | **Pass**: ~9 s each; admin password, API key, settings, history preserved |
| 6 | Failed upgrade (new migration + crashing app) | **Pass on 1.0.2** (rollback to previous version, DB restored to old schema, healthy, 26 s). **Failed on 1.0.1**: see bugs |
| 7 | Crash (`kill -9`) | **Pass**: systemd restarted it, healthy after 6 s |
| 8 | Reboot (distro cold start) | **Pass**: service and timers started automatically |
| 9 | Backup → change data → restore | **Pass**: settings restored; pre-restore backup made |
| 10 | Restore corrupted archive | **Pass**: rejected before any change; service unaffected |
| 11 | Standard uninstall | **Pass**: app/services/port gone; data, config, backups kept |
| 12 | Reinstall onto kept data | **Pass**: existing config kept, DB backed up then migrated, same login works |
| 13 | Complete uninstall | **Pass**: final backup written; data, config, logs, user removed; backups kept |
| 14 | Interrupted install (SIGINT at step 9) | **Pass**: rolled back completely; re-run succeeded |
| 15 | No internet + online package | **Pass**: clear refusal at step 4, nothing left behind |
| 16 | No internet + offline package | **Pass**: full install from bundled wheels + GeoIP; feeds honestly show errors |
| 17 | Low RAM | **Simulated** (profile function with stubbed RAM): <1.8 GB refused, 2/4/8/16 GB profiles correct |
| 18 | Low disk | **Not executed**: code path reviewed only |
| 19 | Internet loss while running, then recovery | Feeds flagged as failing (tested); automatic recovery after reconnection **covered by unit test only** (15-min retry) |
| 20 | Full disk while running | **Not tested** |

## Bugs found and fixed during testing (all retested)

1. Clearing an API key on an enabled source returned an error instead of disabling it.
2. JavaScript served as `text/plain` on hosts with a wrong MIME database, so the dashboard was blank. Fixed with explicit MIME types.
3. Static files were cached by browsers, which would leave old JavaScript after an update. They are now revalidated.
4. Map tiles (CARTO) started returning "API key required". Replaced with a bundled Natural Earth basemap: no external requests.
5. Phone layout: feed table overflowed; map filter dropdowns squashed; overlays overlapped.
6. Sensor arcs drew beneath the basemap (pane order) and crossed the antimeridian off-map.
7. Health-check script used Python syntax that fails on Python 3.11 (Raspberry Pi OS bookworm).
8. `die` did not trigger rollback (bash `exit` skips the ERR trap) in install and update scripts.
9. update.sh same-version reinstall could delete the running release. It now refers to `install.sh --repair`.
10. `/etc/os-release` overwrote the installer's VERSION variable, so the installer printed "v24.04.3 LTS".
11. Local sensor accepted `logger -t sshd` lines from any local user. Now only root-owned sshd lines and kernel lines are accepted.
12. **Failed upgrade left the service down** (1.0.1): the crashing new version exhausted systemd's restart limit, so the
    rolled-back version could not start. Fixed: reset-failed before start, and the health wait aborts as soon as the new
    version crash-loops.
13. Offline bundle re-resolved dependencies instead of using the hash-locked versions.
14. Radware: two polls in the same second produced identical row keys, so a whole batch was silently dropped. Batches now carry their own id.
15. Check Point stream: the final flush after a disconnect marked the source healthy and erased the error. Errors now stay visible.
16. Country positions: Natural Earth's "Ashmore and Cartier Is." (fallback code AU) replaced Australia, putting every
    Australian target on an uninhabited reef. Real codes now win; a test pins key countries inside their borders.
17. Same-country vendor events (e.g. US → US) drew zero-length arcs. They are pulses now.
18. Health check reported the normal "capped at per-source limit" note as a warning.
19. Arc animation could freeze: the animation frame's timestamp can be earlier than a new arc's start time; the
    negative progress threw an error that stopped the animation loop (heads stuck on the map). Clamped.
20. With replay off, the legend's arc totals and the Top activity panel never loaded (they were only fetched by
    replay). They now load at start and refresh every minute.
21. Replay was on by default and labelled "last 24h", but replayed arcs only covered the last hour and looped. Live
    is now the default; replay is labelled as a loop of recorded data with its real time ranges.

## 1.2.0: IP activity, exploits, AI-software attacks (gti-test, upgraded from 1.1.0)

| Test | Result |
|---|---|
| `gti update` 1.1.0 → 1.2.0 (schema v4 → v5) | **Pass** in 10 s: backup first, migration ok, healthy; 48,696 indicators, admin user and settings preserved; 1.1.0 kept for rollback |
| Fresh `git clone` of the GitHub commit (via git bundle) | **Pass**: LF line endings, executable scripts, shellcheck clean, 88 tests pass, release builds |
| `sudo ./install.sh --repair --yes` run directly from the git checkout | **Pass**: 13/13 steps, config and database kept (backup taken), healthy, no journal warnings |
| Update without the `.sha256` file next to the package | **Pass**: refused ("Refusing an unverified update") |
| blocklist.de service lists inside the systemd sandbox | **Pass**: 13,300 of 20,000 IPs tagged (ssh, mail, imap, apache, bots, ...); no warnings in the journal |
| IP panel in the browser (dev server, Windows) | **Pass**: activity lines with source and observed/reported marking; port context; AbuseIPDB hint without key |
| Host section (dev server, live DNS) | **Pass**: verified PTR names (e.g. a Verizon FiOS home line), network/location blocks match DB-IP, neighbour counts. Windows adds ~4.5 s per reverse lookup, so the timeout is 5 s and the section loads separately. Reverse DNS inside the Linux service sandbox **not exercised** (the sandbox already resolves feed hostnames through the same resolver) |
| Live feed, both views (dev server, live data) | **Pass**: IP rows show what each IP is doing (from stored service tags, malware, ports); attack rows show exploit/CVE, malware families, botnets, scanners, tactics (all 3,840 of the last hour shown); an observed local-sensor attack (one temporary test row in the dev database, removed afterwards; the sensor needs Linux) shows its IP and opens the IP panel on click; live rows arrive over the WebSocket; no horizontal overflow at 1440 px |
| Clicking stacked dots | **Pass**: a click on a crowded spot lists the IPs there (106 in one test); choosing one opens it |
| Top exploits / attacks on AI software (live Check Point data) | **Pass**: e.g. LangChain SSRF (CVE-2025-2828), Langflow RCE, MLflow (CVE-2023-43472) |
| AbuseIPDB per-IP lookup against the live API | **Not tested**: no AbuseIPDB key was available; covered by unit tests with recorded responses |

## 1.1.0: new arc sources (gti-test, upgraded from 1.0.2, 4 GB Pi profile)

| Test | Result |
|---|---|
| `gti update` 1.0.2 → 1.1.0 (schema v3 → v4) | **Pass**: backup first, migration ok, healthy, previous release kept |
| Check Point stream inside the systemd sandbox | **Pass**: connected, healthy, live events (e.g. "Multiple SSH Initial Connection Requests", South Korea → Germany ×395) |
| Radware playback inside the sandbox | **Pass**: scanners, web attackers, intruders, DDoS attackers, botnets ingested once per scheduled event |
| GreyNoise, feeds, local sensor after upgrade | **Pass**: all healthy |
| 6-minute observation | memory steady **46 MB**; CPU **2.25 s** total; no restarts; no warnings in the journal |
| Network (systemd IPAccounting) | **864 KB in 6 min ≈ 200 MB/day** with all sources on (most of it Radware) |
| Check Point / Radware endpoint loss | Covered by unit tests (reconnect with backoff, error shown, data kept); not exercised against the live services |

Note on what these sources are: all three arc sources are the undocumented endpoints behind the vendors' public
threat-map pages. Their use was confirmed as permitted by the owner of this installation. They contain no IP
addresses. Radware's endpoint is a pre-scheduled playback (timestamps up to ~6 minutes in the future, identical on
repeated requests), so its timing is labelled "playback". Check Point's page also contains a client-side random
attack generator; this platform uses only the real server stream.

## Measured performance (x86-64 host, NOT a Raspberry Pi)

Configuration: 4 GB Pi profile (20,000 IPs per source, `MemoryMax=512M`), fresh database, all 6 sources enabled.

| Metric | Value |
|---|---|
| Start to healthy | 1 s |
| Memory right after start | 35 MB |
| Memory during collection (6 min, sampled every 15 s) | 145 to 173 MB |
| Memory after API load test | 275 MB (limit 512 MB) |
| CPU, first 6 minutes incl. initial ingest of ~40,000 IPs | 2.1 s total |
| Ingest of a 20,000-IP feed (download + parse + GeoIP + write) | under 1 s (dev log) |
| API median latency: health / ip / events / flows / stats | 1.9 / 2.4 / 6.5 / 5.2 / 15.9 ms |
| API `/api/map` (5,000 points) | median 116 ms, max 647 ms (uncached), 68 KB gzipped |
| Database size with ~40,000 IPs | 8.3 MB |

Raspberry Pi CPUs are several times slower per core than this host; expect proportionally higher latencies
(for example a first map load of a few seconds on a Pi 4). **These are not Pi measurements.** WebSocket delivery
latency was verified functionally (events arrive) but not timed.

## Still to do before calling Raspberry Pi support verified

1. Run `sudo ./install.sh` on a Pi 4 (4 GB) and a Pi 5 with 64-bit Raspberry Pi OS. Record each step's output.
2. Run `sudo gti health`, leave it 24 h, record `systemctl show global-threat-intel -p MemoryPeak -p CPUUsageNSec`.
3. Repeat test 5 (update) and test 8 (real reboot) on the Pi.
4. Ubuntu Server 24.04 ARM64 on a Pi or ARM VM.
