# Data sources

Every record carries its source and an **observation type**:

| Observation type | Meaning |
|---|---|
| `direct_observation` | This machine saw the traffic itself (local sensor). |
| `sensor_network_observation` | A sensor network (GreyNoise) recorded a real session against one of *its* sensors. |
| `third_party_report` | A provider lists the IP as malicious. **Not proof** that the IP attacked anything. |
| `vendor_telemetry` | A security vendor (Check Point, Radware) publishes attacks its own sensors/customers saw, as shown on its public threat map. Area-level, no IPs. |

| Source | Type | Key needed | Interval | Shown as |
|---|---|---|---|---|
| abuse.ch Feodo Tracker | third-party report (botnet C2) | no | 1 h | dots, IP detail |
| blocklist.de (48 h) | third-party report (reported attacker, with the service attacked) | no | 3 h | dots, IP detail |
| CINS Army list | third-party report (reported attacker) | no | 3 h | dots, IP detail |
| Emerging Threats compromised IPs | third-party report (compromised host) | no | 6 h | dots, IP detail |
| AbuseIPDB blacklist | third-party report (reported attacker) | **yes**, free account at abuseipdb.com | 24 h | dots, IP detail, per-IP report lookups |
| Local sensor (this host) | direct observation: SSH auth failures, UFW blocks from the systemd journal | no | 1 min | dots + arcs to your location |
| GreyNoise global sensor network | sensor-network observation, attacker area to GreyNoise sensor, MITRE tactic | no | 1 min | arcs + sensor diamonds |
| Check Point ThreatCloud live map | vendor telemetry: attack name (often with CVE), type, source and target region | no | live stream | arcs |
| Radware live threat map | vendor telemetry: attack type, source and target country (playback, see below) | no | 1 min | arcs, or pulses when no target |

## Arc sources (GreyNoise, Check Point, Radware)

The owner of this installation confirmed that use of all three is permitted. All three are the data
endpoints behind the vendors' public threat-map pages, **not documented APIs**. They can change or
disappear without notice; the source then shows *error* or *stale* and the rest of the platform keeps working.
None of them publishes attacker IP addresses, so arcs cannot be investigated per IP and are never counted in
IP statistics or scores. Every arc is labelled with its source in the ticker, legend and API.

| | GreyNoise | Check Point | Radware |
|---|---|---|---|
| Transport | poll every 60 s | one persistent server-sent-events stream (reconnects 10 s → 5 min backoff) | poll every 60 s (100 s of schedule) |
| Location precision | city (attacker), sensor city (target) | region/state coordinates | country only (Natural Earth label point) |
| Classification | MITRE ATT&CK tactic | attack type + attack name, often with CVE | scanner, botnet, web attacker, DDoS attacker, IoT botnet, intruder, anonymizer |
| Timing | real 1-minute windows | real time of arrival | **playback**: see below |
| Stored as | one row per session per minute, 72 h | identical events within 10 s merged (counts added), 24 h | per-minute counts by (source country, target country, type), 2 h |
| Download | small (estimate ~5 MB/day) | not separately measured | the bulk of the total (~100 KB/poll gzip) |

Measured total for the whole service with every source on: **~200 MB/day** (864 KB in a 6-minute sample, 1.1.0).

**Radware timing.** Radware's endpoint returns a pre-scheduled queue whose event timestamps run several minutes
into the future; the same future second returns the same events on every request. So Radware's per-event times
are display times it assigns, not attack times. This platform ingests each scheduled event exactly once, records
it at the time it was received, labels the source "Radware (playback)", and animates each batch spread over the
following minute (the same pacing Radware uses). About half of Radware's events name no target country: these are
drawn as a pulse at the source country, never as an arc to an invented target. Same-country events (e.g. US → US)
are also pulses, because both ends share one country label point.

**Check Point** repeats identical events several times in a row; these are merged per 10-second window with the
counts added, so totals are preserved without duplicate arcs. The "attacks reported today" figure is Check Point's
own counter from the stream. Attack names and CVE IDs are Check Point's classification, shown as published.

**Bandwidth on a Raspberry Pi.** Radware is by far the largest download (gzip cuts each poll from ~925 KB to ~71 KB). If your connection is metered, disable it
on the **Sources** page. Nothing else changes.

**Mixed scales.** Sources count differently (a GreyNoise session, a Check Point detection and a Radware event are not
equivalent), so the "Top activity" panel's combined totals mix scales; it says so on screen.

## IP details: "What this IP is doing"

Click a dot (or a ticker / live-feed row) to open the IP panel. Where several dots overlap, a list of the IPs
near that spot appears first. The panel explains, line by line, what the evidence says the IP does. Each line is
marked **Observed here** (this machine's own logs) or **Reported** (a third party's claim), and names its source:

The **Host** section comes first:

| Field | Meaning | Source |
|---|---|---|
| Hostname | Reverse DNS (PTR) name, e.g. `pool-…fios.verizon.net` (a home line) or `mx.example.ru` (a mail server). **Verified** means the name resolves back to the same IP; an unverified name is whatever the IP's owner set and may be misleading | this machine's DNS resolver, on click, cached 24 h |
| Region, network block, location block | Region/continent, the announced route containing the IP, and the smaller block DB-IP locates | local DB-IP databases (no outbound request) |
| Network type | "Hosting / cloud provider" when the operator's name says so (a rented server rather than a home connection). A name match only, labelled as a guess | built-in name list |
| In this database / Same /24 / Same network | When this platform first and last saw the IP, and how many other listed IPs share its /24 and its ASN (many neighbours often means a hostile or compromised network) | local database |

Reverse DNS means your resolver asks the DNS server responsible for that IP's reverse zone, which the IP's owner may
run, so the owner could notice the lookup. It happens only when you open the IP.

| Evidence | What it tells you | Source |
|---|---|---|
| Feodo Tracker listing | Runs a botnet command-and-control server, with the malware family and C2 port | abuse.ch |
| blocklist.de service lists | Which services it was reported attacking: SSH, mail (SMTP), mailbox logins (IMAP/POP3), web servers, website logins (WordPress/Joomla), FTP, VoIP (SIP), spam bots, or "persistent attacker" | blocklist.de per-service lists, fetched with the main list (about 0.5 MB every 3 h) |
| CINS / Emerging Threats listing | Hit CINS sensors with scans or attacks / believed compromised | CINS, Proofpoint ET |
| Local sensor | Exact count of SSH login failures or blocked connections to this machine, and the ports | this host |
| Ports involved | What the port is for and what attempts on it usually aim at (e.g. 3389 → RDP password guessing). **General context, not proof of this IP's intent** | built-in table |
| AbuseIPDB reports (optional) | Report categories with counts (brute-force, port scan, SQL injection, web app attack, ...), total reports and reporters, network type (data centre, ISP, ...), ISP, domain, Tor, and up to 5 recent reporter notes | AbuseIPDB `check` API, **only with your key** |

**AbuseIPDB lookups** happen when you open an IP with an AbuseIPDB key saved and the source enabled. The server
makes the request with the stored key (the key never reaches the browser), only for public IPs that are already in
the database, and caches each result for 24 h (pruned after 7 days) to stay within the free plan's 1,000 lookups per
day. If the daily limit is reached, the saved result is shown with a notice. Reporter notes are free text written by
other AbuseIPDB users: they are shown as plain text, truncated, and labelled unverified.

## Exploits and attacks on AI software

Check Point names the exploit or signature it detected (often with a CVE or Microsoft bulletin id). The **Top
activity** panel lists the most-detected exploits in the last hour with their CVE, and the ticker shows the name on
each Check Point arc. **Attacks on AI software** lists exploits whose name targets an AI/machine-learning product
(LangChain, Langflow, LlamaIndex, Ollama, Open WebUI, Flowise, MLflow, Ray, ComfyUI, Gradio, Jupyter, MCP servers,
AI plugins, ...); those arcs carry an "AI target" badge in the ticker. Examples seen in testing: *LangChain
Community Server-Side Request Forgery (CVE-2025-2828)*, *Langflow Remote Code Execution*, *Flowise Authentication
Bypass (CVE-2024-36421)*, *MLflow Information Disclosure (CVE-2023-43472)*.

This means attacks **aimed at** AI software. None of the sources reports whether an attacker **used** AI to carry
out an attack, so the platform does not claim that. Per-IP exploit names are not available: the vendors that name
exploits (Check Point) do not publish attacker IPs, and the IP feeds do not name exploits. AbuseIPDB categories
(e.g. "SQL injection", "Web app attack") are the closest per-IP equivalent.

## Live feed

The **Live feed** tab has two views (the choice is remembered):

- **IP listings**: each new listing with a one-line *What it's doing*, built from the same evidence as the IP panel:
  blocklist.de service tags ("Attacking SSH logins, mail servers", "Spam bot", "persistent attacker"), Feodo
  ("Botnet C2 server for QakBot (port 447)"), the local sensor ("SSH password guessing against this machine",
  "Blocked connection to this machine on port 3389 (RDP)") or the source's meaning (CINS, Emerging Threats,
  AbuseIPDB). Each line is marked *Observed* or *Reported*. Click a row to open the IP panel. New listings arrive
  in bursts, when a list is downloaded again (hourly to every 6 hours, as the providers ask), so the view shows
  when each list is next downloaded. Only the local sensor adds rows continuously.
- **Attacks**: every attack from the last hour (up to 5,000 rows; the note above the table shows how many):
  - **Threat-map rows** (GreyNoise, Check Point, Radware): time, attacker area → target, type (exploit, malware,
    phishing, scanner, botnet, MITRE tactic, ...), attack or exploit name with CVE and an "AI target" badge, count
    and source. **These vendors publish no attacker IP addresses**, so these rows cannot be investigated per IP.
    The platform does not pair them with blocklist IPs: that would be a guess presented as fact.
  - **Observed rows** (local sensor): attacks on this machine, with the attacker's real IP. Click the row to open
    the IP panel. These appear only on Linux with the local sensor enabled.

  Sources are interleaved, newest first, so no single source fills the top of the list. New rows arrive live.

## Ticker: live and replay

The ticker (bottom right) starts in **LIVE** mode: it shows items as they arrive (Check Point within seconds,
GreyNoise and Radware each minute, paced over that minute, feeds when they are fetched). **Replay** is optional: it
loops real stored data at about one item per second, IP listings from the last 24 h and arcs from the last hour,
showing each item's recorded time. Replay repeats items and is not real-time pacing; the ticker says so while it runs.

## Notes and limits

- **Local sensor** needs systemd-journald (always present on supported systems). It only sees traffic that
  reaches this machine: behind a home router with no forwarded ports it will often be quiet. That is
  accurate, not a fault. UFW must have logging on (`sudo ufw logging on`) for firewall blocks to appear.
  Source addresses of UDP/ICMP can be spoofed.
- **Feeds are snapshots.** An IP that disappears from a list is marked "no longer listed", not deleted, and
  is removed after the retention period.
- **Safety guards:** a feed returning no valid records, or shrinking below half of its previous size, is
  treated as a format change or outage. The previous data is kept and the source is flagged.
- **Caps:** each source keeps at most `GTI_MAX_INDICATORS_PER_SOURCE` IPs (in provider order). The live feed
  emits at most `GTI_MAX_EVENTS_PER_RUN` "new listing" events per fetch so a first fetch does not flood the
  map. Sources that hit the cap say so on the Sources page.
- **GeoIP**: DB-IP Lite (CC BY 4.0), refreshed monthly by a timer. City-level positions are approximate.
  Anycast addresses (e.g. 1.1.1.1, 8.8.8.8) are placed at one arbitrary site.
