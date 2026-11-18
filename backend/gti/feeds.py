"""Intelligence feed definitions and parsers.

Every record carries: ip, category, optional malware/port.
All current feeds are THIRD-PARTY REPORTS (observation_type="third_party_report"):
they say a provider listed an IP, not that this platform observed an attack.
"""
import ipaddress
import json
import re

OBSERVATION_TYPE = "third_party_report"
MAX_BODY = 25 * 1024 * 1024


def norm_ip(text):
    """Return canonical global IP string or None."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except (ValueError, AttributeError):
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return None
    return str(ip)


_IP_LINE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*(?:[#;].*)?$")


def parse_plain_ip_list(body, category):
    out = []
    for line in body.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        m = _IP_LINE.match(line)
        ip = norm_ip(m.group(1)) if m else None
        if ip:
            out.append({"ip": ip, "category": category})
    return out


def parse_feodo(body):
    data = json.loads(body)
    if isinstance(data, dict):
        data = data.get("blocklist", data.get("data"))
    if not isinstance(data, list):
        raise ValueError("unexpected Feodo format: no list")
    out = []
    for r in data:
        if not isinstance(r, dict):
            continue
        ip = norm_ip(str(r.get("ip_address", "")))
        if not ip:
            continue
        port = r.get("port")
        out.append({"ip": ip, "category": "botnet_c2",
                    "malware": r.get("malware") or None,
                    "port": port if isinstance(port, int) and 0 < port < 65536 else None})
    return out


def parse_blocklist_de(body):
    return parse_plain_ip_list(body, "reported_attacker")


def parse_cins(body):
    return parse_plain_ip_list(body, "reported_attacker")


def parse_et_compromised(body):
    return parse_plain_ip_list(body, "compromised_host")


def parse_abuseipdb(body):
    data = json.loads(body)
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError("unexpected AbuseIPDB format: no data list")
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = norm_ip(str(r.get("ipAddress", "")))
        if ip:
            out.append({"ip": ip, "category": "reported_attacker"})
    return out


TACTICS = ("reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
           "collection", "command-and-control", "exfiltration", "impact")
_SENSOR_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
MAX_FLOWS_PER_RUN = 500


def _coord(v, lim):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and -lim <= v <= lim


def parse_greynoise_beacons(body):
    """GreyNoise threat-map beacons: attacker area -> GreyNoise sensor, with MITRE tactic.

    Returns (generated_at_epoch_or_None, flows). Entries with invalid coordinates, unknown tactics or
    bad counts are dropped. An empty beacon list is valid (quiet minute); a missing list is a format change.
    """
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("beacons"), list):
        raise ValueError("unexpected GreyNoise format: no beacons list")
    gen = None
    g = data.get("generatedAt")
    if isinstance(g, str):
        from datetime import datetime
        try:
            gen = int(datetime.fromisoformat(g.replace("Z", "+00:00")).timestamp())
        except ValueError:
            gen = None
    out = []
    for b in data["beacons"]:
        if not isinstance(b, dict):
            continue
        sl, so, dl, do = b.get("srcLat"), b.get("srcLng"), b.get("lat"), b.get("lng")
        if not (_coord(sl, 90) and _coord(so, 180) and _coord(dl, 90) and _coord(do, 180)):
            continue
        tactic = b.get("tactic")
        if tactic not in TACTICS:
            continue
        cnt = b.get("count")
        if isinstance(cnt, bool) or not isinstance(cnt, int) or not 0 < cnt <= 10_000_000:
            continue
        sid = str(b.get("sessionId") or "")[:64]
        if not sid:
            continue
        name = b.get("sensorName")
        name = name if isinstance(name, str) and _SENSOR_NAME.match(name) else None
        also = [t for t in (b.get("alsoSeen") or []) if t in TACTICS][:len(TACTICS)]
        out.append({"session_id": sid, "src_lat": float(sl), "src_lon": float(so), "dst_lat": float(dl),
                    "dst_lon": float(do), "dst_name": name, "tactic": tactic, "also_seen": also, "count": cnt})
        if len(out) >= MAX_FLOWS_PER_RUN:
            break
    return gen, out


# ---------------------------------------------------------------------------------------------
# Vendor threat-map feeds (no attacker IPs). Use permitted by the owner of this installation.
# ---------------------------------------------------------------------------------------------
_COUNTRIES = None


def countries():
    """ISO-3166 alpha-2 -> (lat, lon, name) label points from Natural Earth (backend/gti/data/countries.json)."""
    global _COUNTRIES
    if _COUNTRIES is None:
        import os
        with open(os.path.join(os.path.dirname(__file__), "data", "countries.json"), encoding="utf-8") as fh:
            _COUNTRIES = {k: tuple(v) for k, v in json.load(fh).items()}
    return _COUNTRIES


_WORD = re.compile(r"^[a-z][a-z_]{0,23}$")
_CC = re.compile(r"^[A-Z]{2}$")


def _clean_text(v, n):
    return v.strip()[:n] if isinstance(v, str) and v.strip() and v.isprintable() else None


def parse_checkpoint_attack(data):
    """One Check Point 'attack' SSE event (JSON text) -> flow dict, or None if invalid."""
    try:
        d = json.loads(data)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    sl, so, dl, do = d.get("s_la"), d.get("s_lo"), d.get("d_la"), d.get("d_lo")
    if not (_coord(sl, 90) and _coord(so, 180) and _coord(dl, 90) and _coord(do, 180)):
        return None
    atype = d.get("a_t")
    if not isinstance(atype, str) or not _WORD.match(atype.lower()):
        return None
    cnt = d.get("a_c", 1)
    if isinstance(cnt, bool) or not isinstance(cnt, int) or not 0 < cnt <= 1_000_000:
        return None
    sc, dc = d.get("s_co"), d.get("d_co")
    names = countries()
    return {"src_lat": float(sl), "src_lon": float(so), "dst_lat": float(dl), "dst_lon": float(do),
            "attack_type": atype.lower(), "attack_name": _clean_text(d.get("a_n"), 120), "count": cnt,
            "src_name": names[sc][2] if isinstance(sc, str) and sc in names else None,
            "dst_name": names[dc][2] if isinstance(dc, str) and dc in names else None}


RADWARE_TYPES = ("scanners", "botnets", "webAttackers", "dDosAttackers", "ioTBotnets", "intruders", "anonymizers")


def radware_time(s):
    """'2026-11-17T23:58:11.9366667' (UTC, up to 7 fractional digits) -> epoch seconds (float)."""
    from datetime import datetime, timezone
    base, _, frac = s.partition(".")
    t = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return t + (float("0." + frac) if frac.isdigit() else 0.0)


def parse_radware(body):
    """Radware /api/map/attacks -> list of events {at, src, dst|None, type}. Invalid entries dropped.

    The response is a list of per-second batches. Radware schedules these for playback: timestamps are display
    times assigned by Radware and extend into the future, so they are NOT used as attack times by this platform.
    """
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError("unexpected Radware format: not a list")
    out = []
    for batch in data:
        if not isinstance(batch, list):
            continue
        for e in batch:
            if not isinstance(e, dict) or e.get("type") not in RADWARE_TYPES:
                continue
            src = (e.get("sourceCountry") or "").strip().upper()
            dst = (e.get("destinationCountry") or "").strip().upper()
            if not _CC.match(src):
                continue
            try:
                at = radware_time(str(e.get("attackTime", "")))
            except ValueError:
                continue
            out.append({"at": at, "src": src, "dst": dst if _CC.match(dst) else None, "type": e["type"]})
    return out


# id -> definition. weight: see scoring.py. interval in seconds. key: HTTP header name for the API key.
FEEDS = {
    "feodo": dict(name="abuse.ch Feodo Tracker", url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                  parse=parse_feodo, weight=90, interval=3600, key=None,
                  desc="Botnet C2 servers (Emotet, Dridex, QakBot, ...). No key required."),
    "blocklist_de": dict(name="blocklist.de (last 48h)", url="https://lists.blocklist.de/lists/all.txt",
                         parse=parse_blocklist_de, weight=50, interval=3 * 3600, key=None,
                         # per-service lists: record WHAT each IP was reported attacking (shown in IP details)
                         tag_lists={t: f"https://lists.blocklist.de/lists/{t}.txt" for t in
                                    ("ssh", "mail", "imap", "apache", "bruteforcelogin", "ftp", "sip", "bots",
                                     "strongips")},
                         desc="IPs reported for SSH/mail/web attacks by fail2ban users, with the service each "
                              "IP attacked. No key required."),
    "cins": dict(name="CINS Army list", url="https://cinsscore.com/list/ci-badguys.txt",
                 parse=parse_cins, weight=55, interval=3 * 3600, key=None,
                 desc="Poorly-rated IPs from Collective Intelligence Network Security. No key required."),
    "et_compromised": dict(name="Emerging Threats compromised IPs",
                           url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                           parse=parse_et_compromised, weight=60, interval=6 * 3600, key=None,
                           desc="Hosts believed compromised. No key required."),
    "abuseipdb": dict(name="AbuseIPDB blacklist", url="https://api.abuseipdb.com/api/v2/blacklist?limit=10000",
                      parse=parse_abuseipdb, weight=65, interval=24 * 3600, key="Key",
                      desc="Community-reported abusive IPs. Requires a free API key (rate limited)."),
    "local_sensor": dict(name="Local sensor (this host)", url=None, parse=None, weight=60, interval=60, key=None,
                         kind="sensor",
                         desc="SSH login failures and UFW firewall blocks seen by this machine's own logs. "
                              "Direct observations of traffic sent to this host. No key required."),
    "greynoise_map": dict(name="GreyNoise global sensor network", url="https://threat-map.greynoise.io/api/activity-beacons",
                          parse=parse_greynoise_beacons, weight=0, interval=60, key=None, kind="flows", keep_hours=72,
                          desc="Live arcs from attacker areas to GreyNoise honeypot sensors worldwide, classified by "
                               "MITRE ATT&CK tactic. Real observed sessions; attacker IPs are not published, so arcs "
                               "cannot be investigated per IP. Attacker locations are approximate. No key required."),
    "checkpoint_map": dict(name="Check Point ThreatCloud live map", url="https://threatmap-api.checkpoint.com/ThreatMap/api/feed",
                           parse=None, weight=0, interval=10, key=None, kind="stream", keep_hours=24,
                           desc="Live stream of attacks detected by Check Point (attack name/CVE, type, source and "
                                "target region). Vendor telemetry; no IP addresses. Locations are region-level. "
                                "Kept for 24 h. No key required."),
    "radware_map": dict(name="Radware live threat map (playback)", url="https://livethreatmap.radware.com/api/map/attacks?limit=100",
                        parse=parse_radware, weight=0, interval=60, key=None, kind="rwplay", keep_hours=2,
                        desc="Attacks seen by Radware's honeypot network and cloud services, by type and country. "
                             "Radware delivers these as a pre-scheduled playback, so individual event times are "
                             "Radware's display times, not exact attack times. Country-level, no IPs, about half "
                             "without a known target. Stored as per-minute counts for 2 h. No key required."),
}

WEIGHTS = {k: v["weight"] for k, v in FEEDS.items()}

CATEGORIES = {   # id -> (label, observation type it comes from)
    "botnet_c2": "Botnet C2 server",
    "reported_attacker": "Reported attacker",
    "compromised_host": "Compromised host",
    "ssh_bruteforce": "SSH brute force (observed)",
    "blocked_connection": "Firewall block (observed)",
}


def observation_type(fid):
    kind = FEEDS.get(fid, {}).get("kind")
    if kind == "sensor":
        return "direct_observation"
    if kind == "flows":
        return "sensor_network_observation"
    if kind in ("stream", "rwplay"):
        return "vendor_telemetry"
    return OBSERVATION_TYPE


FLOW_KINDS = ("flows", "stream", "rwplay")   # sources that produce arcs (flows table), not IP indicators


def request_headers(feed_id, api_key):
    f = FEEDS[feed_id]
    h = {"User-Agent": "GlobalThreatIntel/1.0", "Accept": "application/json, text/plain", "Accept-Encoding": "gzip"}
    if f["key"] and api_key:
        h[f["key"]] = api_key
    return h
