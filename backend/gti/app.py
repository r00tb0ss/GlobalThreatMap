"""FastAPI application: API, WebSocket live feed, static dashboard."""
import asyncio
import hmac
import ipaddress
import logging
import mimetypes
import os
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, config, feeds as F, intel, scoring
from .collector import Collector, gunzip_bounded
from .db import Database, now
from .geo import Geo
from .stream import CheckpointStream

log = logging.getLogger("gti")
# Do not trust the host MIME database (Windows registry / minimal images can map .js to text/plain,
# which browsers refuse to execute under nosniff).
for _ext, _type in ((".js", "text/javascript"), (".css", "text/css"), (".png", "image/png"),
                    (".svg", "image/svg+xml"), (".html", "text/html")):
    mimetypes.add_type(_type, _ext)
COOKIE = "gti_session"
USERNAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

SETTING_DEFS = {   # key: (type, min, max, default)
    "retention_days": (int, 1, 3650, None),
    "map_max_points": (int, 100, 20000, 5000),
    "min_score_default": (int, 0, 100, 0),
}


class Broadcaster:
    def __init__(self, max_clients):
        self.clients = set()
        self.max = max_clients
        self.loop = None

    def publish(self, ev, kind="event"):
        """Thread-safe; called from collector worker threads. kind: 'event' (IP-based) or 'flow' (arc)."""
        if self.loop is None:
            return
        self.loop.call_soon_threadsafe(self._fanout, (kind, ev))

    def _fanout(self, ev):
        for q in list(self.clients):
            if q.full():              # slow client: drop oldest so memory stays bounded
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(ev)


class SetupBody(BaseModel):
    token: str
    username: str
    password: str


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


class SourceBody(BaseModel):
    enabled: bool | None = None
    api_key: str | None = None


WS_RECHECK_S = 5                # how often an open live-feed socket re-validates its session
LOOKUP_TTL = 24 * 3600          # per-IP AbuseIPDB lookups are cached this long (free plan: 1,000 checks/day)


def default_lookup_fetcher(url, headers):
    """GET a small JSON document (per-IP lookups). Bounded size, gzip-safe."""
    import urllib.request
    req = urllib.request.Request(url, headers={**headers, "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read(F.MAX_BODY + 1)
        gz = (r.headers.get("Content-Encoding") or "").lower() == "gzip"
    if len(body) > F.MAX_BODY:
        raise ValueError("response exceeds size limit")
    return (gunzip_bounded(body, F.MAX_BODY) if gz else body).decode("utf-8", "replace")


def create_app(cfg=None, fetcher=None, journal_reader=None, stream_opener=None, lookup_fetcher=None):
    lookup_fetcher = lookup_fetcher or default_lookup_fetcher
    cfg = cfg or config.load()
    db = Database(cfg.db_path)
    geo = Geo(cfg.geoip_dir)
    bc = Broadcaster(cfg.ws_max_clients)
    kwargs = {"fetcher": fetcher} if fetcher else {}
    if journal_reader:
        kwargs["journal_reader"] = journal_reader
    collector = Collector(db, geo, cfg, publish=bc.publish, **kwargs)
    stream = CheckpointStream(collector, opener=stream_opener)
    throttle = auth.Throttle()
    ip_throttle = auth.Throttle(max_fails=30, lock=300)   # all usernames from one address together
    started = time.time()
    token_path = os.path.join(cfg.data_dir, "setup_token")
    cache = {"ver": -1, "t": 0, "agg": None}

    def has_users():
        with db.conn() as c:
            return c.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def ensure_setup_token():
        if has_users():
            return
        if not os.path.exists(token_path):
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(18) + "\n")

    @asynccontextmanager
    async def lifespan(app):
        logging.basicConfig(level=os.environ.get("GTI_LOG_LEVEL", "INFO"),
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        bc.loop = asyncio.get_running_loop()
        ensure_setup_token()
        if cfg.collectors_enabled:
            collector.start()
            stream.start()
        log.info("Global Threat Intel %s started (geoip=%s)", __version__, geo.available)
        yield
        stream.stop()
        await collector.stop()

    app = FastAPI(title="Global Threat Intel", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.collector, app.state.cfg, app.state.stream = db, collector, cfg, stream
    app.add_middleware(GZipMiddleware, minimum_size=2048, compresslevel=5)

    # ---- middleware: security headers + same-origin check on unsafe methods ----
    @app.middleware("http")
    async def secure(request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin and urlparse(origin).netloc != request.headers.get("host"):
                return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        else:   # static UI: always revalidate (ETag) so an upgrade never leaves stale JS in browsers
            resp.headers["Cache-Control"] = "no-cache"
        return resp

    # ---- auth dependencies ----
    def current(request: Request):
        s = auth.get_session(db, request.cookies.get(COOKIE))
        if not s:
            raise HTTPException(401, "Not authenticated")
        return s

    def current_csrf(request: Request, s=Depends(current)):
        if request.method not in ("GET", "HEAD"):
            if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
                raise HTTPException(403, "Missing or invalid CSRF token")
        return s

    def set_cookie(resp, token):
        resp.set_cookie(COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="strict",
                        secure=cfg.cookie_secure, path="/")

    # ---- public ----
    @app.get("/api/health")
    def health():
        # Deliberately minimal: no versions of dependencies, paths or configuration.
        try:
            ver = db.schema_version()
            ok = True
        except Exception:
            ok, ver = False, None
        return JSONResponse({"status": "ok" if ok else "degraded", "version": __version__,
                             "setup_required": (not has_users()) if ok else None},
                            status_code=200 if ok else 503)

    @app.post("/api/setup")
    def setup(body: SetupBody, request: Request, response: Response):
        key = "setup:" + (request.client.host if request.client else "?")
        if throttle.blocked(key):
            raise HTTPException(429, "Too many attempts. Try again later.")
        if has_users():
            raise HTTPException(409, "Setup already completed")
        try:
            want = open(token_path).read().strip()
        except OSError:
            raise HTTPException(500, "Setup token missing on server; restart the service")
        if not hmac.compare_digest(body.token.strip(), want):
            throttle.fail(key)
            raise HTTPException(403, "Invalid setup token. It is stored in the file shown by the installer.")
        u = body.username.strip()
        if not (3 <= len(u) <= 32) or set(u) - USERNAME_OK:
            raise HTTPException(422, "Username must be 3-32 characters: letters, digits, . _ -")
        err = auth.check_password_policy(body.password, u)
        if err:
            raise HTTPException(422, err)
        with db.tx() as c:   # BEGIN IMMEDIATE: only one concurrent setup can win
            if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise HTTPException(409, "Setup already completed")
            cur = c.execute("INSERT INTO users(username,pw_hash,created_at) VALUES(?,?,?)",
                            (u, auth.hash_password(body.password), now()))
            uid = cur.lastrowid
        try:
            os.remove(token_path)
        except OSError:
            pass
        token, csrf = auth.create_session(db, uid)
        set_cookie(response, token)
        return {"username": u, "csrf": csrf}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response):
        host = request.client.host if request.client else "?"
        name = body.username.strip()
        # the key must use the same normalised name that is authenticated, or "admin", "admin " and " admin"
        # would each get their own five attempts
        key = f"login:{host}:{name.lower()}"
        ipkey = f"loginip:{host}"
        if throttle.blocked(key) or ip_throttle.blocked(ipkey):
            raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
        uid = auth.authenticate(db, name, body.password)
        if uid is None:
            throttle.fail(key)
            ip_throttle.fail(ipkey)
            raise HTTPException(401, "Invalid username or password")
        throttle.ok(key)
        token, csrf = auth.create_session(db, uid)
        set_cookie(response, token)
        return {"username": name, "csrf": csrf}

    @app.post("/api/logout")
    def logout(request: Request, response: Response, s=Depends(current_csrf)):
        auth.delete_session(db, request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(s=Depends(current)):
        return {"username": s["username"], "csrf": s["csrf"]}

    @app.post("/api/password")
    def change_password(body: PasswordBody, request: Request, s=Depends(current_csrf)):
        pkey = f"password:{s['uid']}"
        if throttle.blocked(pkey):
            raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
        if auth.authenticate(db, s["username"], body.current) is None:
            throttle.fail(pkey)
            raise HTTPException(403, "Current password is incorrect")
        throttle.ok(pkey)
        err = auth.check_password_policy(body.new, s["username"])
        if err:
            raise HTTPException(422, err)
        with db.conn() as c:
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (auth.hash_password(body.new), s["uid"]))
        auth.delete_user_sessions(db, s["uid"], keep_token=request.cookies.get(COOKIE))
        return {"ok": True}

    # ---- data ----
    def source_rows():
        out = {}
        with db.conn() as c:
            for r in c.execute("SELECT * FROM sources"):
                out[r["id"]] = dict(r)
        return out

    def source_status(row, feed):
        if feed.get("kind") == "sensor" and not collector.sensor_available:
            return "unavailable"
        if not row["enabled"]:
            return "disabled"
        if feed["key"] and not row["api_key"]:
            return "needs_key"
        if not row["last_success"]:
            return "error" if row["last_error"] else "pending"
        stale = now() - row["last_success"] > 2 * feed["interval"] + 600
        if stale:
            return "stale"
        return "ok" if not row["last_error"] or row["last_error"].startswith("list truncated") else "degraded"

    def aggregate():
        """Per-IP aggregate over active indicators from enabled sources; cached until data changes."""
        if cache["agg"] is not None and cache["ver"] == collector.version and time.time() - cache["t"] < 20:
            return cache["agg"]
        agg = {}
        with db.conn() as c:
            q = """SELECT i.ip,i.source,i.category,i.malware,i.port,i.last_seen,i.first_seen,i.country,i.city,i.lat,i.lon,
                          i.asn,i.org FROM indicators i JOIN sources s ON s.id=i.source
                   WHERE i.active=1 AND s.enabled=1"""
            for r in c.execute(q):
                a = agg.get(r["ip"])
                if a is None:
                    a = agg[r["ip"]] = {"ip": r["ip"], "lat": r["lat"], "lon": r["lon"], "country": r["country"],
                                        "city": r["city"], "asn": r["asn"], "org": r["org"],
                                        "sources": set(), "categories": set(), "malware": set(),
                                        "ports": set(), "rows": [], "last_seen": 0, "first_seen": r["first_seen"]}
                a["sources"].add(r["source"])
                a["categories"].add(r["category"])
                if r["malware"]:
                    a["malware"].add(r["malware"])
                if r["port"]:
                    a["ports"].add(r["port"])
                a["rows"].append((r["source"], r["last_seen"]))
                a["last_seen"] = max(a["last_seen"], r["last_seen"])
                a["first_seen"] = min(a["first_seen"], r["first_seen"])
        t = now()
        for a in agg.values():
            sc = scoring.score_ip(a["rows"], F.WEIGHTS, t)
            a["score"], a["confidence"] = sc["score"], sc["confidence"]
        cache.update(ver=collector.version, t=time.time(), agg=agg)
        return agg

    def public_point(a):
        return {"ip": a["ip"], "lat": a["lat"], "lon": a["lon"], "country": a["country"], "city": a["city"],
                "asn": a["asn"], "org": a["org"], "score": a["score"], "confidence": a["confidence"],
                "sources": sorted(a["sources"]), "categories": sorted(a["categories"]),
                "malware": sorted(a["malware"]), "last_seen": a["last_seen"],
                "observed": any(F.observation_type(s) == "direct_observation" for s in a["sources"])}

    def filtered(source=None, category=None, q=None, min_score=0, located=False):
        out = []
        for a in aggregate().values():
            if source and source not in a["sources"]:
                continue
            if category and category not in a["categories"]:
                continue
            if q and q not in a["ip"]:
                continue
            if a["score"] < min_score:
                continue
            if located and (a["lat"] is None or a["lon"] is None):
                continue
            out.append(a)
        out.sort(key=lambda a: (-a["score"], -a["last_seen"], a["ip"]))
        return out

    def get_setting_int(key):
        typ, lo, hi, default = SETTING_DEFS[key]
        raw = db.get_setting(key)
        if raw is None:
            return default if default is not None else cfg.retention_days
        try:
            return int(raw)
        except ValueError:
            return default if default is not None else cfg.retention_days

    def stale_info():
        rows = source_rows()
        return sorted(fid for fid, f in F.FEEDS.items()
                      if rows.get(fid, {}).get("enabled") and source_status(rows[fid], f) in ("stale", "error", "degraded"))

    @app.get("/api/map")
    def map_points(source: str | None = None, category: str | None = None, q: str | None = None,
                   min_score: int = 0, limit: int = 0, s=Depends(current)):
        if not 0 <= min_score <= 100:
            raise HTTPException(422, "min_score must be 0-100")
        cap = get_setting_int("map_max_points")
        limit = cap if limit <= 0 else min(limit, cap)
        items = filtered(source, category, (q or "").strip() or None, min_score, located=True)
        return {"total": len(items), "returned": min(len(items), limit), "truncated": len(items) > limit,
                "geoip_available": geo.available, "unhealthy_sources": stale_info(),
                "points": [public_point(a) for a in items[:limit]]}

    @app.get("/api/events")
    def events(limit: int = 100, before_id: int | None = None, source: str | None = None,
               category: str | None = None, s=Depends(current)):
        limit = max(1, min(limit, 500))
        sql = """SELECT e.*, i.tags FROM events e JOIN sources s ON s.id=e.source
                 LEFT JOIN indicators i ON i.ip=e.ip AND i.source=e.source AND i.category=e.category
                 WHERE s.enabled=1"""
        args = []
        if before_id:
            sql += " AND e.id<?"
            args.append(before_id)
        if source:
            sql += " AND e.source=?"
            args.append(source)
        if category:
            sql += " AND e.category=?"
            args.append(category)
        sql += " ORDER BY e.id DESC LIMIT ?"
        args.append(limit)
        with db.conn() as c:
            rows = [dict(r) for r in c.execute(sql, args)]
        for r in rows:
            r["tags"] = [t for t in (r["tags"] or "").split(",") if t]
            r["doing"] = intel.short_activity(r["source"], r["category"], r["malware"], r["port"], r["tags"])
        return {"events": rows, "unhealthy_sources": stale_info()}

    def flows_enabled():
        return [fid for fid, f in F.FEEDS.items() if f.get("kind") in F.FLOW_KINDS and source_rows().get(fid, {}).get("enabled")]

    @app.get("/api/flows")
    def flows(minutes: int = 60, limit: int = 1000, tactic: str | None = None, source: str | None = None,
              s=Depends(current)):
        """Recent attacker-area -> target arcs (GreyNoise, Check Point, Radware), newest and biggest first.

        `tactics` = GreyNoise totals by MITRE tactic; `types` = {source: {attack type: total}} for all arc sources.
        """
        import json
        minutes = max(1, min(minutes, 1440))
        limit = max(1, min(limit, 5000))
        srcs = flows_enabled()
        if source:
            srcs = [x for x in srcs if x == source]
        if not srcs:
            return {"flows": [], "tactics": {}, "types": {}, "minutes": minutes, "unhealthy_sources": stale_info()}
        ph = ",".join("?" * len(srcs))
        since = now() - minutes * 60
        sql = f"SELECT * FROM flows WHERE ts>=? AND source IN ({ph})"
        args = [since, *srcs]
        if tactic:
            sql += " AND (tactic=? OR attack_type=?)"
            args += [tactic, tactic]
        with db.conn() as c:
            # per source, newest first, so one busy source cannot crowd the others out of the limit
            rows = []
            per = max(1, limit // len(srcs))
            for sid in srcs:
                rows += [dict(r) for r in c.execute(
                    sql.replace(f"source IN ({ph})", "source=?") + " ORDER BY ts DESC, count DESC LIMIT ?",
                    [since, sid] + args[1 + len(srcs):] + [per])]
            tac = {r[0]: r[1] for r in c.execute(
                f"SELECT tactic, SUM(count) FROM flows WHERE ts>=? AND source IN ({ph}) AND tactic<>'' GROUP BY tactic",
                [since, *srcs])}
            types = {}
            for sid, kind, n in c.execute(
                    f"""SELECT source, COALESCE(NULLIF(tactic,''), attack_type), SUM(count) FROM flows
                        WHERE ts>=? AND source IN ({ph}) GROUP BY 1, 2""", [since, *srcs]):
                types.setdefault(sid, {})[kind] = n
            names = c.execute(
                """SELECT attack_name, attack_type, SUM(count) n FROM flows WHERE ts>=? AND source='checkpoint_map'
                   AND attack_name IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC""",
                [since]).fetchall() if "checkpoint_map" in srcs else []
        for r in rows:
            r["also_seen"] = json.loads(r["also_seen"] or "[]")
            r["source_name"] = F.FEEDS[r["source"]]["name"]
            r["observation_type"] = F.observation_type(r["source"])
            r["cves"] = intel.cves(r["attack_name"])
            r["ai_target"] = intel.ai_target(r["attack_name"])
        exploits = [{"name": n, "type": t, "count": k, "cves": intel.cves(n), "ai_target": intel.ai_target(n)}
                    for n, t, k in names]
        return {"flows": rows, "tactics": tac, "types": types, "minutes": minutes,
                "exploits": exploits[:10],
                "ai_attacks": [e for e in exploits if e["ai_target"]][:20],
                "checkpoint_today": int(db.get_setting("checkpoint_map_today", "0") or 0) or None,
                "note": "Arcs run from the attacker's approximate area (city, region or country) to the target area. "
                        "No attacker IP addresses are provided by these sources. Radware times are playback times.",
                "unhealthy_sources": stale_info()}

    @app.get("/api/ip/{ip}")
    def ip_detail(ip: str, s=Depends(current)):
        try:
            norm = str(ipaddress.ip_address(ip))
        except ValueError:
            raise HTTPException(422, "Not a valid IP address")
        with db.conn() as c:
            rows = [dict(r) for r in c.execute(
                """SELECT i.source,i.category,i.malware,i.port,i.first_seen,i.last_seen,i.active,i.hits,i.tags
                   FROM indicators i WHERE i.ip=? ORDER BY i.last_seen DESC""", (norm,))]
            ab = c.execute("SELECT enabled, api_key FROM sources WHERE id='abuseipdb'").fetchone()
            evs = [dict(r) for r in c.execute("SELECT * FROM events WHERE ip=? ORDER BY id DESC LIMIT 50", (norm,))]
        if not rows:
            raise HTTPException(404, "No intelligence on this IP")
        g = geo.lookup(norm)
        active = [(r["source"], r["last_seen"]) for r in rows if r["active"]]
        sc = scoring.score_ip(active, F.WEIGHTS)
        for r in rows:
            r["source_name"] = F.FEEDS.get(r["source"], {}).get("name", r["source"])
            r["observation_type"] = F.observation_type(r["source"])
            r["category_label"] = F.CATEGORIES.get(r["category"], r["category"])
            r["tags"] = [t for t in (r["tags"] or "").split(",") if t]
        observed = any(r["observation_type"] == "direct_observation" for r in rows)
        reported = any(r["observation_type"] != "direct_observation" for r in rows)
        notes = []
        if observed:
            notes.append("Observed: this IP sent traffic to this host that was logged as an attack attempt "
                         "(SSH login failure or firewall block). Source IPs can be spoofed for UDP and may belong "
                         "to compromised machines rather than the attacker behind them.")
        if reported:
            notes.append("Reported: third-party listings. They do not prove this IP performed any specific attack.")
        return {"ip": norm, "geo": g, "score": sc, "observed": observed,
                "evidence_note": " ".join(notes),
                "indicators": rows, "events": evs,
                "activity": intel.activity([{**r, "tags": ",".join(r["tags"])} for r in rows], evs),
                "port_info": [intel.port_info(p) for p in sorted({r["port"] for r in rows if r["port"]} |
                                                                 {e["port"] for e in evs if e.get("port")})],
                "abuseipdb_lookup": bool(ab and ab["enabled"] and ab["api_key"]),
                "ports": sorted({r["port"] for r in rows if r["port"]}),
                "malware": sorted({r["malware"] for r in rows if r["malware"]})}

    @app.get("/api/ip/{ip}/host")
    def ip_host(ip: str, s=Depends(current)):
        """Host details: reverse DNS (cached 24 h), network blocks and region from the local GeoIP databases,
        and how many other listed IPs share this IP's network and ASN."""
        import json
        norm = F.norm_ip(ip)
        if not norm:
            raise HTTPException(422, "Not a public IP address")
        with db.conn() as c:
            rows = c.execute("SELECT first_seen, last_seen, asn, org FROM indicators WHERE ip=?", (norm,)).fetchall()
            if not rows:
                raise HTTPException(404, "No intelligence on this IP")
            hit = c.execute("SELECT fetched_at, data FROM ip_lookups WHERE ip=? AND provider='rdns'", (norm,)).fetchone()
        g = geo.lookup(norm)
        det = geo.details(norm) if hasattr(geo, "details") else {}
        if hit and now() - hit["fetched_at"] < LOOKUP_TTL:
            rd = json.loads(hit["data"])
        else:
            rd = intel.reverse_dns(norm)
            if not rd.get("timeout"):
                with db.conn() as c:
                    c.execute("""INSERT INTO ip_lookups(ip, provider, fetched_at, data) VALUES(?, 'rdns', ?, ?)
                                 ON CONFLICT(ip, provider) DO UPDATE SET fetched_at=excluded.fetched_at,
                                 data=excluded.data""", (norm, now(), json.dumps(rd)))
        asn = g.get("asn") or next((r["asn"] for r in rows if r["asn"]), None)
        org = g.get("org") or next((r["org"] for r in rows if r["org"]), None)
        with db.conn() as c:
            same_asn = c.execute("SELECT COUNT(DISTINCT ip) FROM indicators WHERE asn=? AND active=1 AND ip<>?",
                                 (asn, norm)).fetchone()[0] if asn else None
            same24 = None
            if ":" not in norm:
                p24 = norm.rsplit(".", 1)[0] + ".%"     # digits and dots only: no LIKE wildcards to escape
                same24 = c.execute("""SELECT COUNT(DISTINCT ip) FROM indicators WHERE ip LIKE ?
                                      AND active=1 AND ip<>?""", (p24, norm)).fetchone()[0]
        return {"ip": norm, "version": 6 if ":" in norm else 4, "reverse_dns": rd,
                "asn": asn, "org": org, "network_kind": intel.network_kind(org), **det,
                "city": g.get("city"), "country": g.get("country"),
                "first_seen": min(r["first_seen"] for r in rows), "last_seen": max(r["last_seen"] for r in rows),
                "listed_in_same_asn": same_asn, "listed_in_same_24": same24}

    @app.get("/api/ip/{ip}/abuseipdb")
    def ip_abuseipdb(ip: str, s=Depends(current)):
        """Per-IP report details from AbuseIPDB (what users reported this IP doing). Uses the server-side key;
        the key never reaches the browser. Cached for 24 h to stay within the free plan's daily quota."""
        import json
        import urllib.error
        from urllib.parse import quote
        norm = F.norm_ip(ip)
        if not norm:
            raise HTTPException(422, "Not a public IP address")
        with db.conn() as c:
            if not c.execute("SELECT 1 FROM indicators WHERE ip=? LIMIT 1", (norm,)).fetchone():
                raise HTTPException(404, "No intelligence on this IP")
            ab = c.execute("SELECT enabled, api_key FROM sources WHERE id='abuseipdb'").fetchone()
            hit = c.execute("SELECT fetched_at, data FROM ip_lookups WHERE ip=? AND provider='abuseipdb'",
                            (norm,)).fetchone()
        if not (ab and ab["enabled"] and ab["api_key"]):
            return {"available": False, "reason": "Add and enable an AbuseIPDB key on the Sources page to see "
                                                  "what users reported this IP doing."}
        if hit and now() - hit["fetched_at"] < LOOKUP_TTL:
            return {"available": True, "cached": True, "fetched_at": hit["fetched_at"], **json.loads(hit["data"])}
        key = ab["api_key"]
        url = ("https://api.abuseipdb.com/api/v2/check?ipAddress=" + quote(norm, safe="") +
               "&maxAgeInDays=90&verbose")
        try:
            summary = intel.summarize_abuseipdb(json.loads(
                lookup_fetcher(url, {"Key": key, "Accept": "application/json", "User-Agent": "GlobalThreatIntel/1.0"})))
        except urllib.error.HTTPError as e:
            msg = ("AbuseIPDB daily lookup limit reached; try again tomorrow" if e.code == 429 else
                   "AbuseIPDB rejected the API key" if e.code in (401, 403) else f"AbuseIPDB returned HTTP {e.code}")
            if hit:
                return {"available": True, "cached": True, "stale": True, "error": msg,
                        "fetched_at": hit["fetched_at"], **json.loads(hit["data"])}
            raise HTTPException(502, msg)
        except Exception as e:
            msg = f"AbuseIPDB lookup failed: {type(e).__name__}: {e}".replace(key, "***")[:300]
            if hit:
                return {"available": True, "cached": True, "stale": True, "error": msg,
                        "fetched_at": hit["fetched_at"], **json.loads(hit["data"])}
            raise HTTPException(502, msg)
        t = now()
        with db.conn() as c:
            c.execute("""INSERT INTO ip_lookups(ip, provider, fetched_at, data) VALUES(?, 'abuseipdb', ?, ?)
                         ON CONFLICT(ip, provider) DO UPDATE SET fetched_at=excluded.fetched_at, data=excluded.data""",
                      (norm, t, json.dumps(summary)))
        return {"available": True, "cached": False, "fetched_at": t, **summary}

    @app.get("/api/stats")
    def stats(s=Depends(current)):
        agg = aggregate()
        by_src, by_cat, by_country = {}, {}, {}
        for a in agg.values():
            for x in a["sources"]:
                by_src[x] = by_src.get(x, 0) + 1
            for x in a["categories"]:
                by_cat[x] = by_cat.get(x, 0) + 1
            by_country[a["country"] or "??"] = by_country.get(a["country"] or "??", 0) + 1
        fsrc = flows_enabled()
        with db.conn() as c:
            ev24 = c.execute("SELECT COUNT(*) FROM events WHERE ts>?", (now() - 86400,)).fetchone()[0]
            ph = ",".join("?" * len(fsrc))
            flows24 = {r[0]: r[1] for r in c.execute(
                f"SELECT tactic, SUM(count) FROM flows WHERE ts>? AND source IN ({ph}) AND tactic<>'' GROUP BY tactic",
                [now() - 86400, *fsrc])} if fsrc else {}
            by_src_type = {}
            for sid, kind, n in (c.execute(
                    f"""SELECT source, COALESCE(NULLIF(tactic,''), attack_type), SUM(count) FROM flows
                        WHERE ts>? AND source IN ({ph}) GROUP BY 1, 2""", [now() - 86400, *fsrc]) if fsrc else []):
                by_src_type.setdefault(sid, {})[kind] = n
            sensors24 = [{"sensor": r[0], "count": r[1]} for r in c.execute(
                f"""SELECT dst_name, SUM(count) n FROM flows WHERE ts>? AND source IN ({ph})
                    GROUP BY dst_name ORDER BY n DESC LIMIT 10""", [now() - 86400, *fsrc])] if fsrc else []
        top = sorted(by_country.items(), key=lambda kv: -kv[1])[:10]
        return {"unique_ips": len(agg), "events_24h": ev24, "by_source": by_src, "by_category": by_cat,
                "sensor_sessions_24h_by_tactic": flows24, "top_sensors_24h": sensors24,
                "arcs_by_source_and_type": by_src_type,
                "arcs_note": "Arc totals cover each source's retention window (GreyNoise 72 h, Check Point 24 h, "
                             "Radware 2 h), at most the last 24 h.",
                "top_countries": [{"country": k, "count": v} for k, v in top],
                "note": "Counts are unique IPs. An IP listed by several sources/categories is counted once in unique_ips "
                        "and once per source/category in the breakdowns."}

    # ---- sources & settings ----
    def source_view(fid, row):
        f = F.FEEDS[fid]
        err = row["last_error"]
        note = None
        if err and err.startswith("list truncated"):
            note = (f"Source lists more IPs than the per-source cap ({cfg.max_indicators_per_source}); "
                    "only the first entries in the provider's order are kept.")
            err = None
        return {"note": note,"id": fid, "name": f["name"], "description": f["desc"], "requires_key": bool(f["key"]),
                "has_key": bool(row["api_key"]), "enabled": bool(row["enabled"]), "interval_seconds": f["interval"],
                "weight": f["weight"], "status": source_status(row, f), "last_attempt": row["last_attempt"],
                "last_success": row["last_success"], "last_error": err, "record_count": row["last_count"],
                "next_run": collector.next_run(row, f) if cfg.collectors_enabled else None,
                "observation_type": F.observation_type(fid)}

    @app.get("/api/sources")
    def sources(s=Depends(current)):
        rows = source_rows()
        return {"sources": [source_view(fid, rows[fid]) for fid in F.FEEDS if fid in rows]}

    @app.put("/api/sources/{fid}")
    def update_source(fid: str, body: SourceBody, s=Depends(current_csrf)):
        if fid not in F.FEEDS:
            raise HTTPException(404, "Unknown source")
        feed = F.FEEDS[fid]
        with db.conn() as c:
            row = c.execute("SELECT * FROM sources WHERE id=?", (fid,)).fetchone()
            key = row["api_key"]
            if body.api_key is not None:
                if not feed["key"]:
                    raise HTTPException(422, "This source does not use an API key")
                k = body.api_key.strip()
                if k and (len(k) > 256 or not k.isprintable() or " " in k):
                    raise HTTPException(422, "API key looks invalid (printable characters, no spaces, max 256)")
                key = k or None
            enabled = row["enabled"] if body.enabled is None else int(body.enabled)
            if body.enabled and feed["key"] and not key:
                raise HTTPException(422, f"{feed['name']} needs an API key before it can be enabled")
            if feed["key"] and not key:
                enabled = 0
            c.execute("UPDATE sources SET enabled=?, api_key=? WHERE id=?", (enabled, key, fid))
        collector.version += 1
        with db.conn() as c:
            row = c.execute("SELECT * FROM sources WHERE id=?", (fid,)).fetchone()
        return source_view(fid, dict(row))

    @app.post("/api/sources/{fid}/refresh")
    async def refresh_source(fid: str, s=Depends(current_csrf)):
        if fid not in F.FEEDS:
            raise HTTPException(404, "Unknown source")
        rows = source_rows()
        if not rows[fid]["enabled"]:
            raise HTTPException(409, "Source is disabled")
        res = await asyncio.to_thread(collector.run_source, fid)
        return res

    def home_view():
        try:
            lat, lon = float(db.get_setting("home_lat")), float(db.get_setting("home_lon"))
        except (TypeError, ValueError):
            return None
        return {"lat": lat, "lon": lon, "label": db.get_setting("home_label", "This host")}

    def settings_view():
        return {"home": home_view(), "categories": F.CATEGORIES, "tactics": list(F.TACTICS),
                "retention_days": get_setting_int("retention_days"),
                "map_max_points": get_setting_int("map_max_points"),
                "min_score_default": get_setting_int("min_score_default"),
                "limits": {k: {"min": v[1], "max": v[2]} for k, v in SETTING_DEFS.items()},
                "geoip_available": geo.available,
                "ingest": {"max_indicators_per_source": cfg.max_indicators_per_source,
                           "max_events_per_run": cfg.max_events_per_run}}

    @app.get("/api/settings")
    def get_settings(s=Depends(current)):
        return settings_view()

    @app.put("/api/settings")
    def put_settings(body: dict, s=Depends(current_csrf)):
        clean = {}
        if "home" in body:
            h = body.pop("home")
            if h is None:
                clean.update(home_lat="", home_lon="", home_label="")
            else:
                if not isinstance(h, dict):
                    raise HTTPException(422, "home must be an object {lat, lon, label} or null")
                lat, lon, label = h.get("lat"), h.get("lon"), str(h.get("label") or "This host").strip()
                for name, v, lim in (("lat", lat, 90), ("lon", lon, 180)):
                    if isinstance(v, bool) or not isinstance(v, (int, float)) or not -lim <= v <= lim:
                        raise HTTPException(422, f"home.{name} must be a number between -{lim} and {lim}")
                if len(label) > 40 or not label.isprintable():
                    raise HTTPException(422, "home.label must be at most 40 printable characters")
                clean.update(home_lat=round(float(lat), 4), home_lon=round(float(lon), 4), home_label=label)
        for k, v in body.items():
            if k not in SETTING_DEFS:
                raise HTTPException(422, f"Unknown setting: {k}")
            typ, lo, hi, _ = SETTING_DEFS[k]
            if isinstance(v, bool) or not isinstance(v, int):
                raise HTTPException(422, f"{k} must be a whole number")
            if not lo <= v <= hi:
                raise HTTPException(422, f"{k} must be between {lo} and {hi}")
            clean[k] = v
        for k, v in clean.items():
            db.set_setting(k, v)
        return settings_view()

    @app.get("/api/locate-me")
    def locate_me(request: Request, s=Depends(current)):
        """Suggest a home location from the GeoIP of the browser's address (only works for public IPs)."""
        ip = request.client.host if request.client else ""
        try:
            if not ipaddress.ip_address(ip).is_global:
                return {"found": False, "reason": "You are connecting from a private address; enter coordinates manually."}
        except ValueError:
            return {"found": False, "reason": "Unknown client address"}
        g = geo.lookup(ip)
        if g["lat"] is None:
            return {"found": False, "reason": "No GeoIP location for your address"}
        return {"found": True, "lat": g["lat"], "lon": g["lon"], "label": g["city"] or g["country"] or "This host"}

    # ---- websocket ----
    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        origin = sock.headers.get("origin")
        if origin and urlparse(origin).netloc != sock.headers.get("host"):
            await sock.close(code=4403)
            return
        token = sock.cookies.get(COOKIE)
        if not auth.get_session(db, token):
            await sock.close(code=4401)
            return
        if len(bc.clients) >= bc.max:
            await sock.close(code=4429)
            return
        await sock.accept()
        q = asyncio.Queue(maxsize=100)
        bc.clients.add(q)
        try:
            await sock.send_json({"type": "hello"})
            checked = time.monotonic()
            while True:
                # a logout, password change or expiry must end the stream, not just block new connections
                if time.monotonic() - checked >= WS_RECHECK_S:
                    if not auth.get_session(db, token):
                        await sock.close(code=4401)
                        break
                    checked = time.monotonic()
                try:
                    kind, ev = await asyncio.wait_for(q.get(), timeout=WS_RECHECK_S)
                    await sock.send_json({"type": kind, kind: ev})
                except asyncio.TimeoutError:
                    await sock.send_json({"type": "ping", "ts": now()})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            bc.clients.discard(q)

    @app.get("/api/{rest:path}")
    def api_404(rest: str):
        raise HTTPException(404, "Not found")

    if os.path.isdir(cfg.frontend_dir):
        app.mount("/", StaticFiles(directory=cfg.frontend_dir, html=True), name="ui")
    return app


def main():
    import uvicorn
    cfg = config.load()
    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port, log_level="info", access_log=False,
                server_header=False, ws_ping_interval=None)


if __name__ == "__main__":
    main()
