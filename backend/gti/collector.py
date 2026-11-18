"""Feed collection, ingestion, retention and scheduling."""
import asyncio
import logging
import time
import urllib.error
import urllib.request

from . import feeds as F
from . import intel
from . import sensor as SENSOR
from .db import now

SENSOR_ACTIVE_WINDOW = 7 * 86400   # an observed attacker stays "active" on the map for 7 days after its last hit
EV_COLS = ("id", "ts", "ip", "source", "category", "malware", "observation_type", "country", "lat", "lon", "port", "proto")

log = logging.getLogger("gti.collector")
RETRY_AFTER_FAILURE = 900
SHRINK_GUARD_MIN = 50       # only apply the shrink check when previous snapshot had at least this many rows
SHRINK_GUARD_RATIO = 0.5    # a new snapshot smaller than this fraction of the previous one is rejected


def default_fetcher(feed_id, api_key):
    """feed_id is a source id, or "source:tag" for one of that source's per-service tag lists."""
    fid, _, tag = feed_id.partition(":")
    f = F.FEEDS[fid]
    url = f["tag_lists"][tag] if tag else f["url"]
    req = urllib.request.Request(url, headers=F.request_headers(fid, api_key))
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read(F.MAX_BODY + 1)
        gz = (r.headers.get("Content-Encoding") or "").lower() == "gzip"
    if len(body) > F.MAX_BODY:
        raise ValueError("response exceeds size limit")
    if gz:
        body = gunzip_bounded(body, F.MAX_BODY)
    return body.decode("utf-8", "replace")


def with_activity(ev, tags=None):
    """Add the feed's one-line description (same wording as GET /api/events)."""
    ev["tags"] = [t for t in (tags or "").split(",") if t]
    ev["doing"] = intel.short_activity(ev["source"], ev["category"], ev.get("malware"), ev.get("port"), ev["tags"])
    return ev


def gunzip_bounded(data, limit):
    """Decompress gzip without allowing a small response to expand beyond `limit` bytes (zip-bomb guard)."""
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError("decompressed response exceeds size limit")
    return out


class Collector:
    def __init__(self, db, geo, cfg, publish=None, fetcher=default_fetcher, journal_reader=None):
        self.db, self.geo, self.cfg = db, geo, cfg
        self.publish = publish or (lambda ev, kind="event": None)
        self.fetcher = fetcher
        self.journal_reader = journal_reader or SENSOR.read_journal
        self.sensor_available = journal_reader is not None or SENSOR.available()
        self._task = None
        self._stop = False
        self.version = 0        # bumped on every ingest; used for cache invalidation
        self.ensure_sources()

    # ---- setup -----------------------------------------------------------
    def ensure_sources(self):
        with self.db.conn() as c:
            for fid, f in F.FEEDS.items():
                # sources needing a key start disabled; the local sensor starts enabled only where journald exists
                on = 0 if f["key"] else (int(self.sensor_available) if f.get("kind") == "sensor" else 1)
                c.execute("INSERT OR IGNORE INTO sources(id, enabled) VALUES(?,?)", (fid, on))

    # ---- local sensor ----------------------------------------------------
    def run_sensor(self, fid="local_sensor"):
        t0 = now()
        with self.db.conn() as c:
            c.execute("UPDATE sources SET last_attempt=? WHERE id=?", (t0, fid))
        if not self.sensor_available:
            return self._fail(fid, "journalctl not available: the local sensor needs systemd-journald (Linux)")
        cursor = self.db.get_setting("sensor_cursor")
        try:
            recs, new_cursor = self.journal_reader(cursor)
        except Exception as e:
            return self._fail(fid, self._describe(e, None))
        # aggregate: hits per (ip, category); one live event per (ip, category, port) per run
        agg, ev_keys = {}, set()
        for r in recs:
            k = (r["ip"], r["category"])
            a = agg.setdefault(k, {"n": 0, "ts": 0, "port": r.get("port")})
            a["n"] += 1
            a["ts"] = max(a["ts"], r["ts"])
            ek = (r["ip"], r["category"], r.get("port"))
            if ek not in ev_keys:
                ev_keys.add(ek)
                r["_ev"] = True
        events = []
        with self.db.tx() as c:
            for (ip, cat), a in agg.items():
                g = self.geo.lookup(ip)
                ts = a["ts"] or t0
                cur = c.execute("""UPDATE indicators SET last_seen=MAX(last_seen,?), active=1, hits=hits+?,
                                   port=COALESCE(?,port), country=?, city=?, lat=?, lon=?, asn=?, org=?
                                   WHERE ip=? AND source=? AND category=?""",
                                (ts, a["n"], a["port"], g["country"], g["city"], g["lat"], g["lon"], g["asn"], g["org"],
                                 ip, fid, cat))
                if cur.rowcount == 0:
                    c.execute("""INSERT INTO indicators(ip,source,category,port,first_seen,last_seen,active,hits,
                                 country,city,lat,lon,asn,org) VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?,?)""",
                              (ip, fid, cat, a["port"], ts, ts, a["n"], g["country"], g["city"], g["lat"], g["lon"],
                               g["asn"], g["org"]))
            for r in recs:
                if not r.get("_ev") or len(events) >= self.cfg.max_events_per_run:
                    continue
                g = self.geo.lookup(r["ip"])
                e = (r["ts"] or t0, r["ip"], fid, r["category"], None, SENSOR.OBSERVATION_TYPE,
                     g["country"], g["lat"], g["lon"], r.get("port"), r.get("proto"))
                cur = c.execute("""INSERT INTO events(ts,ip,source,category,malware,observation_type,country,lat,lon,port,proto)
                                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""", e)
                events.append((cur.lastrowid,) + e)
            c.execute("UPDATE indicators SET active=0 WHERE source=? AND last_seen<?", (fid, t0 - SENSOR_ACTIVE_WINDOW))
            if new_cursor:
                c.execute("INSERT INTO settings(key,value) VALUES('sensor_cursor',?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (new_cursor,))
            c.execute("UPDATE sources SET last_success=?, last_error=NULL, last_count=? WHERE id=?",
                      (t0, len(recs), fid))
        if agg:
            self.version += 1
        for row in events:
            self.publish(with_activity(dict(zip(EV_COLS, row))))
        return {"ok": True, "count": len(recs), "new_events": len(events)}

    # ---- flows: attacker area -> target arcs (GreyNoise, Check Point, Radware); no attacker IPs ----------
    FLOW_COLS = ("id", "ts", "source", "session_id", "src_lat", "src_lon", "dst_lat", "dst_lon", "dst_name",
                 "tactic", "also_seen", "count", "src_name", "attack_type", "attack_name")
    MAX_PUBLISH = 150      # arcs pushed to browsers per batch (all rows are stored; this only bounds animation)

    def _store_flows(self, fid, ts, rows, spread_s=0, status_count=None, mark_ok=True):
        """Insert flow rows (deduplicated by UNIQUE(source, session_id, ts)), publish new ones, update status.

        spread_s: browsers animate the batch spread over this many seconds (paced like the provider's own map).
        """
        import json
        import random
        new = []
        keep_h = F.FEEDS[fid].get("keep_hours", 72)
        with self.db.tx() as c:
            for f in rows:
                vals = (ts, fid, f["session_id"], f["src_lat"], f["src_lon"], f["dst_lat"], f["dst_lon"],
                        f.get("dst_name"), f.get("tactic", ""), json.dumps(f.get("also_seen", [])), f["count"],
                        f.get("src_name"), f.get("attack_type"), f.get("attack_name"))
                cur = c.execute("""INSERT OR IGNORE INTO flows(ts,source,session_id,src_lat,src_lon,dst_lat,dst_lon,
                                   dst_name,tactic,also_seen,count,src_name,attack_type,attack_name)
                                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
                if cur.rowcount:
                    new.append((cur.lastrowid,) + vals)
            c.execute("DELETE FROM flows WHERE source=? AND ts<?", (fid, now() - keep_h * 3600))
            if mark_ok:   # False when saving what was buffered before a failure: must not hide the error
                c.execute("UPDATE sources SET last_success=?, last_error=NULL, last_count=? WHERE id=?",
                          (now(), len(rows) if status_count is None else status_count, fid))
        pub = sorted(new, key=lambda r: -r[11])[: self.MAX_PUBLISH]
        for row in pub:
            d = dict(zip(self.FLOW_COLS, row))
            d["also_seen"] = json.loads(d["also_seen"])
            d["delay_ms"] = int(random.random() * spread_s * 1000) if spread_s else 0
            d["cves"] = intel.cves(d["attack_name"])
            d["ai_target"] = intel.ai_target(d["attack_name"])
            self.publish(d, kind="flow")
        return new

    def run_flows(self, fid):
        """GreyNoise: one-minute windows of sessions against its sensors."""
        t0 = now()
        with self.db.conn() as c:
            c.execute("UPDATE sources SET last_attempt=? WHERE id=?", (t0, fid))
        try:
            gen, flows = F.FEEDS[fid]["parse"](self.fetcher(fid, None))
        except Exception as e:
            return self._fail(fid, self._describe(e, None))
        # the provider's window time; fall back to ours if missing/implausible (>10 min skew)
        ts = gen if gen and abs(gen - t0) < 600 else t0
        ts -= ts % 60
        new = self._store_flows(fid, ts, flows, spread_s=55)
        return {"ok": True, "count": len(flows), "new_events": len(new)}

    def run_radware(self, fid):
        """Radware: pre-scheduled playback. Each scheduled event is ingested once (by its scheduled time),
        aggregated to (source country, target country, type) counts, recorded at OUR receive time."""
        t0 = now()
        with self.db.conn() as c:
            c.execute("UPDATE sources SET last_attempt=? WHERE id=?", (t0, fid))
        try:
            events = F.FEEDS[fid]["parse"](self.fetcher(fid, None))
        except Exception as e:
            return self._fail(fid, self._describe(e, None))
        try:
            last = float(self.db.get_setting(f"{fid}_last_at", "0"))
        except ValueError:
            last = 0.0
        fresh = [e for e in events if e["at"] > last]
        names = F.countries()
        agg = {}
        for e in fresh:
            if e["src"] not in names or (e["dst"] and e["dst"] not in names):
                continue
            k = (e["src"], e["dst"], e["type"])
            agg[k] = agg.get(k, 0) + 1
        rows = []
        # batch id = newest scheduled time in this batch: unique per batch even when two polls land in the same
        # second (regression: same-second polls collided on UNIQUE(source, session_id, ts) and a batch was lost)
        batch = f"{max(e['at'] for e in fresh):.3f}" if fresh else "0"
        for (src, dst, typ), n in agg.items():
            s = names[src]
            d = names[dst] if dst else s          # unknown target: arc collapses to a pulse at the source
            rows.append({"session_id": f"{src}>{dst or '?'}:{typ}@{batch}", "src_lat": s[0], "src_lon": s[1],
                         "dst_lat": d[0], "dst_lon": d[1], "src_name": s[2], "dst_name": d[2] if dst else None,
                         "attack_type": typ, "count": n})
        new = self._store_flows(fid, t0, rows, spread_s=58, status_count=len(fresh))
        if fresh:
            self.db.set_setting(f"{fid}_last_at", max(e["at"] for e in fresh))
        return {"ok": True, "count": len(fresh), "new_events": len(new)}

    # ---- one run ---------------------------------------------------------
    def run_source(self, fid):
        feed = F.FEEDS[fid]
        if feed.get("kind") == "sensor":
            return self.run_sensor(fid)
        if feed.get("kind") == "flows":
            return self.run_flows(fid)
        if feed.get("kind") == "rwplay":
            return self.run_radware(fid)
        if feed.get("kind") == "stream":
            return {"ok": True, "count": 0, "new_events": 0, "note": "streaming source: runs continuously"}
        t0 = now()
        with self.db.conn() as c:
            src = c.execute("SELECT * FROM sources WHERE id=?", (fid,)).fetchone()
            c.execute("UPDATE sources SET last_attempt=? WHERE id=?", (t0, fid))
        if feed["key"] and not src["api_key"]:
            return self._fail(fid, "API key not configured")
        try:
            body = self.fetcher(fid, src["api_key"])
            records = feed["parse"](body)
        except Exception as e:  # network error, HTTP error, parse error: all recorded, none fatal
            return self._fail(fid, self._describe(e, src["api_key"]))

        # de-duplicate by (ip, category)
        seen, uniq = set(), []
        for r in records:
            k = (r["ip"], r["category"])
            if k not in seen:
                seen.add(k)
                uniq.append(r)
        truncated = len(uniq) > self.cfg.max_indicators_per_source
        uniq = uniq[: self.cfg.max_indicators_per_source]

        with self.db.conn() as c:
            prev = c.execute("SELECT COUNT(*) FROM indicators WHERE source=? AND active=1", (fid,)).fetchone()[0]
        if not uniq:
            return self._fail(fid, "feed returned no valid records (format change or empty response); previous data kept")
        if prev >= SHRINK_GUARD_MIN and len(uniq) < prev * SHRINK_GUARD_RATIO:
            return self._fail(fid, f"snapshot shrank from {prev} to {len(uniq)} records; rejected as suspicious, previous data kept")

        events = []
        with self.db.tx() as c:
            existing = {(r["ip"], r["category"]): r["id"]
                        for r in c.execute("SELECT id, ip, category FROM indicators WHERE source=?", (fid,))}
            for r in uniq:
                g = self.geo.lookup(r["ip"])
                key = (r["ip"], r["category"])
                if key in existing:
                    c.execute("""UPDATE indicators SET last_seen=?, active=1, malware=COALESCE(?,malware),
                                 port=COALESCE(?,port), country=?, city=?, lat=?, lon=?, asn=?, org=? WHERE id=?""",
                              (t0, r.get("malware"), r.get("port"), g["country"], g["city"], g["lat"], g["lon"],
                               g["asn"], g["org"], existing[key]))
                else:
                    c.execute("""INSERT INTO indicators(ip,source,category,malware,port,first_seen,last_seen,active,
                                 country,city,lat,lon,asn,org) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?)""",
                              (r["ip"], fid, r["category"], r.get("malware"), r.get("port"), t0, t0,
                               g["country"], g["city"], g["lat"], g["lon"], g["asn"], g["org"]))
                    if len(events) < self.cfg.max_events_per_run:
                        events.append((t0, r["ip"], fid, r["category"], r.get("malware"), F.OBSERVATION_TYPE,
                                       g["country"], g["lat"], g["lon"], r.get("port"), None))
            c.execute("UPDATE indicators SET active=0 WHERE source=? AND last_seen<?", (fid, t0))
            ev_rows = []
            for e in events:
                cur = c.execute("""INSERT INTO events(ts,ip,source,category,malware,observation_type,country,lat,lon,port,proto)
                                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""", e)
                ev_rows.append((cur.lastrowid,) + e)
            c.execute("""UPDATE sources SET last_success=?, last_error=?, last_count=? WHERE id=?""",
                      (t0, "list truncated to configured cap" if truncated else None, len(uniq), fid))
        tagged = self._apply_tags(fid, feed) if feed.get("tag_lists") else None
        self.version += 1
        tagmap = {}
        if tagged and ev_rows:
            with self.db.conn() as c:
                ips = list({r[2] for r in ev_rows})
                for i in range(0, len(ips), 500):
                    part = ips[i:i + 500]
                    tagmap.update({r["ip"]: r["tags"] for r in c.execute(
                        f"SELECT ip, tags FROM indicators WHERE source=? AND ip IN ({','.join('?' * len(part))})",
                        [fid, *part])})
        for row in ev_rows:
            self.publish(with_activity(dict(zip(EV_COLS, row)), tagmap.get(row[2])))
        log.info("source %s: %d records, %d new events", fid, len(uniq), len(ev_rows))
        out = {"ok": True, "count": len(uniq), "new_events": len(ev_rows)}
        if tagged is not None:
            out["tags"] = tagged
        return out

    def _apply_tags(self, fid, feed):
        """Record which services each of this source's IPs was reported attacking, from its per-service lists.
        Best effort: a list that fails to download keeps the previous tags for that service; the main
        ingest has already succeeded and is not affected."""
        ok, failed = {}, []
        for tag in feed["tag_lists"]:
            try:
                ok[tag] = {r["ip"] for r in F.parse_plain_ip_list(self.fetcher(f"{fid}:{tag}", None), "x")}
            except Exception as e:
                failed.append(tag)
                log.warning("source %s: tag list %s failed: %s", fid, tag, self._describe(e, None))
        if not ok:
            return {"ok": [], "failed": failed}
        order = list(feed["tag_lists"])
        with self.db.tx() as c:
            rows = c.execute("SELECT id, ip, tags FROM indicators WHERE source=? AND active=1", (fid,)).fetchall()
            for r in rows:
                old = set((r["tags"] or "").split(",")) & set(failed)
                new = {t for t, ips in ok.items() if r["ip"] in ips} | old
                val = ",".join(t for t in order if t in new) or None
                if val != r["tags"]:
                    c.execute("UPDATE indicators SET tags=? WHERE id=?", (val, r["id"]))
        return {"ok": sorted(ok), "failed": failed}

    @staticmethod
    def _describe(e, key):
        msg = f"{type(e).__name__}: {e}"
        if key:
            msg = msg.replace(key, "***")
        return msg[:300]

    def _fail(self, fid, msg):
        log.warning("source %s failed: %s", fid, msg)
        with self.db.conn() as c:
            c.execute("UPDATE sources SET last_error=? WHERE id=?", (msg, fid))
        return {"ok": False, "error": msg}

    # ---- maintenance -----------------------------------------------------
    def retention_days(self):
        try:
            return int(self.db.get_setting("retention_days", self.cfg.retention_days))
        except (TypeError, ValueError):
            return self.cfg.retention_days

    def run_retention(self):
        cutoff = now() - self.retention_days() * 86400
        with self.db.tx() as c:
            a = c.execute("DELETE FROM indicators WHERE active=0 AND last_seen<?", (cutoff,)).rowcount
            b = c.execute("DELETE FROM events WHERE ts<?", (cutoff,)).rowcount
            c.execute("DELETE FROM sessions WHERE expires_at<?", (now(),))
            c.execute("DELETE FROM ip_lookups WHERE fetched_at<?", (now() - 7 * 86400,))
            fcut = now() - min(self.retention_days(), self.cfg.flow_retention_days) * 86400
            b += c.execute("DELETE FROM flows WHERE ts<?", (fcut,)).rowcount
        if a or b:
            self.version += 1
        log.info("retention: removed %d indicators, %d events", a, b)
        return a, b

    # ---- scheduler -------------------------------------------------------
    @staticmethod
    def next_run(r, f):
        """When the scheduler will next run this source (epoch seconds; the loop checks every 30 s).
        None for disabled or streaming sources. A failed source is retried sooner (RETRY_AFTER_FAILURE)."""
        if not r["enabled"] or f.get("kind") == "stream":
            return None
        last = r["last_attempt"] or 0
        failed = r["last_error"] and not r["last_error"].startswith("list truncated") and (r["last_success"] or 0) < last
        return last + (min(f["interval"], RETRY_AFTER_FAILURE) if failed else f["interval"])

    def due_sources(self):
        t = now()
        out = []
        with self.db.conn() as c:
            for r in c.execute("SELECT * FROM sources WHERE enabled=1"):
                f = F.FEEDS.get(r["id"])
                nxt = self.next_run(r, f) if f else None
                if nxt is not None and t >= nxt:
                    out.append(r["id"])
        return out

    async def loop(self):
        await asyncio.sleep(3)
        last_maint = 0
        while not self._stop:
            try:
                for fid in self.due_sources():
                    if self._stop:
                        break
                    await asyncio.to_thread(self.run_source, fid)   # sequential: bounded CPU/RAM
                if time.time() - last_maint > 86400:
                    await asyncio.to_thread(self.run_retention)
                    last_maint = time.time()
            except Exception:
                log.exception("collector loop error (continuing)")
            await asyncio.sleep(30)

    def start(self):
        self._task = asyncio.get_running_loop().create_task(self.loop())

    async def stop(self):
        self._stop = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
