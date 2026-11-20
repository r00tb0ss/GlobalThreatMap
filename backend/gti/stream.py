"""Server-sent-events (SSE) stream reader for the Check Point live threat map.

One daemon thread keeps one HTTPS connection open, parses 'attack' and 'counter' events, buffers them and
flushes every FLUSH_S seconds: identical attacks inside a flush window are merged into one arc with the counts
added (the stream often repeats an identical event several times in a row), then stored and pushed to browsers.
Reconnects with exponential backoff (10 s .. 5 min). Health is recorded on the source row like any other source.
"""
import json
import logging
import threading
import time
import urllib.request

from . import feeds as F
from .db import now

log = logging.getLogger("gti.stream")
FLUSH_S = 10
MAX_EVENT_BYTES = 256 * 1024   # an SSE event larger than this is dropped (a stream that never sends a blank line)
IDLE_TIMEOUT = 90          # no bytes (not even keep-alives) for this long -> reconnect
MAX_BUFFER = 5000          # bounded memory if the database stalls


def iter_sse(lines):
    """Parse SSE lines -> (event, data) tuples. Handles multi-line data and comments."""
    event, data, size = None, [], 0
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data:
                yield event or "message", "\n".join(data)
            event, data, size = None, [], 0
        elif line.startswith(":"):
            yield "keepalive", ""      # lets the reader flush/update health on a quiet but live stream
        else:
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "event":
                event = value
            elif field == "data":
                size += len(value) + 1
                if size <= MAX_EVENT_BYTES:
                    data.append(value)
                else:
                    data = []       # oversize event: keep consuming lines but never keep the data


def _open_lines(url, headers):
    req = urllib.request.Request(url, headers={**headers, "Accept": "text/event-stream", "Accept-Encoding": "identity"})
    resp = urllib.request.urlopen(req, timeout=IDLE_TIMEOUT)
    for raw in resp:
        yield raw.decode("utf-8", "replace")


class CheckpointStream:
    def __init__(self, collector, fid="checkpoint_map", opener=None):
        self.c, self.fid = collector, fid
        self.opener = opener or (lambda: _open_lines(F.FEEDS[fid]["url"], F.request_headers(fid, None)))
        self.buf = []
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None
        self.last_flush = time.monotonic()

    # ---- event handling (also used directly by tests) ----
    def handle(self, event, data):
        if event == "attack":
            f = F.parse_checkpoint_attack(data)
            if f:
                with self.lock:
                    if len(self.buf) < MAX_BUFFER:
                        self.buf.append(f)
        elif event == "counter":
            try:
                today = json.loads(data).get("today")
            except (ValueError, AttributeError):
                return
            if isinstance(today, int) and today >= 0:
                self.c.db.set_setting(f"{self.fid}_today", today)

    def flush(self, mark_ok=True):
        with self.lock:
            items, self.buf = self.buf, []
        self.last_flush = time.monotonic()
        t = now()
        agg = {}
        for f in items:
            k = (f["attack_type"], f["attack_name"], f["src_lat"], f["src_lon"], f["dst_lat"], f["dst_lon"])
            if k in agg:
                agg[k]["count"] += f["count"]
            else:
                agg[k] = dict(f)
        rows = []
        for i, f in enumerate(agg.values()):
            f["session_id"] = f"{t}:{i}"
            rows.append(f)
        new = self.c._store_flows(self.fid, t, rows, spread_s=FLUSH_S, status_count=sum(f["count"] for f in rows),
                                  mark_ok=mark_ok)
        if rows:
            self.c.version += 1
        return new

    # ---- connection loop ----
    def enabled(self):
        with self.c.db.conn() as cx:
            r = cx.execute("SELECT enabled FROM sources WHERE id=?", (self.fid,)).fetchone()
        return bool(r and r[0])

    def run(self):
        backoff = 10
        while not self._stop.is_set():
            if not self.enabled():
                self._stop.wait(30)
                continue
            with self.c.db.conn() as cx:
                cx.execute("UPDATE sources SET last_attempt=? WHERE id=?", (now(), self.fid))
            failed = False
            try:
                for ev, data in iter_sse(self.opener()):
                    self.handle(ev, data)
                    if time.monotonic() - self.last_flush >= FLUSH_S:
                        self.flush()
                        backoff = 10
                    if self._stop.is_set() or not self.enabled():
                        break
                else:
                    raise ConnectionError("stream closed by server")
            except Exception as e:
                failed = True
                try:   # keep what arrived before the failure, without marking the source healthy
                    self.flush(mark_ok=False)
                except Exception:
                    log.exception("flush failed")
                if self._stop.is_set():
                    break
                self.c._fail(self.fid, f"{type(e).__name__}: {e}"[:300] + f" (reconnecting in {backoff}s)")
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 300)
            finally:
                if not failed:
                    try:
                        self.flush()
                    except Exception:
                        log.exception("flush failed")

    def start(self):
        self.thread = threading.Thread(target=self.run, name="checkpoint-stream", daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()
