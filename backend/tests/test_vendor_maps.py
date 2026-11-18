"""Check Point (SSE stream) and Radware (scheduled playback) arc sources."""
import gzip
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient
from gti import feeds as F
from gti.collector import gunzip_bounded
from gti.stream import CheckpointStream, iter_sse
from conftest import do_setup


def cp(**over):
    d = {"a_c": 1, "a_n": "Realtek Jungle SDK Command Injection (CVE-2021-35394)", "a_t": "exploit",
         "d_co": "MX", "d_la": 20.6381, "d_lo": -103.348, "d_s": "JAL",
         "s_co": "US", "s_lo": -97.3842, "s_la": 32.7446, "s_s": "TX", "t": None}
    d.update(over)
    return json.dumps(d)


# ---------------- Check Point ----------------
def test_checkpoint_parser_valid_and_invalid():
    f = F.parse_checkpoint_attack(cp())
    assert f["attack_type"] == "exploit" and f["count"] == 1
    assert f["src_name"] == "United States of America" and f["dst_name"] == "Mexico"
    assert "CVE-2021-35394" in f["attack_name"]
    for bad in [cp(s_la=91), cp(d_lo="x"), cp(a_t="DROP TABLE"), cp(a_t=5), cp(a_c=0), cp(a_c=True), "not json", "[]"]:
        assert F.parse_checkpoint_attack(bad) is None, bad
    assert F.parse_checkpoint_attack(cp(a_n="evil\x00name"))["attack_name"] is None   # non-printable dropped
    assert F.parse_checkpoint_attack(cp(s_co="ZZ"))["src_name"] is None              # unknown country -> no name


def test_iter_sse():
    lines = ["event:counter\n", 'data:{"today":5}\n', "retry:10000\n", "\n", ":keep-alive\n", "\n",
             "event:attack\n", "data:{\"a\":\n", "data:1}\n", "\n", "data:no-event-name\n", "\n"]
    assert list(iter_sse(lines)) == [("counter", '{"today":5}'), ("keepalive", ""), ("attack", '{"a":\n1}'),
                                     ("message", "no-event-name")]


def test_stream_merges_identical_events_and_records_total(make_app):
    app = make_app(None)
    st = app.state.stream
    got = []
    app.state.collector.publish = lambda ev, kind="event": got.append((kind, ev))
    for _ in range(4):
        st.handle("attack", cp(a_n="Memcached Flood", a_t="exploit"))        # stream repeats identical events
    st.handle("attack", cp(a_t="malware", a_n="Mirai"))
    st.handle("attack", "garbage")
    st.handle("counter", '{"recentPeriod":[1,2],"today":14906476}')
    new = st.flush()
    assert len(new) == 2
    with app.state.db.conn() as c:
        rows = {r[0]: r[1] for r in c.execute("SELECT attack_type, count FROM flows WHERE source='checkpoint_map'")}
        src = dict(c.execute("SELECT * FROM sources WHERE id='checkpoint_map'").fetchone())
    assert rows == {"exploit": 4, "malware": 1}                    # counts kept, no duplicate arcs
    assert src["last_success"] and src["last_error"] is None and src["last_count"] == 5
    assert app.state.db.get_setting("checkpoint_map_today") == "14906476"
    assert all(k == "flow" and 0 <= ev["delay_ms"] <= 10000 for k, ev in got)


def test_stream_quiet_but_connected_stays_healthy(make_app):
    app = make_app(None)
    app.state.stream.flush()                                        # keep-alives only, no attacks
    with app.state.db.conn() as c:
        assert c.execute("SELECT last_success FROM sources WHERE id='checkpoint_map'").fetchone()[0]


def test_stream_reconnects_and_reports_errors(make_app):
    calls = {"n": 0}

    def opener():
        calls["n"] += 1
        yield "event:attack\n"
        yield f"data:{cp()}\n"
        yield "\n"
        raise ConnectionError("network unreachable")

    app = make_app(None, stream_opener=opener)
    st = app.state.stream
    th = threading.Thread(target=st.run, daemon=True)
    th.start()
    time.sleep(1.0)
    st.stop()
    th.join(5)
    assert not th.is_alive()
    with app.state.db.conn() as c:
        err = c.execute("SELECT last_error FROM sources WHERE id='checkpoint_map'").fetchone()[0]
        n = c.execute("SELECT SUM(count) FROM flows WHERE source='checkpoint_map'").fetchone()[0]
    assert "network unreachable" in err and "reconnecting" in err
    assert n == 1                                                   # buffered event was flushed before reconnect


def test_stream_retention_24h(make_app):
    app = make_app(None)
    st = app.state.stream
    st.handle("attack", cp())
    st.flush()
    with app.state.db.conn() as c:
        c.execute("UPDATE flows SET ts=?", (int(time.time()) - 25 * 3600,))
    st.flush()                                                      # every store prunes the source's old rows
    with app.state.db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0


# ---------------- Radware ----------------
def rw_body(events):
    return json.dumps([[{"sourceCountry": s, "destinationCountry": d, "millisecond": 0, "type": t,
                         "weight": "Light", "attackTime": at} for (s, d, t, at) in events]])


def test_radware_time_and_parser():
    assert F.radware_time("2026-11-17T23:58:11.9366667") == pytest.approx(F.radware_time("2026-11-17T23:58:11") + 0.9366667)
    ev = F.parse_radware(rw_body([("US", "  ", "webAttackers", "2026-11-17T23:58:11.93"),
                                  ("BG", "IL", "scanners", "2026-11-17T23:58:12"),
                                  ("XX1", "IL", "scanners", "2026-11-17T23:58:12"),
                                  ("US", "IL", "hacking", "2026-11-17T23:58:12"),
                                  ("US", "IL", "scanners", "yesterday")]))
    assert [(e["src"], e["dst"], e["type"]) for e in ev] == [("US", None, "webAttackers"), ("BG", "IL", "scanners")]
    with pytest.raises(ValueError):
        F.parse_radware('{"nope": 1}')


def test_radware_ingests_each_scheduled_event_once(make_app):
    base = "2026-11-17T23:58:"
    first = [("US", "  ", "webAttackers", base + "10.1"), ("US", "  ", "webAttackers", base + "10.2"),
             ("BG", "IL", "scanners", base + "11"), ("HK", "NZ", "botnets", base + "12")]
    second = first[2:] + [("BG", "IL", "scanners", base + "13"), ("CN", "US", "dDosAttackers", base + "14")]
    bodies = iter([rw_body(first), rw_body(second)])
    app = make_app(lambda f, k: next(bodies))
    c = app.state.collector
    assert c.run_source("radware_map")["count"] == 4
    assert c.run_source("radware_map")["count"] == 2               # overlap (11, 12) not counted again
    with app.state.db.conn() as cx:
        tot = {r[0]: r[1] for r in cx.execute("SELECT attack_type, SUM(count) FROM flows GROUP BY 1")}
        unknown = dict(cx.execute("SELECT * FROM flows WHERE attack_type='webAttackers'").fetchone())
    assert tot == {"webAttackers": 2, "scanners": 2, "botnets": 1, "dDosAttackers": 1}
    assert unknown["dst_name"] is None and unknown["dst_lat"] == unknown["src_lat"]   # unknown target -> pulse
    assert unknown["count"] == 2                                     # aggregated, not two rows


def test_radware_bad_response_flags_error(make_app):
    app = make_app(lambda f, k: "<html>maintenance</html>")
    r = app.state.collector.run_source("radware_map")
    assert r["ok"] is False


# ---------------- shared ----------------
def test_country_positions_are_inside_the_country():
    # Regression: Natural Earth's "Ashmore and Cartier Is." (fallback code AU) replaced Australia.
    boxes = {"AU": (-39, -11, 113, 154), "FR": (42, 51, -5, 8), "NO": (58, 71, 4, 31), "US": (25, 49, -125, -67),
             "CY": (34.5, 35.7, 32.2, 34.6), "MA": (27, 36, -13, -1), "CN": (18, 54, 73, 135), "TW": (21.8, 25.4, 119.9, 122.1)}
    names = F.countries()
    for cc, (lat0, lat1, lon0, lon1) in boxes.items():
        lat, lon, _ = names[cc]
        assert lat0 <= lat <= lat1 and lon0 <= lon <= lon1, (cc, lat, lon)
    assert names["AU"][2] == "Australia"



def test_gzip_bomb_guard():
    small = gzip.compress(b"a" * 1000)
    assert gunzip_bounded(small, 2000) == b"a" * 1000
    with pytest.raises(ValueError):
        gunzip_bounded(gzip.compress(b"a" * 100_000), 10_000)


def test_api_reports_all_arc_sources(make_app):
    bodies = iter([rw_body([("BG", "IL", "scanners", "2026-11-17T23:58:11")])])
    app = make_app(lambda f, k: next(bodies))
    app.state.collector.run_source("radware_map")
    st = app.state.stream
    st.handle("attack", cp())
    st.flush()
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        d = cl.get("/api/flows").json()
        assert d["types"] == {"radware_map": {"scanners": 1}, "checkpoint_map": {"exploit": 1}}
        assert {f["observation_type"] for f in d["flows"]} == {"vendor_telemetry"}
        assert {f["source"] for f in cl.get("/api/flows?source=radware_map").json()["flows"]} == {"radware_map"}
        st_ = cl.get("/api/stats").json()
        assert st_["arcs_by_source_and_type"]["checkpoint_map"] == {"exploit": 1}
        assert st_["unique_ips"] == 0                                # arcs never inflate IP statistics
        srcs = {s["id"]: s for s in cl.get("/api/sources").json()["sources"]}
        assert srcs["radware_map"]["observation_type"] == "vendor_telemetry"
        assert "playback" in srcs["radware_map"]["description"]
