"""GreyNoise sensor-network arcs: parsing, validation, de-duplication, API, WebSocket, retention, staleness."""
import json
import time

import pytest
from fastapi.testclient import TestClient
from gti import feeds as F
from conftest import do_setup


def beacon(**over):
    b = {"sensorId": "s1", "sensorName": "Fremont, United States", "srcLat": 45.75, "srcLng": 21.22,
         "lat": 37.54, "lng": -121.98, "tactic": "discovery", "count": 58, "sessionId": "sess-1",
         "alsoSeen": ["defense-evasion", "not-a-tactic"]}
    b.update(over)
    return b


def body(beacons, gen=None):
    gen = gen or time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    return json.dumps({"windowMinutes": 1, "generatedAt": gen, "beacons": beacons, "tacticCounts": {}})


def test_parser_valid_and_rejects_bad_entries():
    good = beacon()
    bad = [beacon(srcLat=95), beacon(lng="10"), beacon(tactic="hacking"), beacon(count=0), beacon(count=True),
           beacon(sessionId=""), "junk", beacon(srcLng=None)]
    gen, out = F.parse_greynoise_beacons(body([good] + bad))
    assert len(out) == 1 and gen
    f = out[0]
    assert f["tactic"] == "discovery" and f["count"] == 58 and f["also_seen"] == ["defense-evasion"]
    assert (f["src_lat"], f["dst_lon"]) == (45.75, -121.98)


def test_parser_sanitizes_sensor_name():
    _, out = F.parse_greynoise_beacons(body([beacon(sensorName="x\x00<script>"), beacon(sessionId="b", sensorName="y" * 200)]))
    assert out[0]["dst_name"] is None and out[1]["dst_name"] is None


def test_parser_format_change_raises_but_empty_is_ok():
    with pytest.raises(ValueError):
        F.parse_greynoise_beacons('{"data": []}')
    with pytest.raises(Exception):
        F.parse_greynoise_beacons("<html>")
    assert F.parse_greynoise_beacons(body([]))[1] == []


def test_ingest_dedup_and_api(make_app):
    payload = body([beacon(), beacon(sessionId="sess-2", tactic="exfiltration", count=12)])
    app = make_app(lambda f, k: payload)
    c = app.state.collector
    r = c.run_source("greynoise_map")
    assert r == {"ok": True, "count": 2, "new_events": 2}
    assert c.run_source("greynoise_map")["new_events"] == 0          # same window -> no duplicates
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        d = cl.get("/api/flows").json()
        assert len(d["flows"]) == 2 and d["tactics"] == {"discovery": 58, "exfiltration": 12}
        assert all(f["source_name"] == "GreyNoise global sensor network" for f in d["flows"])
        assert "No attacker IP addresses" in d["note"]
        assert cl.get("/api/flows?tactic=exfiltration").json()["flows"][0]["count"] == 12
        st = cl.get("/api/stats").json()
        assert st["sensor_sessions_24h_by_tactic"] == {"discovery": 58, "exfiltration": 12}
        assert st["unique_ips"] == 0      # arcs never inflate IP statistics
        src = {s["id"]: s for s in cl.get("/api/sources").json()["sources"]}["greynoise_map"]
        assert src["observation_type"] == "sensor_network_observation" and src["status"] == "ok"
        cl.put("/api/sources/greynoise_map", json={"enabled": False}, headers={"x-csrf-token": cl.get("/api/me").json()["csrf"]})
        assert cl.get("/api/flows").json()["flows"] == []


def test_implausible_provider_time_uses_local_clock(make_app):
    app = make_app(lambda f, k: body([beacon()], gen="2001-01-01T00:00:00Z"))
    app.state.collector.run_source("greynoise_map")
    with app.state.db.conn() as cx:
        ts = cx.execute("SELECT ts FROM flows").fetchone()[0]
    assert abs(ts - time.time()) < 120


def test_outage_marks_stale_not_live(make_app):
    app = make_app(lambda f, k: body([beacon()]))
    app.state.collector.run_source("greynoise_map")
    with app.state.db.conn() as cx:
        cx.execute("UPDATE sources SET last_success=? WHERE id='greynoise_map'", (int(time.time()) - 3600,))
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        assert "greynoise_map" in cl.get("/api/flows").json()["unhealthy_sources"]


def test_flow_retention(make_app):
    app = make_app(lambda f, k: body([beacon()]))
    app.state.collector.run_source("greynoise_map")
    with app.state.db.conn() as cx:
        cx.execute("UPDATE flows SET ts=?", (int(time.time()) - 4 * 86400,))   # older than flow_retention_days=3
    app.state.collector.run_retention()
    with app.state.db.conn() as cx:
        assert cx.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0


def test_flow_pushed_over_websocket(make_app):
    app = make_app(lambda f, k: body([beacon()]))
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        with cl.websocket_connect("/ws") as ws:
            assert ws.receive_json()["type"] == "hello"
            app.state.collector.run_source("greynoise_map")
            m = ws.receive_json()
            assert m["type"] == "flow" and m["flow"]["tactic"] == "discovery" and m["flow"]["also_seen"] == ["defense-evasion"]
