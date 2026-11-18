import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from conftest import FEODO, do_setup


def stateful(responses):
    state = {"i": 0}

    def f(fid, key):
        r = responses[min(state["i"], len(responses) - 1)]
        state["i"] += 1
        if isinstance(r, Exception):
            raise r
        return r
    return f


def source(app, fid):
    with app.state.db.conn() as c:
        return dict(c.execute("SELECT * FROM sources WHERE id=?", (fid,)).fetchone())


def count_active(app):
    with app.state.db.conn() as c:
        return c.execute("SELECT COUNT(*) FROM indicators WHERE active=1").fetchone()[0]


def test_outage_keeps_data_records_error(make_app):
    app = make_app(stateful([FEODO, TimeoutError("timed out")]))
    c = app.state.collector
    assert c.run_source("feodo")["ok"]
    t_ok = source(app, "feodo")["last_success"]
    assert c.run_source("feodo")["ok"] is False
    s = source(app, "feodo")
    assert s["last_success"] == t_ok and "TimeoutError" in s["last_error"]
    assert count_active(app) == 2


def test_stale_never_reported_as_live(make_app):
    app = make_app(stateful([FEODO]))
    app.state.collector.run_source("feodo")
    with app.state.db.conn() as cx:
        cx.execute("UPDATE sources SET last_success=? WHERE id='feodo'", (int(time.time()) - 3 * 86400,))
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        src = {s["id"]: s for s in cl.get("/api/sources").json()["sources"]}
        assert src["feodo"]["status"] == "stale"
        assert "feodo" in cl.get("/api/map").json()["unhealthy_sources"]


def test_format_change_rejected_and_data_kept(make_app):
    app = make_app(stateful([FEODO, "<html>Maintenance</html>", "[]"]))
    c = app.state.collector
    c.run_source("feodo")
    assert c.run_source("feodo")["ok"] is False
    assert c.run_source("feodo")["ok"] is False
    assert count_active(app) == 2


def test_shrink_guard(make_app):
    big = "\n".join(f"8.{i // 250}.{i % 250}.7" for i in range(200))
    app = make_app(stateful([big, "8.0.0.7\n"]))
    c = app.state.collector
    assert c.run_source("blocklist_de")["ok"]
    r = c.run_source("blocklist_de")
    assert r["ok"] is False and "shrank" in r["error"]
    assert count_active(app) == 200


def test_removed_ips_deactivated(make_app):
    a = "\n".join(f"8.8.{i}.1" for i in range(1, 11))
    b = "\n".join(f"8.8.{i}.1" for i in range(1, 9))
    app = make_app(stateful([a, b]))
    c = app.state.collector
    c.run_source("cins")
    time.sleep(1.1)
    c.run_source("cins")
    assert count_active(app) == 8


def test_cap_enforced_and_event_flood_limited(make_app):
    big = "\n".join(f"8.{i // 250}.{i % 250}.9" for i in range(600))
    app = make_app(stateful([big]), max_indicators_per_source=100, max_events_per_run=10)
    r = app.state.collector.run_source("cins")
    assert r["count"] == 100 and r["new_events"] == 10
    assert "truncated" in source(app, "cins")["last_error"]


def test_missing_key_and_error_redaction(make_app):
    app = make_app(stateful([RuntimeError("401 for key supersecret")]))
    c = app.state.collector
    assert "API key not configured" in c.run_source("abuseipdb")["error"]
    with app.state.db.conn() as cx:
        cx.execute("UPDATE sources SET api_key='supersecret', enabled=1 WHERE id='abuseipdb'")
    err = c.run_source("abuseipdb")["error"]
    assert "supersecret" not in err and "***" in err


def test_retention_cleanup(make_app):
    app = make_app(stateful([FEODO]))
    c = app.state.collector
    c.run_source("feodo")
    old = int(time.time()) - 100 * 86400
    with app.state.db.conn() as cx:
        cx.execute("UPDATE indicators SET active=0, last_seen=?", (old,))
        cx.execute("UPDATE events SET ts=?", (old,))
    assert c.run_retention() == (2, 2)


def test_due_scheduling_and_backoff(make_app):
    app = make_app(stateful([TimeoutError("x")]))
    c = app.state.collector
    assert "feodo" in c.due_sources() and "abuseipdb" not in c.due_sources()
    c.run_source("feodo")
    assert "feodo" not in c.due_sources()
    with app.state.db.conn() as cx:
        cx.execute("UPDATE sources SET last_attempt=? WHERE id='feodo'", (int(time.time()) - 960,))
    assert "feodo" in c.due_sources()


def test_survives_restart(make_app):
    app = make_app(stateful([FEODO]))
    app.state.collector.run_source("feodo")
    app2 = make_app(stateful([FEODO]))
    with app2.state.db.conn() as cx:
        assert cx.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2


def test_failed_ingest_rolls_back(make_app, monkeypatch):
    app = make_app(stateful([FEODO]))
    c = app.state.collector
    calls = {"n": 0}
    orig = c.geo.lookup

    def boom(ip):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return orig(ip)
    monkeypatch.setattr(c.geo, "lookup", boom)
    with pytest.raises(RuntimeError):
        c.run_source("feodo")
    with app.state.db.conn() as cx:
        assert cx.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 0


def test_migration_refuses_newer_schema(tmp_path):
    from gti.db import Database
    d = Database(str(tmp_path / "x.db"))
    with d.conn() as c:
        c.execute("INSERT INTO schema_version(v) VALUES(99)")
    with pytest.raises(RuntimeError):
        Database(str(tmp_path / "x.db"))


def test_websocket_auth_origin_and_delivery(make_app):
    app = make_app(stateful([FEODO]))
    with TestClient(app, base_url="http://testserver") as cl:
        with pytest.raises(WebSocketDisconnect):
            with cl.websocket_connect("/ws"):
                pass
        do_setup(cl, app)
        with cl.websocket_connect("/ws") as ws:
            assert ws.receive_json()["type"] == "hello"
            app.state.collector.run_source("feodo")
            ev = ws.receive_json()
            assert ev["type"] == "event" and ev["event"]["observation_type"] == "third_party_report"
            assert ev["event"]["source"] == "feodo"
        with pytest.raises(WebSocketDisconnect):
            with cl.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
                pass
