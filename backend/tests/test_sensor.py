import json
import sqlite3
import time

from fastapi.testclient import TestClient
from gti import sensor
from gti.db import MIGRATIONS, Database, _split
from conftest import do_setup

LINES = [
    ("sshd", "Failed password for root from 45.33.32.156 port 51234 ssh2"),
    ("sshd", "Failed password for invalid user admin from 45.33.32.156 port 51240 ssh2"),
    ("sshd-session", "Invalid user oracle from 2001:4860:4860::8888 port 4444"),
    ("sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.4.4  user=root"),
    ("sshd", "Accepted publickey for pi from 45.33.32.156 port 5000 ssh2"),         # success: ignored
    ("sshd", "Failed password for root from 192.168.1.20 port 5000 ssh2"),           # LAN: ignored
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=185.220.101.1 DST=192.168.1.10 LEN=40 TOS=0x00 PROTO=TCP SPT=4444 DPT=3389 WINDOW=1024"),
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=1.1.1.1 DST=192.168.1.10 LEN=40 PROTO=ICMP TYPE=8"),
    ("kernel", "[UFW ALLOW] IN=eth0 SRC=185.220.101.1 DST=192.168.1.10 PROTO=TCP DPT=22"),  # allow: ignored
    ("kernel", "usb 1-1: new device"),
]


def test_parse_lines():
    out = [sensor.parse_line(i, m) for i, m in LINES]
    assert out[0] == {"ip": "45.33.32.156", "category": "ssh_bruteforce", "port": 22, "proto": "tcp"}
    assert out[1]["ip"] == "45.33.32.156"
    assert out[2]["ip"] == "2001:4860:4860::8888"
    assert out[3]["ip"] == "8.8.4.4"
    assert out[4] is None and out[5] is None
    assert out[6] == {"ip": "185.220.101.1", "category": "blocked_connection", "port": 3389, "proto": "tcp"}
    assert out[7] == {"ip": "1.1.1.1", "category": "blocked_connection", "port": None, "proto": "icmp"}
    assert out[8] is None and out[9] is None
    assert sensor.parse_line("sshd", None) is None


def test_forged_sshd_lines_from_normal_users_rejected():
    assert sensor.trusted({"_UID": "0", "SYSLOG_IDENTIFIER": "sshd"})
    assert not sensor.trusted({"_UID": "1000", "SYSLOG_IDENTIFIER": "sshd"})   # `logger -t sshd` by a user
    assert not sensor.trusted({"SYSLOG_IDENTIFIER": "sshd"})                   # no trusted UID field
    assert sensor.trusted({"_TRANSPORT": "kernel"})


def test_parse_journal_json_dump():
    now_us = int(time.time() * 1e6)
    dump = "\n".join(json.dumps({"SYSLOG_IDENTIFIER": i, "MESSAGE": m, "__REALTIME_TIMESTAMP": str(now_us)}) for i, m in LINES)
    recs = sensor.parse_text_dump(dump + "\nnot json")
    assert len(recs) == 6 and all(abs(r["ts"] - now_us // 1_000_000) <= 1 for r in recs)


def fake_reader(batches):
    state = {"i": 0, "cursors": []}

    def read(cursor):
        state["cursors"].append(cursor)
        b = batches[min(state["i"], len(batches) - 1)]
        state["i"] += 1
        recs = [dict(sensor.parse_line(i, m), ts=int(time.time())) for i, m in b if sensor.parse_line(i, m)]
        return recs, f"c{state['i']}"
    read.state = state
    return read


def test_sensor_ingest_events_hits_cursor(make_app):
    reader = fake_reader([LINES, [], LINES[:2]])
    app = make_app(None, journal_reader=reader)
    c = app.state.collector
    r = c.run_source("local_sensor")
    assert r["ok"] and r["count"] == 6
    # one event per (ip, category, port): 45.33.32.156 twice -> one event
    assert r["new_events"] == 5
    with app.state.db.conn() as cx:
        ev = [dict(x) for x in cx.execute("SELECT * FROM events")]
        hits = cx.execute("SELECT hits FROM indicators WHERE ip='45.33.32.156'").fetchone()[0]
    assert all(e["observation_type"] == "direct_observation" for e in ev)
    assert {e["port"] for e in ev if e["ip"] == "185.220.101.1"} == {3389}
    assert hits == 2
    assert app.state.db.get_setting("sensor_cursor") == "c1"
    assert c.run_source("local_sensor")["count"] == 0
    c.run_source("local_sensor")
    assert reader.state["cursors"] == [None, "c1", "c2"]      # resumes from saved cursor, no re-import
    with app.state.db.conn() as cx:
        assert cx.execute("SELECT hits FROM indicators WHERE ip='45.33.32.156'").fetchone()[0] == 4


def test_sensor_unavailable_reports_clearly(make_app, monkeypatch):
    monkeypatch.setattr(sensor, "available", lambda: False)
    app = make_app(None)
    r = app.state.collector.run_source("local_sensor")
    assert r["ok"] is False and "journalctl" in r["error"]
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        src = {s["id"]: s for s in cl.get("/api/sources").json()["sources"]}
        assert src["local_sensor"]["status"] == "unavailable" and src["local_sensor"]["enabled"] is False


def test_observed_vs_reported_in_api(make_app):
    from conftest import FEODO
    app = make_app(lambda f, k: FEODO, journal_reader=fake_reader([[("sshd", "Failed password for root from 8.8.8.8 port 1 ssh2")]]))
    app.state.collector.run_source("feodo")
    app.state.collector.run_source("local_sensor")
    with TestClient(app, base_url="http://testserver") as cl:
        do_setup(cl, app)
        d = cl.get("/api/ip/8.8.8.8").json()
        types = {i["source"]: i["observation_type"] for i in d["indicators"]}
        assert types == {"feodo": "third_party_report", "local_sensor": "direct_observation"}
        assert d["observed"] is True and "Observed" in d["evidence_note"] and "Reported" in d["evidence_note"]
        pts = {p["ip"]: p for p in cl.get("/api/map").json()["points"]}
        assert pts["8.8.8.8"]["observed"] is True and pts["1.1.1.1"]["observed"] is False


def test_home_location_settings(authed):
    assert authed.get("/api/settings").json()["home"] is None
    for bad in [{"lat": 91, "lon": 0}, {"lat": "1", "lon": 0}, {"lat": 0, "lon": 181}, {"lat": True, "lon": 0},
                {"lat": 0, "lon": 0, "label": "x" * 41}, "nope"]:
        assert authed.put("/api/settings", json={"home": bad}).status_code == 422, bad
    r = authed.put("/api/settings", json={"home": {"lat": 51.5074, "lon": -0.1278, "label": "Home lab"}}).json()
    assert r["home"] == {"lat": 51.5074, "lon": -0.1278, "label": "Home lab"}
    assert authed.put("/api/settings", json={"home": None}).json()["home"] is None
    assert authed.get("/api/locate-me").json()["found"] is False    # test client is not a public IP


def test_upgrade_v1_database_preserves_data(tmp_path):
    p = str(tmp_path / "gti.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE schema_version(v INTEGER NOT NULL)")
    for s in _split(MIGRATIONS[0]):
        c.execute(s)
    c.execute("INSERT INTO schema_version VALUES(1)")
    c.execute("INSERT INTO users(username,pw_hash,created_at) VALUES('admin','scrypt$x$y',1)")
    c.execute("INSERT INTO sources(id,enabled,api_key) VALUES('abuseipdb',1,'KEEPME')")
    c.execute("INSERT INTO indicators(ip,source,category,first_seen,last_seen) VALUES('8.8.8.8','feodo','botnet_c2',1,2)")
    c.execute("INSERT INTO events(ts,ip,source,category,observation_type) VALUES(1,'8.8.8.8','feodo','botnet_c2','third_party_report')")
    c.commit()
    c.close()
    db = Database(p)
    assert db.schema_version() == len(MIGRATIONS)
    with db.conn() as cx:
        assert cx.execute("SELECT username FROM users").fetchone()[0] == "admin"
        assert cx.execute("SELECT api_key FROM sources WHERE id='abuseipdb'").fetchone()[0] == "KEEPME"
        assert cx.execute("SELECT hits FROM indicators").fetchone()[0] == 1
        assert cx.execute("SELECT port FROM events").fetchone()[0] is None
