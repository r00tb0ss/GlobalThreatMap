"""IP activity explanations, blocklist.de service tags, AbuseIPDB per-IP lookups, exploit/AI labelling."""
import json
import sqlite3
import urllib.error

from fastapi.testclient import TestClient

from gti import intel
from gti.db import MIGRATIONS, Database, now
from conftest import BLD, FEODO, do_setup

KEY = "secretkey123"


def check_response(ip="8.8.8.8"):
    return json.dumps({"data": {
        "ipAddress": ip, "abuseConfidenceScore": 100, "totalReports": 3, "numDistinctUsers": 2,
        "lastReportedAt": "2026-11-18T10:00:00+00:00", "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting", "domain": "example.net", "isTor": False,
        "reports": [
            {"reportedAt": "2026-11-18T10:00:00+00:00", "categories": [18, 22],
             "comment": "sshd  invalid   user admin " + "x" * 400},
            {"reportedAt": "2026-11-17T10:00:00+00:00", "categories": [22, 999, "bad"],
             "comment": "<script>alert(1)</script>"},
            {"reportedAt": "2026-11-16T10:00:00+00:00", "categories": [14], "comment": None},
            "garbage"]}})


def fetch_with_tags(fid, key):
    if fid == "feodo":
        return FEODO
    if fid == "blocklist_de":
        return BLD
    if fid == "blocklist_de:ssh":
        return "8.8.8.8\n"
    if fid == "blocklist_de:mail":
        return "8.8.8.8\n9.9.9.9\n"
    if fid.startswith("blocklist_de:"):
        return "\n"
    return "1.2.3.4\n"


def test_cves_and_ai_target():
    assert intel.cves("Apache Log4j Remote Code Execution (CVE-2021-44228)") == ["CVE-2021-44228"]
    assert intel.cves("Microsoft Windows SMB Information Disclosure (MS17-010: CVE-2017-0147)") == \
        ["CVE-2017-0147", "MS17-010"]
    assert intel.cves(None) == []
    assert intel.ai_target("LangChain Community Server-Side Request Forgery (CVE-2025-2828)") == "LangChain"
    assert intel.ai_target("LF Projects MLFlow Information Disclosure (CVE-2023-43472)") == "MLFlow"
    assert intel.ai_target("Langflow Remote Code Execution") == "Langflow"
    for not_ai in ("Apache Log4j Remote Code Execution", "Phishing SNI", "Rayon", "Email Spam", None):
        assert intel.ai_target(not_ai) is None


def test_summarize_abuseipdb_counts_and_sanitizes():
    s = intel.summarize_abuseipdb(json.loads(check_response()))
    assert [(c["label"], c["reports"]) for c in s["categories"]] == [("SSH", 2), ("Brute-force", 1), ("Port scan", 1)]
    assert len(s["recent_comments"]) == 2                       # empty comment and non-dict report skipped
    assert len(s["recent_comments"][0]["text"]) == 300 and "  " not in s["recent_comments"][0]["text"]
    assert s["recent_comments"][1]["text"] == "<script>alert(1)</script>"   # plain string; the UI renders text only
    assert s["usage_type"].startswith("Data Center") and s["total_reports"] == 3 and s["is_tor"] is False
    try:
        intel.summarize_abuseipdb({"errors": []})
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_port_info():
    assert intel.port_info(3389)["service"].startswith("RDP")
    assert intel.port_info(31337) == {"port": 31337, "service": None, "usual_aim": None}
    assert intel.port_info(None) is None


def test_blocklist_tags_and_activity(make_app):
    app = make_app(fetch_with_tags)
    with TestClient(app, base_url="http://testserver") as cl:
        cl.headers["x-csrf-token"] = do_setup(cl, app)
        r = app.state.collector.run_source("blocklist_de")
        assert r["ok"] and r["tags"]["failed"] == [] and "ssh" in r["tags"]["ok"]
        app.state.collector.run_source("feodo")
        d = cl.get("/api/ip/8.8.8.8").json()
        bl = [i for i in d["indicators"] if i["source"] == "blocklist_de"][0]
        assert bl["tags"] == ["ssh", "mail"]                       # stored in the defined order
        whats = " ".join(a["what"] for a in d["activity"])
        assert "SSH logins" in whats and "mail servers" in whats
        assert "QakBot" in whats and "port 447" in whats           # feodo: malware family + C2 port
        assert all(a["kind"] == "reported" for a in d["activity"])
        assert d["abuseipdb_lookup"] is False
        assert any(p["port"] == 447 for p in d["port_info"])
        assert cl.get("/api/ip/9.9.9.9").json()["indicators"][0]["tags"] == ["mail"]


def test_tag_list_failure_keeps_previous_tags_and_never_fails_source(make_app):
    state = {"fail": False}

    def fetch(fid, key):
        if state["fail"] and fid == "blocklist_de:ssh":
            raise urllib.error.URLError("down")
        if state["fail"] and fid == "blocklist_de:mail":
            return "\n"                                          # mail list now empty: 8.8.8.8 loses mail
        return fetch_with_tags(fid, key)
    app = make_app(fetch)
    c = app.state.collector
    c.run_source("blocklist_de")
    state["fail"] = True
    r = c.run_source("blocklist_de")
    assert r["ok"] and r["tags"]["failed"] == ["ssh"]
    with app.state.db.conn() as cn:
        assert cn.execute("SELECT tags FROM indicators WHERE ip='8.8.8.8' AND source='blocklist_de'").fetchone()[0] == "ssh"


def test_abuseipdb_lookup_key_cache_and_errors(make_app):
    calls = []
    mode = {"m": "ok"}

    def lookup(url, headers):
        calls.append((url, headers))
        if mode["m"] == "429":
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None)
        if mode["m"] == "boom":
            raise RuntimeError("failure mentioning " + headers["Key"])
        return check_response()
    app = make_app(fetch_with_tags, lookup_fetcher=lookup)
    with TestClient(app, base_url="http://testserver") as cl:
        cl.headers["x-csrf-token"] = do_setup(cl, app)
        app.state.collector.run_source("blocklist_de")
        # no key: explains how to enable, makes no outbound request
        r = cl.get("/api/ip/8.8.8.8/abuseipdb").json()
        assert r["available"] is False and "Sources" in r["reason"] and not calls
        assert cl.put("/api/sources/abuseipdb", json={"api_key": KEY, "enabled": True}).status_code == 200
        r = cl.get("/api/ip/8.8.8.8/abuseipdb")
        assert r.status_code == 200 and KEY not in r.text
        d = r.json()
        assert d["available"] and not d["cached"] and d["categories"][0]["label"] == "SSH"
        assert calls[0][1]["Key"] == KEY and "ipAddress=8.8.8.8" in calls[0][0] and "verbose" in calls[0][0]
        assert cl.get("/api/ip/8.8.8.8").json()["abuseipdb_lookup"] is True
        # cached: no second request
        assert cl.get("/api/ip/8.8.8.8/abuseipdb").json()["cached"] is True and len(calls) == 1
        # unknown IP and private IP never leave the server
        assert cl.get("/api/ip/4.4.4.4/abuseipdb").status_code == 404
        assert cl.get("/api/ip/10.0.0.1/abuseipdb").status_code == 422
        assert len(calls) == 1
        # quota exhausted with no saved result -> clear 502; with a stale saved result -> served, error shown
        mode["m"] = "429"
        r = cl.get("/api/ip/9.9.9.9/abuseipdb")
        assert r.status_code == 502 and "limit" in r.json()["detail"]
        with app.state.db.conn() as cn:
            cn.execute("UPDATE ip_lookups SET fetched_at=fetched_at-90000")
        d = cl.get("/api/ip/8.8.8.8/abuseipdb").json()
        assert d["stale"] and "limit" in d["error"] and d["categories"]
        # an error message never contains the key
        mode["m"] = "boom"
        r = cl.get("/api/ip/9.9.9.9/abuseipdb")
        assert r.status_code == 502 and KEY not in r.text and "***" in r.text
        # disabling the source stops lookups
        cl.put("/api/sources/abuseipdb", json={"enabled": False})
        n = len(calls)
        assert cl.get("/api/ip/8.8.8.8/abuseipdb").json()["available"] is False and len(calls) == n


def test_flows_carry_exploit_and_ai_labels(make_app):
    app = make_app(fetch_with_tags)
    c = app.state.collector
    pub = []
    c.publish = lambda ev, kind="event": pub.append((kind, ev))
    base = {"src_lat": 1.0, "src_lon": 2.0, "dst_lat": 3.0, "dst_lon": 4.0, "attack_type": "exploit"}
    c._store_flows("checkpoint_map", now(), [
        {**base, "session_id": "a", "count": 5,
         "attack_name": "LangChain Community Server-Side Request Forgery (CVE-2025-2828)"},
        {**base, "session_id": "b", "count": 9, "attack_name": "Apache Log4j Remote Code Execution (CVE-2021-44228)"}])
    live = {e["session_id"]: e for k, e in pub if k == "flow"}
    assert live["a"]["ai_target"] == "LangChain" and live["a"]["cves"] == ["CVE-2025-2828"]
    assert live["b"]["ai_target"] is None
    with TestClient(app, base_url="http://testserver") as cl:
        cl.headers["x-csrf-token"] = do_setup(cl, app)
        d = cl.get("/api/flows?minutes=60").json()
        assert [e["name"][:6] for e in d["exploits"]] == ["Apache", "LangCh"]   # by count
        assert [e["ai_target"] for e in d["ai_attacks"]] == ["LangChain"]
        assert all("cves" in f and "ai_target" in f for f in d["flows"])
        cl.put("/api/sources/checkpoint_map", json={"enabled": False})
        d = cl.get("/api/flows?minutes=60").json()
        assert d["exploits"] == [] and d["ai_attacks"] == []


def test_host_details_rdns_cache_and_neighbours(make_app, monkeypatch):
    calls = []

    def fake_rdns(ip, timeout=2.0):
        calls.append(ip)
        return {"hostname": "dns.example.net", "confirmed": True}
    monkeypatch.setattr(intel, "reverse_dns", fake_rdns)
    app = make_app(fetch_with_tags)
    with TestClient(app, base_url="http://testserver") as cl:
        cl.headers["x-csrf-token"] = do_setup(cl, app)
        app.state.collector.run_source("blocklist_de")
        app.state.collector.run_source("feodo")
        d = cl.get("/api/ip/8.8.8.8/host").json()
        assert d["reverse_dns"] == {"hostname": "dns.example.net", "confirmed": True}
        assert d["version"] == 4 and d["asn"] == 15169 and d["org"] == "TestNet"
        assert d["first_seen"] <= d["last_seen"]
        assert d["listed_in_same_24"] == 0                      # 8.8.8.x: only itself
        assert d["listed_in_same_asn"] >= 2                     # FakeGeo puts every IP in AS15169
        assert cl.get("/api/ip/8.8.8.8/host").status_code == 200 and calls == ["8.8.8.8"]   # cached
        assert cl.get("/api/ip/2001:4860:4860::8888/host").json()["listed_in_same_24"] is None
        assert cl.get("/api/ip/4.4.4.4/host").status_code == 404
        assert cl.get("/api/ip/10.0.0.1/host").status_code == 422
        assert calls == ["8.8.8.8", "2001:4860:4860::8888"]


def test_network_kind_and_reverse_dns_timeout(monkeypatch):
    assert intel.network_kind("DigitalOcean, LLC") == "hosting"
    assert intel.network_kind("Hetzner Online GmbH") == "hosting"
    assert intel.network_kind("Comcast Cable Communications, LLC") is None
    assert intel.network_kind(None) is None
    import socket
    import time as _t
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_t.sleep(1), ("x", [], [ip]))[1])
    assert intel.reverse_dns("192.0.2.1", timeout=0.1) == {"hostname": None, "confirmed": False, "timeout": True}
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(socket.herror("no PTR")))
    assert intel.reverse_dns("192.0.2.1") == {"hostname": None, "confirmed": False}


def test_short_activity_wording():
    assert intel.short_activity("feodo", "botnet_c2", "QakBot", 447) == "Botnet C2 server for QakBot (port 447)"
    assert intel.short_activity("blocklist_de", "reported_attacker", tags=["ssh", "mail", "strongips"]) == \
        "Attacking SSH logins, mail servers; persistent attacker"
    assert intel.short_activity("blocklist_de", "reported_attacker", tags=["bots"]) == "Spam bot"
    assert intel.short_activity("cins", "reported_attacker") == "Scanning / attacking CINS sensors"
    assert intel.short_activity("local_sensor", "blocked_connection", port=3389).endswith("port 3389 (RDP (Remote Desktop))")
    assert intel.short_activity("et_compromised", "compromised_host").startswith("Compromised")


def test_events_and_live_events_say_what_ip_is_doing(make_app):
    app = make_app(fetch_with_tags)
    c = app.state.collector
    pub = []
    c.publish = lambda ev, kind="event": pub.append((kind, ev))
    c.run_source("blocklist_de")
    c.run_source("feodo")
    live = {e["ip"]: e for k, e in pub if k == "event" and e["source"] == "blocklist_de"}
    assert live["8.8.8.8"]["tags"] == ["ssh", "mail"] and live["8.8.8.8"]["doing"] == "Attacking SSH logins, mail servers"
    with TestClient(app, base_url="http://testserver") as cl:
        cl.headers["x-csrf-token"] = do_setup(cl, app)
        ev = cl.get("/api/events?limit=100").json()["events"]
        by = {(e["ip"], e["source"]): e for e in ev}
        assert by[("8.8.8.8", "blocklist_de")]["doing"] == "Attacking SSH logins, mail servers"
        assert by[("8.8.8.8", "feodo")]["doing"] == "Botnet C2 server for QakBot (port 447)"
        assert len(ev) == len({e["id"] for e in ev})            # the join adds no duplicate rows


def test_next_run_matches_scheduler(make_app):
    from gti import collector as C
    app = make_app(fetch_with_tags)
    c = app.state.collector
    c.run_source("feodo")
    with app.state.db.conn() as cn:
        row = cn.execute("SELECT * FROM sources WHERE id='feodo'").fetchone()
    f = C.F.FEEDS["feodo"]
    assert c.next_run(row, f) == row["last_attempt"] + f["interval"]
    assert "feodo" not in c.due_sources()
    with app.state.db.conn() as cn:                          # a failed run is retried sooner
        cn.execute("UPDATE sources SET last_error='boom', last_success=last_attempt-1 WHERE id='feodo'")
        row = cn.execute("SELECT * FROM sources WHERE id='feodo'").fetchone()
    assert c.next_run(row, f) == row["last_attempt"] + min(f["interval"], C.RETRY_AFTER_FAILURE)
    with app.state.db.conn() as cn:
        cn.execute("UPDATE sources SET last_attempt=last_attempt-4000 WHERE id='feodo'")
        row = cn.execute("SELECT * FROM sources WHERE id='checkpoint_map'").fetchone()
    assert "feodo" in c.due_sources()
    assert c.next_run(row, C.F.FEEDS["checkpoint_map"]) is None   # streams run continuously


def test_migration_v4_to_v5_keeps_data(tmp_path):
    p = str(tmp_path / "old.db")
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE schema_version(v INTEGER NOT NULL)")
    for i, m in enumerate(MIGRATIONS[:4], 1):
        con.executescript(m)
        con.execute("INSERT INTO schema_version(v) VALUES(?)", (i,))
    con.execute("""INSERT INTO indicators(ip,source,category,first_seen,last_seen,active)
                   VALUES('8.8.8.8','cins','reported_attacker',1,1,1)""")
    con.commit()
    con.close()
    db = Database(p)
    assert db.schema_version() == len(MIGRATIONS) == 5
    with db.conn() as c:
        assert c.execute("SELECT ip, tags FROM indicators").fetchall()[0][:] == ("8.8.8.8", None)
        assert c.execute("SELECT name FROM sqlite_master WHERE name='ip_lookups'").fetchone()
