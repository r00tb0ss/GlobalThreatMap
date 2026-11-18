import os

from fastapi.testclient import TestClient
from conftest import do_setup


def test_health_public_and_minimal(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert set(r.json()) == {"status", "version", "setup_required"}
    assert r.json()["setup_required"] is True


def test_everything_requires_auth(client):
    for path in ["/api/me", "/api/map", "/api/events", "/api/stats", "/api/sources", "/api/settings", "/api/ip/8.8.8.8"]:
        assert client.get(path).status_code == 401, path
    assert client.put("/api/settings", json={}).status_code == 401


def test_setup_requires_token_and_policy(client, app):
    good = "correct horse battery"
    assert client.post("/api/setup", json={"token": "wrong", "username": "admin", "password": good}).status_code == 403
    tok = open(os.path.join(app.state.cfg.data_dir, "setup_token")).read().strip()
    assert client.post("/api/setup", json={"token": tok, "username": "ad", "password": good}).status_code == 422
    assert client.post("/api/setup", json={"token": tok, "username": "admin", "password": "short"}).status_code == 422
    assert client.post("/api/setup", json={"token": tok, "username": "admin", "password": "aaaaaaaaaaaaaaaa"}).status_code == 422
    assert client.post("/api/setup", json={"token": tok, "username": "ad min", "password": good}).status_code == 422
    assert client.post("/api/setup", json={"token": tok, "username": "admin", "password": good}).status_code == 200
    assert not os.path.exists(os.path.join(app.state.cfg.data_dir, "setup_token"))
    assert client.post("/api/setup", json={"token": tok, "username": "x2x", "password": good}).status_code == 409
    assert client.get("/api/health").json()["setup_required"] is False


def test_setup_token_file_is_private(client, app):
    if os.name == "posix":
        mode = os.stat(os.path.join(app.state.cfg.data_dir, "setup_token")).st_mode & 0o777
        assert mode == 0o600


def test_setup_token_bruteforce_throttled(client):
    codes = [client.post("/api/setup", json={"token": f"g{i}", "username": "admin", "password": "correct horse battery"}).status_code
             for i in range(7)]
    assert codes[:5] == [403] * 5 and codes[5] == 429


def test_login_logout_and_throttle(client, app):
    do_setup(client, app)
    client.cookies.clear()
    assert client.post("/api/login", json={"username": "admin", "password": "bad"}).status_code == 401
    r = client.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 200
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc
    csrf = r.json()["csrf"]
    assert client.get("/api/me").json()["username"] == "admin"
    assert client.post("/api/logout").status_code == 403
    assert client.post("/api/logout", headers={"x-csrf-token": csrf}).status_code == 200
    assert client.get("/api/me").status_code == 401
    client.cookies.clear()
    for _ in range(5):
        client.post("/api/login", json={"username": "admin", "password": "nope"})
    assert client.post("/api/login", json={"username": "admin", "password": "correct horse battery"}).status_code == 429


def test_csrf_and_origin_enforced(authed):
    assert authed.put("/api/settings", json={"retention_days": 10}, headers={"x-csrf-token": "bogus"}).status_code == 403
    assert authed.put("/api/settings", json={"retention_days": 10}, headers={"origin": "http://evil.example"}).status_code == 403
    assert authed.put("/api/settings", json={"retention_days": 10}).status_code == 200


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_settings_validation_and_persistence(authed, app):
    assert authed.put("/api/settings", json={"retention_days": 0}).status_code == 422
    assert authed.put("/api/settings", json={"retention_days": "7"}).status_code == 422
    assert authed.put("/api/settings", json={"retention_days": True}).status_code == 422
    assert authed.put("/api/settings", json={"bogus": 1}).status_code == 422
    r = authed.put("/api/settings", json={"retention_days": 7, "map_max_points": 500})
    assert r.json()["retention_days"] == 7
    assert app.state.db.get_setting("retention_days") == "7"


def test_password_change_invalidates_other_sessions(authed, app):
    other = TestClient(app, base_url="http://testserver")
    other.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert other.get("/api/me").status_code == 200
    assert authed.post("/api/password", json={"current": "wrong", "new": "another long passphrase"}).status_code == 403
    assert authed.post("/api/password", json={"current": "correct horse battery", "new": "short"}).status_code == 422
    assert authed.post("/api/password", json={"current": "correct horse battery", "new": "another long passphrase"}).status_code == 200
    assert other.get("/api/me").status_code == 401
    assert authed.get("/api/me").status_code == 200


def test_unknown_api_and_input_validation(authed):
    assert authed.get("/api/nope").status_code == 404
    assert authed.get("/api/ip/not-an-ip").status_code == 422
    assert authed.get("/api/ip/8.8.4.4").status_code == 404
    assert authed.get("/api/map?min_score=500").status_code == 422
    assert authed.get("/api/events?limit=-5").status_code == 200
    assert authed.get("/api/ip/1.1.1.1'%20OR%201=1--").status_code == 422


def test_ingest_end_to_end_and_ip_detail(authed, app):
    c = app.state.collector
    assert c.run_source("feodo")["ok"] and c.run_source("blocklist_de")["ok"]
    m = authed.get("/api/map").json()
    ips = {p["ip"] for p in m["points"]}
    assert ips == {"8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888"}   # documentation range and 10.x rejected
    p8 = next(p for p in m["points"] if p["ip"] == "8.8.8.8")
    assert p8["sources"] == ["blocklist_de", "feodo"] and p8["confidence"] == "medium"
    assert p8["score"] == 95   # 1-(0.1*0.5)=0.95
    d = authed.get("/api/ip/8.8.8.8").json()
    assert d["ports"] == [447] and d["malware"] == ["QakBot"]
    assert all(i["observation_type"] == "third_party_report" for i in d["indicators"])
    assert "do not prove" in d["evidence_note"]
    st = authed.get("/api/stats").json()
    assert st["unique_ips"] == 4 and st["by_source"] == {"feodo": 2, "blocklist_de": 3}


def test_dedup_no_inflation_on_rerun(authed, app):
    c = app.state.collector
    c.run_source("feodo")
    n1 = authed.get("/api/stats").json()
    e1 = len(authed.get("/api/events?limit=500").json()["events"])
    c.run_source("feodo")
    assert authed.get("/api/stats").json()["unique_ips"] == n1["unique_ips"]
    assert len(authed.get("/api/events?limit=500").json()["events"]) == e1


def test_filters(authed, app):
    c = app.state.collector
    c.run_source("feodo")
    c.run_source("blocklist_de")
    assert {p["ip"] for p in authed.get("/api/map?source=feodo").json()["points"]} == {"8.8.8.8", "1.1.1.1"}
    assert "9.9.9.9" in {p["ip"] for p in authed.get("/api/map?category=reported_attacker").json()["points"]}
    assert [p["ip"] for p in authed.get("/api/map?q=9.9").json()["points"]] == ["9.9.9.9"]
    assert all(p["score"] >= 90 for p in authed.get("/api/map?min_score=90").json()["points"])
    assert len(authed.get("/api/map?limit=1").json()["points"]) == 1


def test_disabled_source_hidden_and_keyed_source_rules(authed, app):
    app.state.collector.run_source("feodo")
    assert authed.put("/api/sources/feodo", json={"enabled": False}).json()["status"] == "disabled"
    assert authed.get("/api/map").json()["total"] == 0
    assert authed.put("/api/sources/abuseipdb", json={"enabled": True}).status_code == 422
    assert authed.put("/api/sources/feodo", json={"api_key": "abc"}).status_code == 422
    r = authed.put("/api/sources/abuseipdb", json={"api_key": "secretkey123", "enabled": True})
    assert r.status_code == 200 and r.json()["has_key"] is True
    assert "secretkey123" not in r.text
    assert "secretkey123" not in authed.get("/api/sources").text
    assert "secretkey123" not in authed.get("/api/settings").text
    assert authed.put("/api/sources/nope", json={"enabled": True}).status_code == 404
    assert authed.put("/api/sources/abuseipdb", json={"api_key": "has space"}).status_code == 422
    r = authed.put("/api/sources/abuseipdb", json={"api_key": ""}).json()
    assert r["has_key"] is False and r["enabled"] is False
