"""Regression tests for the 1.2.1 security fixes."""
import io
import tarfile

import pytest
from starlette.websockets import WebSocketDisconnect

from gti import app as appmod, auth, sensor, stream
from conftest import do_setup

PW = "correct horse battery"


# ---- login lockout cannot be dodged by changing the spelling of the user name ----
def test_lockout_applies_across_whitespace_variants(client, app):
    csrf = do_setup(client, app)
    client.post("/api/logout", headers={"x-csrf-token": csrf})
    codes = [client.post("/api/login", json={"username": "admin" + " " * i, "password": "wrong%d" % i}).status_code
             for i in range(8)]
    assert codes[:5] == [401] * 5 and 429 in codes[5:]
    assert client.post("/api/login", json={"username": " ADMIN", "password": PW}).status_code == 429


def test_one_address_is_limited_across_many_usernames(client, app):
    csrf = do_setup(client, app)
    client.post("/api/logout", headers={"x-csrf-token": csrf})
    codes = [client.post("/api/login", json={"username": "user%d" % i, "password": "x"}).status_code for i in range(40)]
    assert 429 in codes
    assert client.post("/api/login", json={"username": "admin", "password": PW}).status_code == 429


def test_login_field_lengths_are_bounded(client, app):
    do_setup(client, app)
    assert client.post("/api/login", json={"username": "a" * 65, "password": "x"}).status_code == 422
    assert client.post("/api/login", json={"username": "admin", "password": "x" * 257}).status_code == 422


def test_password_change_guesses_are_throttled(authed):
    codes = [authed.post("/api/password", json={"current": "nope%d" % i, "new": "another long passphrase"}).status_code
             for i in range(7)]
    assert codes[:5] == [403] * 5 and codes[5] == 429
    assert authed.post("/api/password", json={"current": PW, "new": "another long passphrase"}).status_code == 429


def test_throttle_eviction_never_drops_an_active_lockout(monkeypatch):
    t = auth.Throttle()
    monkeypatch.setattr(auth.Throttle, "CAPACITY", 50)
    for _ in range(5):
        t.fail("victim")
    assert t.blocked("victim")
    for i in range(500):               # flood with random keys
        t.fail("junk%d" % i)
    assert t.blocked("victim")
    assert len(t._d) <= 51


# ---- live-feed socket ends with the session ----
def test_websocket_closes_after_logout(authed, app, monkeypatch):
    monkeypatch.setattr(appmod, "WS_RECHECK_S", 0.2)
    with authed.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "hello"
        assert authed.post("/api/logout").status_code == 200
        with pytest.raises(WebSocketDisconnect) as e:
            for _ in range(20):
                ws.receive_json()          # pings are fine; the close must arrive
        assert e.value.code == 4401


# ---- sshd lines: the user name is attacker text ----
@pytest.mark.parametrize("msg,want", [
    ("Invalid user x from 8.8.8.8 y from 45.33.32.156 port 4444", "45.33.32.156"),
    ("Failed password for invalid user a from 1.1.1.1 port 9 from 45.33.32.156 port 5 ssh2", "45.33.32.156"),
    ("Invalid user bob from 45.33.32.156 port 22", "45.33.32.156"),
    ("Connection closed by invalid user admin 45.33.32.156 port 5 [preauth]", "45.33.32.156"),
    ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.33.32.156  user=root",
     "45.33.32.156"),
    ("pam_unix(sshd:auth): authentication failure; ruser= rhost=45.33.32.156  user=x rhost=8.8.8.8", "45.33.32.156"),
])
def test_sshd_username_cannot_redirect_the_source_address(msg, want):
    assert sensor.parse_line("sshd", msg)["ip"] == want


def test_sshd_forged_tail_with_private_address_is_dropped_not_misattributed():
    # the real source is a LAN address (ignored); the forged earlier public address must not be used instead
    assert sensor.parse_line("sshd", "Invalid user x from 8.8.8.8 y from 192.168.1.5 port 22") is None


# ---- bounded parsers ----
def test_oversize_sse_event_is_dropped():
    big = ["data: " + "a" * 1000 + "\n"] * 400 + ["\n", "event: attack\n", "data: ok\n", "\n"]
    assert list(stream.iter_sse(big)) == [("attack", "ok")]


def test_verify_backup_streams_members(tmp_path):
    from gti import admin
    src = tmp_path / "s"
    src.mkdir()
    admin.main(["--data-dir", str(src), "migrate"])
    out = tmp_path / "b.tar.gz"
    admin.main(["--data-dir", str(src), "backup", str(out)])
    admin.main(["--data-dir", str(src), "verify-backup", str(out), "--extract-to", str(tmp_path / "x")])
    assert (tmp_path / "x" / "gti.db").exists()
