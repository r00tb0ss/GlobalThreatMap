import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from fastapi.testclient import TestClient
from gti import app as appmod, config

FEODO = '[{"ip_address":"198.51.100.0","port":443,"malware":"Emotet"},{"ip_address":"8.8.8.8","port":447,"malware":"QakBot"},{"ip_address":"1.1.1.1","port":8080,"malware":"Dridex"}]'
BLD = "# comment\n8.8.8.8\n9.9.9.9\n10.0.0.1\nnot-an-ip\n2001:4860:4860::8888\n"


class FakeGeo:
    available = True

    def __init__(self, *_):
        pass

    def lookup(self, ip):
        return {"country": "US", "city": "Testville", "lat": 10.0 + (sum(map(ord, ip)) % 50), "lon": 20.0,
                "asn": 15169, "org": "TestNet"}


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "Geo", FakeGeo)

    def _make(fetch=None, journal_reader=None, stream_opener=None, lookup_fetcher=None, **over):
        base = dict(data_dir=str(tmp_path), frontend_dir=str(tmp_path / "nofront"), geoip_dir=str(tmp_path),
                    host="127.0.0.1", port=1, max_indicators_per_source=1000, max_events_per_run=200,
                    ws_max_clients=2, retention_days=30, flow_retention_days=3, cookie_secure=False, collectors_enabled=False)
        base.update(over)
        return appmod.create_app(config.Config(**base), fetcher=fetch, journal_reader=journal_reader,
                                 stream_opener=stream_opener, lookup_fetcher=lookup_fetcher)
    return _make


def default_fetch(fid, key):
    if fid == "feodo":
        return FEODO
    if fid == "blocklist_de":
        return BLD
    return "1.2.3.4\n"


@pytest.fixture
def app(make_app):
    return make_app(default_fetch)


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://testserver") as c:
        yield c


def do_setup(client, app, user="admin", pw="correct horse battery"):
    tok = open(os.path.join(app.state.cfg.data_dir, "setup_token")).read().strip()
    r = client.post("/api/setup", json={"token": tok, "username": user, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


@pytest.fixture
def authed(client, app):
    csrf = do_setup(client, app)
    client.headers["x-csrf-token"] = csrf
    return client
