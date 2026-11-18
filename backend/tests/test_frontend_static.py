"""Static frontend is served with correct types and contains no secrets or inline scripts."""
import os
import re

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FRONT = os.path.join(ROOT, "frontend")


@pytest.fixture
def ui(make_app):
    app = make_app(None, frontend_dir=FRONT)
    with TestClient(app, base_url="http://testserver") as c:
        yield c


def test_static_mime_types(ui):
    # Regression: Windows registry served .js as text/plain, which browsers refuse under nosniff.
    assert ui.get("/").headers["content-type"].startswith("text/html")
    assert ui.get("/app.js").headers["content-type"].startswith("text/javascript")
    assert ui.get("/vendor/leaflet/leaflet.js").headers["content-type"].startswith("text/javascript")
    assert ui.get("/style.css").headers["content-type"].startswith("text/css")
    assert ui.get("/app.js").headers["cache-control"] == "no-cache"   # upgrades must not leave stale JS


def test_no_inline_script_and_no_innerhtml():
    html = open(os.path.join(FRONT, "index.html"), encoding="utf-8").read()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline script would violate CSP"
    js = open(os.path.join(FRONT, "app.js"), encoding="utf-8").read()
    assert not re.search(r"\.(innerHTML|outerHTML|insertAdjacentHTML)\b|\beval\(|document\.write", js)


def test_no_third_party_requests(ui):
    # Regression: CARTO tiles started returning "API KEY REQUIRED"; the UI must not depend on external hosts.
    js = open(os.path.join(FRONT, "app.js"), encoding="utf-8").read()
    html = open(os.path.join(FRONT, "index.html"), encoding="utf-8").read()
    assert not re.search(r"https?://", js + html)
    csp = ui.get("/").headers["content-security-policy"]
    assert "http" not in csp
    r = ui.get("/vendor/world.geojson", headers={"accept-encoding": "gzip"})
    assert r.status_code == 200 and r.headers.get("content-encoding") == "gzip"
    assert len(r.json()["features"]) > 200


def test_version_file_matches_package():
    from gti import __version__
    assert open(os.path.join(ROOT, "VERSION")).read().strip() == __version__


def test_vendored_leaflet_integrity():
    import base64
    import hashlib
    want = {"leaflet.js": "20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=",
            "leaflet.css": "p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="}
    for f, h in want.items():
        data = open(os.path.join(FRONT, "vendor", "leaflet", f), "rb").read()
        assert base64.b64encode(hashlib.sha256(data).digest()).decode() == h, f
