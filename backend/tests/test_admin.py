"""Backup/verify/restore round trip — an actual restore is exercised, not just archive creation."""
import json
import os
import tarfile

import pytest
from gti import admin
from gti.db import Database
from conftest import FEODO


def run(capsys, *argv):
    admin.main(list(argv))
    return capsys.readouterr().out.strip()


def test_backup_and_restore_round_trip(make_app, tmp_path, capsys):
    app = make_app(lambda f, k: FEODO)
    app.state.collector.run_source("feodo")
    data = app.state.cfg.data_dir
    cfg = tmp_path / "gti.env"
    cfg.write_text("GTI_PORT=8080\n")
    out = tmp_path / "bk" / "b.tar.gz"
    run(capsys, "--data-dir", data, "backup", str(out), "--config", str(cfg))
    if os.name == "posix":
        assert os.stat(out).st_mode & 0o777 == 0o600
    # mutate live data after backup
    with app.state.db.conn() as c:
        c.execute("DELETE FROM indicators")
    restored = tmp_path / "restore"
    info = json.loads(run(capsys, "verify-backup", str(out), "--extract-to", str(restored)))
    assert info["ok"] and info["schema_version"] == admin.SCHEMA_VERSION
    assert (restored / "gti.env").read_text() == "GTI_PORT=8080\n"
    db = Database(str(restored / "gti.db"))
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2


def test_verify_rejects_tampered_and_foreign_archives(make_app, tmp_path, capsys):
    app = make_app(lambda f, k: FEODO)
    out = tmp_path / "b.tar.gz"
    run(capsys, "--data-dir", app.state.cfg.data_dir, "backup", str(out))
    # tamper: rewrite archive with a changed db
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(out) as src, tarfile.open(bad, "w:gz") as dst:
        for m in src.getmembers():
            f = src.extractfile(m).read()
            if m.name == "gti.db":
                f = f[:-10] + b"x" * 10
            m.size = len(f)
            import io
            dst.addfile(m, io.BytesIO(f))
    with pytest.raises(SystemExit):
        admin.main(["verify-backup", str(bad)])
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as t:
        p = tmp_path / "x"
        p.write_text("x")
        t.add(p, arcname="../../etc/passwd")
    with pytest.raises(SystemExit):
        admin.main(["verify-backup", str(evil)])
    with pytest.raises(SystemExit):
        admin.main(["verify-backup", str(tmp_path / "missing.tar.gz")])


def test_health_db_and_migrate(tmp_path, capsys):
    run(capsys, "--data-dir", str(tmp_path), "migrate")
    h = json.loads(run(capsys, "--data-dir", str(tmp_path), "health-db"))
    assert h["integrity"] == "ok" and h["schema_version"] == admin.SCHEMA_VERSION and h["admin_configured"] is False


def test_reset_password(make_app, tmp_path, capsys, monkeypatch):
    import io
    from fastapi.testclient import TestClient
    from conftest import do_setup
    app = make_app(None)
    with TestClient(app, base_url="http://testserver") as c:
        do_setup(c, app)
        monkeypatch.setattr("sys.stdin", io.StringIO("a brand new passphrase\n"))
        run(capsys, "--data-dir", app.state.cfg.data_dir, "reset-password", "admin")
        assert c.get("/api/me").status_code == 401   # sessions revoked
        assert c.post("/api/login", json={"username": "admin", "password": "a brand new passphrase"}).status_code == 200
