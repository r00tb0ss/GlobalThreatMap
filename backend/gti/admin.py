"""Administrative commands used by the shell scripts (python -m gti.admin <cmd>).

Uses only the standard library + gti.db so it works without the web stack running.
Exit codes: 0 ok, 1 failure, 2 usage.
"""
import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time

from . import __version__
from .db import MIGRATIONS, Database

SCHEMA_VERSION = len(MIGRATIONS)


def _db_path(args):
    return os.path.join(args.data_dir, "gti.db")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _schema_of(db_file):
    c = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        return c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
    finally:
        c.close()


def _integrity(db_file):
    c = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        return c.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        c.close()


def cmd_migrate(args):
    os.makedirs(args.data_dir, exist_ok=True)
    db = Database(_db_path(args))
    print(f"schema v{db.schema_version()} (application v{__version__})")


def cmd_backup(args):
    """Consistent online backup (SQLite backup API) + config into a tar.gz with a manifest."""
    src = _db_path(args)
    if not os.path.exists(src):
        sys.exit(f"no database at {src}")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with tempfile.TemporaryDirectory(dir=os.path.dirname(os.path.abspath(args.out))) as tmp:
        snap = os.path.join(tmp, "gti.db")
        s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        d = sqlite3.connect(snap)
        with d:
            s.backup(d)
        s.close()
        d.close()
        if _integrity(snap) != "ok":
            sys.exit("integrity check of the snapshot failed; backup aborted")
        manifest = {"app_version": __version__, "schema_version": _schema_of(snap), "created": int(time.time()),
                    "files": {"gti.db": _sha256(snap)}}
        members = [(snap, "gti.db")]
        if args.config and os.path.exists(args.config):
            members.append((args.config, "gti.env"))
            manifest["files"]["gti.env"] = _sha256(args.config)
        part = args.out + ".partial"
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh, tarfile.open(fileobj=fh, mode="w:gz") as tar:
            data = json.dumps(manifest, indent=2).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
            tar.addfile(ti, io.BytesIO(data))
            for path, name in members:
                tar.add(path, arcname=name)
        os.replace(part, args.out)   # atomic: never leaves a truncated archive under the final name
    print(args.out)


def _open_backup(path):
    tar = tarfile.open(path, "r:gz")
    names = set(tar.getnames())
    if "manifest.json" not in names or "gti.db" not in names:
        raise ValueError("not a Global Threat Intel backup (manifest.json/gti.db missing)")
    for m in tar.getmembers():
        if not m.isfile() or m.name not in ("manifest.json", "gti.db", "gti.env"):
            raise ValueError(f"unexpected member in backup: {m.name!r}")
    return tar


def cmd_verify_backup(args):
    """Check archive structure, checksums, SQLite integrity and schema compatibility. Optionally extract."""
    try:
        tar = _open_backup(args.file)
    except (OSError, tarfile.TarError, ValueError) as e:
        sys.exit(f"invalid backup: {e}")
    manifest = json.load(tar.extractfile("manifest.json"))
    with tempfile.TemporaryDirectory() as tmp:
        for name in manifest.get("files", {}):
            out = os.path.join(tmp, name)
            with tar.extractfile(name) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            if _sha256(out) != manifest["files"][name]:
                sys.exit(f"checksum mismatch for {name}")
        db = os.path.join(tmp, "gti.db")
        if _integrity(db) != "ok":
            sys.exit("database in backup failed integrity check")
        sv = _schema_of(db)
        if sv > SCHEMA_VERSION:
            sys.exit(f"backup schema v{sv} is newer than this application (v{SCHEMA_VERSION}); install a newer release first")
        if args.extract_to:
            os.makedirs(args.extract_to, exist_ok=True)
            for name in manifest["files"]:
                os.replace(os.path.join(tmp, name), os.path.join(args.extract_to, name))
    print(json.dumps({"ok": True, **manifest}))


def cmd_health_db(args):
    p = _db_path(args)
    if not os.path.exists(p):
        sys.exit("database missing")
    res = _integrity(p) if args.full else None
    c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        if not args.full:
            res = c.execute("PRAGMA quick_check").fetchone()[0]
        users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        srcs = [dict(zip(("id", "enabled", "last_success", "last_error"), r)) for r in
                c.execute("SELECT id, enabled, last_success, last_error FROM sources ORDER BY id")]
        inds = c.execute("SELECT COUNT(*) FROM indicators WHERE active=1").fetchone()[0]
    finally:
        c.close()
    out = {"integrity": res, "schema_version": _schema_of(p), "app_schema": SCHEMA_VERSION,
           "admin_configured": users > 0, "active_indicators": inds, "sources": srcs,
           "db_bytes": os.path.getsize(p)}
    if args.human:
        admin_state = "configured" if out["admin_configured"] else "NOT yet created (open the dashboard)"
        print(f"  {'OK  ' if res == 'ok' else 'FAIL'}  database: integrity {res}, schema v{out['schema_version']}, "
              f"{inds} active indicators, {out['db_bytes'] // 1048576} MB, administrator {admin_state}")
        now = time.time()
        for s in srcs:
            if not s["enabled"]:
                continue
            age = (now - s["last_success"]) / 60 if s["last_success"] else None
            state = "never succeeded" if age is None else f"last success {age:.0f} min ago"
            note = s["last_error"] if s["last_error"] and not s["last_error"].startswith("list truncated") else None
            flag = "WARN" if (age is None or note) else "OK  "
            err = f" - {note[:90]}" if note else (" (capped at the configured per-source limit)" if s["last_error"] else "")
            print(f"  {flag}  source {s['id']}: {state}{err}")
    else:
        print(json.dumps(out))
    if res != "ok":
        sys.exit(1)


def cmd_reset_password(args):
    """Emergency: reset the admin password from the console (root only via the gti CLI)."""
    from . import auth
    pw = sys.stdin.readline().rstrip("\n")
    err = auth.check_password_policy(pw, args.username)
    if err:
        sys.exit(err)
    db = Database(_db_path(args))
    with db.conn() as c:
        n = c.execute("UPDATE users SET pw_hash=? WHERE username=?", (auth.hash_password(pw), args.username)).rowcount
        c.execute("DELETE FROM sessions")
    if not n:
        sys.exit(f"no such user: {args.username}")
    print("password reset; all sessions signed out")


def main(argv=None):
    p = argparse.ArgumentParser(prog="gti.admin")
    p.add_argument("--data-dir", default=os.environ.get("GTI_DATA_DIR", "/var/lib/global-threat-intel"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    b = sub.add_parser("backup")
    b.add_argument("out")
    b.add_argument("--config")
    v = sub.add_parser("verify-backup")
    v.add_argument("file")
    v.add_argument("--extract-to")
    h = sub.add_parser("health-db")
    h.add_argument("--full", action="store_true")
    h.add_argument("--human", action="store_true")
    r = sub.add_parser("reset-password")
    r.add_argument("username")
    sub.add_parser("version")
    args = p.parse_args(argv)
    if args.cmd == "version":
        print(json.dumps({"app_version": __version__, "schema_version": SCHEMA_VERSION}))
        return
    {"migrate": cmd_migrate, "backup": cmd_backup, "verify-backup": cmd_verify_backup,
     "health-db": cmd_health_db, "reset-password": cmd_reset_password}[args.cmd](args)


if __name__ == "__main__":
    main()
