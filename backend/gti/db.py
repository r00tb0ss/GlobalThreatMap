"""SQLite access layer (WAL mode) with versioned migrations."""
import os
import sqlite3
import time
from contextlib import contextmanager

MIGRATIONS = [
    # 1: core schema
    """
    CREATE TABLE users(
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
      pw_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE sessions(
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE sources(
      id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
      api_key TEXT, last_attempt INTEGER, last_success INTEGER,
      last_error TEXT, last_count INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE indicators(
      id INTEGER PRIMARY KEY, ip TEXT NOT NULL, source TEXT NOT NULL,
      category TEXT NOT NULL, malware TEXT, port INTEGER,
      first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      country TEXT, city TEXT, lat REAL, lon REAL, asn INTEGER, org TEXT,
      UNIQUE(ip, source, category));
    CREATE INDEX ix_ind_ip ON indicators(ip);
    CREATE INDEX ix_ind_src ON indicators(source, active);
    CREATE INDEX ix_ind_seen ON indicators(last_seen);
    CREATE TABLE events(
      id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip TEXT NOT NULL,
      source TEXT NOT NULL, category TEXT NOT NULL, malware TEXT,
      observation_type TEXT NOT NULL, country TEXT, lat REAL, lon REAL);
    CREATE INDEX ix_ev_ts ON events(ts);
    """,
    # 2: local sensor - target port/protocol on events, journal cursor storage
    """
    ALTER TABLE events ADD COLUMN port INTEGER;
    ALTER TABLE events ADD COLUMN proto TEXT;
    ALTER TABLE indicators ADD COLUMN hits INTEGER NOT NULL DEFAULT 1;
    """,
    # 3: flows - attacker-area -> sensor arcs from sensor networks (no attacker IP available)
    """
    CREATE TABLE flows(
      id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, session_id TEXT NOT NULL,
      src_lat REAL NOT NULL, src_lon REAL NOT NULL, dst_lat REAL NOT NULL, dst_lon REAL NOT NULL,
      dst_name TEXT, tactic TEXT NOT NULL, also_seen TEXT, count INTEGER NOT NULL,
      UNIQUE(source, session_id, ts));
    CREATE INDEX ix_flows_ts ON flows(ts);
    """,
    # 4: vendor threat-map feeds (Check Point, Radware): attack type/name, source area name
    """
    ALTER TABLE flows ADD COLUMN src_name TEXT;
    ALTER TABLE flows ADD COLUMN attack_type TEXT;
    ALTER TABLE flows ADD COLUMN attack_name TEXT;
    CREATE INDEX ix_flows_src_ts ON flows(source, ts);
    """,
    # 5: what an IP was reported attacking (blocklist.de service lists), cached per-IP lookups (AbuseIPDB)
    """
    ALTER TABLE indicators ADD COLUMN tags TEXT;
    CREATE TABLE ip_lookups(
      ip TEXT NOT NULL, provider TEXT NOT NULL, fetched_at INTEGER NOT NULL, data TEXT NOT NULL,
      PRIMARY KEY(ip, provider));
    CREATE INDEX ix_lookups_at ON ip_lookups(fetched_at);
    """,
]


def connect(path, readonly=False):
    conn = sqlite3.connect(path, timeout=15, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL; fewer fsyncs on SD/SSD
    return conn


class Database:
    def __init__(self, path):
        self.path = path
        d = os.path.dirname(path)
        os.makedirs(d, exist_ok=True)
        existed = os.path.exists(path)
        self.migrate()
        if not existed:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    @contextmanager
    def conn(self):
        c = connect(self.path)
        try:
            yield c
        finally:
            c.close()

    @contextmanager
    def tx(self):
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            else:
                c.execute("COMMIT")

    def migrate(self):
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("CREATE TABLE IF NOT EXISTS schema_version(v INTEGER NOT NULL)")
            row = c.execute("SELECT MAX(v) FROM schema_version").fetchone()
            cur = row[0] or 0
            if cur > len(MIGRATIONS):
                c.execute("ROLLBACK")
                raise RuntimeError(f"Database schema v{cur} is newer than this application (v{len(MIGRATIONS)}). Refusing to run; restore a matching release.")
            try:
                for i in range(cur, len(MIGRATIONS)):
                    for stmt in _split(MIGRATIONS[i]):
                        c.execute(stmt)
                    c.execute("INSERT INTO schema_version(v) VALUES(?)", (i + 1,))
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def schema_version(self):
        with self.conn() as c:
            return c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]

    # settings -----------------------------------------------------------
    def get_setting(self, key, default=None):
        with self.conn() as c:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r[0] if r else default

    def set_setting(self, key, value):
        with self.conn() as c:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def _split(script):
    return [s.strip() for s in script.split(";") if s.strip()]


def now():
    return int(time.time())
