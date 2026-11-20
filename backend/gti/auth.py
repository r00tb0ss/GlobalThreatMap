"""Authentication: scrypt password hashing, server-side sessions, login throttling."""
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

from .db import now

SESSION_TTL = 12 * 3600
MIN_PASSWORD_LEN = 12
_SCRYPT = dict(n=2 ** 14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return "scrypt$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, want = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
        got = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        return hmac.compare_digest(got, want)
    except Exception:
        return False


_DUMMY = hash_password("dummy-password-for-timing")


def check_password_policy(password: str, username: str = ""):
    """Return an error string, or None if acceptable."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password) > 256:
        return "Password must be at most 256 characters."
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    if len(set(password)) < 5:
        return "Password is too repetitive."
    return None


class Throttle:
    """`max_fails` failures lock a key for `lock` seconds. In-memory.

    The table is bounded: when it is full, expired and unlocked entries go first and then the oldest ones, but
    an active lockout is never evicted to make room (flooding it with random keys must not clear a lockout).
    """
    MAX, LOCK, CAPACITY = 5, 300, 10000

    def __init__(self, max_fails=None, lock=None):
        self.max = max_fails or self.MAX
        self.lock_s = lock or self.LOCK
        self._d = {}
        self._lock = threading.Lock()

    def blocked(self, key):
        with self._lock:
            n, until = self._d.get(key, (0, 0))
            return until > time.time()

    def fail(self, key):
        with self._lock:
            t = time.time()
            n, until = self._d.get(key, (0, 0))
            if until and until <= t:
                n = 0
            n += 1
            until = t + self.lock_s if n >= self.max else 0
            self._d.pop(key, None)       # re-insert so dict order tracks recency
            self._d[key] = (n, until)
            if len(self._d) > self.CAPACITY:
                self._evict(t)

    def _evict(self, t):
        for k in [k for k, (_, u) in self._d.items() if u <= t][: len(self._d) - self.CAPACITY]:
            del self._d[k]               # unlocked entries, oldest first
        while len(self._d) > self.CAPACITY:   # all remaining are locked: drop the oldest lockout
            del self._d[next(iter(self._d))]

    def ok(self, key):
        with self._lock:
            self._d.pop(key, None)


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user_id):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with db.conn() as c:
        c.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)",
                  (_h(token), user_id, csrf, now() + SESSION_TTL))
    return token, csrf


def get_session(db, token):
    if not token:
        return None
    with db.conn() as c:
        r = c.execute("""SELECT s.csrf, s.expires_at, u.id AS uid, u.username FROM sessions s
                         JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""", (_h(token),)).fetchone()
    if not r or r["expires_at"] < now():
        return None
    return dict(r)


def delete_session(db, token):
    if token:
        with db.conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_h(token),))


def delete_user_sessions(db, user_id, keep_token=None):
    with db.conn() as c:
        if keep_token:
            c.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, _h(keep_token)))
        else:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def authenticate(db, username, password):
    with db.conn() as c:
        r = c.execute("SELECT id, pw_hash FROM users WHERE username=?", (username,)).fetchone()
    ok = verify_password(password, r["pw_hash"] if r else _DUMMY)
    return r["id"] if (r and ok) else None
