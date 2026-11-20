"""Local sensor: attacks observed directly against THIS host, read from the systemd journal.

Sources (read-only, via `journalctl`; the service user is in the systemd-journal group):
  * sshd authentication failures / invalid users  -> category ssh_bruteforce, target port 22
  * UFW firewall blocks ([UFW BLOCK] kernel lines) -> category blocked_connection, target port DPT

These are direct observations (observation_type="direct_observation"): the source IP really sent
traffic to this machine. Only globally-routable source IPs are kept (LAN noise is ignored).
"""
import json
import re
import shutil
import subprocess

from .feeds import norm_ip

OBSERVATION_TYPE = "direct_observation"
MAX_LINES = 5000          # per collection run; bounds CPU/RAM after long downtime
FIRST_RUN_SINCE = "-15min"  # do not import an unbounded backlog on first start

_SSH_KIND = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam)|Invalid user|authentication failure"
    r"|Connection closed by invalid user|Disconnected from invalid user|maximum authentication attempts")
# The attacker chooses the user name, and sshd logs it verbatim: `Invalid user x from 8.8.8.8 y from <real> port 5`.
# The real address is therefore the LAST "<address> port <n>" in the line (nothing attacker-controlled follows it),
# never the first "from". PAM lines have no port; there the first rhost= comes before the user name.
_SSH_PORT = re.compile(r"(?:^|\s)([0-9a-fA-F:.]+)\s+port\s+\d+")
_SSH_RHOST = re.compile(r"\brhost=([0-9a-fA-F:.]+)")
_UFW = re.compile(r"\[UFW BLOCK\].*?\bSRC=(\S+).*?\bPROTO=(\w+)(?:.*?\bDPT=(\d+))?")


def available():
    return shutil.which("journalctl") is not None


def parse_line(ident, message):
    """Return a record dict or None. ident = SYSLOG_IDENTIFIER / _COMM."""
    if not message:
        return None
    if ident in ("sshd", "sshd-session", "ssh"):
        if _SSH_KIND.search(message):
            found = _SSH_PORT.findall(message)
            if found:
                cand = found[-1]
            else:
                m = _SSH_RHOST.search(message)
                cand = m.group(1) if m else None
            ip = norm_ip(cand) if cand else None
            if ip:
                return {"ip": ip, "category": "ssh_bruteforce", "port": 22, "proto": "tcp"}
        return None
    if "[UFW BLOCK]" in message:
        m = _UFW.search(message)
        if m:
            ip = norm_ip(m.group(1))
            if ip:
                port = int(m.group(3)) if m.group(3) else None
                return {"ip": ip, "category": "blocked_connection",
                        "port": port if port and 0 < port < 65536 else None, "proto": m.group(2).lower()}
    return None


def trusted(entry):
    """Reject log lines a normal local user could have forged with `logger -t sshd ...`.

    Kernel lines (UFW) cannot be written by unprivileged users. sshd runs as root, so an sshd line is only
    accepted when journald recorded the sender as UID 0 (the trusted _UID field is set by journald itself).
    """
    if entry.get("_TRANSPORT") == "kernel":
        return True
    return entry.get("_UID") == "0"


def read_journal(cursor):
    """Return (records, new_cursor). records carry ts (unix seconds)."""
    cmd = ["journalctl", "-o", "json", "--no-pager", "-q", "-n", str(MAX_LINES),
           "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "_TRANSPORT=kernel"]
    cmd += ["--after-cursor", cursor] if cursor else ["--since", FIRST_RUN_SINCE]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if out.returncode not in (0, 1):
        raise RuntimeError(f"journalctl failed: {out.stderr.strip()[:200]}")
    recs, last = [], cursor
    for line in out.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        last = j.get("__CURSOR", last)
        msg = j.get("MESSAGE")
        if isinstance(msg, list):   # journald encodes non-UTF8 as byte arrays
            msg = bytes(msg).decode("utf-8", "replace")
        ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ""
        if not trusted(j):
            continue
        r = parse_line(ident, msg)
        if r:
            try:
                r["ts"] = int(j.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000
            except ValueError:
                continue
            recs.append(r)
    return recs, last


def parse_text_dump(text):
    """Testing/diagnostics helper: `journalctl -o json` output as a string -> records."""
    recs = []
    for line in text.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        r = parse_line(j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or "", j.get("MESSAGE"))
        if r:
            r["ts"] = int(j.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000
            recs.append(r)
    return recs
