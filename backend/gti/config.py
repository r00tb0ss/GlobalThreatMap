"""Runtime configuration, read from environment (systemd EnvironmentFile)."""
import os
from dataclasses import dataclass


def _int(name, default, lo, hi):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        v = int(raw)
    except ValueError:
        raise SystemExit(f"Invalid {name}={raw!r}: must be an integer")
    if not lo <= v <= hi:
        raise SystemExit(f"Invalid {name}={v}: must be between {lo} and {hi}")
    return v


@dataclass(frozen=True)
class Config:
    data_dir: str
    frontend_dir: str
    geoip_dir: str
    host: str
    port: int
    max_indicators_per_source: int   # hard cap on rows kept per source
    max_events_per_run: int          # live-feed events emitted per collector run
    ws_max_clients: int
    retention_days: int              # default; admin can change in Settings
    flow_retention_days: int         # arcs are high-volume (~20k/day); kept shorter than indicators
    cookie_secure: bool
    collectors_enabled: bool

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "gti.db")


def load() -> Config:
    here = os.path.dirname(os.path.abspath(__file__))
    home = os.environ.get("GTI_HOME") or os.path.abspath(os.path.join(here, "..", ".."))
    return Config(
        data_dir=os.environ.get("GTI_DATA_DIR", os.path.join(home, "data")),
        frontend_dir=os.environ.get("GTI_FRONTEND_DIR", os.path.join(home, "frontend")),
        geoip_dir=os.environ.get("GTI_GEOIP_DIR", os.path.join(home, "geoip")),
        host=os.environ.get("GTI_HOST", "0.0.0.0"),
        port=_int("GTI_PORT", 8080, 1, 65535),
        max_indicators_per_source=_int("GTI_MAX_INDICATORS_PER_SOURCE", 20000, 100, 2_000_000),
        max_events_per_run=_int("GTI_MAX_EVENTS_PER_RUN", 200, 0, 100000),
        ws_max_clients=_int("GTI_WS_MAX_CLIENTS", 20, 1, 1000),
        retention_days=_int("GTI_RETENTION_DAYS", 30, 1, 3650),
        flow_retention_days=_int("GTI_FLOW_RETENTION_DAYS", 3, 1, 90),
        cookie_secure=os.environ.get("GTI_COOKIE_SECURE", "0") == "1",
        collectors_enabled=os.environ.get("GTI_COLLECTORS", "1") == "1",
    )
