"""GeoIP/ASN lookup using DB-IP Lite MMDB files (no licence key required).

Accuracy is limited to the underlying database; city-level location is approximate.
If the files are absent, lookups return empty results and the UI shows "unknown".
"""
import functools
import glob
import os

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None


class Geo:
    def __init__(self, geoip_dir):
        self.city = self._open(geoip_dir, "dbip-city-lite*.mmdb")
        self.asn = self._open(geoip_dir, "dbip-asn-lite*.mmdb")
        self.lookup = functools.lru_cache(maxsize=50000)(self._lookup)

    @staticmethod
    def _open(d, pattern):
        if maxminddb is None:
            return None
        files = sorted(glob.glob(os.path.join(d, pattern)))
        if not files:
            return None
        try:
            return maxminddb.open_database(files[-1])
        except Exception:
            return None

    @property
    def available(self):
        return self.city is not None

    def _lookup(self, ip):
        out = {"country": None, "city": None, "lat": None, "lon": None, "asn": None, "org": None}
        try:
            if self.city:
                r = self.city.get(ip) or {}
                out["country"] = (r.get("country") or {}).get("iso_code")
                names = (r.get("city") or {}).get("names") or {}
                out["city"] = names.get("en")
                loc = r.get("location") or {}
                out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
            if self.asn:
                r = self.asn.get(ip) or {}
                out["asn"] = r.get("autonomous_system_number")
                out["org"] = r.get("autonomous_system_organization")
        except Exception:
            pass
        return out

    def details(self, ip):
        """Fuller record for the IP panel (not cached): region, country/continent names and the network
        blocks the databases assign this IP to (the ASN block approximates the announced route)."""
        out = {"country_name": None, "region": None, "continent": None, "city_block": None, "asn_block": None}
        try:
            if self.city:
                r, plen = self.city.get_with_prefix_len(ip)
                r = r or {}
                out["country_name"] = ((r.get("country") or {}).get("names") or {}).get("en")
                out["continent"] = ((r.get("continent") or {}).get("names") or {}).get("en")
                subs = r.get("subdivisions") or []
                out["region"] = ((subs[0] if subs else {}).get("names") or {}).get("en")
                out["city_block"] = _block(ip, plen) if r else None
            if self.asn:
                r, plen = self.asn.get_with_prefix_len(ip)
                out["asn_block"] = _block(ip, plen) if r else None
        except Exception:
            pass
        return out


def _block(ip, plen):
    import ipaddress
    return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
