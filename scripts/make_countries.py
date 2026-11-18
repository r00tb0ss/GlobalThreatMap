"""Generate backend/gti/data/countries.json from Natural Earth 1:50m admin-0 countries.

usage: python scripts/make_countries.py <ne_50m_admin_0_countries.geojson>
Source: Natural Earth 5.1.2 (public domain), SHA-256 3e458fc0...7fdeb (see frontend/vendor/VENDOR.md).
Output: {"US": [lat, lon, "United States of America"], ...} using Natural Earth's LABEL_Y/LABEL_X
(a point inside the country chosen for labelling; better than a polygon centroid for odd shapes).
"""
import json
import os
import sys

src = json.load(open(sys.argv[1], encoding="utf-8"))
out = {}
fallback = {}   # ISO_A2_EH-only entries; e.g. Ashmore and Cartier Islands carries EH "AU" (regression: it
                # overwrote Australia, placing every Australian target on an uninhabited reef)
for f in src["features"]:
    p = f["properties"]
    lat, lon = p.get("LABEL_Y"), p.get("LABEL_X")
    if lat is None or lon is None:
        continue
    entry = [round(lat, 3), round(lon, 3), p.get("NAME") or ""]
    real = p.get("ISO_A2")
    if real and real != "-99" and len(real) == 2:
        out[real.upper()] = entry
        continue
    eh = p.get("ISO_A2_EH")
    if eh and eh != "-99" and len(eh) == 2:
        pop = p.get("POP_EST") or 0
        if eh.upper() not in fallback or pop > fallback[eh.upper()][0]:
            fallback[eh.upper()] = (pop, entry)
for code, (_, entry) in fallback.items():
    out.setdefault(code, entry)        # only fills codes with no real ISO_A2 feature (France, Norway, ...)
# Natural Earth 5.1.2 gives Taiwan no standard ISO_A2 value; feeds use "TW".
out.setdefault("TW", [23.65, 120.95, "Taiwan"])
dst = os.path.join(os.path.dirname(__file__), "..", "backend", "gti", "data", "countries.json")
with open(dst, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(dict(sorted(out.items())), fh, separators=(",", ":"), ensure_ascii=False)
print(len(out), "countries ->", os.path.abspath(dst))
