# Vendored third-party files

| File | Version | Source | SHA-256 (base64, SRI form) | Licence |
|---|---|---|---|---|
| leaflet/leaflet.js | 1.9.4 | https://unpkg.com/leaflet@1.9.4/dist/leaflet.js | 20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo= | BSD-2-Clause |
| leaflet/leaflet.css | 1.9.4 | https://unpkg.com/leaflet@1.9.4/dist/leaflet.css | p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY= | BSD-2-Clause |

| world.geojson | Natural Earth 5.1.2, 1:50m admin-0 countries | https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_50m_admin_0_countries.geojson (source SHA-256 hex 3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb) | Public domain |

Both Leaflet hashes were checked against the SRI values Leaflet publishes for 1.9.4 at download time.
world.geojson is the Natural Earth file reduced to country names + geometry rounded to 0.01 degrees.
Everything is vendored: the frontend needs no Node.js build step, no CDN, no tile server and no API key,
and the browser makes no third-party requests.

Earlier builds used CARTO raster tiles; those now return "API KEY REQUIRED" images, so they were removed.
