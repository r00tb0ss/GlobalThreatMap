# Security model

- **No default credentials.** The first administrator is created in the browser with a random one-time
  setup token that only root can read (`/var/lib/global-threat-intel/setup_token`, mode 0600). The token is
  deleted once setup completes and the setup endpoint is permanently closed. Token guessing is throttled.
- **Passwords**: scrypt (N=2^14, r=8, p=1, 16-byte salt), minimum 12 characters, must not contain the
  username. Login is throttled per client+username (5 failures, then a 5-minute lock). Changing a password
  signs out all other sessions. `sudo gti reset-password` works from the console.
- **Sessions**: random 256-bit tokens stored only as SHA-256 hashes; cookie `HttpOnly`, `SameSite=Strict`,
  12 h lifetime, `Secure` when `GTI_COOKIE_SECURE=1`.
- **CSRF**: every state-changing request needs the per-session `X-CSRF-Token` header, and cross-origin
  `Origin` headers are rejected (HTTP and WebSocket).
- **API keys** (AbuseIPDB) are stored in the database (file mode 0600, owned by `gti`) and are **never**
  returned to the browser: the API only reports `has_key: true/false`. Errors are scrubbed of the key
  before being stored or shown.
- **XSS**: the frontend inserts all data with `textContent` (a test enforces no `innerHTML`). The
  Content-Security-Policy allows only same-origin scripts, styles, images and connections, so the browser
  makes **no third-party requests**.
- **SQL**: all queries are parameterised.
- **Input validation**: every API parameter is type- and range-checked; feed data is parsed defensively
  (IPs normalised, non-global addresses dropped, coordinates/tactics/counts validated).
- **Service sandbox** (systemd): runs as unprivileged `gti`, `NoNewPrivileges`, `ProtectSystem=strict`
  (write access only to `/var/lib/global-threat-intel`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  empty capability set, syscall filter, memory limit.
- **Exposure**: one TCP port. No database or cache port exists. `/api/health` is the only unauthenticated
  data endpoint and reveals only status, app version and whether setup is pending. API docs/OpenAPI
  endpoints are disabled. No server header.
- **Supply chain**: Python dependencies are pinned with SHA-256 hashes for every wheel and installed with
  `--require-hashes --only-binary`. Leaflet is vendored and checked against its published SRI hashes.
  Update archives must match their `.sha256` (or the manifest's hash) before anything is extracted.
- **Backups** are root-only (0600) and include `gti.env` and the database (which contains API keys and
  password hashes). Treat backup files as secrets.

Not provided: built-in TLS (use a reverse proxy or VPN), multi-user roles (single administrator), 2FA.
