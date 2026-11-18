/* Global Threat Intel dashboard. All untrusted data is inserted with textContent (never innerHTML). */
"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const S = { csrf: null, setup: false, view: "map", sources: [], map: null, layer: null, markers: new Map(),
              selected: null, paused: false, ws: null, wsRetry: 1000, mapTimer: null, settings: null };
  const CAT = { botnet_c2: "Botnet C2 server", reported_attacker: "Reported attacker", compromised_host: "Compromised host",
                ssh_bruteforce: "SSH brute force (observed)", blocked_connection: "Firewall block (observed)" };
  // One colour per category, used for markers, pulses, arcs, legend and the ticker.
  const COLOR = { botnet_c2: "#ff4d6d", ssh_bruteforce: "#38d9ff", blocked_connection: "#69db7c",
                  compromised_host: "#c77dff", reported_attacker: "#ffa94d" };
  const CAT_PRIORITY = ["botnet_c2", "ssh_bruteforce", "blocked_connection", "compromised_host", "reported_attacker"];
  const primaryCat = (cats) => CAT_PRIORITY.find((c) => cats.includes(c)) || cats[0];
  // MITRE ATT&CK tactic colours for sensor-network arcs (GreyNoise)
  const TACTIC = {
    "reconnaissance": ["Reconnaissance", "#74c0fc"], "resource-development": ["Resource development", "#91a7ff"],
    "initial-access": ["Initial access", "#ff6b6b"], "execution": ["Execution", "#f783ac"],
    "persistence": ["Persistence", "#da77f2"], "privilege-escalation": ["Privilege escalation", "#9775fa"],
    "defense-evasion": ["Defense evasion", "#ffd43b"], "credential-access": ["Credential access", "#ffa94d"],
    "discovery": ["Discovery (scanning)", "#4dabf7"], "lateral-movement": ["Lateral movement", "#63e6be"],
    "collection": ["Collection", "#a9e34b"], "command-and-control": ["Command & control", "#ff4d6d"],
    "exfiltration": ["Exfiltration", "#e64980"], "impact": ["Impact", "#fa5252"],
  };
  // Vendor threat-map attack types
  const CP_TYPE = { exploit: ["Exploit", "#ff6b6b"], malware: ["Malware", "#cc5de8"], phishing: ["Phishing", "#fcc419"] };
  const RW_TYPE = {
    scanners: ["Scanner", "#4dabf7"], botnets: ["Botnet", "#ff8787"], webAttackers: ["Web attacker", "#ffa94d"],
    dDosAttackers: ["DDoS attacker", "#f03e3e"], ioTBotnets: ["IoT botnet", "#20c997"], intruders: ["Intruder", "#e599f7"],
    anonymizers: ["Anonymizer", "#adb5bd"],
  };
  // arc sources: id -> [short label, palette, key field]
  const ARC_SRC = {
    greynoise_map: ["GreyNoise", TACTIC, "tactic"],
    checkpoint_map: ["Check Point", CP_TYPE, "attack_type"],
    radware_map: ["Radware (playback)", RW_TYPE, "attack_type"],
  };
  const flowStyle = (f) => {
    const [srcLabel, pal, field] = ARC_SRC[f.source] || ["?", {}, "attack_type"];
    const key = f[field] || f.attack_type || f.tactic;
    const [label, color] = pal[key] || [key || "Other", "#adb5bd"];
    return { srcLabel, key, label, color };
  };
  const MAX_ANIM = 60;   // concurrent animations; keeps Raspberry Pi / phone browsers smooth

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v; else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
      else e.setAttribute(k, v);
    }
    for (const k of kids) if (k != null) e.append(k instanceof Node ? k : String(k));
    return e;
  }
  const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "never");
  const ago = (t) => { if (!t) return "never"; const s = Date.now() / 1000 - t;
    return s < 90 ? Math.round(s) + "s ago" : s < 5400 ? Math.round(s / 60) + "m ago" : s < 172800 ? Math.round(s / 3600) + "h ago" : Math.round(s / 86400) + "d ago"; };
  const scoreClass = (s) => (s >= 70 ? "s-high" : s >= 40 ? "s-med" : "s-low");
  const srcName = (id) => (S.sources.find((s) => s.id === id) || {}).name || id;

  async function api(path, opts = {}) {
    const o = { method: opts.method || "GET", headers: {}, credentials: "same-origin" };
    if (opts.body !== undefined) { o.body = JSON.stringify(opts.body); o.headers["Content-Type"] = "application/json"; }
    if (o.method !== "GET" && S.csrf) o.headers["X-CSRF-Token"] = S.csrf;
    const r = await fetch(path, o);
    let data = null;
    try { data = await r.json(); } catch (_) { /* non-JSON */ }
    if (r.status === 401 && !path.startsWith("/api/login")) { showAuth(false); throw new Error("Session expired"); }
    if (!r.ok) {
      const d = data && data.detail;
      throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : "Request failed (" + r.status + ")");
    }
    return data;
  }

  // ---------------- auth ----------------
  function showAuth(setup) {
    S.setup = setup;
    stopLive();
    $("main").classList.add("hidden"); $("auth").classList.remove("hidden");
    $("token-row").classList.toggle("hidden", !setup); $("pass2-row").classList.toggle("hidden", !setup);
    $("f-token").required = setup; $("f-pass2").required = setup;
    $("f-pass").autocomplete = setup ? "new-password" : "current-password";
    $("auth-btn").textContent = setup ? "Create administrator" : "Sign in";
    $("auth-intro").textContent = setup ? "First-time setup: create the administrator account. There are no default credentials." : "Sign in to continue.";
  }
  $("auth-form").addEventListener("submit", async (e) => {
    e.preventDefault(); $("auth-err").textContent = "";
    const body = { username: $("f-user").value.trim(), password: $("f-pass").value };
    try {
      if (S.setup) {
        if (body.password !== $("f-pass2").value) throw new Error("Passwords do not match");
        body.token = $("f-token").value.trim();
      }
      const r = await api(S.setup ? "/api/setup" : "/api/login", { method: "POST", body });
      S.csrf = r.csrf; $("f-pass").value = ""; $("f-pass2").value = "";
      start(S.setup);
    } catch (err) { $("auth-err").textContent = err.message; }
  });
  $("logout").addEventListener("click", async () => { try { await api("/api/logout", { method: "POST" }); } catch (_) {} S.csrf = null; showAuth(false); });

  // ---------------- navigation ----------------
  $("tabs").addEventListener("click", (e) => { const v = e.target.dataset && e.target.dataset.view; if (v) show(v); });
  function show(v) {
    S.view = v;
    for (const b of $("tabs").children) b.classList.toggle("active", b.dataset.view === v);
    for (const s of document.querySelectorAll(".view")) s.classList.toggle("hidden", s.id !== "view-" + v);
    if (v === "map") { S.map.invalidateSize(); loadMap(); }
    if (v === "feed") loadFeed();
    if (v === "analytics") loadAnalytics();
    if (v === "sources") loadSources();
    if (v === "settings") loadSettings();
  }

  function banner(unhealthy, geo) {
    const msgs = [];
    if (unhealthy && unhealthy.length) msgs.push("Not current: " + unhealthy.map(srcName).join(", ") + ". Their data may be out of date; see Sources.");
    if (geo === false) msgs.push("GeoIP database not installed: IPs cannot be placed on the map. Run sudo gti-update-geoip.");
    $("banner").textContent = msgs.join("  ");
    $("banner").classList.toggle("hidden", !msgs.length);
  }

  // ---------------- map ----------------
  function initMap() {
    S.map = L.map("map", { worldCopyJump: true, preferCanvas: true, minZoom: 1, maxZoom: 8, maxBounds: [[-85, -200], [85, 200]] }).setView([25, 10], 2);
    // Bundled Natural Earth basemap: no tile server, no API key, works offline.
    S.map.attributionControl.addAttribution("Basemap: Natural Earth | IP geolocation: DB-IP.com (approximate) | Sensor arcs: GreyNoise");
    // explicit stacking: basemap (bottom) < IP dots (overlayPane 400) < arcs < markers/pulses (600)
    S.map.createPane("basemap").style.zIndex = 200;
    S.map.createPane("arcs").style.zIndex = 450;
    S.map.getPane("arcs").style.pointerEvents = "none";
    fetch("vendor/world.geojson").then((r) => r.json()).then((g) => {
      S.world = g.features;
      L.geoJSON(g, { pane: "basemap", renderer: L.canvas({ pane: "basemap" }), interactive: false, style: { color: "#3a4656", weight: 0.7, fillColor: "#1b2330", fillOpacity: 1 } })
        .addTo(S.map).bringToBack();
    }).catch(() => { $("m-count").textContent = "Basemap failed to load"; });
    S.layer = L.layerGroup().addTo(S.map);
    // dots are small and often stacked (many IPs geolocate to one city): a generous hit area, and a click
    // picks every dot within PICK_PX so overlapping IPs can be chosen from a list
    S.dotRenderer = L.canvas({ tolerance: 7 });
    S.map.on("click", (e) => pickAt(e.containerPoint));
    S.fx = L.layerGroup().addTo(S.map);            // animations (pulses, arcs)
    S.svg = L.svg({ padding: 0.5, pane: "arcs" });               // arcs need SVG (dash animation); markers stay on canvas
    S.homeLayer = L.layerGroup().addTo(S.map);
    S.sensorLayer = L.layerGroup().addTo(S.map);
    S.sensors = new Map();
    S.show = { ip: true, greynoise_map: true, checkpoint_map: true, radware_map: true };
    S.arcTotals = {};
    S.anim = 0;
    buildLegend();
    $("detail-close").addEventListener("click", closeDetail);
    for (const id of ["m-source", "m-cat", "m-min"]) $(id).addEventListener("change", loadMap);
    let t; $("m-q").addEventListener("input", () => { clearTimeout(t); t = setTimeout(loadMap, 350); });
    $("m-full").addEventListener("click", () => {
      const w = $("map-wrap");
      if (document.fullscreenElement) document.exitFullscreen(); else if (w.requestFullscreen) w.requestFullscreen();
    });
    document.addEventListener("fullscreenchange", () => setTimeout(() => S.map.invalidateSize(), 100));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });
  }

  async function loadMap() {
    const p = new URLSearchParams();
    if ($("m-q").value.trim()) p.set("q", $("m-q").value.trim());
    if ($("m-source").value) p.set("source", $("m-source").value);
    if ($("m-cat").value) p.set("category", $("m-cat").value);
    const min = parseInt($("m-min").value, 10);
    if (min > 0) p.set("min_score", String(Math.min(100, min)));
    let d;
    try { d = await api("/api/map?" + p); } catch (e) { $("m-count").textContent = e.message; return; }
    banner(d.unhealthy_sources, d.geoip_available);
    S.layer.clearLayers(); S.markers.clear();
    for (const pt of d.points) {
      const cat = primaryCat(pt.categories);
      const color = COLOR[cat] || "#8b949e";
      const m = L.circleMarker([pt.lat, pt.lon], { renderer: S.dotRenderer, radius: 2.5 + pt.score / 30, color,
        weight: pt.observed ? 2 : 1, fillColor: color, fillOpacity: pt.observed ? 0.85 : 0.45, opacity: 0.9 });
      m.pt = pt; m.cat = cat;
      m.on("click", (e) => { L.DomEvent.stopPropagation(e); pickAt(e.containerPoint); });
      m.bindTooltip(pt.ip + " · " + (CAT[cat] || cat) + " · score " + pt.score);
      m.addTo(S.layer); S.markers.set(pt.ip, m);
    }
    $("m-count").textContent = d.returned + " of " + d.total + " located IPs" + (d.truncated ? " (highest scores shown; raise the limit in Settings)" : "");
    if (S.selected) highlight(S.selected);
  }

  const PICK_PX = 14;
  function pickAt(cp) {
    if (!S.show.ip || !cp) return;
    const hits = [];
    for (const m of S.markers.values()) {
      const d = S.map.latLngToContainerPoint(m.getLatLng()).distanceTo(cp);
      if (d <= PICK_PX + m.getRadius()) hits.push([d, m]);
    }
    if (!hits.length) return;
    hits.sort((a, b) => a[0] - b[0] || b[1].pt.score - a[1].pt.score);
    const near = hits.filter((h) => h[0] - hits[0][0] < 4);   // dots stacked on the same spot
    if (near.length === 1) { openDetail(near[0][1].pt.ip); return; }
    showPicker(hits.slice(0, 50).map((h) => h[1]), hits.length);
  }
  function showPicker(ms, total) {
    S.selected = null;
    if (S.hl) { S.hl.remove(); S.hl = null; }
    const list = el("ul", { class: "pick-list" });
    for (const m of ms.sort((a, b) => b.pt.score - a.pt.score)) {
      const b = el("button", { type: "button", class: "pick" }, el("i", { class: "dot", style: "background:" + (COLOR[m.cat] || "#8b949e") }),
        el("span", { class: "pick-ip" }, m.pt.ip), el("span", { class: "muted" }, (CAT[m.cat] || m.cat) + " · score " + m.pt.score));
      b.addEventListener("click", () => openDetail(m.pt.ip));
      list.append(el("li", {}, b));
    }
    $("detail-body").replaceChildren(el("h3", {}, total + " IPs near this spot"),
      el("p", { class: "muted small" }, "These dots overlap at this zoom level. Choose one" + (total > ms.length ? " (top " + ms.length + " by score shown; zoom in to separate them)" : "") + "."), list);
    $("detail").classList.remove("hidden");
  }

  function highlight(ip) {
    if (S.hl) { S.hl.remove(); S.hl = null; }
    const m = S.markers.get(ip);
    if (m) S.hl = L.circleMarker(m.getLatLng(), { radius: 11, color: "#ffffff", weight: 2, fill: false, interactive: false }).addTo(S.fx);
  }

  function closeDetail() { $("detail").classList.add("hidden"); S.selected = null; if (S.hl) { S.hl.remove(); S.hl = null; } }

  // ---------------- live animation: pulses, arcs, legend, ticker, replay ----------------
  function buildLegend() {
    const legend = L.control({ position: "bottomleft" });
    legend.onAdd = () => {
      const box = el("details", { class: "legend" }, el("summary", {}, "Legend"));
      if (window.innerWidth >= 768) box.open = true;   // collapsed on phones so the map stays usable
      box.append(el("div", { class: "lg-title" }, "IP intelligence (dots)"));
      for (const c of CAT_PRIORITY) box.append(el("div", { class: "lg-row" }, el("i", { style: "background:" + COLOR[c] }), CAT[c]));
      box.append(el("div", { class: "lg-row" }, el("i", { class: "lg-pulse" }), "Pulse: new listing"),
        el("div", { class: "lg-row" }, el("i", { class: "lg-arc" }), "Arc to ◉ this host: observed here"),
        el("div", { id: "lg-home", class: "lg-note" }),
        el("div", { class: "lg-title lg-sep" }, "Attack arcs (attacker area → target), last hour"),
        el("div", { id: "lg-arcs" }, el("div", { class: "lg-note" }, "Waiting for data…")));
      const tog = (id, label, key) => {
        const cb = el("input", { type: "checkbox", id });
        cb.checked = S.show[key];
        cb.addEventListener("change", () => { S.show[key] = cb.checked; applyLayers(); });
        return el("label", { class: "lg-row lg-toggle" }, cb, label);
      };
      box.append(el("div", { class: "lg-title lg-sep" }, "Show"), tog("tg-ip", "IP dots", "ip"),
        tog("tg-gn", "GreyNoise arcs", "greynoise_map"), tog("tg-cp", "Check Point arcs", "checkpoint_map"),
        tog("tg-rw", "Radware arcs", "radware_map"));
      L.DomEvent.disableClickPropagation(box); L.DomEvent.disableScrollPropagation(box);
      return box;
    };
    legend.addTo(S.map);
    const tick = L.control({ position: "bottomright" });
    tick.onAdd = () => {
      const box = el("div", { class: "ticker" }, el("div", { class: "tk-head" }, el("span", { id: "tk-mode", class: "chip" }, "LIVE"),
        el("button", { id: "tk-replay", class: "ghost small-btn", type: "button" }, "Replay")), el("ol", { id: "tk-list" }),
        el("div", { id: "tk-note", class: "lg-note" }));
      L.DomEvent.disableClickPropagation(box); L.DomEvent.disableScrollPropagation(box);
      return box;
    };
    tick.addTo(S.map);
    const top = L.control({ position: "topright" });
    top.onAdd = () => {
      const box = el("details", { class: "legend top-panel" }, el("summary", {}, "Top activity"), el("div", { id: "top-body" }, el("div", { class: "lg-note" }, "Waiting for sensor data…")),
        el("div", { id: "top-ex" }));
      if (window.innerWidth >= 1024) box.open = true;
      L.DomEvent.disableClickPropagation(box); L.DomEvent.disableScrollPropagation(box);
      return box;
    };
    top.addTo(S.map);
    $("tk-replay").addEventListener("click", () => setReplay(!S.replay));
  }

  function setHome(home) {
    S.home = home;
    S.homeLayer.clearLayers();
    if (home) {
      L.circleMarker([home.lat, home.lon], { radius: 6, color: "#ffffff", weight: 2, fillColor: "#0d1117", fillOpacity: 1 })
        .bindTooltip(home.label + " (this host)", { permanent: false }).addTo(S.homeLayer);
    }
    const note = $("lg-home");
    if (note) note.textContent = home ? "Arcs end at: " + home.label : "Set this host's location in Settings to draw arcs.";
  }

  function arcPoints(a, b) {
    // quadratic bezier bowed towards the pole. Arcs never cross the antimeridian: the basemap is drawn
    // once (-180..180), so a "shortest way" Pacific arc would leave the visible world.
    const lon2 = b[1];
    const dx = lon2 - a[1], dy = b[0] - a[0], dist = Math.hypot(dx, dy);
    const mid = [(a[0] + b[0]) / 2 + Math.min(30, dist * 0.25), (a[1] + lon2) / 2];
    const pts = [];
    for (let i = 0; i <= 32; i++) {
      const t = i / 32, u = 1 - t;
      pts.push([u * u * a[0] + 2 * u * t * mid[0] + t * t * b[0], u * u * a[1] + 2 * u * t * mid[1] + t * t * lon2]);
    }
    return pts;
  }

  function animate(ev) {
    if (!S.show.ip) return;
    tickerAdd(ev);
    // drawing is skipped when nobody can see it (background tab / other view) to save CPU on a Pi
    if (ev.lat == null || ev.lon == null || S.anim >= MAX_ANIM || S.view !== "map" || document.hidden) return;
    const color = COLOR[ev.category] || "#8b949e";
    S.anim++;
    const done = (layer, ms) => setTimeout(() => { layer.remove(); S.anim--; }, ms);
    const pulse = L.marker([ev.lat, ev.lon], { interactive: false, keyboard: false,
      icon: L.divIcon({ className: "pulse", html: "", iconSize: [22, 22] }) }).addTo(S.fx);
    const pe = pulse.getElement(); if (pe) pe.style.setProperty("--c", color);
    if (ev.observation_type === "direct_observation" && S.home) {
      const line = L.polyline(arcPoints([ev.lat, ev.lon], [S.home.lat, S.home.lon]),
        { renderer: S.svg, color, weight: 2, opacity: 0.95, interactive: false, className: "arc" }).addTo(S.fx);
      const p = line.getElement();
      if (p && p.getTotalLength) { const len = p.getTotalLength(); p.style.strokeDasharray = len; p.style.strokeDashoffset = len;
        p.style.setProperty("--len", len); p.style.color = color; }
      S.anim++; done(line, 4000);
    }
    done(pulse, 2400);
  }

  function applyLayers() {
    for (const [layer, on] of [[S.layer, S.show.ip], [S.sensorLayer, S.show.greynoise_map]]) {
      if (on && !S.map.hasLayer(layer)) layer.addTo(S.map);
      if (!on && S.map.hasLayer(layer)) layer.remove();
    }
  }

  // point-in-polygon on the bundled country shapes: names the attacker's area for the ticker
  const countryCache = new Map();
  function countryAt(lat, lon) {
    if (!S.world) return null;
    const key = lat.toFixed(2) + "," + lon.toFixed(2);
    if (countryCache.has(key)) return countryCache.get(key);
    const name = countryAtRaw(lat, lon);
    if (countryCache.size > 5000) countryCache.clear();
    countryCache.set(key, name);
    return name;
  }
  function countryAtRaw(lat, lon) {
    const inRing = (r) => { let ins = false;
      for (let i = 0, j = r.length - 1; i < r.length; j = i++) {
        const [xi, yi] = r[i], [xj, yj] = r[j];
        if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) ins = !ins;
      } return ins; };
    for (const f of S.world) {
      const g = f.geometry, polys = g.type === "Polygon" ? [g.coordinates] : g.coordinates;
      for (const p of polys) if (inRing(p[0]) && !p.slice(1).some(inRing)) return f.properties.n;
    }
    return null;
  }

  function addSensor(f) {
    const k = f.dst_lat.toFixed(2) + "," + f.dst_lon.toFixed(2);
    if (S.sensors.has(k)) return;
    const m = L.marker([f.dst_lat, f.dst_lon], { keyboard: false,
      icon: L.divIcon({ className: "sensor", html: "", iconSize: [9, 9] }) })
      .bindTooltip("GreyNoise sensor: " + (f.dst_name || "unnamed"));
    m.addTo(S.sensorLayer); S.sensors.set(k, m);
  }

  // legend: per arc source, the attack types seen in the last hour with totals
  function renderArcLegend() {
    const box = $("lg-arcs"); if (!box) return;
    const parts = [];
    for (const [sid, [label, pal]] of Object.entries(ARC_SRC)) {
      const t = S.arcTotals[sid];
      if (!t || !Object.keys(t).length) continue;
      parts.push(el("div", { class: "lg-src" }, label + (sid === "checkpoint_map" && S.cpToday ? " · " + S.cpToday.toLocaleString() + " attacks reported today" : "")));
      for (const [k, v] of Object.entries(t).sort((a, b) => b[1] - a[1]).slice(0, 8)) {
        const [l, c] = pal[k] || [k, "#adb5bd"];
        parts.push(el("div", { class: "lg-row" }, el("i", { style: "background:" + c }), l, el("span", { class: "lg-count" }, v.toLocaleString())));
      }
    }
    box.replaceChildren(...(parts.length ? parts : [el("div", { class: "lg-note" }, "No arcs in the last hour (sources disabled or not yet collected).")]));
  }
  function noteArc(f) {
    const { key } = flowStyle(f);
    const t = (S.arcTotals[f.source] = S.arcTotals[f.source] || {});
    t[key] = (t[key] || 0) + f.count;
    clearTimeout(S.lgTimer); S.lgTimer = setTimeout(renderArcLegend, 1000);
  }

  // a glowing head that travels along the arc (one shared rAF loop for all heads)
  S.heads = [];
  function projectile(pts, color, ms) {
    const head = L.circleMarker(pts[0], { renderer: S.svg, radius: 3.5, color: "#fff", weight: 1.5, fillColor: color,
      fillOpacity: 1, interactive: false, className: "head" }).addTo(S.fx);
    S.heads.push({ head, pts, t0: performance.now(), ms });
    if (S.heads.length === 1) requestAnimationFrame(stepHeads);
  }
  function stepHeads(now) {
    S.heads = S.heads.filter((h) => {
      // clamp at 0: the rAF timestamp can be slightly older than the head's start time (performance.now()),
      // and a negative progress indexed past the start of the point list and stopped the animation loop
      const k = Math.max(0, Math.min(1, (now - h.t0) / h.ms));
      const e = 1 - Math.pow(1 - k, 2);              // ease-out
      const pos = e * (h.pts.length - 1), i = Math.floor(pos), fr = pos - i;
      const a = h.pts[i], b = h.pts[Math.min(i + 1, h.pts.length - 1)];
      h.head.setLatLng([a.lat + (b.lat - a.lat) * fr, a.lng + (b.lng - a.lng) * fr]);
      if (k >= 1) { h.head.remove(); return false; }
      return true;
    });
    if (S.heads.length) requestAnimationFrame(stepHeads);
  }

  // "Top origins / targets" panel from the last hour of sensor arcs
  function updateTop(flows) {
    const box = $("top-body"); if (!box) return;
    const orig = {}, tgt = {};
    for (const f of flows) {
      if (!S.show[f.source]) continue;
      const c = f.src_name || countryAt(f.src_lat, f.src_lon) || "Unknown";
      orig[c] = (orig[c] || 0) + f.count;
      const unknownTarget = f.dst_lat === f.src_lat && f.dst_lon === f.src_lon && !f.dst_name;
      if (!unknownTarget) { const t = f.dst_name || countryAt(f.dst_lat, f.dst_lon) || "Unknown"; tgt[t] = (tgt[t] || 0) + f.count; }
    }
    const list = (o) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) =>
      el("div", { class: "lg-row" }, el("span", { class: "top-name" }, k), el("span", { class: "lg-count" }, v.toLocaleString())));
    box.replaceChildren(el("div", { class: "lg-title" }, "Top attack origins"), ...list(orig),
      el("div", { class: "lg-title lg-sep" }, "Most-targeted"), ...list(tgt),
      el("div", { class: "lg-note" }, "Shown arc sources, recent hour. Sources count differently, so totals mix scales."));
  }

  // most-detected exploits (Check Point names them, often with a CVE) and attacks aimed at AI software
  function renderExploits(top, ai) {
    const box = $("top-ex"); if (!box) return;
    if (!top.length) { box.replaceChildren(); return; }
    const row = (e) => el("div", { class: "ex-row", title: e.name },
      el("span", { class: "ex-name" }, e.name.replace(/\s*\((?:CVE|MS)[^)]*\)\s*$/, "")),
      ...e.cves.slice(0, 1).map((c) => el("span", { class: "ex-cve" }, c)), el("span", { class: "lg-count" }, e.count.toLocaleString()));
    const parts = [el("div", { class: "lg-title lg-sep" }, "Top exploits (Check Point)"), ...top.slice(0, 6).map(row)];
    parts.push(el("div", { class: "lg-title lg-sep" }, "Attacks on AI software"));
    if (ai.length) parts.push(...ai.slice(0, 5).map((e) => el("div", { class: "ex-row", title: e.name },
      el("span", { class: "badge b-ai" }, e.ai_target), el("span", { class: "ex-name" }, e.name), el("span", { class: "lg-count" }, e.count.toLocaleString()))));
    else parts.push(el("div", { class: "lg-note" }, "None detected in the last hour."));
    parts.push(el("div", { class: "lg-note" }, "Exploits aimed at AI/ML products (LangChain, Langflow, MLflow, Ollama…). No source reports whether an attacker used AI."));
    box.replaceChildren(...parts);
  }

  function animateFlow(f, fromReplay) {
    if (!S.show[f.source]) return;
    const { srcLabel, label, color } = flowStyle(f);
    if (f.source === "greynoise_map") addSensor(f);
    if (!fromReplay) noteArc(f);
    const from = f.src_name || countryAt(f.src_lat, f.src_lon) || "Unknown area";
    const samePoint = f.dst_lat === f.src_lat && f.dst_lon === f.src_lon;   // unknown target, or same-country (one label point)
    const known = !samePoint;
    const to = f.dst_name || (known ? countryAt(f.dst_lat, f.dst_lon) : null);
    const detail = f.attack_name ? ": " + f.attack_name : "";
    tickerAdd({ ts: f.ts, color, ip: from + " → " + (to || f.dst_name || "target not disclosed"), ai: f.ai_target,
      what: label + detail + (f.count > 1 ? " ×" + f.count : "") + " · " + srcLabel });
    if (S.view !== "map" || document.hidden || S.anim >= MAX_ANIM) return;
    if (!known) {   // no target published, or source and target share one point: pulse (never invent a destination)
      S.anim++;
      const p = L.marker([f.src_lat, f.src_lon], { interactive: false, keyboard: false,
        icon: L.divIcon({ className: "pulse", html: "", iconSize: [22, 22] }) }).addTo(S.fx);
      const pe = p.getElement(); if (pe) pe.style.setProperty("--c", color);
      setTimeout(() => { p.remove(); S.anim--; }, 2400);
      return;
    }
    S.anim += 2;
    const w = Math.min(5, 2 + Math.log10(f.count + 1));
    const line = L.polyline(arcPoints([f.src_lat, f.src_lon], [f.dst_lat, f.dst_lon]),
      { renderer: S.svg, color, weight: w, opacity: 1, interactive: false, className: "arc" }).addTo(S.fx);
    const p = line.getElement();
    if (p && p.getTotalLength) { const len = p.getTotalLength(); p.style.strokeDasharray = len; p.style.strokeDashoffset = len;
      p.style.setProperty("--len", len); p.style.color = color; }
    projectile(line.getLatLngs(), color, 1400);
    const hit = L.marker([f.dst_lat, f.dst_lon], { interactive: false, keyboard: false,
      icon: L.divIcon({ className: "pulse pulse-late", html: "", iconSize: [22, 22] }) }).addTo(S.fx);
    const he = hit.getElement(); if (he) he.style.setProperty("--c", color);
    setTimeout(() => { line.remove(); S.anim--; }, 4000);
    setTimeout(() => { hit.remove(); S.anim--; }, 3800);
  }

  async function loadFlows() {
    try {
      const d = await api("/api/flows?minutes=60&limit=1500");
      S.arcTotals = d.types || {};
      S.cpToday = d.checkpoint_today;
      renderArcLegend();
      renderExploits(d.exploits || [], d.ai_attacks || []);
      for (const f of d.flows) if (f.source === "greynoise_map") addSensor(f);
      S.recentFlows = d.flows;
      updateTop(d.flows);
      return d.flows;
    } catch (_) { return []; }
  }

  function tickerAdd(ev) {
    if (ev.what) {   // pre-formatted (sensor flows)
      const list = $("tk-list"); if (!list) return;
      list.prepend(el("li", {}, el("i", { style: "background:" + ev.color }),
        el("span", { class: "tk-t" }, new Date(ev.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })),
        el("span", { class: "tk-ip" }, ev.ip), el("span", { class: "tk-what" }, ...(ev.ai ? [el("span", { class: "badge b-ai" }, "AI target: " + ev.ai)] : []), ev.what)));
      while (list.children.length > 6) list.lastChild.remove();
      return;
    }
    const list = $("tk-list"); if (!list) return;
    const where = ev.country ? " (" + ev.country + ")" : "";
    const what = ev.doing || ((CAT[ev.category] || ev.category) + (ev.port ? " :" + ev.port : "") + (ev.malware ? " · " + ev.malware : ""));
    const how = ev.observation_type === "direct_observation" ? "observed" : "reported by " + srcName(ev.source);
    const li = el("li", {}, el("i", { style: "background:" + (COLOR[ev.category] || "#8b949e") }),
      el("span", { class: "tk-t" }, new Date(ev.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })),
      el("span", { class: "tk-ip" }, ev.ip + where), el("span", { class: "tk-what" }, what + " · " + how));
    li.addEventListener("click", () => openDetail(ev.ip));
    list.prepend(li);
    while (list.children.length > 6) list.lastChild.remove();
  }

  async function setReplay(on) {
    S.replay = on;
    try { localStorage.setItem("gti.replay2", on ? "1" : "0"); } catch (_) {}
    clearTimeout(S.replayTimer); clearTimeout(S.flowTimer);
    $("tk-mode").textContent = on ? "REPLAY · looping recent history" : "LIVE";
    $("tk-mode").classList.toggle("chip-replay", on);
    $("tk-replay").textContent = on ? "Back to live" : "Replay";
    $("tk-note").textContent = on ? "Replay loops real stored data at ~1 item/s: IP listings from the last 24 h and attack arcs from the last hour. Times shown are when each item was recorded." : "";
    if (!on) return;
    let evs = [];
    try { evs = (await api("/api/events?limit=500")).events.filter((e) => e.ts > Date.now() / 1000 - 86400 && e.lat != null); }
    catch (_) { return; }
    let flows = await loadFlows();
    if (!evs.length && !flows.length) { $("tk-mode").textContent = "REPLAY · nothing in the last 24h"; return; }
    // Items from one fetch share a timestamp and arrive in the provider's (often numeric) order.
    // Their relative order carries no meaning, so shuffle within equal timestamps; chronology is kept.
    const order = (a) => a.map((e) => [e.ts, Math.random(), e]).sort((x, y) => x[0] - y[0] || x[1] - y[1]).map((x) => x[2]);
    evs = order(evs); flows = order(flows);
    // Two independent loops so the (few, high-value) sensor arcs are not drowned out by many IP listings.
    let i = 0, j = 0, refreshAt = Date.now() + 60000;
    const nextIp = () => {
      if (!S.replay) return;
      if (evs.length && S.show.ip) animate(evs[i++ % evs.length]);
      S.replayTimer = setTimeout(nextIp, 700 + Math.random() * 600);
    };
    const nextFlow = async () => {
      if (!S.replay) return;
      if (Date.now() > refreshAt) { refreshAt = Date.now() + 60000; const f = await loadFlows(); if (f.length) flows = order(f); }
      if (flows.length) animateFlow(flows[j++ % flows.length], true);
      S.flowTimer = setTimeout(nextFlow, 450 + Math.random() * 400);
    };
    nextIp(); nextFlow();
  }

  async function openDetail(ip) {
    S.selected = ip;
    const body = $("detail-body"); body.replaceChildren(el("p", { class: "muted" }, "Loading " + ip + "…"));
    $("detail").classList.remove("hidden");
    let d;
    try { d = await api("/api/ip/" + encodeURIComponent(ip)); } catch (e) { body.replaceChildren(el("p", { class: "err" }, e.message)); return; }
    if (S.selected !== ip) return; // a newer selection won
    const g = d.geo || {}, sc = d.score;
    const m = S.markers.get(ip);
    if (m) { highlight(ip); S.map.panTo(m.getLatLng()); }
    const dl = el("dl", {});
    const row = (k, v) => dl.append(el("dt", {}, k), el("dd", {}, v == null || v === "" ? "unknown" : v));
    row("Location", [g.city, g.country].filter(Boolean).join(", ") || null);
    row("ASN", g.asn ? "AS" + g.asn : null); row("Network", g.org);
    row("Ports", d.ports.length ? d.ports.join(", ") : "none reported");
    row("Malware", d.malware.length ? d.malware.join(", ") : "none reported");
    row("Confidence", sc.confidence + " (" + sc.breakdown.length + " source" + (sc.breakdown.length === 1 ? "" : "s") + ")");
    const ind = el("table", { class: "tbl small" }, el("thead", {}, el("tr", {}, el("th", {}, "Source"), el("th", {}, "Category"), el("th", {}, "Last listed"), el("th", {}, "Status"))));
    const tb = el("tbody", {});
    for (const r of d.indicators) {
      const obs = r.observation_type === "direct_observation";
      tb.append(el("tr", {}, el("td", {}, r.source_name + (obs ? " (observed)" : " (reported)")),
        el("td", {}, el("i", { class: "dot", style: "background:" + (COLOR[r.category] || "#8b949e") }), " ", CAT[r.category] || r.category),
        el("td", {}, ago(r.last_seen)),
        el("td", {}, obs ? r.hits + " hit" + (r.hits === 1 ? "" : "s") : r.active ? "listed" : "no longer listed")));
    }
    ind.append(tb);
    const how = el("p", { class: "muted small" }, "Score = combined source weights (" +
      sc.breakdown.map((b) => srcName(b.source) + " " + b.weight).join(", ") + ") × recency " + sc.recency_factor + ". See docs/SCORING.md.");
    // what the evidence says this IP does: each line names its source and whether it was observed or reported
    const act = el("ul", { class: "act-list" });
    for (const a of d.activity) {
      act.append(el("li", {}, el("span", { class: "badge " + (a.kind === "observed" ? "b-obs" : "b-rep") }, a.kind === "observed" ? "Observed here" : "Reported"),
        " ", a.what, el("span", { class: "muted small" }, " (" + srcName(a.source) + ")")));
    }
    if (!d.activity.length) act.append(el("li", { class: "muted" }, "The listing gives no detail beyond its category."));
    const ports = d.port_info.filter((p) => p.service);
    const portBox = ports.length ? [el("h4", {}, "Ports involved"), el("ul", { class: "act-list" }, ...ports.map((p) =>
      el("li", {}, el("b", {}, p.port + " " + p.service), ": attempts on this port usually aim at " + p.usual_aim + ".")))] : [];
    const abBox = el("div", { id: "ab-box" });
    const hostBox = el("div", { id: "host-box" }, el("p", { class: "muted small" }, "Looking up host details…"));
    body.replaceChildren(
      el("h3", {}, d.ip), el("span", { class: "score " + scoreClass(sc.score) }, "Score " + sc.score),
      dl, hostBox, el("h4", {}, "What this IP is doing"), act, ...portBox, abBox,
      el("p", { class: "note" }, d.evidence_note), el("h4", {}, "Intelligence sources"), el("div", { style: "overflow-x:auto" }, ind), how);
    loadHost(ip, hostBox);
    loadAbuse(ip, abBox, d.abuseipdb_lookup);
  }

  async function loadHost(ip, box) {
    let h;
    try { h = await api("/api/ip/" + encodeURIComponent(ip) + "/host"); }
    catch (e) { if (S.selected === ip) box.replaceChildren(el("p", { class: "err small" }, e.message)); return; }
    if (S.selected !== ip) return;
    const dl = el("dl", {});
    const row = (k, v, note) => { if (v == null || v === "") return;
      dl.append(el("dt", {}, k), el("dd", {}, String(v), ...(note ? [" ", el("span", { class: "muted small" }, note)] : []))); };
    const rd = h.reverse_dns || {};
    if (rd.hostname) row("Hostname", rd.hostname, rd.confirmed ? "(verified: resolves back to this IP)" : "(not verified: set by the network owner, may be misleading)");
    else row("Hostname", rd.timeout ? "lookup timed out" : "none (no reverse DNS)");
    row("Region", [h.region, h.country_name || h.country, h.continent].filter(Boolean).join(", "));
    row("Network block", h.asn_block, "(announced route, per DB-IP)");
    if (h.city_block && h.city_block !== h.asn_block) row("Location block", h.city_block);
    row("Network type", h.network_kind === "hosting" ? "Hosting / cloud provider" : null, "(guessed from the operator's name: likely a rented server, not a home connection)");
    row("IP version", "IPv" + h.version);
    row("In this database", "first " + new Date(h.first_seen * 1000).toLocaleString() + ", last " + new Date(h.last_seen * 1000).toLocaleString());
    if (h.listed_in_same_24 != null) row("Same /24", h.listed_in_same_24 + " other listed IP" + (h.listed_in_same_24 === 1 ? "" : "s"));
    if (h.listed_in_same_asn != null) row("Same network (AS" + h.asn + ")", h.listed_in_same_asn.toLocaleString() + " other listed IP" + (h.listed_in_same_asn === 1 ? "" : "s"));
    box.replaceChildren(el("h4", {}, "Host"), dl);
  }

  async function loadAbuse(ip, box, enabled) {
    if (!enabled) {
      box.replaceChildren(el("p", { class: "muted small" }, "For what other users reported this IP doing (brute-force, port scans, web attacks, with their notes), add an AbuseIPDB key on the Sources page."));
      return;
    }
    box.replaceChildren(el("h4", {}, "AbuseIPDB reports"), el("p", { class: "muted small" }, "Looking up…"));
    let a;
    try { a = await api("/api/ip/" + encodeURIComponent(ip) + "/abuseipdb"); }
    catch (e) { if (S.selected === ip) box.replaceChildren(el("h4", {}, "AbuseIPDB reports"), el("p", { class: "err small" }, e.message)); return; }
    if (S.selected !== ip) return;
    if (!a.available) { box.replaceChildren(el("p", { class: "muted small" }, a.reason)); return; }
    const parts = [el("h4", {}, "AbuseIPDB reports (last 90 days)")];
    if (a.error) parts.push(el("p", { class: "err small" }, a.error + " (showing the saved result)"));
    const dl = el("dl", {});
    const row = (k, v) => { if (v != null && v !== "") dl.append(el("dt", {}, k), el("dd", {}, String(v))); };
    row("Reports", a.total_reports != null ? a.total_reports + " from " + a.distinct_reporters + " reporters" : null);
    row("Confidence", a.confidence != null ? a.confidence + "%" : null);
    row("Last reported", a.last_reported ? new Date(a.last_reported).toLocaleString() : null);
    row("Network type", a.usage_type); row("ISP", a.isp); row("Domain", a.domain);
    if (a.is_tor) row("Tor", "Tor exit node");
    parts.push(dl);
    if (a.categories.length) {
      parts.push(el("div", { class: "muted small" }, "Reported for:"),
        el("div", { class: "badges" }, ...a.categories.map((c) => el("span", { class: "badge" }, c.label + " ×" + c.reports))));
    }
    if (a.recent_comments.length) {
      parts.push(el("div", { class: "muted small" }, "Recent reporter notes (written by other users, unverified):"));
      const ul = el("ul", { class: "act-list comments" });
      for (const c of a.recent_comments) ul.append(el("li", {}, el("span", { class: "muted small" }, (c.at ? new Date(c.at).toLocaleDateString() + " · " : "") + c.categories.join(", ")), el("div", { class: "cmt" }, c.text)));
      parts.push(ul);
    }
    parts.push(el("p", { class: "muted small" }, (a.cached ? "Saved lookup from " + new Date(a.fetched_at * 1000).toLocaleString() : "Fetched just now") + ". Reports are claims by AbuseIPDB users, not proof."));
    box.replaceChildren(...parts);
  }

  // ---------------- live feed ----------------
  // Two streams: IP listings (each IP can be investigated) and attacks from the threat maps (no IPs published,
  // but named: exploit + CVE, botnet, scanner, MITRE tactic). Same wording as the map ticker.
  const FEED_HEAD = {
    ips: ["Time", "IP", "Country", "Category", "What it's doing", "Source"],
    attacks: ["Time", "From \u2192 to", "Type", "Attack / exploit", "Count", "Source"],
  };
  const FEED_NOTE = {
    ips: "New listings from IP reputation feeds and this machine's own logs. Reported listings are a source's claim, not an attack observed by this system. Click a row to investigate the IP.",
    attacks: "Attacks from the GreyNoise, Check Point and Radware sensor networks (attacker area \u2192 target; these vendors publish no attacker IP addresses, so those rows cannot be investigated) and attacks on this machine seen by its own sensor (with the attacker's IP: click to investigate). Radware times are playback times.",
  };
  const feedKind = () => $("f-kind").value;
  function feedRow(ev, fresh) {
    const obs = ev.observation_type === "direct_observation";
    const tr = el("tr", { class: "click" + (fresh ? " new" : "") },
      el("td", {}, new Date(ev.ts * 1000).toLocaleTimeString()), el("td", { class: "mono" }, ev.ip), el("td", {}, ev.country || "?"),
      el("td", {}, el("i", { class: "dot", style: "background:" + (COLOR[ev.category] || "#8b949e") }), " ", CAT[ev.category] || ev.category),
      el("td", {}, el("span", { class: "badge " + (obs ? "b-obs" : "b-rep") }, obs ? "Observed" : "Reported"), ev.doing || ev.malware || ""),
      el("td", {}, srcName(ev.source)));
    tr.addEventListener("click", () => { show("map"); openDetail(ev.ip); });
    return tr;
  }
  function attackRow(f, fresh) {
    const { srcLabel, label, color } = flowStyle(f);
    const from = f.src_name || countryAt(f.src_lat, f.src_lon) || "Unknown area";
    const same = f.dst_lat === f.src_lat && f.dst_lon === f.src_lon;
    const to = f.dst_name || (same ? null : countryAt(f.dst_lat, f.dst_lon));
    const name = f.attack_name || (f.also_seen && f.also_seen.length ? "Also seen: " + f.also_seen.join(", ") : "");
    return el("tr", { class: fresh ? "new" : "" },
      el("td", {}, new Date(f.ts * 1000).toLocaleTimeString()),
      el("td", {}, from + " \u2192 " + (to || "target not disclosed")),
      el("td", {}, el("i", { class: "dot", style: "background:" + color }), " ", label),
      el("td", {}, ...(f.ai_target ? [el("span", { class: "badge b-ai" }, "AI target: " + f.ai_target)] : []),
        name, ...(f.cves || []).filter((c) => !name.includes(c)).map((c) => el("span", { class: "ex-cve" }, " " + c))),
      el("td", {}, f.count.toLocaleString()), el("td", {}, srcLabel));
  }
  function feedEmpty(text) { $("feed-body").replaceChildren(el("tr", {}, el("td", { colspan: "6", class: "muted" }, text))); }
  const ATTACK_ROWS = 5000;   // the whole last hour in normal conditions (the API returns at most 5,000)
  // attacks view: the threat-map sources (no IPs published) plus this machine's own sensor (real attacker IPs)
  const inAttacks = (id) => !!ARC_SRC[id] || id === "local_sensor";
  function observedAttackRow(ev, fresh) {
    const tr = el("tr", { class: "click" + (fresh ? " new" : "") },
      el("td", {}, new Date(ev.ts * 1000).toLocaleTimeString()),
      el("td", {}, el("span", { class: "mono ip-link" }, ev.ip), (ev.country ? " (" + ev.country + ")" : "") + " \u2192 this machine"),
      el("td", {}, el("i", { class: "dot", style: "background:" + (COLOR[ev.category] || "#8b949e") }), " ", CAT[ev.category] || ev.category),
      el("td", {}, el("span", { class: "badge b-obs" }, "Observed here"), ev.doing || ""),
      el("td", {}, "1"), el("td", {}, srcName(ev.source)));
    tr.title = "Click to investigate " + ev.ip;
    tr.addEventListener("click", () => { show("map"); openDetail(ev.ip); });
    return tr;
  }
  function fillSourceSelect() {
    const sel = $("f-source"), cur = sel.value, arcs = feedKind() === "attacks";
    const list = (S.sources || []).filter((s) => (arcs ? inAttacks(s.id) : !ARC_SRC[s.id]));
    sel.replaceChildren(el("option", { value: "" }, "All sources"), ...list.map((s) => el("option", { value: s.id }, s.name)));
    sel.value = list.some((s) => s.id === cur) ? cur : "";
  }
  async function loadFeed() {
    const kind = feedKind();
    $("feed-head").replaceChildren(el("tr", {}, ...FEED_HEAD[kind].map((h) => el("th", {}, h))));
    $("feed-head").parentElement.className = "tbl feed-tbl feed-" + kind;
    $("f-note").textContent = FEED_NOTE[kind];
    $("f-next").textContent = "";
    const src = $("f-source").value;
    try {
      if (kind === "ips") {
        showNextUpdates(src);
        const p = new URLSearchParams({ limit: "200" }); if (src) p.set("source", src);
        const d = await api("/api/events?" + p);
        if (feedKind() !== kind) return;
        $("feed-body").replaceChildren(...d.events.map((e) => feedRow(e, false)));
        if (!d.events.length) feedEmpty("No events yet. Feeds are collected on a schedule; check Sources for status.");
        banner(d.unhealthy_sources);
      } else {
        const since = Date.now() / 1000 - 3600;
        const wantArcs = !src || !!ARC_SRC[src], wantLocal = !src || src === "local_sensor";
        const p = new URLSearchParams({ minutes: "60", limit: "5000" }); if (src && ARC_SRC[src]) p.set("source", src);
        const [d, obs] = await Promise.all([
          wantArcs ? api("/api/flows?" + p) : Promise.resolve({ flows: [] }),
          wantLocal ? api("/api/events?source=local_sensor&limit=500").catch(() => ({ events: [] })) : Promise.resolve({ events: [] })]);
        if (feedKind() !== kind) return;
        // interleave sources, newest first within each: Radware's per-minute batches would otherwise
        // fill the whole list and hide the other sources. Observed attacks (with IPs) count as one source.
        const per = {};
        for (const f of d.flows) (per[f.source] = per[f.source] || []).push({ f });
        per.local_sensor = obs.events.filter((e) => e.ts >= since).map((e) => ({ e, ts: e.ts }));
        for (const k in per) per[k].sort((a, b) => (b.ts || b.f.ts) - (a.ts || a.f.ts) || ((b.f || {}).count || 0) - ((a.f || {}).count || 0));
        const lists = Object.values(per), rows = [];
        for (let i = 0; rows.length < ATTACK_ROWS && lists.some((l) => i < l.length); i++)
          for (const l of lists) if (i < l.length && rows.length < ATTACK_ROWS) rows.push(l[i]);
        $("feed-body").replaceChildren(...rows.map((r) => (r.e ? observedAttackRow(r.e, false) : attackRow(r.f, false))));
        if (!rows.length) feedEmpty("No attacks in the last hour. The sources may be disabled or not yet collected; check Sources.");
        $("f-note").textContent = FEED_NOTE.attacks + " Showing " + rows.length.toLocaleString() + " of " +
          (d.flows.length + per.local_sensor.length).toLocaleString() + " from the last hour.";
        banner(d.unhealthy_sources || []);
      }
    } catch (e) { $("f-status").textContent = e.message; }
  }
  // IP listings arrive in bursts when a list is downloaded again: say when each list is next fetched
  async function showNextUpdates(src) {
    let list;
    try { list = (await api("/api/sources")).sources; S.sources = list; } catch (_) { return; }
    if (feedKind() !== "ips") return;
    const t = (s) => new Date(s * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
    const day = (s) => new Date(s * 1000).toDateString() !== new Date().toDateString() ? " tomorrow" : "";
    const parts = [];
    for (const s of list) {
      if (ARC_SRC[s.id] || !s.enabled || (src && s.id !== src)) continue;
      if (s.id === "local_sensor") { if (s.status !== "unavailable") parts.push(s.name + ": continuous (checked every minute)"); continue; }
      if (s.next_run == null) continue;
      parts.push(s.name + ": " + (s.next_run <= Date.now() / 1000 + 30 ? "due now" : t(s.next_run) + day(s.next_run)) +
        " (every " + Math.round(s.interval_seconds / 3600) + " h)");
    }
    $("f-next").textContent = parts.length ? "Next list downloads, which bring new listings: " + parts.join(" · ") +
      ". Between downloads this list stays the same." : "";
  }
  function feedPush(row) {
    const body = $("feed-body");
    if (body.firstChild && body.firstChild.children.length === 1) body.replaceChildren();
    body.prepend(row);
    while (body.children.length > (feedKind() === "attacks" ? ATTACK_ROWS : 200)) body.lastChild.remove();
  }
  $("f-source").addEventListener("change", loadFeed);
  $("f-kind").addEventListener("change", () => {
    try { localStorage.setItem("gti.feedKind", feedKind()); } catch (_) {}
    fillSourceSelect(); loadFeed();
  });
  try { const k = localStorage.getItem("gti.feedKind"); if (k && FEED_HEAD[k]) $("f-kind").value = k; } catch (_) {}
  $("f-pause").addEventListener("click", () => {
    S.paused = !S.paused; $("f-pause").textContent = S.paused ? "Resume" : "Pause";
    if (!S.paused) loadFeed();   // catch up on what arrived while paused
    wsStatus();
  });
  function wsStatus(state) {
    if (state) S.wsState = state;
    $("f-status").textContent = (S.paused ? "Paused. " : "") + (S.wsState === "open" ? "Live" : "Disconnected, reconnecting…");
  }
  function connectWS() {
    const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
    S.ws = ws;
    ws.onopen = () => { S.wsRetry = 1000; wsStatus("open"); };
    ws.onmessage = (m) => {
      let msg; try { msg = JSON.parse(m.data); } catch (_) { return; }
      if (msg.type === "flow") {
        // batches are paced over their window (like the providers' own maps) instead of arriving all at once
        const f = msg.flow;
        const arrive = () => {
          animateFlow(f, false);
          if (S.view === "feed" && !S.paused && feedKind() === "attacks" &&
              (!$("f-source").value || $("f-source").value === f.source)) feedPush(attackRow(f, true));
        };
        if (f.delay_ms > 0) setTimeout(arrive, Math.min(f.delay_ms, 60000)); else arrive();
        S.recentFlows = [msg.flow].concat(S.recentFlows || []).filter((f) => f.ts > Date.now() / 1000 - 3600).slice(0, 2000);
        clearTimeout(S.topTimer); S.topTimer = setTimeout(() => updateTop(S.recentFlows), 2000);
        return;
      }
      if (msg.type !== "event") return;
      const ev = msg.event;
      if (S.view === "feed" && !S.paused && (!$("f-source").value || $("f-source").value === ev.source)) {
        if (feedKind() === "ips") feedPush(feedRow(ev, true));
        else if (ev.source === "local_sensor") feedPush(observedAttackRow(ev, true));
      }
      animate(ev);   // live events always animate, also during replay
      if (S.view === "map") { clearTimeout(S.mapTimer); S.mapTimer = setTimeout(loadMap, 5000); } // coalesce bursts
    };
    ws.onclose = (e) => {
      wsStatus("closed");
      if (S.ws !== ws || !S.csrf) return;
      if (e.code === 4401) { showAuth(false); return; }
      setTimeout(() => { if (S.csrf) connectWS(); }, S.wsRetry);
      S.wsRetry = Math.min(S.wsRetry * 2, 30000);
    };
  }
  function stopLive() { if (S.ws) { const w = S.ws; S.ws = null; w.close(); } }

  // ---------------- analytics ----------------
  function bars(title, entries, label) {
    const max = Math.max(1, ...entries.map((e) => e[1]));
    const c = el("div", { class: "card wide" }, el("h3", {}, title));
    if (!entries.length) c.append(el("p", { class: "muted" }, "No data yet."));
    for (const [k, v] of entries) c.append(el("div", { class: "bar" }, el("span", { title: label(k) }, label(k)),
      el("div", { class: "fill", style: "width:" + (100 * v / max).toFixed(1) + "%" }), el("span", {}, v.toLocaleString())));
    return c;
  }
  async function loadAnalytics() {
    const box = $("analytics");
    try {
      const d = await api("/api/stats");
      box.replaceChildren(
        el("div", { class: "grid" },
          el("div", { class: "card wide" }, el("div", { class: "muted" }, "Unique listed IPs"), el("div", { class: "stat" }, d.unique_ips.toLocaleString())),
          el("div", { class: "card wide" }, el("div", { class: "muted" }, "New listings, last 24h (capped per run)"), el("div", { class: "stat" }, d.events_24h.toLocaleString()))),
        el("p", { class: "muted small" }, d.note),
        el("div", { class: "grid" },
          bars("By source", Object.entries(d.by_source).sort((a, b) => b[1] - a[1]), srcName),
          bars("By category", Object.entries(d.by_category).sort((a, b) => b[1] - a[1]), (k) => CAT[k] || k),
          bars("Top countries", d.top_countries.map((x) => [x.country, x.count]), (k) => (k === "??" ? "Unknown" : k))));
    } catch (e) { box.replaceChildren(el("p", { class: "err" }, e.message)); }
  }

  // ---------------- sources ----------------
  async function refreshSourceList() {
    const d = await api("/api/sources"); S.sources = d.sources;
    {   // the map's filter applies to IP dots only: arc sources have their own legend toggles
      const sel = $("m-source"), cur = sel.value;
      sel.replaceChildren(el("option", { value: "" }, "All sources"), ...d.sources.filter((s) => !ARC_SRC[s.id]).map((s) => el("option", { value: s.id }, s.name)));
      sel.value = cur;
    }
    fillSourceSelect();
    return d.sources;
  }
  async function loadSources() {
    const box = $("sources");
    let list;
    try { list = await refreshSourceList(); } catch (e) { box.replaceChildren(el("p", { class: "err" }, e.message)); return; }
    box.replaceChildren(el("p", { class: "muted small" }, "All sources are third-party reputation lists. Weights feed the threat score (docs/SCORING.md)."));
    for (const s of list) {
      const msg = el("p", { class: "small", role: "status" });
      const toggle = el("button", {}, s.enabled ? "Disable" : "Enable");
      toggle.addEventListener("click", async () => {
        try { await api("/api/sources/" + s.id, { method: "PUT", body: { enabled: !s.enabled } }); loadSources(); }
        catch (e) { msg.textContent = e.message; msg.className = "small err"; }
      });
      const refresh = el("button", { class: "ghost" }, "Fetch now");
      refresh.addEventListener("click", async () => {
        refresh.disabled = true; msg.textContent = "Fetching…"; msg.className = "small";
        try { const r = await api("/api/sources/" + s.id + "/refresh", { method: "POST" });
          msg.textContent = r.ok ? "Fetched " + r.count + " records, " + r.new_events + " new." : "Failed: " + r.error; if (r.ok) setTimeout(loadSources, 800); }
        catch (e) { msg.textContent = e.message; msg.className = "small err"; }
        refresh.disabled = false;
      });
      if (!s.enabled) refresh.disabled = true;
      const card = el("div", { class: "card wide src" },
        el("div", { class: "row" }, el("strong", {}, s.name), el("span", { class: "pill st-" + s.status }, s.status.replace("_", " ")),
          s.requires_key ? el("span", { class: "pill" }, "API key required") : el("span", { class: "pill" }, "No key needed")),
        el("p", { class: "muted small" }, s.description),
        el("p", { class: "small" }, "Last success: " + fmtTime(s.last_success) + " (" + ago(s.last_success) + ") · records: " + s.record_count +
          " · every " + Math.round(s.interval_seconds / 3600) + "h · weight " + s.weight),
        s.last_error ? el("p", { class: "small err" }, "Last error: " + s.last_error) : null,
        s.note ? el("p", { class: "small muted" }, "Note: " + s.note) : null,
        el("div", { class: "row" }, toggle, refresh), msg);
      if (s.requires_key) {
        const inp = el("input", { type: "password", autocomplete: "off", placeholder: s.has_key ? "Key saved (hidden). Enter a new key to replace" : "Paste API key" });
        const save = el("button", {}, "Save key");
        const clear = el("button", { class: "ghost" }, "Remove key");
        save.addEventListener("click", async () => {
          if (!inp.value.trim()) { msg.textContent = "Enter a key first"; return; }
          try { await api("/api/sources/" + s.id, { method: "PUT", body: { api_key: inp.value.trim() } }); inp.value = ""; loadSources(); }
          catch (e) { msg.textContent = e.message; msg.className = "small err"; }
        });
        clear.addEventListener("click", async () => { try { await api("/api/sources/" + s.id, { method: "PUT", body: { api_key: "" } }); loadSources(); } catch (e) { msg.textContent = e.message; } });
        card.append(el("div", { class: "row" }, inp, save, s.has_key ? clear : null));
      }
      box.append(card);
    }
  }

  // ---------------- settings ----------------
  async function loadSettings() {
    try {
      const s = await api("/api/settings"); S.settings = s;
      for (const [id, k] of [["s-ret", "retention_days"], ["s-pts", "map_max_points"], ["s-min", "min_score_default"]]) {
        $(id).value = s[k]; $(id).min = s.limits[k].min; $(id).max = s.limits[k].max;
      }
      $("s-lat").value = s.home ? s.home.lat : ""; $("s-lon").value = s.home ? s.home.lon : "";
      $("s-label").value = s.home ? s.home.label : "";
      $("s-ingest").textContent ="Ingestion limits (set at install time for this hardware, in /etc/global-threat-intel/gti.env): " +
        s.ingest.max_indicators_per_source.toLocaleString() + " IPs per source, " + s.ingest.max_events_per_run + " live-feed events per fetch.";
    } catch (e) { $("s-msg").textContent = e.message; }
  }
  $("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const m = $("s-msg"); m.className = "";
    m.textContent = "";
    try {
      const lat = $("s-lat").value.trim(), lon = $("s-lon").value.trim();
      if ((lat === "") !== (lon === "")) throw new Error("Enter both latitude and longitude, or leave both empty.");
      const home = lat === "" ? null : { lat: parseFloat(lat), lon: parseFloat(lon), label: $("s-label").value.trim() || "This host" };
      const s = await api("/api/settings", { method: "PUT", body: { retention_days: parseInt($("s-ret").value, 10),
        map_max_points: parseInt($("s-pts").value, 10), min_score_default: parseInt($("s-min").value, 10), home } });
      m.textContent = "Saved."; $("m-min").value = $("s-min").value; setHome(s.home);
    } catch (err) { m.textContent = err.message; m.className = "err"; }
  });
  $("s-locate").addEventListener("click", async () => {
    const m = $("s-msg"); m.className = "";
    try {
      const r = await api("/api/locate-me");
      if (!r.found) { m.textContent = r.reason; return; }
      $("s-lat").value = r.lat; $("s-lon").value = r.lon; $("s-label").value = r.label;
      m.textContent = "Suggested from GeoIP (approximate, city level). Press Save to use it.";
    } catch (err) { m.textContent = err.message; m.className = "err"; }
  });
  $("s-clear").addEventListener("click", () => { $("s-lat").value = ""; $("s-lon").value = ""; $("s-label").value = ""; $("s-msg").textContent = "Press Save to remove the location."; });
  $("pw-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const m = $("p-msg"); m.className = "";
    try { await api("/api/password", { method: "POST", body: { current: $("p-cur").value, new: $("p-new").value } });
      m.textContent = "Password changed. Other sessions were signed out."; $("p-cur").value = ""; $("p-new").value = ""; }
    catch (err) { m.textContent = err.message; m.className = "err"; }
  });

  // ---------------- boot ----------------
  async function start(firstRun) {
    $("auth").classList.add("hidden"); $("main").classList.remove("hidden");
    if (!S.map) initMap();
    try { await refreshSourceList(); } catch (_) {}
    try { const s = await api("/api/settings"); $("m-min").value = s.min_score_default; setHome(s.home); } catch (_) {}
    connectWS();
    show(firstRun ? "sources" : "map");
    // live by default (live sources now arrive every few seconds); replay is opt-in and remembered
    let rp = "0"; try { rp = localStorage.getItem("gti.replay2") || "0"; } catch (_) {}
    setReplay(rp === "1");
    // legend totals, top origins/targets and top exploits: loaded now and refreshed each minute
    // (replay refreshes them itself)
    loadFlows();
    if (!S.flowPoll) S.flowPoll = setInterval(() => { if (!S.replay && !document.hidden && S.csrf) loadFlows(); }, 60000);
  }
  (async function boot() {
    try {
      const h = await (await fetch("/api/health")).json();
      if (h.setup_required) return showAuth(true);
      const me = await fetch("/api/me", { credentials: "same-origin" });
      if (me.ok) { S.csrf = (await me.json()).csrf; return start(false); }
      showAuth(false);
    } catch (e) { showAuth(false); $("auth-err").textContent = "Cannot reach the server: " + e.message; }
  })();
})();
