/* =====================================================
   MlinziOps — page renderers (loaded after app.js)
   Every UI action maps to a real backend endpoint.
   ===================================================== */
"use strict";

window.PAGES = window.PAGES || {};

/* ---------------- shared bits ---------------- */
function modal(title, bodyHtml, footHtml) {
  const m = document.createElement("div");
  m.style.cssText = "position:fixed;inset:0;background:rgba(4,8,14,.72);display:flex;align-items:center;justify-content:center;z-index:500;";
  m.innerHTML = `<div style="width:640px;max-width:94vw;max-height:88vh;overflow:auto;background:var(--bg-1);border:1px solid var(--border-strong);border-radius:12px;padding:20px;">
    <div class="flex" style="justify-content:space-between;margin-bottom:8px;">
      <h3 style="margin:0;">${title}</h3>
      <button class="ghost" id="modal-x"><i class="fa-solid fa-xmark"></i></button></div>
    ${bodyHtml}
    ${footHtml ? `<div class="flex" style="justify-content:flex-end;margin-top:16px;">${footHtml}</div>` : ""}
  </div>`;
  document.body.appendChild(m);
  m.addEventListener("click", (e) => { if (e.target === m) m.remove(); });
  const x = m.querySelector("#modal-x"); if (x) x.onclick = () => m.remove();
  return m;
}
function field(id, label, value, placeholder) {
  return `<label>${label}</label><input id="${id}" value="${esc(value || "")}" placeholder="${placeholder || ""}">`;
}
function selectField(id, label, options, selected) {
  return `<label>${label}</label><select id="${id}">${options.map(o =>
    `<option value="${o}" ${o === selected ? "selected" : ""}>${o}</option>`).join("")}</select>`;
}
function val(id) { const el = document.getElementById(id); return el ? el.value.trim() : ""; }

const SEVS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/* ================================================================
   DASHBOARD
   ================================================================ */
window.PAGES.dashboard = async function (el) {
  let html = `<div class="grid cols-4" id="stat-cards"><div class="muted">Loading metrics…</div></div>
  <div class="grid cols-3" id="sys-cards"></div>
  <div class="grid cols-2">
    <div class="card"><h3>Authentication over last 24h</h3><div style="height:240px;"><canvas id="ch-auth"></canvas></div></div>
    <div class="card"><h3>Events by severity</h3><div style="height:240px;"><canvas id="ch-sev"></canvas></div></div>
  </div>
  <div class="grid cols-2">
    <div class="card"><h3>Incidents by status</h3><div style="height:220px;"><canvas id="ch-inc"></canvas></div></div>
    <div class="card"><h3>Events over 24h</h3><div style="height:220px;"><canvas id="ch-act"></canvas></div></div>
  </div>
  <div class="grid cols-2">
    <div class="card"><h3>Recent events</h3><div id="recent-events" class="table-wrap"></div></div>
    <div class="card"><h3>Scan history</h3><div id="scan-history" class="table-wrap"></div></div>
  </div>`;
  el.innerHTML = html;

  try {
    const [stats, sys, res, net, waz] = await Promise.all([
      getJSON("/dashboard/stats"), getJSON("/system/status"),
      getJSON("/system/resources"), getJSON("/system/network"),
      getJSON("/wazuh/status").catch(() => ({ connected: false, status: "OFFLINE" })),
    ]);
    renderStats(stats);
    renderSysCards(sys, res, net, waz);
    drawCharts(stats);
    renderRecent(stats.recent_events);
    renderScans(stats.scan_history);
  } catch (e) {
    el.innerHTML = `<div class="card"><p class="muted">Could not load dashboard: ${esc(e.message)}</p></div>`;
  }
};

function renderStats(s) {
  const c = s.counts;
  const cards = [
    ["CRITICAL", c.critical, "fa-burst", "critical", "Critical alerts"],
    ["HIGH", c.high, "fa-arrow-up", "high", "High alerts"],
    ["MEDIUM", c.medium, "fa-minus", "medium", "Medium alerts"],
    ["LOW", c.low, "fa-arrow-down", "low", "Low alerts"],
    ["OPEN INCIDENTS", c.open_incidents, "fa-triangle-exclamation", "high", "Open incidents"],
    ["ACTIVE HOSTS", `${c.active_hosts}/${c.total_hosts}`, "fa-server", "low", "Active hosts"],
    ["TOTAL EVENTS", c.total_events, "fa-database", "", "Security events indexed"],
    ["OPEN VULNS", c.open_vulnerabilities, "fa-bug", "medium", "Open vulnerabilities"],
  ];
  document.getElementById("stat-cards").innerHTML = cards.map(x =>
    `<div class="stat-card ${x[3]}"><i class="fa-solid ${x[2]} ic"></i><div class="big">${x[1]}</div><div class="lbl">${x[4]}</div></div>`).join("");
}

function renderSysCards(sys, res, net, waz) {
  const mem = res.memory || {};
  const disk = (res.disk && res.disk[0]) || {};
  const up = sys.boot_time ? (Date.now() - new Date(sys.boot_time).getTime()) / 1000 : 0;
  const upTxt = up ? `${Math.floor(up / 86400)}d ${Math.floor(up % 86400 / 3600)}h ${Math.floor(up % 3600 / 60)}m` : "-";
  const color = (p) => p > 85 ? "danger" : p > 65 ? "warn" : "";
  document.getElementById("sys-cards").innerHTML = `
    <div class="card"><h3><i class="fa-solid fa-microchip"></i> System</h3>
      <div class="space-y small">
        <p class="mono">${esc(sys.hostname)} · ${esc(sys.operating_system)} ${esc(sys.os_release)}</p>
        <p class="muted">Kernel ${esc(sys.kernel)} · ${esc(sys.architecture)}</p>
        <p class="muted">Uptime: ${upTxt}</p>
        <p class="muted">Python ${esc(sys.python_version)}</p>
      </div></div>
    <div class="card"><h3><i class="fa-solid fa-memory"></i> Resources</h3>
      <p class="small">CPU <span class="mono">${res.cpu_percent ?? 0}%</span> (${res.cpu_count} cores)</p>
      <div class="progress ${color(res.cpu_percent)}"><div style="width:${Math.min(100, res.cpu_percent || 0)}%"></div></div>
      <p class="small" style="margin-top:8px;">RAM <span class="mono">${Math.round((mem.used_bytes || 0) / 1e9 * 10) / 10} / ${Math.round((mem.total_bytes || 0) / 1e9 * 10) / 10} GB</span></p>
      <div class="progress ${color(mem.percent)}"><div style="width:${mem.percent || 0}%"></div></div>
      <p class="small" style="margin-top:8px;">Disk ${disk.mountpoint || "/"} <span class="mono">${disk.percent ?? 0}% used</span></p>
      <div class="progress ${color(disk.percent)}"><div style="width:${disk.percent || 0}%"></div></div>
      ${res.load_average && res.load_average["1"] != null ? `<p class="muted small" style="margin-top:8px;">Load: ${res.load_average["1"]} / ${res.load_average["5"]} / ${res.load_average["15"]}</p>` : ""}
    </div>
    <div class="card"><h3><i class="fa-solid fa-network-wired"></i> Network & Wazuh</h3>
      <div class="space-y small">
        ${(net.interfaces || []).slice(0, 4).map(i => `
          <p><span class="mono">${esc(i.name)}</span> ${(i.stats && i.stats.is_up) ? '<span class="badge st-ONLINE">UP</span>' : '<span class="badge st-OFFLINE">DOWN</span>'}</p>`).join("")}
        <div class="sep"></div>
        <p>Wazuh: ${waz.connected ? '<span class="badge st-ONLINE">CONNECTED</span>' : '<span class="badge st-OFFLINE">OFFLINE</span>'}</p>
        ${waz.reason ? `<p class="faint small">${esc(waz.reason)}</p>` : ""}
      </div></div>`;
}

function drawCharts(s) {
  const dark = { ticks: { color: "#8b98ab" }, grid: { color: "rgba(31,42,58,.7)" } };
  const opts = (o) => Object.assign({ responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#8b98ab" } } } }, o);

  const auth = s.auth_trend || {};
  const authLabels = Object.keys(auth);
  new Chart(document.getElementById("ch-auth"), { type: "bar",
    data: { labels: authLabels, datasets: [
      { label: "Success", data: authLabels.map(k => auth[k].success), backgroundColor: "#22c55e" },
      { label: "Failed", data: authLabels.map(k => auth[k].failed), backgroundColor: "#ef4444" }] },
    options: opts({ scales: { x: dark, y: dark } }) });

  const bySev = s.events_by_severity || {};
  const sevLabels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevColors = { CRITICAL: "#c026d3", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e", INFO: "#38bdf8" };
  new Chart(document.getElementById("ch-sev"), { type: "doughnut",
    data: { labels: sevLabels, datasets: [{ data: sevLabels.map(x => bySev[x] || 0), backgroundColor: sevLabels.map(x => sevColors[x]), borderColor: "#0a0e14" }] },
    options: opts({}) });

  const byStatus = s.incidents_by_status || {};
  const stLabels = Object.keys(byStatus); const stColors = ["#ef4444", "#f97316", "#eab308", "#38bdf8", "#8b98ab", "#22c55e"];
  new Chart(document.getElementById("ch-inc"), { type: "doughnut",
    data: { labels: stLabels, datasets: [{ data: stLabels.map(x => byStatus[x]), backgroundColor: stLabels.map((_, i) => stColors[i % stColors.length]), borderColor: "#0a0e14" }] },
    options: opts({}) });

  const r24 = s.recent24 || [];
  new Chart(document.getElementById("ch-act"), { type: "line",
    data: { labels: r24.map(x => x.label), datasets: [{ label: "events", data: r24.map(x => x.count), borderColor: "#2f7ef7", backgroundColor: "rgba(47,126,247,.12)", fill: true, tension: .3 }] },
    options: opts({ scales: { x: dark, y: dark } }) });
}

function renderRecent(events) {
  const el = document.getElementById("recent-events");
  if (!events || !events.length) { el.innerHTML = "<p class='muted'>No events yet — analyze logs or run a scan.</p>"; return; }
  el.innerHTML = `<table class="data"><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source IP</th><th>User</th><th>Description</th></tr></thead>
    <tbody>${events.map(e => `<tr><td class="mono">${fmtTime(e.timestamp)}</td><td>${sevBadge(e.severity)}</td><td>${esc(e.event_type)}</td><td class="mono">${esc(e.source_ip || "-")}</td><td>${esc(e.username || "-")}</td><td class="clamp" title="${esc(e.description)}">${esc(e.description)}</td></tr>`).join("")}</tbody></table>`;
}
function renderScans(scans) {
  const el = document.getElementById("scan-history");
  if (!scans || !scans.length) { el.innerHTML = "<p class='muted'>No scans yet.</p>"; return; }
  el.innerHTML = `<table class="data"><thead><tr><th>Started</th><th>Target</th><th>Type</th><th>Status</th><th>Services</th></tr></thead>
    <tbody>${scans.map(s => `<tr><td class="mono">${fmtTime(s.started_at)}</td><td class="mono">${esc(s.target)}</td><td>${esc(s.type)}</td><td>${statusBadge(s.status)}</td><td>${s.services}</td></tr>`).join("")}</tbody></table>`;
}

/* ================================================================
   HOSTS
   ================================================================ */
window.PAGES.hosts = async function (el, seg) {
  if (seg[1]) return hostDetail(el, seg[1]);
  el.innerHTML = `<div class="flex" style="margin-bottom:14px;">
      <input id="host-q" placeholder="Search hostname or IP…" style="max-width:260px;">
      ${can("hosts:write") ? `<button class="primary" id="add-host"><i class="fa-solid fa-plus"></i> Add Host</button>` : ""}
      <button id="refresh-all"><i class="fa-solid fa-rotate"></i> Refresh All</button>
    </div>
    <div class="card"><div class="table-wrap" id="hosts-tbl"><div class="muted">Loading…</div></div></div>`;
  const list = async () => {
    const q = val("host-q");
    const hosts = await getJSON("/hosts" + (q ? "?q=" + encodeURIComponent(q) : ""));
    document.getElementById("hosts-tbl").innerHTML =
      `<table class="data"><thead><tr><th>Hostname</th><th>IP</th><th>OS</th><th>Environment</th><th>Status</th><th>Last seen</th><th>Monitoring</th><th></th></tr></thead><tbody>
      ${hosts.map(h => `<tr>
        <td><a href="#/hosts/${h.id}">${esc(h.hostname)}</a></td>
        <td class="mono">${esc(h.ip_address)}</td>
        <td>${esc(h.operating_system || "-")}</td>
        <td><span class="badge">${esc(h.environment)}</span></td>
        <td>${statusBadge(h.status)}</td>
        <td class="mono small">${fmtAgo(h.last_seen)}</td>
        <td>${h.monitoring_enabled ? "✔" : "—"}</td>
        <td class="flex" style="gap:6px;justify-content:flex-end;">
          <button title="Refresh status" class="refresh-host" data-id="${h.id}"><i class="fa-solid fa-rotate"></i></button>
          ${can("hosts:write") ? `<button title="Edit" class="edit-host" data-id="${h.id}"><i class="fa-solid fa-pen"></i></button>
          <button title="Delete" class="del-host danger" data-id="${h.id}"><i class="fa-solid fa-trash"></i></button>` : ""}
        </td></tr>`).join("")}</tbody></table>`;
    el.querySelectorAll(".refresh-host").forEach(b => b.onclick = async () => {
      try { const r = await postJSON(`/hosts/${b.dataset.id}/refresh`); toast(`${r.hostname} → ${r.status}`, "ok"); list(); } catch (e) { toast(e.message, "err"); }
    });
    el.querySelectorAll(".edit-host").forEach(b => b.onclick = async () => {
      const h = await getJSON(`/hosts/${b.dataset.id}`);
      openHostModal(h); 
    });
    el.querySelectorAll(".del-host").forEach(b => b.onclick = async () => {
      if (!confirm("Delete this host? This does not modify the host itself.")) return;
      try { await delJSON(`/hosts/${b.dataset.id}`); toast("Host deleted", "ok"); list(); } catch (e) { toast(e.message, "err"); }
    });
  };
  await list();
  if (can("hosts:write")) {
    el.querySelector("#add-host").onclick = () => openHostModal(null, list);
    const q = document.getElementById("host-q");
    q.oninput = debounce(list, 300);
  }
  el.querySelector("#refresh-all").onclick = async () => {
    try { const r = await postJSON("/hosts/refresh-all"); toast(`Checked ${r.checked} hosts`, "ok"); list(); } catch (e) { toast(e.message, "err"); }
  };
};

function openHostModal(host, after) {
  const isEdit = !!host;
  const m = modal(isEdit ? "Edit Host" : "Add Authorized Host", `
    ${field("h-hostname", "Hostname", host ? host.hostname : "")}
    ${field("h-ip", "IP address (must be authorized)", host ? host.ip_address : "")}
    ${field("h-os", "Operating system", host ? host.operating_system : "")}
    ${selectField("h-env", "Environment", ["lab", "production", "staging", "development", "dmz", "other"], host ? host.environment : "lab")}
    <label>Description</label><textarea id="h-desc">${esc(host ? host.description : "")}</textarea>
    <label style="display:flex;align-items:center;gap:8px;"><input type="checkbox" id="h-mon" style="width:auto;" ${(!host || host.monitoring_enabled) ? "checked" : ""}> Monitoring enabled</label>
    <p class="faint small">Hosts must fall inside the authorized scan scope (private/lab networks or configured CIDRs).</p>`,
    `<button class="primary" id="h-save">Save</button>`);
  m.querySelector("#h-save").onclick = async () => {
    const body = { hostname: val("h-hostname"), ip_address: val("h-ip"), operating_system: val("h-os"),
      environment: val("h-env"), description: val("h-desc"), monitoring_enabled: document.getElementById("h-mon").checked };
    try {
      if (isEdit) { await putJSON(`/hosts/${host.id}`, body); } else { await postJSON("/hosts", body); }
      toast("Host saved", "ok"); m.remove(); after && after();
    } catch (e) { toast(e.message, "err"); }
  };
}

async function hostDetail(el, id) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  try {
    const h = await getJSON("/hosts/" + id);
    el.innerHTML = `<a href="#/hosts" class="faint small"><i class="fa-solid fa-arrow-left"></i> Back to hosts</a>
      <div class="card" style="margin-top:10px;">
        <div class="flex"><h3 style="margin:0;">${esc(h.hostname)}</h3>${statusBadge(h.status)}
          <div class="right">${can("hosts:write") ? `<button id="edit-h"><i class="fa-solid fa-pen"></i> Edit</button>` : ""}
          <button id="refresh-h"><i class="fa-solid fa-rotate"></i> Refresh Status</button></div></div>
        <div class="grid cols-3 small" style="margin-top:12px;">
          <div><span class="faint">IP address</span><p class="mono">${esc(h.ip_address)}</p></div>
          <div><span class="faint">Operating system</span><p>${esc(h.operating_system || "-")}</p></div>
          <div><span class="faint">Environment</span><p><span class="badge">${esc(h.environment)}</span></p></div>
          <div><span class="faint">Last seen</span><p class="mono">${fmtTime(h.last_seen)}</p></div>
          <div><span class="faint">Created</span><p class="mono">${fmtTime(h.created_at)}</p></div>
          <div><span class="faint">Monitoring</span><p>${h.monitoring_enabled ? "Enabled" : "Disabled"}</p></div>
        </div>
        ${h.description ? `<div class="sep"></div><p class="small muted">${esc(h.description)}</p>` : ""}
      </div>`;
    if (can("hosts:write")) el.querySelector("#edit-h").onclick = () => openHostModal(h, () => hostDetail(el, id));
    el.querySelector("#refresh-h").onclick = async () => { await postJSON(`/hosts/${id}/refresh`); hostDetail(el, id); };
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

/* ================================================================
   SCANNER
   ================================================================ */
window.PAGES.scanner = async function (el, seg) {
  if (seg[1]) return scanDetail(el, seg[1]);
  el.innerHTML = `
    <div class="grid cols-2">
      <div class="card">
        <h3><i class="fa-solid fa-radar"></i> Run Authorized Scan</h3>
        <p class="faint small">Targets are validated against the authorized scope (private/lab networks, registered hosts, configured CIDRs) before any traffic is sent.</p>
        ${field("scan-target", "Target (IP or hostname)", "", "192.168.187.108")}
        ${selectField("scan-type", "Scan type", ["quick", "service", "custom"], "quick")}
        ${field("scan-ports", "Ports (optional; e.g. 22,80,443 or 1-1024)", "", "top ports")}
        ${field("scan-extra", "Extra arguments (optional, vetted flags only)", "")}
        <div class="sep"></div>
        ${can("scan:run") ? `<button class="primary" id="run-scan"><i class="fa-solid fa-play"></i> Start Scan</button>` : `<p class="faint">Your role is read-only for scanning.</p>`}
        <div id="scan-progress" class="muted small" style="margin-top:10px;"></div>
      </div>
      <div class="card">
        <h3><i class="fa-solid fa-lock"></i> Authorized Scope</h3>
        <div id="scope-box" class="muted small">Loading…</div>
        <p class="faint small" style="margin-top:10px;">Scanning targets outside this scope is rejected and audited. This control cannot be bypassed from the UI.</p>
      </div>
    </div>
    <div class="card"><h3>Scan History</h3><div class="table-wrap" id="scan-tbl" style="margin-top:6px;"></div></div>`;

  try {
    const scope = await getJSON("/scanner/scope");
    document.getElementById("scope-box").innerHTML =
      `<p>Networks:</p><p class="mono">${esc(scope.networks.join(", "))}</p>
       <div class="sep"></div>
       <p>Nmap: ${scope.nmap_available ? '<span class="badge st-ONLINE">AVAILABLE</span>' : '<span class="badge st-OFFLINE">NOT FOUND</span>'}</p>`;
  } catch (e) { document.getElementById("scope-box").textContent = e.message; }

  const listScans = async () => {
    const scans = await getJSON("/scanner");
    document.getElementById("scan-tbl").innerHTML =
      `<table class="data"><thead><tr><th>Started</th><th>Target</th><th>Type</th><th>Ports</th><th>Status</th><th>Services</th></tr></thead><tbody>
      ${scans.map(s => `<tr>
        <td class="mono">${fmtTime(s.started_at)}</td>
        <td class="mono"><a href="#/scanner/${s.id}">${esc(s.target)}</a></td>
        <td>${esc(s.scan_type)}</td><td class="mono small">${esc(s.ports || "-")}</td>
        <td>${statusBadge(s.status)}</td><td>${s.num_services}</td></tr>`).join("")}</tbody></table>`;
  };
  await listScans();

  const btn = document.getElementById("run-scan");
  if (btn && can("scan:run")) btn.onclick = async () => {
    btn.disabled = true;
    document.getElementById("scan-progress").textContent = "Authorizing target and running Nmap…";
    try {
      const r = await postJSON("/scanner", { target: val("scan-target"), scan_type: val("scan-type"),
        ports: val("scan-ports") || null, extra_args: val("scan-extra") || null });
      toast(`Scan complete: ${r.services.length} services on ${r.target}`, "ok");
      navigate("scanner/" + r.id);
    } catch (e) {
      toast(e.message, "err");
      document.getElementById("scan-progress").textContent = "Scan rejected or failed (see toast).";
    }
    btn.disabled = false;
  };
};

async function scanDetail(el, id) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  try {
    const s = await getJSON("/scanner/" + id);
    el.innerHTML = `<a href="#/scanner" class="faint small"><i class="fa-solid fa-arrow-left"></i> Back to scanner</a>
      <div class="card" style="margin-top:10px;">
        <div class="flex"><h3 style="margin:0;">Scan #${s.id} — ${esc(s.target)}</h3>${statusBadge(s.status)}<span class="right small muted">initiated by ${esc(s.initiated_by_name || "unknown")}</span></div>
        <p class="small muted" style="margin-top:6px;">Type ${esc(s.scan_type)} · started ${fmtTime(s.started_at)} · completed ${fmtTime(s.completed_at)}</p>
        ${s.error_message ? `<p class="small" style="color:#f87171;">${esc(s.error_message)}</p>` : ""}
        <div class="sep"></div>
        <h3>Discovered services</h3>
        <div class="table-wrap">${s.services.length ? `<table class="data"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
          <tbody>${s.services.map(x => `<tr><td class="mono">${x.port}</td><td>${esc(x.protocol)}</td><td><span class="badge ${x.state.toUpperCase() === "OPEN" ? "st-ONLINE" : ""}">${esc(x.state)}</span></td><td>${esc(x.service || "-")}</td><td>${esc(x.product || "-")}</td><td class="mono small">${esc(x.version || "-")}</td></tr>`).join("")}</tbody></table>` : "<p class='muted'>No open services parsed.</p>"}</div>
        <div class="sep"></div>
        <h3>Raw Nmap output</h3>
        <pre class="log">${esc(s.raw_output || "(empty)")}</pre>
      </div>`;
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

/* ================================================================
   LOGS
   ================================================================ */
window.PAGES.logs = async function (el) {
  el.innerHTML = `
    <div class="card">
      <h3><i class="fa-solid fa-file-lines"></i> Log Sources</h3>
      <div id="src-box" class="muted small">Loading…</div>
      <div class="sep"></div>
      <div class="flex">
        <button class="primary" id="analyze"><i class="fa-solid fa-magnifying-glass-chart"></i> Analyze Now</button>
        <button id="run-det"><i class="fa-solid fa-shield-halved"></i> Run Detection Engine</button>
        <span id="log-status" class="muted small"></span>
      </div>
    </div>
    <div class="grid cols-2">
      <div class="card"><h3>Parsed Events</h3><div id="parsed" class="table-wrap"></div></div>
      <div class="card"><h3>Detection Results</h3><div id="detections"></div></div>
    </div>`;
  try {
    const src = await getJSON("/logs/sources");
    document.getElementById("src-box").innerHTML = `<table class="data"><thead><tr><th>Source</th><th>Path</th><th>Available</th></tr></thead><tbody>
      <tr><td>auth.log</td><td class="mono">${esc(src.auth.path)}</td><td>${src.auth.available ? "✔" : "✘"}</td></tr>
      <tr><td>syslog</td><td class="mono">${esc(src.syslog.path)}</td><td>${src.syslog.available ? "✔" : "✘"}</td></tr>
      <tr><td>journalctl</td><td class="mono">journalctl</td><td>${src.journal.available ? "✔" : "✘"}</td></tr></tbody></table>`;
  } catch (e) { document.getElementById("src-box").textContent = e.message; }

  const run = async () => {
    if (!can("logs:view")) { toast("Read-only role", "err"); return; }
    document.getElementById("log-status").textContent = "Analyzing…";
    try {
      const r = await getJSON("/logs/analyze");
      toast(`${r.total} events parsed, ${r.detections.length} detections`, "ok");
      document.getElementById("parsed").innerHTML = r.events.length ? `<table class="data"><thead><tr><th>Time</th><th>Type</th><th>User</th><th>Source IP</th><th>Message</th></tr></thead><tbody>
        ${r.events.slice().reverse().map(ev => `<tr><td class="mono">${fmtTime(ev.timestamp)}</td><td>${esc(ev.event_type)}</td><td>${esc(ev.username || "-")}</td><td class="mono">${esc(ev.source_ip || "-")}</td><td class="clamp" title="${esc(ev.message)}">${esc(ev.message)}</td></tr>`).join("")}</tbody></table>` : "<p class='muted'>No events matched the auth patterns in the configured sources.</p>";
      document.getElementById("detections").innerHTML = r.detections.length ? r.detections.map(d =>
        `<div class="card" style="padding:12px;"><div class="flex">${sevBadge(d.severity)} <span class="small">${esc(d.rule)}</span></div><p class="small" style="margin-top:6px;">${esc(d.description)}</p>${d.source_ip ? `<p class="faint mono small">source: ${esc(d.source_ip)}</p>` : ""}</div>`).join("") : "<div class='card' style='padding:12px'><p class='muted'>No detections fired.</p></div>";
    } catch (e) { toast(e.message, "err"); }
    document.getElementById("log-status").textContent = "";
  };
  document.getElementById("analyze").onclick = run;
  document.getElementById("run-det").onclick = run;
};

/* ================================================================
   EVENTS
   ================================================================ */
window.PAGES.events = async function (el) {
  el.innerHTML = `
    <div class="card">
      <div class="form-row">
        ${selectField("f-sev", "Severity", ["", ...SEVS], "")}
        ${selectField("f-cat", "Category", ["", "authentication", "network", "detection", "service", "security", "system", "scan"], "")}
        ${selectField("f-status", "Status", ["", "NEW", "ACKNOWLEDGED", "CLOSED", "FALSE_POSITIVE"], "")}
        ${field("f-ip", "Source IP", "")}
        ${field("f-user", "Username", "")}
      </div>
      <div class="flex" style="margin-top:12px;">
        <input id="f-q" placeholder="Search description / type…" style="max-width:280px;">
        <button class="primary" id="apply-f"><i class="fa-solid fa-filter"></i> Filter</button>
        <button id="csv-btn"><i class="fa-solid fa-download"></i> Export CSV</button>
      </div>
    </div>
    <div class="card"><div class="table-wrap" id="ev-tbl"><div class="muted">Loading…</div><div id="ev-pager" class="pager"></div></div></div>`;

  let page = 1;
  const listEvents = async (p = 1) => {
    page = p;
    const params = new URLSearchParams({ page, page_size: 25 });
    if (val("f-sev")) params.set("severity", val("f-sev"));
    if (val("f-cat")) params.set("category", val("f-cat"));
    if (val("f-status")) params.set("status", val("f-status"));
    if (val("f-ip")) params.set("source_ip", val("f-ip"));
    if (val("f-user")) params.set("username", val("f-user"));
    if (val("f-q")) params.set("q", val("f-q"));
    const r = await getJSON("/events?" + params.toString());
    document.getElementById("ev-tbl").innerHTML =
      `<table class="data"><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Type</th><th>Source IP</th><th>User</th><th>Status</th><th>Description</th><th></th></tr></thead><tbody>
      ${r.items.map(e => `<tr>
        <td class="mono">${fmtTime(e.timestamp)}</td><td>${sevBadge(e.severity)}</td>
        <td><span class="badge">${esc(e.category)}</span></td><td>${esc(e.event_type)}</td>
        <td class="mono">${esc(e.source_ip || "-")}</td><td>${esc(e.username || "-")}</td>
        <td>${statusBadge(e.status)}</td>
        <td class="clamp" title="${esc(e.description)}">${esc(e.description)}</td>
        <td><button class="view-ev" data-id="${e.id}"><i class="fa-solid fa-eye"></i></button></td></tr>`).join("")}</tbody></table>`;
    const pager = document.getElementById("ev-pager");
    pager.innerHTML = `<span>${r.total} events</span>
      <button ${page <= 1 ? "disabled" : ""} id="pg-prev">‹ Prev</button>
      <span>page ${page} / ${Math.max(1, Math.ceil(r.total / 25))}</span>
      <button ${page * 25 >= r.total ? "disabled" : ""} id="pg-next">Next ›</button>`;
    if (r.total > 0) {
      document.getElementById("pg-prev").onclick = () => listEvents(page - 1);
      document.getElementById("pg-next").onclick = () => listEvents(page + 1);
    }
    el.querySelectorAll(".view-ev").forEach(b => b.onclick = () => openEvent(b.dataset.id, () => listEvents(page)));
  };
  await listEvents();
  document.getElementById("apply-f").onclick = () => listEvents(1);
  document.getElementById("csv-btn").onclick = async () => {
    const resp = await fetch(API + "/events/export/csv", { headers: { "Authorization": "Bearer " + TOKEN } });
    if (!resp.ok) { toast("Export failed", "err"); return; }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "security_events.csv"; a.click();
    URL.revokeObjectURL(url);
  };
};

async function openEvent(id, after) {
  const e = await getJSON("/events/" + id);
  const m = modal("Security Event", `
    <div class="grid cols-2 small">
      <div><span class="faint">Timestamp</span><p class="mono">${fmtTime(e.timestamp)}</p></div>
      <div><span class="faint">Severity</span><p>${sevBadge(e.severity)}</p></div>
      <div><span class="faint">Type</span><p>${esc(e.event_type)}</p></div>
      <div><span class="faint">Category</span><p>${esc(e.category)}</p></div>
      <div><span class="faint">Source IP</span><p class="mono">${esc(e.source_ip || "-")}</p></div>
      <div><span class="faint">Username</span><p>${esc(e.username || "-")}</p></div>
      <div><span class="faint">Source</span><p>${esc(e.source)}</p></div>
      <div><span class="faint">Status</span><p>${statusBadge(e.status)}</p></div>
    </div>
    <div class="sep"></div>
    <p class="small">${esc(e.description)}</p>
    ${e.raw_event ? `<div class="sep"></div><pre class="log">${esc(e.raw_event)}</pre>` : ""}
    <div class="sep"></div>
    ${selectField("ev-status", "Update status", ["NEW", "ACKNOWLEDGED", "CLOSED", "FALSE_POSITIVE"], e.status)}`,
    can("events:write") ? `<button class="primary" id="ev-save">Save status</button>` : "");
  const save = m.querySelector("#ev-save");
  if (save) save.onclick = async () => {
    try { await patchJSON(`/events/${id}/status`, { status: val("ev-status") }); toast("Status updated", "ok"); m.remove(); after && after(); }
    catch (err) { toast(err.message, "err"); }
  };
}

/* ================================================================
   WAZUH
   ================================================================ */
window.PAGES.wazuh = async function (el) {
  el.innerHTML = `<div class="flex" style="margin-bottom:14px;"><span class="pill"><span class="dot"></span><span id="waz-pill">Checking…</span></span>
    <button id="waz-refresh" class="right"><i class="fa-solid fa-rotate"></i> Refresh</button></div>
    <div class="grid cols-2">
      <div class="card"><h3>Agents</h3><div id="waz-agents" class="table-wrap"></div></div>
      <div class="card"><h3>Alerts (mirrored)</h3><div id="waz-alerts" class="table-wrap"></div></div>
    </div>`;
  const loadWaz = async () => {
    let st;
    try { st = await getJSON("/wazuh/status"); } catch (e) { st = { connected: false, status: "OFFLINE", reason: e.message }; }
    document.getElementById("waz-pill").textContent = "Wazuh: " + (st.connected ? "CONNECTED" : "OFFLINE");
    document.querySelector("#waz-pill").parentElement.querySelector(".dot").className = "dot " + (st.connected ? "ok" : "bad");
    try {
      const agents = await getJSON("/wazuh/agents");
      document.getElementById("waz-agents").innerHTML = agents.length ? `<table class="data"><thead><tr><th>ID</th><th>Name</th><th>IP</th><th>OS</th><th>Status</th></tr></thead><tbody>
        ${agents.map(a => `<tr><td class="mono">${esc(a.id)}</td><td>${esc(a.name)}</td><td class="mono">${esc(a.ip || "-")}</td><td>${esc(a.os || "-")}</td><td>${statusBadge((a.status || "unknown").toUpperCase())}</td></tr>`).join("")}</tbody></table>`
        : `<p class="muted">${st.connected ? "No agents." : "Wazuh unavailable — no agent data. MlinziOps continues to operate."}</p>`;
    } catch (e) { document.getElementById("waz-agents").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
    try {
      const alerts = await getJSON("/wazuh/alerts");
      document.getElementById("waz-alerts").innerHTML = alerts.length ? `<table class="data"><thead><tr><th>Time</th><th>Rule</th><th>Level</th><th>Agent</th><th>Src IP</th><th>Description</th></tr></thead><tbody>
        ${alerts.map(a => `<tr><td class="mono">${fmtTime(a.timestamp)}</td><td class="mono">${esc(a.rule_id || "-")}</td><td>${a.level ?? "-"}</td><td>${esc(a.agent_name || "-")}</td><td class="mono">${esc(a.srcip || "-")}</td><td class="clamp" title="${esc(a.rule_description || "")}">${esc(a.rule_description || "")}</td></tr>`).join("")}</tbody></table>`
        : `<p class="muted">${st.connected ? "No alerts." : "Wazuh unavailable — no alerts. Nothing is fabricated."}</p>`;
    } catch (e) { document.getElementById("waz-alerts").innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
  };
  await loadWaz();
  document.getElementById("waz-refresh").onclick = loadWaz;
};

/* ================================================================
   INCIDENTS
   ================================================================ */
window.PAGES.incidents = async function (el, seg) {
  if (seg[1]) return incidentDetail(el, seg[1]);
  el.innerHTML = `
    <div class="flex" style="margin-bottom:14px;">
      ${selectField("inc-status", "Status", ["", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"], "")}
      ${selectField("inc-sev", "Severity", ["", ...SEVS], "")}
      ${can("incidents:write") ? `<button class="primary right" id="new-inc"><i class="fa-solid fa-plus"></i> New Incident</button>` : ""}
    </div>
    <div class="card"><div class="table-wrap" id="inc-tbl"><div class="muted">Loading…</div></div></div>`;
  const list = async () => {
    const p = new URLSearchParams();
    if (val("inc-status")) p.set("status_filter", val("inc-status"));
    if (val("inc-sev")) p.set("severity", val("inc-sev"));
    const incs = await getJSON("/incidents?" + p.toString());
    document.getElementById("inc-tbl").innerHTML =
      `<table class="data"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Source</th><th>Assignee</th><th>Created</th></tr></thead><tbody>
      ${incs.map(i => `<tr><td class="mono"><a href="#/incidents/${i.id}">${esc(i.incident_number)}</a></td>
        <td>${esc(i.title)}</td><td>${sevBadge(i.severity)}</td><td>${statusBadge(i.status)}</td>
        <td>${esc(i.source || "-")}</td><td>${esc(i.assigned_to || "-")}</td><td class="mono">${fmtTime(i.created_at)}</td></tr>`).join("")}</tbody></table>`;
  };
  await list();
  document.getElementById("inc-status").onchange = list;
  document.getElementById("inc-sev").onchange = list;
  const nb = document.getElementById("new-inc");
  if (nb) nb.onclick = () => openIncidentModal(list);
};

function openIncidentModal(after) {
  const m = modal("Create Incident", `
    ${field("i-title", "Title", "", "e.g. Brute-force heuristic on 192.168.187.107")}
    <label>Description</label><textarea id="i-desc"></textarea>
    ${selectField("i-sev", "Severity", SEVS, "MEDIUM")}
    ${selectField("i-status", "Status", ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"], "OPEN")}
    ${field("i-source", "Source (e.g. detection-engine, analyst)", "")}
    ${field("i-assign", "Assigned to", "")}
    ${field("i-evids", "Event IDs to attach (comma separated)", "")}`,
    `<button class="primary" id="i-save">Create</button>`);
  m.querySelector("#i-save").onclick = async () => {
    const event_ids = val("i-evids").split(",").map(x => parseInt(x.trim())).filter(x => !isNaN(x));
    try {
      const r = await postJSON("/incidents", { title: val("i-title"), description: val("i-desc"),
        severity: val("i-sev"), status: val("i-status"), source: val("i-source") || null,
        assigned_to: val("i-assign") || null, event_ids });
      toast(`Created ${r.incident_number}`, "ok"); m.remove(); after && after();
      navigate("incidents/" + r.id);
    } catch (e) { toast(e.message, "err"); }
  };
}

async function incidentDetail(el, id) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  const render = async () => {
    try {
      const i = await getJSON("/incidents/" + id);
      const tl = await getJSON(`/incidents/${id}/timeline`);
      el.innerHTML = `<a href="#/incidents" class="faint small"><i class="fa-solid fa-arrow-left"></i> Back to incidents</a>
        <div class="card" style="margin-top:10px;">
          <div class="flex"><h3 style="margin:0;"><span class="mono faint">${esc(i.incident_number)}</span> ${esc(i.title)}</h3>
            <span class="right">${sevBadge(i.severity)} ${statusBadge(i.status)}</span></div>
          <div class="grid cols-3 small" style="margin-top:10px;">
            <div><span class="faint">Source</span><p>${esc(i.source || "-")}</p></div>
            <div><span class="faint">Assigned to</span><p>${esc(i.assigned_to || "-")}</p></div>
            <div><span class="faint">Created</span><p class="mono">${fmtTime(i.created_at)}</p></div>
          </div>
          <p class="small" style="margin-top:8px;">${esc(i.description || "(no description)")}</p>
          ${can("incidents:write") ? `<div class="sep"></div>
            <div class="flex">
              ${selectField("d-status", "Change status", ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"], i.status)}
              <button class="primary" id="d-status-btn">Update</button>
              <input id="d-note" placeholder="Add investigation note…" style="flex:2;">
              <button id="d-note-btn"><i class="fa-solid fa-plus"></i> Add Note</button>
            </div>` : ""}
        </div>
        <div class="grid cols-2">
          <div class="card"><h3>Timeline</h3><div class="timeline" id="timeline"></div></div>
          <div class="card"><h3>Attached Evidence (Events)</h3><div id="evidence" class="table-wrap"></div></div>
        </div>`;
      document.getElementById("timeline").innerHTML = tl.length ? tl.map(t =>
        `<div class="item"><div class="ts">${fmtTime(t.timestamp)}</div>
          ${t.kind === "event" ? `${sevBadge(t.severity)} ` : `<span class="badge st-ACKNOWLEDGED">NOTE</span> `}
          <span class="small">${esc(t.text)}</span>${t.source_ip ? ` <span class="faint mono small">← ${esc(t.source_ip)}</span>` : ""}</div>`).join("")
        : "<p class='muted'>Timeline empty. Attach events or add notes.</p>";
      document.getElementById("evidence").innerHTML = i.events.length ? `<table class="data"><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>IP</th></tr></thead><tbody>
        ${i.events.map(e => `<tr><td class="mono">${fmtTime(e.timestamp)}</td><td>${esc(e.event_type)}</td><td>${sevBadge(e.severity)}</td><td class="mono">${esc(e.source_ip || "-")}</td></tr>`).join("")}</tbody></table>` : "<p class='muted'>No events attached. Link events from the Security Events page.</p>";
      const sb = document.getElementById("d-status-btn");
      if (sb) sb.onclick = async () => {
        try { await putJSON(`/incidents/${id}`, { status: val("d-status") }); toast("Status updated", "ok"); render(); }
        catch (e) { toast(e.message, "err"); }
      };
      const nb = document.getElementById("d-note-btn");
      if (nb) nb.onclick = async () => {
        try { await postJSON(`/incidents/${id}/notes`, { note: val("d-note") }); toast("Note added", "ok"); render(); }
        catch (e) { toast(e.message, "err"); }
      };
    } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
  };
  await render();
}

/* ================================================================
   VULNERABILITIES
   ================================================================ */
window.PAGES.vulnerabilities = async function (el) {
  el.innerHTML = `
    <div class="flex" style="margin-bottom:14px;">
      ${selectField("v-status", "Status", ["", "OPEN", "INVESTIGATING", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE"], "")}
      ${selectField("v-sev", "Severity", ["", ...SEVS], "")}
      ${can("vulnerabilities:write") ? `<button class="primary right" id="v-add"><i class="fa-solid fa-plus"></i> Add Finding</button>` : ""}
    </div>
    <div class="card"><div class="table-wrap" id="v-tbl"><div class="muted">Loading…</div></div></div>`;
  const list = async () => {
    const p = new URLSearchParams();
    if (val("v-status")) p.set("status", val("v-status"));
    if (val("v-sev")) p.set("severity", val("v-sev"));
    const vulns = await getJSON("/vulnerabilities?" + p.toString());
    document.getElementById("v-tbl").innerHTML =
      `<table class="data"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th><th>Status</th><th></th></tr></thead><tbody>
      ${vulns.map(v => `<tr>
        <td class="mono">${esc(v.host)}</td><td class="mono">${v.port ?? "-"}</td><td>${esc(v.service || "-")}</td>
        <td>${esc(v.software || "-")}</td><td class="mono small">${esc(v.version || "-")}</td>
        <td class="mono small">${esc(v.cve || "-")}</td><td>${sevBadge(v.severity)}</td><td>${statusBadge(v.status)}</td>
        <td>${can("vulnerabilities:write") ? `<button class="v-edit" data-id="${v.id}"><i class="fa-solid fa-pen"></i></button>` : ""}</td></tr>`).join("")}</tbody></table>`;
    el.querySelectorAll(".v-edit").forEach(b => b.onclick = () => openVulnModal(vulns.find(x => x.id == b.dataset.id), list));
  };
  await list();
  document.getElementById("v-status").onchange = list;
  document.getElementById("v-sev").onchange = list;
  const ab = document.getElementById("v-add");
  if (ab) ab.onclick = () => openVulnModal(null, list);
};

function openVulnModal(v, after) {
  const m = modal(v ? "Update Finding" : "Add Potential Vulnerability", `
    ${field("v-host", "Host (IP)", v ? v.host : "")}
    ${field("v-port", "Port", v ? v.port : "")}
    ${field("v-service", "Service", v ? v.service : "")}
    ${field("v-software", "Software", v ? v.software : "")}
    ${field("v-version", "Version", v ? v.version : "")}
    ${field("v-cve", "CVE (optional)", v ? v.cve : "")}
    ${selectField("v-sev2", "Severity", SEVS, v ? v.severity : "MEDIUM")}
    ${selectField("v-status2", "Status", ["OPEN", "INVESTIGATING", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE"], v ? v.status : "OPEN")}
    <label>Description</label><textarea id="v-desc">${esc(v ? v.description : "")}</textarea>
    <label>Recommendation</label><textarea id="v-rec">${esc(v ? v.recommendation : "")}</textarea>
    <p class="faint small">Version/CVE matches are <b>potential</b> findings — validate before treating as confirmed.</p>`,
    `<button class="primary" id="v-save">Save</button>`);
  m.querySelector("#v-save").onclick = async () => {
    const body = { host: val("v-host"), port: parseInt(val("v-port")) || null, service: val("v-service") || null,
      software: val("v-software") || null, version: val("v-version") || null, cve: val("v-cve") || null,
      severity: val("v-sev2"), status: val("v-status2"), description: val("v-desc") || null, recommendation: val("v-rec") || null };
    try {
      if (v) await patchJSON(`/vulnerabilities/${v.id}`, body); else await postJSON("/vulnerabilities", body);
      toast("Saved", "ok"); m.remove(); after && after();
    } catch (e) { toast(e.message, "err"); }
  };
}

/* ================================================================
   REPORTS
   ================================================================ */
window.PAGES.reports = async function (el) {
  el.innerHTML = `
    <div class="grid cols-2">
      ${can("reports:write") ? `<div class="card">
        <h3><i class="fa-solid fa-file-circle-plus"></i> Generate Assessment Report</h3>
        ${field("r-title", "Title", "", "Lab Security Assessment")}
        <label>Scope</label><textarea id="r-scope" placeholder="e.g. Ubuntu lab server 192.168.187.108 + Kali 192.168.187.107"></textarea>
        <label>Executive summary notes</label><textarea id="r-summary"></textarea>
        <div class="sep"></div>
        <button class="primary" id="r-gen"><i class="fa-solid fa-wand-magic-sparkles"></i> Generate PDF Report</button>
      </div>` : ""}
      <div class="card"><h3><i class="fa-solid fa-folder-open"></i> Reports</h3><div id="r-list" class="table-wrap"></div></div>
    </div>`;
  const list = async () => {
    const reports = await getJSON("/reports");
    document.getElementById("r-list").innerHTML =
      `<table class="data"><thead><tr><th>ID</th><th>Title</th><th>Analyst</th><th>Created</th><th></th></tr></thead><tbody>
      ${reports.map(r => `<tr><td class="mono">${esc(r.report_number)}</td><td>${esc(r.title)}</td>
        <td>${esc(r.created_by_name || "-")}</td><td class="mono">${fmtTime(r.created_at)}</td>
        <td class="flex" style="gap:6px;justify-content:flex-end;">
          <a class="btn small" href="${API}/reports/${r.id}/preview" target="_blank" title="Preview"><i class="fa-solid fa-eye"></i></a>
          <a class="btn small" href="${API}/reports/${r.id}/pdf" onclick="return dlReport(this)" title="Download PDF"><i class="fa-solid fa-download"></i></a>
        </td></tr>`).join("")}</tbody></table>`;
  };
  window.dlReport = async function (a) {
    try {
      const resp = await fetch(a.href, { headers: { "Authorization": "Bearer " + TOKEN } });
      if (!resp.ok) throw new Error("Download failed");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const tmp = document.createElement("a"); tmp.href = url;
      tmp.download = "report.pdf"; tmp.click(); URL.revokeObjectURL(url);
    } catch (e) { toast(e.message, "err"); }
    return false;
  };
  await list();
  const gb = document.getElementById("r-gen");
  if (gb) gb.onclick = async () => {
    gb.disabled = true; gb.innerHTML = "<i class='fa-solid fa-spinner fa-spin'></i> Generating…";
    try {
      const r = await postJSON("/reports", { title: val("r-title") || "Security Assessment",
        scope: val("r-scope") || null, summary: val("r-summary") || null });
      toast(`Report ${r.report_number} generated`, "ok"); list();
      window.open(API + `/reports/${r.id}/preview`, "_blank");
    } catch (e) { toast(e.message, "err"); }
    gb.disabled = false; gb.innerHTML = "<i class='fa-solid fa-wand-magic-sparkles'></i> Generate PDF Report";
  };
};

/* ================================================================
   AUDIT
   ================================================================ */
window.PAGES.audit = async function (el) {
  if (!can("audit:view")) { el.innerHTML = '<div class="card"><p class="muted">Audit log is restricted to ADMIN.</p></div>'; return; }
  el.innerHTML = `
    <div class="card">
      <div class="form-row">
        ${field("a-user", "Username", "")}
        ${field("a-action", "Action contains", "")}
        <div></div>
        <button class="primary" id="a-f"><i class="fa-solid fa-filter"></i> Filter</button>
      </div>
    </div>
    <div class="card"><div class="table-wrap" id="a-tbl"><div class="muted">Loading…</div><div id="a-pager" class="pager"></div></div></div>`;
  let page = 1;
  const list = async (p = 1) => {
    page = p;
    const q = new URLSearchParams({ page: p, page_size: 25 });
    if (val("a-user")) q.set("username", val("a-user"));
    if (val("a-action")) q.set("action", val("a-action"));
    const r = await getJSON("/audit?" + q.toString());
    document.getElementById("a-tbl").innerHTML =
      `<table class="data"><thead><tr><th>Time</th><th>User</th><th>Role</th><th>Action</th><th>Resource</th><th>IP</th><th>Result</th></tr></thead><tbody>
      ${r.items.map(a => `<tr><td class="mono">${fmtTime(a.timestamp)}</td><td>${esc(a.username || "-")}</td>
        <td>${a.role ? `<span class="badge role-${esc(a.role)}">${esc(a.role)}</span>` : "-"}</td>
        <td>${esc(a.action)}</td><td>${esc(a.resource || "-")}</td><td class="mono">${esc(a.ip_address || "-")}</td>
        <td><span class="badge ${a.result === "SUCCESS" ? "st-COMPLETED" : a.result === "DENIED" ? "st-FAILED" : ""}">${esc(a.result)}</span></td></tr>`).join("")}</tbody></table>`;
    document.getElementById("a-pager").innerHTML = `<span>${r.total} entries</span>
      <button ${page <= 1 ? "disabled" : ""} id="a-prev">‹ Prev</button>
      <span>page ${page}</span>
      <button ${page * 25 >= r.total ? "disabled" : ""} id="a-next">Next ›</button>`;
    if (r.total) {
      document.getElementById("a-prev").onclick = () => list(page - 1);
      document.getElementById("a-next").onclick = () => list(page + 1);
    }
  };
  await list();
  document.getElementById("a-f").onclick = () => list(1);
};

/* ================================================================
   SETTINGS
   ================================================================ */
window.PAGES.settings = async function (el) {
  const tabs = [
    ["operational", "Application"],
    ["security", "Security", can("settings:write")],
    ["hardening", "Hardening Checks"],
    ["users", "Users", can("users:write")],
  ].filter(t => t[2] !== false).map(t => `<a href="#" class="stab" data-tab="${t[0]}">${t[1]}</a>`).join("");
  el.innerHTML = `<div class="nav-tabs">${tabs}</div><div id="s-body"></div>`;
  const show = async (tab) => {
    el.querySelectorAll(".stab").forEach(a => a.classList.toggle("active", a.dataset.tab === tab));
    const body = document.getElementById("s-body");
    if (tab === "operational") return showOperational(body);
    if (tab === "security") return showSecurity(body);
    if (tab === "hardening") return showHardening(body);
    if (tab === "users") return showUsers(body);
  };
  el.querySelectorAll(".stab").forEach(a => a.onclick = (e) => { e.preventDefault(); show(a.dataset.tab); });
  show("operational");
};

async function showOperational(el) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  try {
    const r = await getJSON("/settings");
    const s = r.settings;
    const rows = Object.keys(s).map(k => `
      <div class="card" style="padding:14px;">
        <div class="flex" style="justify-content:space-between;"><div><b>${esc(k)}</b><p class="faint small" style="margin:2px 0 0;">${esc(s[k].description || "")}</p></div></div>
        <textarea id="set-${esc(k)}" style="margin-top:8px;" ${r.can_write ? "" : "disabled"}>${esc(JSON.stringify(s[k].value, null, 1))}</textarea>
        ${r.can_write ? `<button class="save-set" data-key="${esc(k)}" style="margin-top:8px;">Save</button>` : ""}
      </div>`).join("");
    el.innerHTML = `<p class="faint small">Values are JSON arrays/objects. Only ADMIN can modify settings. Secrets (Wazuh password, SECRET_KEY) are managed via environment variables only.</p>` + rows;
    if (r.can_write) el.querySelectorAll(".save-set").forEach(b => b.onclick = async () => {
      let v; try { v = JSON.parse(document.getElementById("set-" + b.dataset.key).value); }
      catch (e) { toast("Invalid JSON: " + e.message, "err"); return; }
      try { await putJSON("/settings/" + b.dataset.key, { value: v }); toast("Saved", "ok"); }
      catch (e) { toast(e.message, "err"); }
    });
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

async function showSecurity(el) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  try {
    const s = await getJSON("/settings/security");
    el.innerHTML = `<div class="card"><h3>Security configuration</h3>
      <table class="data"><tbody>
        <tr><th>Environment</th><td>${esc(s.app.env)}</td></tr>
        <tr><th>SECRET_KEY set</th><td>${s.app.secret_key_set ? "✔ configured" : "<span style='color:#f87171'>✘ CHANGE_ME — set it in .env!</span>"}</td></tr>
        <tr><th>Authorized CIDRs</th><td class="mono">${esc(s.authorized_cidrs.join(", "))}</td></tr>
        <tr><th>auth.log</th><td class="mono">${esc(s.log_sources.auth)}</td></tr>
        <tr><th>syslog</th><td class="mono">${esc(s.log_sources.syslog)}</td></tr>
        <tr><th>Nmap available</th><td>${s.nmap.available ? "✔" : "✘"}</td></tr>
        <tr><th>Wazuh configured</th><td>${s.wazuh.configured ? "✔" : "✘ (OFFLINE — set WAZUH_* in .env)"}</td></tr>
        <tr><th>Login rate limit</th><td>${s.rate_limit.login_max} attempts / ${s.rate_limit.window_seconds}s</td></tr>
      </tbody></table>
      <p class="faint small" style="margin-top:10px;">Secret values are never displayed or editable here. Change them in <code>.env</code> and restart.</p></div>`;
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

async function showHardening(el) {
  el.innerHTML = '<div class="muted">Running read-only checks…</div>';
  try {
    const r = await getJSON("/settings/hardening");
    const chips = `<div class="flex" style="margin-bottom:14px;">
      ${r.summary.PASS ? `<span class="badge chk-PASS">${r.summary.PASS} PASS</span>` : ""}
      ${r.summary.WARNING ? `<span class="badge chk-WARNING">${r.summary.WARNING} WARNING</span>` : ""}
      ${r.summary.FAIL ? `<span class="badge chk-FAIL">${r.summary.FAIL} FAIL</span>` : ""}
      ${r.summary.INFO ? `<span class="badge chk-INFO">${r.summary.INFO} INFO</span>` : ""}
    </div>`;
    el.innerHTML = chips + `<div class="card"><div class="table-wrap"><table class="data"><thead><tr><th>Result</th><th>Check</th><th>Detail</th><th>Remediation</th></tr></thead><tbody>
      ${r.checks.map(c => `<tr><td>${chkBadge(c.status)}</td><td>${esc(c.title)}</td><td class="small">${esc(c.detail)}</td><td class="small muted">${esc(c.remediation)}</td></tr>`).join("")}</tbody></table></div>
      <p class="faint small" style="margin-top:10px;">Checks are read-only — MlinziOps never modifies your system configuration.</p></div>`;
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

async function showUsers(el) {
  el.innerHTML = '<div class="muted">Loading…</div>';
  try {
    const users = await getJSON("/settings/users");
    let html = `<div class="flex" style="justify-content:flex-end;margin-bottom:12px;"><button class="primary" id="u-add"><i class="fa-solid fa-user-plus"></i> Add User</button></div>
      <div class="card"><div class="table-wrap"><table class="data"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Active</th><th>Last login</th><th>Failed</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td class="mono">${esc(u.username)}</td><td>${esc(u.email)}</td>
        <td><span class="badge role-${esc(u.role)}">${esc(u.role)}</span></td>
        <td>${u.is_active ? "✔" : "✘"}</td><td class="mono">${fmtAgo(u.last_login)}</td>
        <td class="mono">${u.failed_login_attempts}${u.locked_until ? " 🔒" : ""}</td>
        <td class="flex" style="gap:6px;justify-content:flex-end;">
          <button class="u-toggle" data-id="${u.id}" data-active="${u.is_active}">${u.is_active ? "Disable" : "Enable"}</button></td></tr>`).join("")}</tbody></table></div></div>`;
    el.innerHTML = html;
    document.getElementById("u-add").onclick = () => {
      const m = modal("Add User", `
        ${field("nu-user", "Username", "")}${field("nu-email", "Email", "")}
        ${field("nu-pass", "Password (min 12 chars)", "", "")}
        ${selectField("nu-role", "Role", ["VIEWER", "ANALYST", "ADMIN"], "VIEWER")}`,
        `<button class="primary" id="nu-save">Create</button>`);
      m.querySelector("#nu-save").onclick = async () => {
        try {
          await postJSON("/settings/users", { username: val("nu-user"), email: val("nu-email"), password: val("nu-pass"), role: val("nu-role") });
          toast("User created", "ok"); m.remove(); showUsers(el);
        } catch (e) { toast(e.message, "err"); }
      };
    };
    el.querySelectorAll(".u-toggle").forEach(b => b.onclick = async () => {
      const enable = b.dataset.active === "true";
      try { await patchJSON(`/settings/users/${b.dataset.id}`, { is_active: !enable }); toast("Updated", "ok"); showUsers(el); }
      catch (e) { toast(e.message, "err"); }
    });
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
}

/* ================================================================
   PROFILE
   ================================================================ */
window.PAGES.profile = async function (el) {
  const me = ME;
  el.innerHTML = `<div class="card"><h3>Profile</h3>
    <table class="data"><tbody>
      <tr><th>Username</th><td class="mono">${esc(me.username)}</td></tr>
      <tr><th>Email</th><td>${esc(me.email)}</td></tr>
      <tr><th>Role</th><td><span class="badge role-${esc(me.role)}">${esc(me.role)}</span></td></tr>
      <tr><th>Member since</th><td class="mono">${fmtTime(me.created_at)}</td></tr>
      <tr><th>Last login</th><td class="mono">${fmtTime(me.last_login)}</td></tr>
    </tbody></table></div>
    <div class="card"><h3>Change password</h3>
      ${field("cp-current", "Current password", "", "")}
      ${field("cp-new", "New password (min 12 chars)", "", "")}
      ${field("cp-confirm", "Confirm new password", "", "")}
      <div class="sep"></div><button class="primary" id="cp-btn">Change Password</button></div>`;
  document.getElementById("cp-btn").onclick = async () => {
    if (val("cp-new") !== val("cp-confirm")) { toast("Passwords do not match", "err"); return; }
    try { await postJSON("/auth/change-password", { current_password: val("cp-current"), new_password: val("cp-new") }); toast("Password changed", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };
};

/* ---------------- utils ---------------- */
function debounce(fn, ms) { let t; return function () { clearTimeout(t); t = setTimeout(fn, ms); }; }

/* ================================================================
   AI ANALYST  (MlinziOps AI)
   ================================================================ */
window.PAGES.ai = async function (el) {
  el.innerHTML = `<div class="muted">Loading AI status…</div>`;
  try {
    const [st, tools] = await Promise.all([
      getJSON("/ai").catch(() => null),
      getJSON("/ai/tools").catch(() => ({ tools: [] })),
    ]);
    const mode = st ? st.mode : "UNKNOWN";
    const stop = st ? st.emergency_stop : true;
    const online = st && st.status !== "DISABLED";
    el.innerHTML = `
      <div class="grid cols-4">
        <div class="card"><div class="small faint">AI Engine</div><div class="big">${esc(st ? st.status : "UNKNOWN")}</div></div>
        <div class="card"><div class="small faint">Autonomy Mode</div><div class="big">${esc(mode)}</div></div>
        <div class="card"><div class="small faint">Decisions</div><div class="big">${st ? st.decisions : "-"}</div></div>
        <div class="card"><div class="small faint">Pending Approvals</div><div class="big">${st ? st.pending_approvals : "-"}</div></div>
      </div>
      <div class="card ${stop ? "danger-border" : ""}" style="margin-top:14px;">
        <div class="flex" style="justify-content:space-between;align-items:center;">
          <div>
            <h3 style="margin:0;">Emergency Stop</h3>
            <p class="faint small" style="margin:2px 0 0;">${stop
              ? "ALL autonomous and non-read-only AI actions are blocked."
              : "Autonomous actions are PERMITTED within the current autonomy mode."}</p>
          </div>
          <button class="${stop ? "danger" : "ghost"}" id="ai-stop">${stop ? "🛑 STOP is ACTIVE" : "Engage STOP"}</button>
        </div>
      </div>
      ${can("settings:write") ? `
      <div class="card" style="margin-top:14px;">
        <h3 style="margin-top:0;">Autonomy Mode <span class="faint small">(ADMIN)</span></h3>
        <div class="flex" style="gap:8px;flex-wrap:wrap;" id="ai-modes"></div>
        <p class="faint small" style="margin-bottom:0;">
          OBSERVE: analysis only · ASSIST: proposals only · CONTROLLED_AUTONOMY: low-risk auto-actions ·
          EMERGENCY_LOCKDOWN: read-only investigation only
        </p>
      </div>` : ""}
      <div class="grid cols-2" style="margin-top:14px;">
        <div>
          <div class="card"><h3 style="margin-top:0;">Ask the Analyst</h3>
            <textarea id="ai-chat-in" placeholder="e.g. Summarize recent authentication anomalies" rows="3"></textarea>
            <div class="flex" style="justify-content:flex-end;margin-top:8px;"><button class="primary" id="ai-chat-btn"><i class="fa-solid fa-paper-plane"></i> Ask</button></div>
            <div id="ai-chat-out" class="muted small" style="margin-top:10px;white-space:pre-wrap;"></div>
          </div>
          <div class="card"><h3 style="margin-top:0;">Investigate an Incident</h3>
            <label>Incident ID</label><input id="ai-inc" type="number" min="1" placeholder="e.g. 1">
            <div class="flex" style="justify-content:flex-end;margin-top:8px;"><button class="primary" id="ai-inv-btn">Investigate</button></div>
            <div id="ai-inv-out" class="muted small" style="margin-top:10px;white-space:pre-wrap;"></div>
          </div>
        </div>
        <div class="card"><h3 style="margin-top:0;">Registered Tools (${tools.tools.length})</h3>
          <p class="faint small">The AI can only call registered tools — never the shell directly.</p>
          <div class="table-wrap"><table class="data"><thead><tr><th>Tool</th><th>Risk</th><th>Approval</th></tr></thead><tbody>
            ${tools.tools.map(t => `<tr><td class="mono">${esc(t.name)}</td>
              <td><span class="badge sev-${esc(t.risk_level.replace("_RISK","")).replace("READ_ONLY","LOW")}">${esc(t.risk_level)}</span></td>
              <td>${t.requires_approval ? "✔ required" : "—"}</td></tr>`).join("")}
          </tbody></table></div>
        </div>
      </div>
      <div class="card" style="margin-top:14px;"><h3 style="margin-top:0;">Recent Decisions</h3>
        <div id="ai-decisions" class="table-wrap"></div>
      </div>`;

    // Emergency stop toggle (ADMIN only via API; non-admin gets 403 toast)
    document.getElementById("ai-stop").onclick = async () => {
      try {
        const r = await postJSON("/ai/emergency-stop", { stop: !stop });
        toast("Emergency stop: " + (r.emergency_stop ? "ACTIVE" : "released"), "ok");
        PAGES.ai(el);
      } catch (e) { toast(e.message, "err"); }
    };

    if (can("settings:write")) {
      const modes = st ? st.modes || ["OBSERVE","ASSIST","CONTROLLED_AUTONOMY","EMERGENCY_LOCKDOWN"] : [];
      const mbox = document.getElementById("ai-modes");
      modes.forEach(m => {
        const b = document.createElement("button");
        b.className = m === mode ? "primary" : "ghost";
        b.textContent = m;
        b.onclick = async () => {
          try { await postJSON("/ai/autonomy", { mode: m }); toast("Mode set to " + m, "ok"); PAGES.ai(el); }
          catch (e) { toast(e.message, "err"); }
        };
        mbox.appendChild(b);
      });
    }

    document.getElementById("ai-chat-btn").onclick = async () => {
      const out = document.getElementById("ai-chat-out");
      out.textContent = "Thinking…";
      try {
        const r = await postJSON("/ai/chat", { message: val("ai-chat-in") });
        out.textContent = summarizeDecision(r);
      } catch (e) { out.textContent = "Error: " + e.message; }
    };

    document.getElementById("ai-inv-btn").onclick = async () => {
      const out = document.getElementById("ai-inv-out");
      out.textContent = "Investigating…";
      try {
        const r = await postJSON("/ai/investigate", { incident_id: Number(val("ai-inc")) });
        out.textContent = summarizeDecision(r);
        loadDecisions();
      } catch (e) { out.textContent = "Error: " + e.message; }
    };

    async function loadDecisions() {
      try {
        const r = await getJSON("/ai/decisions");
        const el2 = document.getElementById("ai-decisions");
        el2.innerHTML = r.decisions.length ? `<table class="data"><thead><tr><th>When</th><th>Kind</th><th>Sev</th><th>Conf</th><th>Summary</th><th>Action</th></tr></thead><tbody>
          ${r.decisions.map(d => `<tr><td class="mono">${fmtAgo(d.timestamp)}</td><td>${esc(d.kind)}</td>
            <td>${sevBadge(d.severity || "UNKNOWN")}</td><td>${Math.round((d.confidence || 0) * 100)}%</td>
            <td class="small">${esc(d.summary || "")}</td><td class="mono small">${esc(d.recommended_action || "-")}${d.approval_required ? " ⚠" : ""}</td></tr>`).join("")}</tbody></table>`
          : `<p class="muted">No decisions yet. Ask the analyst or run an investigation.</p>`;
      } catch (e) { /* ignore */ }
    }
    loadDecisions();
  } catch (e) {
    el.innerHTML = `<div class="card"><p class="muted">Could not load AI page: ${esc(e.message)}</p></div>`;
  }
};

function summarizeDecision(d) {
  const a = d.assessment || {};
  const act = d.action || {};
  const lines = [];
  if (a.summary) lines.push("Summary: " + a.summary);
  if (a.severity) lines.push("Severity: " + a.severity);
  if (a.confidence != null) lines.push("Confidence: " + Math.round(a.confidence * 100) + "%");
  if (a.observations && a.observations.length) lines.push("Observed: " + a.observations.join("; "));
  if (a.inferences && a.inferences.length) lines.push("Inferred: " + a.inferences.join("; "));
  if (a.unknowns && a.unknowns.length) lines.push("Unknown: " + a.unknowns.join("; "));
  if (act.type) lines.push("Action: " + act.type + (act.requires_approval ? " (requires human approval)" : ""));
  return lines.join("\n") || "(no assessment returned)";
}

/* ================================================================
   APPROVALS QUEUE
   ================================================================ */
window.PAGES.approvals = async function (el) {
  el.innerHTML = `<div class="muted">Loading approvals…</div>`;
  try {
    const r = await getJSON("/approvals");
    const items = r.approvals || [];
    const isApprover = ME && (ME.role === "ADMIN" || ME.role === "ANALYST");
    el.innerHTML = `<p class="faint small">Human approval is required before any MEDIUM/HIGH-risk AI action runs. Nothing executes automatically in "requires approval" workflows.</p>
      <div class="grid cols-3" style="margin-top:8px;">
        <div class="card"><div class="big">${r.pending}</div><div class="small faint">Pending</div></div>
        <div class="card"><div class="big">${items.filter(a => a.status === "APPROVED").length}</div><div class="small faint">Approved</div></div>
        <div class="card"><div class="big">${items.filter(a => a.status === "REJECTED").length}</div><div class="small faint">Rejected</div></div>
      </div>
      <div class="card" style="margin-top:14px;"><div class="table-wrap">
      ${items.length ? `<table class="data"><thead><tr><th>#</th><th>Status</th><th>Tool</th><th>Risk</th><th>Reason</th><th>Requested</th><th></th></tr></thead><tbody>
        ${items.map(a => `<tr>
          <td class="mono">#${a.id}</td>
          <td>${statusBadge(a.status)}</td>
          <td class="mono">${esc(a.action ? a.action.tool : "-")}</td>
          <td><span class="badge">${esc(a.action ? a.action.risk_level : "-")}</span></td>
          <td class="small">${esc(a.reason || "")}${a.confidence != null ? ` <span class="faint">(${Math.round(a.confidence * 100)}%)</span>` : ""}</td>
          <td class="mono">${fmtAgo(a.created_at)}</td>
          <td class="flex" style="gap:6px;justify-content:flex-end;">
            ${a.status === "PENDING" && isApprover ? `
              <button class="primary a-rev" data-id="${a.id}" data-approve="1"><i class="fa-solid fa-check"></i> Approve</button>
              <button class="danger a-rev" data-id="${a.id}" data-approve="0"><i class="fa-solid fa-xmark"></i> Reject</button>` :
              a.status === "PENDING" ? `<span class="faint small">ADMIN only</span>` :
              a.status === "APPROVED" && a.action && a.action.executed_at ? `<span class="small">Executed ${fmtAgo(a.action.executed_at)}</span>` : ""}
          </td></tr>`).join("")}</tbody></table>`
        : `<p class="muted">No approvals recorded yet.</p>`}
      </div></div>`;
    el.querySelectorAll(".a-rev").forEach(b => b.onclick = async () => {
      try {
        const r = await postJSON(`/approvals/${b.dataset.id}/review`, { approve: b.dataset.approve === "1" });
        toast("Approval " + r.status, b.dataset.approve === "1" ? "ok" : "info");
        if (r.status === "APPROVED" && r.execution && r.execution.executed === false) toast("Execution: " + (r.execution.reason || "failed"), "err");
        PAGES.approvals(el);
      } catch (e) { toast(e.message, "err"); }
    });
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
};

/* ================================================================
   PLAYBOOKS
   ================================================================ */
window.PAGES.playbooks = async function (el) {
  el.innerHTML = `<div class="muted">Loading playbooks…</div>`;
  try {
    const r = await getJSON("/playbooks");
    const allow = r.service_allowlist || [];
    el.innerHTML = `<p class="faint small">Playbooks are predefined remediation procedures with verification and rollback. Service names are restricted to an allowlist; activation always requires human approval.</p>
      <div class="card" style="margin-top:8px;"><div class="table-wrap">
      <table class="data"><thead><tr><th>Playbook</th><th>Risk</th><th>Kind</th><th>Description</th><th>Verification</th><th></th></tr></thead><tbody>
        ${r.playbooks.map(p => `<tr>
          <td class="mono">${esc(p.name)}</td>
          <td><span class="badge">${esc(p.risk_level)}</span></td>
          <td class="mono">${esc(p.kind)}</td>
          <td class="small">${esc(p.description || "")}</td>
          <td class="small mono">${esc(JSON.stringify(p.verification))}</td>
          <td>${can("settings:write") ? `<button class="primary p-act" data-name="${esc(p.name)}">Request Activation</button>` : `<span class="faint small">ADMIN only</span>`}</td>
        </tr>`).join("")}</tbody></table>
      </div></div>
      <div class="card" style="margin-top:14px;"><h3 style="margin-top:0;">Service allowlist</h3>
        <p class="mono small">${allow.map(esc).join(", ") || "(none)"}</p>
        <p class="faint small">Playbook actions can only restart services on this allowlist. Arbitrary commands are never accepted.</p>
      </div>`;
    el.querySelectorAll(".p-act").forEach(b => b.onclick = async () => {
      try {
        const r = await postJSON("/playbooks/activate", { playbook: b.dataset.name });
        toast("Approval requested (#" + r.approval_id + ")", "ok");
        navigate("approvals");
      } catch (e) { toast(e.message, "err"); }
    });
  } catch (e) { el.innerHTML = `<div class="card"><p class="muted">${esc(e.message)}</p></div>`; }
};
