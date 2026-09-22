/* =====================================================
   SecureOps — frontend application core
   Hash-based SPA router + API client + page renderers.
   ===================================================== */
"use strict";

const API = "/api";
let TOKEN = localStorage.getItem("secureops_token") || "";
let ME = null;

/* ---------------- state / permissions ---------------- */
const ROLE_PERMS = {
  ADMIN: ["hosts:write","scan:run","events:write","incidents:write","vulnerabilities:write","reports:write","settings:write","users:write","audit:view"],
  ANALYST: ["hosts:write","scan:run","events:write","incidents:write","vulnerabilities:write","reports:write"],
  VIEWER: [],
};
const can = (perm) => ME && (ME.role === "ADMIN" || (ROLE_PERMS[ME.role] || []).includes(perm));

/* ---------------- fetch helper ---------------- */
let _loggingOut = false;
async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  const resp = await fetch(API + path, Object.assign({ headers }, opts));
  if (resp.status === 401 && !path.startsWith("/auth/") && !_loggingOut) {
    _loggingOut = true;
    logout(true);
    throw new Error("Session expired");
  }
  let data = null;
  const ct = resp.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    data = await resp.json();
  } else {
    data = await resp.text();
  }
  if (!resp.ok) {
    const msg = (data && (data.detail || data.message)) || ("HTTP " + resp.status);
    throw new Error(msg);
  }
  return data;
}
const getJSON = (p) => api(p);
const postJSON = (p, body) => api(p, { method: "POST", body: JSON.stringify(body || {}) });
const putJSON = (p, body) => api(p, { method: "PUT", body: JSON.stringify(body || {}) });
const patchJSON = (p, body) => api(p, { method: "PATCH", body: JSON.stringify(body || {}) });
const delJSON = (p) => api(p, { method: "DELETE" });

/* ---------------- toasts ---------------- */
function toast(msg, kind = "info") {
  const wrap = document.getElementById("toasts");
  const el = document.createElement("div");
  el.className = "toast " + (kind === "ok" ? "ok" : kind === "err" ? "err" : "warn");
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

/* ---------------- helpers ---------------- */
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (s) => { if (!s) return "-"; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString(); };
const fmtAgo = (s) => { if (!s) return "-"; const d = new Date(s); const s2 = (Date.now() - d.getTime()) / 1000; if (s2 < 60) return Math.floor(s2) + "s ago"; if (s2 < 3600) return Math.floor(s2 / 60) + "m ago"; if (s2 < 86400) return Math.floor(s2 / 3600) + "h ago"; return Math.floor(s2 / 86400) + "d ago"; };
const sevBadge = (s) => `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
const statusBadge = (s) => `<span class="badge st-${esc(s)}">${esc(s)}</span>`;
const chkBadge = (s) => `<span class="badge chk-${esc(s)}">${esc(s)}</span>`;

/* ---------------- routing ---------------- */
const ROUTES = {
  "": "dashboard", "login": "login", "dashboard": "dashboard", "hosts": "hosts",
  "scanner": "scanner", "logs": "logs", "events": "events", "wazuh": "wazuh",
  "incidents": "incidents", "vulnerabilities": "vulnerabilities", "reports": "reports",
  "audit": "audit", "settings": "settings", "profile": "profile",
  "ai": "ai", "approvals": "approvals", "playbooks": "playbooks",
};

function route() {
  const hash = location.hash.replace(/^#\/?/, "");
  const seg = hash.split("/");
  const name = ROUTES[seg[0]] || "dashboard";
  if (name === "login") { renderLogin(); return; }
  if (!TOKEN) { location.hash = "#/login"; return; }
  renderShell(name, seg);
}

function navigate(path) { location.hash = "#/" + path; }

/* ---------------- shell ---------------- */
function renderShell(page, seg) {
  const nav = [
    { p: "dashboard", i: "fa-gauge-high", l: "Dashboard" },
    { p: "hosts", i: "fa-server", l: "Hosts" },
    { p: "scanner", i: "fa-radar", l: "Network Scanner" },
    { p: "logs", i: "fa-file-lines", l: "Log Analyzer" },
    { p: "events", i: "fa-shield-halved", l: "Security Events" },
    { p: "wazuh", i: "fa-network-wired", l: "Wazuh" },
    { p: "incidents", i: "fa-triangle-exclamation", l: "Incidents" },
    { p: "vulnerabilities", i: "fa-bug", l: "Vulnerabilities" },
    { p: "reports", i: "fa-file-pdf", l: "Reports" },
    { p: "audit", i: "fa-list-check", l: "Audit Log" },
    { p: "settings", i: "fa-gear", l: "Settings" },
  ];
  const aiNav = [
    { p: "ai", i: "fa-brain", l: "AI Analyst" },
    { p: "approvals", i: "fa-clipboard-check", l: "Approvals" },
    { p: "playbooks", i: "fa-screwdriver-wrench", l: "Playbooks" },
  ];
  const items = nav.filter(n => n.p !== "audit" || can("audit:view"))
    .map(n => `<a href="#/${n.p}" class="${n.p === page ? "active" : ""}"><i class="fa-solid ${n.i}"></i><span>${n.l}</span></a>`)
    .join("");
  const aiItems = aiNav
    .map(n => `<a href="#/${n.p}" class="${n.p === page ? "active" : ""}"><i class="fa-solid ${n.i}"></i><span>${n.l}</span></a>`)
    .join("");

  document.getElementById("app").innerHTML = `
    ${loginBanner()}
    <aside class="sidebar">
      <div class="brand"><span class="shield"><i class="fa-solid fa-shield-halved"></i></span>
        <span>SecureOps<span class="sub">SOC Console</span></span></div>
      <nav class="nav-group"><div class="label">Operations</div>${items}</nav>
      <nav class="nav-group"><div class="label">AI &amp; Automation</div>${aiItems}</nav>
      <div class="sidebar-foot">v2.0.0 · authorized lab use only</div>
    </aside>
    <div class="main">
      <div class="topbar">
        <div class="page-title">${pageTitle(page)}</div>
        <div class="spacer"></div>
        <span id="conn-pill" class="pill"><span class="dot"></span><span id="conn-label">…</span></span>
        <span class="clock" id="clock"></span>
        <div class="user-chip">
          <div class="avatar">${esc((ME.username || "?").slice(0, 1).toUpperCase())}</div>
          <div><div class="uname">${esc(ME.username)}</div><div class="urole badge role-${esc(ME.role)}">${esc(ME.role)}</div></div>
          <a href="#/profile" title="Profile"><i class="fa-solid fa-user-gear muted"></i></a>
          <a href="#" title="Logout" id="logout-btn"><i class="fa-solid fa-right-from-bracket muted"></i></a>
        </div>
      </div>
      <div class="content" id="page">
        <div class="muted">Loading…</div>
      </div>
    </div>
    <div id="toasts"></div>`;

  document.getElementById("logout-btn").addEventListener("click", (e) => { e.preventDefault(); logout(); });
  startClock();
  startSSE();

  if (typeof load === "function") load(document.getElementById("page"), seg);
}

function loginBanner() { return ""; }

function pageTitle(p) {
  return { dashboard: "Dashboard", hosts: "Hosts", scanner: "Network Scanner", logs: "Log Analyzer",
    events: "Security Events", wazuh: "Wazuh Integration", incidents: "Incidents",
    vulnerabilities: "Vulnerabilities", reports: "Reports", audit: "Audit Log",
    settings: "Settings", profile: "Profile",
    ai: "AI Analyst", approvals: "Approval Queue", playbooks: "Playbooks" }[p] || "SecureOps";
}

/* ---------------- clock ---------------- */
function startClock() {
  const el = document.getElementById("clock");
  const tick = () => { if (el) el.textContent = new Date().toLocaleString() + " (local)"; };
  tick(); setInterval(tick, 1000);
}

/* ---------------- SSE ---------------- */
let _sse = null;
function startSSE() {
  if (_sse) return;
  _sse = new EventSource(API + "/stream");
  _sse.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type && d.type !== "heartbeat") {
        toast(`${seText(d)}`, "info");
        if (location.hash.replace("#/", "") === "dashboard" || !location.hash.replace("#/", "")) load(document.getElementById("page"), []);
      }
    } catch (_) {}
  };
  _sse.onerror = () => setConn(false);
  setConn(true);
}
function seText(d) {
  if (d.type === "scan_completed") return `Scan of ${d.target} completed — ${d.services} services`;
  if (d.type === "log_analysis") return `Log analysis: ${d.events} events, ${d.detections} detections`;
  return "New security event";
}
function setConn(ok) {
  const p = document.getElementById("conn-pill");
  if (!p) return;
  p.innerHTML = `<span class="dot ${ok ? "ok" : ""}"></span><span id="conn-label">${ok ? "LIVE" : "OFFLINE"}</span>`;
}

/* ---------------- auth ---------------- */
async function login(username, password) {
  const form = new URLSearchParams(); form.set("username", username); form.set("password", password);
  const resp = await fetch(API + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || "Login failed");
  TOKEN = data.access_token;
  ME = data.user;
  localStorage.setItem("secureops_token", TOKEN);
  localStorage.setItem("secureops_me", JSON.stringify(ME));
  location.hash = "#/dashboard";
  toast("Welcome, " + ME.username, "ok");
}

function logout(expired) {
  try { if (TOKEN) api("/auth/logout", { method: "POST" }); } catch (_) {}
  _loggingOut = false;
  TOKEN = ""; ME = null;
  localStorage.removeItem("secureops_token"); localStorage.removeItem("secureops_me");
  if (_sse) { _sse.close(); _sse = null; }
  location.hash = "#/login";
  if (expired) toast("Session expired", "warn");
}

function renderLogin() {
  document.getElementById("app").innerHTML = `
  <div class="login-wrap">
    <div class="login-card">
      <div class="brand" style="padding:0 0 14px; border:none;">
        <span class="shield"><i class="fa-solid fa-shield-halved"></i></span>
        <span>SecureOps<span class="sub">Security Operations</span></span>
      </div>
      <p class="muted small" style="margin-top:0;">Authorized security operations console. All activity is monitored and audited.</p>
      <label>Username</label>
      <input id="login-user" autocomplete="username" placeholder="admin">
      <label>Password</label>
      <input id="login-pass" type="password" autocomplete="current-password" placeholder="••••••••">
      <div class="sep"></div>
      <button class="primary" id="login-btn" style="width:100%; justify-content:center;">Sign in</button>
      <p id="login-err" class="small" style="color:#f87171; margin-top:10px; display:none;"></p>
      <p class="faint" style="font-size:11px; margin-top:14px;">Unauthorized access is prohibited. Sessions and actions are logged.</p>
    </div>
  </div>
  <div id="toasts"></div>`;
  const doLogin = async () => {
    const btn = document.getElementById("login-btn");
    btn.disabled = true; btn.textContent = "Authenticating…";
    const err = document.getElementById("login-err");
    err.style.display = "none";
    try {
      await login(document.getElementById("login-user").value.trim(),
                  document.getElementById("login-pass").value);
    } catch (e) {
      err.textContent = e.message; err.style.display = "block";
      btn.disabled = false; btn.textContent = "Sign in";
    }
  };
  document.getElementById("login-btn").addEventListener("click", doLogin);
  document.getElementById("login-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
  document.getElementById("login-user").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
}

/* ---------------- init ---------------- */
async function boot() {
  const t = localStorage.getItem("secureops_token");
  const m = localStorage.getItem("secureops_me");
  if (t) { TOKEN = t; ME = JSON.parse(m || "null"); }
  window.addEventListener("hashchange", route);
  if (!TOKEN) {
    if (location.hash.replace("#/", "") !== "login") location.hash = "#/login";
    else route();
    return;
  }
  if (!ME) {
    try {
      ME = await getJSON("/auth/me");
      localStorage.setItem("secureops_me", JSON.stringify(ME));
    } catch (e) {
      logout(false);
      return;
    }
  }
  route();
}

document.addEventListener("DOMContentLoaded", boot);

/* Page dispatcher — page implementations live in js/pages.js (window.PAGES). */
function load(el, seg) {
  const page = ROUTES[(location.hash.replace(/^#\/?/, "").split("/")[0])] || "dashboard";
  const fn = window.PAGES && window.PAGES[page];
  if (typeof fn === "function") {
    el.innerHTML = '<div class="muted">Loading…</div>';
    fn(el, seg || []);
  } else {
    el.innerHTML = '<div class="muted">Page not found.</div>';
  }
}
