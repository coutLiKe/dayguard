// DayGuard v0.3.2 — 7-panel build with HTML escaping.

const SECTIONS = [
  { label: "This Mac",         panels: ["macos", "network", "vpn", "disk", "apps"] },
  { label: "Out in the World", panels: ["domains", "cves"] },
];

const META = {
  macos:    { title: "macOS Security Posture", icon: "laptop" },
  network:  { title: "Home Network",           icon: "wifi" },
  vpn:      { title: "VPN & Tunnels",          icon: "lock" },
  disk:     { title: "Disk Space",             icon: "drive" },
  apps:     { title: "Recent App Changes",     icon: "package" },
  domains:  { title: "Domain & SSL Health",    icon: "globe" },
  cves:     { title: "Recent CVEs",            icon: "bug" },
};

// Inline monochrome SVG icons. stroke="currentColor" so they inherit color from
// the parent tile's CSS. Lucide-family line style, 1.75px stroke, rounded caps.
const _SVG = (paths) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;

const ICON = {
  laptop:    _SVG(`<rect x="3" y="5" width="18" height="12" rx="1.5"/><path d="M2 19h20"/>`),
  wifi:      _SVG(`<path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="0.6" fill="currentColor"/>`),
  lock:      _SVG(`<rect x="4" y="11" width="16" height="10" rx="1.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>`),
  drive:     _SVG(`<rect x="2" y="14" width="20" height="6" rx="1.5"/><path d="M4 14l3-9h10l3 9"/><circle cx="6.5" cy="17" r="0.6" fill="currentColor"/>`),
  package:   _SVG(`<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5"/><path d="M12 13v9"/>`),
  globe:     _SVG(`<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2c2.5 3 3.5 6 3.5 10s-1 7-3.5 10"/><path d="M12 2c-2.5 3-3.5 6-3.5 10s1 7 3.5 10"/>`),
  bug:       _SVG(`<path d="M8 7V5a4 4 0 0 1 8 0v2"/><rect x="6" y="7" width="12" height="13" rx="6"/><path d="M2 12h4M18 12h4M3 17l3-2M21 17l-3-2M3 7l3 2M21 7l-3 2"/>`),
  sparkles:  _SVG(`<path d="M10 3 11.5 7.5 16 9l-4.5 1.5L10 15 8.5 10.5 4 9l4.5-1.5z"/><path d="M18 14l.9 2.1L21 17l-2.1.9L18 20l-.9-2.1L15 17l2.1-.9z"/>`),
  check:     _SVG(`<circle cx="12" cy="12" r="10"/><path d="m8.5 12 2.5 2.5L15.5 10"/>`),
  alertTri:  _SVG(`<path d="M10.3 3.86a2 2 0 0 1 3.4 0l8.6 14.16a2 2 0 0 1-1.7 3H3.4a2 2 0 0 1-1.7-3z"/><line x1="12" y1="10" x2="12" y2="14"/><circle cx="12" cy="17.3" r="0.6" fill="currentColor"/>`),
  alertCir:  _SVG(`<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16.3" r="0.6" fill="currentColor"/>`),
  chevron:   _SVG(`<path d="m9 6 6 6-6 6"/>`),
};

function icon(name) { return ICON[name] || ""; }

const SEV_RANK = { ok: 0, warn: 1, critical: 2 };

// ---- escaping ----
const ESCAPE_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, ch => ESCAPE_MAP[ch]);
}

function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }); }
  catch { return esc(iso); }
}

function sevStyle(sev) {
  return ({
    ok: "background: var(--ok-bg); color: var(--ok-fg);",
    warn: "background: var(--warn-bg); color: var(--warn-fg);",
    critical: "background: var(--crit-bg); color: var(--crit-fg);",
  })[sev] || "background: var(--ok-bg); color: var(--ok-fg);";
}

const statusLabel = sev => ({ ok: "OK", warn: "Review", critical: "Action" }[sev] || "OK");

// ---- one-line summaries for each panel ----
function oneLiner(key, panel) {
  if (!panel) return "—";
  const items = panel.items || [];
  if (key === "macos") {
    const failing = items.filter(c => !c.ok).map(c => c.name);
    if (!failing.length) return "All security checks passing";
    return `${items.length - failing.length}/${items.length} passing · issues: ${failing.join(", ")}`;
  }
  if (key === "domains") {
    if (!items.length) return "No domains configured";
    const min = items.reduce((acc, d) => {
      const days = d.ssl?.days_left;
      return (days !== undefined && (acc === null || days < acc)) ? days : acc;
    }, null);
    const ok = items.filter(d => d.http?.status && d.http.status < 400).length;
    return `${ok}/${items.length} responding · soonest cert in ${min ?? "?"} days`;
  }
  if (key === "cves") {
    if (!items.length) return "No relevant CVEs in last 48h";
    const top = items[0];
    return `${items.length} relevant · highest CVSS ${top.score ?? "?"}`;
  }
  if (key === "network") {
    const stable = items.filter(d => !d.known && !d.randomized).length;
    const priv = items.filter(d => d.randomized).length;
    const parts = [`${items.length} device(s) on LAN`];
    if (stable) parts.push(`${stable} unidentified`);
    if (priv) parts.push(`${priv} private`);
    return parts.join(" · ");
  }
  return panel.message || "—";
}

// ---- per-panel detail renderers ----
function renderDetail(key, panel) {
  const items = panel.items || [];
  if (!items.length) {
    return `<div class="item"><span class="muted-3">${esc(panel.message || "No items.")}</span></div>`;
  }

  if (key === "macos") {
    const okMark   = `<span class="inline-icon" style="color:var(--ok-fg);">${icon("check")}</span>`;
    const failMark = `<span class="inline-icon" style="color:var(--crit-fg);">${icon("alertTri")}</span>`;
    return items.map(c => `
      <div class="item">
        <span>${c.ok ? okMark : failMark}${esc(c.name)}</span>
        <span class="muted-3 mono">${esc((c.detail || "").slice(0, 42))}</span>
      </div>`).join("");
  }
  if (key === "domains") {
    return items.map(d => {
      const ssl = d.ssl || {}, http = d.http || {};
      const sslText = ssl.days_left !== undefined ? `SSL ${ssl.days_left}d` : "SSL ?";
      const httpText = http.status ? `${http.status} · ${http.elapsed_ms}ms` : (http.error || "—");
      return `<div class="item">
        <span class="mono">${esc(d.domain)}</span>
        <span class="muted-3">${esc(sslText)} · ${esc(httpText)}</span>
      </div>`;
    }).join("");
  }
  if (key === "cves") {
    return items.map(c => {
      const cls = (c.score || 0) >= 9 ? "pill-critical" : (c.score || 0) >= 7 ? "pill-warn" : "pill-ok";
      const id = esc(c.id);
      const url = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id || "")}`;
      return `<div class="item" style="flex-direction:column; align-items:flex-start; gap:4px;">
        <div style="display:flex; width:100%; justify-content:space-between;">
          <a href="${url}" target="_blank" rel="noopener" class="mono">${id}</a>
          <span class="pill ${cls}">CVSS ${esc(c.score ?? "—")}</span>
        </div>
        <div class="muted-3" style="font-size:12px;">${esc(c.summary || "")}</div>
      </div>`;
    }).join("");
  }
  if (key === "network") {
    return items.map(d => {
      // Secondary line: IP, then whatever identifying detail we resolved.
      const bits = [esc(d.ip)];
      if (d.gateway) bits.push("router");
      if (d.vendor && d.name !== `${d.vendor} device`) bits.push(esc(d.vendor));
      if (d.randomized && !d.known) bits.push("randomized MAC");
      const sub = bits.join(" · ");
      return `<div class="item">
        <span>${esc(d.name)} <span class="muted-3 mono" style="margin-left:6px;">${sub}</span></span>
        <span class="pill ${d.known ? "pill-ok" : "pill-warn"}">${d.known ? "known" : "unknown"}</span>
      </div>`;
    }).join("");
  }
  if (key === "vpn") {
    return items.map(v => {
      if (v.error) return `<div class="item"><span class="pill pill-warn">error</span><span>${esc(v.error)}</span></div>`;
      const cls = v.connected ? "pill-ok" : "pill-warn";
      const sub = `${esc(v.type)}${v.ip ? " · " + esc(v.ip) : ""}`;
      return `<div class="item">
        <span>${esc(v.name)} <span class="muted-3 mono" style="margin-left:6px;">${sub}</span></span>
        <span class="pill ${cls}">${v.connected ? "connected" : "off"}</span>
      </div>`;
    }).join("");
  }
  if (key === "disk") {
    return items.map(i => `<div class="item"><span>${esc(i.label)}</span><span class="muted-3 mono">${esc(i.value)}</span></div>`).join("");
  }
  if (key === "apps") {
    return items.map(a => {
      const tag = a.signed === false ? `<span class="pill pill-warn">unsigned</span>` :
                  a.signed === true  ? `<span class="pill pill-ok">signed</span>` :
                                       `<span class="muted-3">?</span>`;
      return `<div class="item">
        <span>${esc(a.name)} <span class="muted-3" style="margin-left:6px;">${esc(a.modified_days_ago)}d ago</span></span>
        ${tag}
      </div>`;
    }).join("");
  }
  return `<pre class="mono muted">${esc(JSON.stringify(items, null, 2))}</pre>`;
}

// ---- top components ----
const BRIEF_LABEL = { morning: "Morning Brief", afternoon: "Afternoon Brief", evening: "Evening Brief" };

function renderBrief(brief) {
  if (!brief) return;
  const cached = brief.cached ? "Cached" : "Fresh";
  const label = BRIEF_LABEL[brief.period] || "Morning Brief";
  document.getElementById("brief").innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:14px;">
      <div class="icon-tile" style="width:36px;height:36px;background:var(--info-bg);color:var(--info-fg);">
        ${icon("sparkles")}
      </div>
      <div style="flex:1;">
        <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;margin-bottom:4px;">${esc(label)}</div>
        <div style="font-size:14px;line-height:1.55;">${esc(brief.text || brief.message || "—")}</div>
        <div style="font-size:11px;color:var(--text-3);margin-top:6px;">${esc(brief.model || "?")} · ${cached}</div>
      </div>
    </div>
  `;
}

function renderHero(panels) {
  const sevs = Object.values(panels).map(p => p.severity || "ok");
  const counts = { ok: 0, warn: 0, critical: 0 };
  sevs.forEach(s => counts[s]++);
  const overall = sevs.reduce((a, b) => SEV_RANK[b] > SEV_RANK[a] ? b : a, "ok");

  const heroIcon = { ok: icon("check"), warn: icon("alertTri"), critical: icon("alertCir") }[overall];
  const heroTitle = {
    ok: "Everything looks good",
    warn: counts.warn === 1 && counts.critical === 0 ? "1 thing needs attention" : `${counts.warn} things need attention`,
    critical: `${counts.critical} critical issue${counts.critical > 1 ? "s" : ""}`,
  }[overall];
  const heroSub = {
    ok: `All ${Object.keys(panels).length} panels report normal status.`,
    warn: "Open the highlighted sections below to review.",
    critical: "Address these as soon as you can.",
  }[overall];

  document.getElementById("hero").innerHTML = `
    <div style="display:flex; align-items:center; justify-content:space-between; gap:16px;">
      <div style="display:flex; align-items:center; gap:14px;">
        <div class="icon-tile" style="width:44px; height:44px; ${sevStyle(overall)}">${heroIcon}</div>
        <div>
          <div style="font-size:17px; font-weight:600; line-height:1.2;">${heroTitle}</div>
          <div class="muted" style="font-size:13px; margin-top:3px;">${heroSub}</div>
        </div>
      </div>
      <div style="display:flex; gap:18px;">
        <div style="text-align:center;"><div style="font-size:20px; font-weight:600; line-height:1; color: var(--ok-fg);">${counts.ok}</div><div class="muted-3" style="font-size:10px; text-transform:uppercase; letter-spacing:0.05em; margin-top:4px;">Healthy</div></div>
        <div style="text-align:center;"><div style="font-size:20px; font-weight:600; line-height:1; color: var(--warn-fg);">${counts.warn}</div><div class="muted-3" style="font-size:10px; text-transform:uppercase; letter-spacing:0.05em; margin-top:4px;">Warnings</div></div>
        <div style="text-align:center;"><div style="font-size:20px; font-weight:600; line-height:1; color: var(--crit-fg);">${counts.critical}</div><div class="muted-3" style="font-size:10px; text-transform:uppercase; letter-spacing:0.05em; margin-top:4px;">Critical</div></div>
      </div>
    </div>
  `;
}

function renderSections(panels) {
  const root = document.getElementById("sections");
  root.innerHTML = SECTIONS.map(sec => {
    const rows = sec.panels.map((key, idx) => {
      const p = panels[key] || {};
      const sev = p.severity || "ok";
      const meta = META[key];
      const summary = oneLiner(key, p);
      return `
        ${idx > 0 ? '<div class="divider"></div>' : ''}
        <div class="row" data-key="${esc(key)}">
          <div class="icon-tile" style="${sevStyle(sev)}">${icon(meta.icon)}</div>
          <div style="flex:1; min-width:0;">
            <div style="font-size:13px; font-weight:500;">${esc(meta.title)}</div>
            <div class="muted" style="font-size:11px; margin-top:1px;">${esc(summary)}</div>
          </div>
          <span class="pill pill-${sev}">${statusLabel(sev)}</span>
          <span class="chev">${icon("chevron")}</span>
        </div>
        <div class="detail">${renderDetail(key, p)}</div>
      `;
    }).join("");
    return `
      <div class="section-label">${esc(sec.label)}</div>
      <div class="surface" style="overflow:hidden;">${rows}</div>
    `;
  }).join("");

  root.querySelectorAll(".row").forEach(row => {
    row.addEventListener("click", () => row.classList.toggle("open"));
  });
}

async function load() {
  const btn = document.getElementById("refresh");
  btn.textContent = "Refreshing…";
  try {
    const r = await fetch("/api/summary");
    const data = await r.json();
    renderBrief(data.brief);
    renderHero(data.panels);
    renderSections(data.panels);
    document.getElementById("last-updated").textContent = "Updated " + fmtTime(data.ts);
  } catch (e) {
    document.getElementById("last-updated").textContent = "Error: " + e.message;
  } finally {
    btn.textContent = "Refresh";
  }
}

document.getElementById("refresh").addEventListener("click", load);
load();
setInterval(load, 5 * 60 * 1000);
