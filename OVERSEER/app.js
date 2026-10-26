"use strict";

/* ------------------------------------------------------------------ *
 * OVERSEER — front-end
 * Datos: /api/data (agregado de ../informes/*.json)
 * ------------------------------------------------------------------ */

const SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"];
const SEV_CLASS = { "CRÍTICO": "crit", "ALTO": "high", "MEDIO": "med", "BAJO": "low", "INFO": "info" };
const SEV_VAR = { "CRÍTICO": "var(--crit)", "ALTO": "var(--high)", "MEDIO": "var(--med)", "BAJO": "var(--low)", "INFO": "var(--info)" };
const RISK_VAR = { crit: "var(--crit)", high: "var(--high)", med: "var(--med)", low: "var(--low)", info: "var(--info)", ok: "var(--ok)" };

const state = {
  data: null,
  selected: "global",
  filter: "",
  tab: "resumen",
  loading: false,
};

const $ = (sel) => document.querySelector(sel);
const brand = $("#brand");
const search = $("#search");
const refreshBtn = $("#refresh");
const sidebar = $("#sidebar");
const detail = $("#detail");
const topMeta = $("#top-meta");
const footMeta = $("#foot-meta");
const toastEl = $("#toast");

let toastTimer = null;

/* ------------------------------ utils ------------------------------ */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function nl2br(value) {
  return esc(value).replace(/\n/g, "<br>");
}

function fmtDate(value) {
  if (!value) return "—";
  const [date, time] = String(value).split(" ");
  const parts = (date || "").split("-");
  if (parts.length !== 3) return String(value);
  const [y, m, d] = parts;
  return `${d}/${m}/${y}${time ? " · " + time.slice(0, 5) : ""}`;
}

function fmtShortDate(value) {
  if (!value) return "—";
  const [date] = String(value).split(" ");
  const [y, m, d] = (date || "").split("-");
  return y ? `${d}/${m}` : String(value);
}

function fmtMode(mode) {
  if (!mode) return "—";
  if (mode === "full") return "completo";
  const m = String(mode).match(/top-ports-(\d+)/);
  return m ? `top ${m[1]}` : String(mode);
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

function sevClass(sev) {
  return SEV_CLASS[sev] || "info";
}

function typeClass(type) {
  const t = String(type || "").toLowerCase();
  if (t.includes("nodo proxmox")) return "proxmox-node";
  if (t === "lxc") return "lxc";
  if (t === "vm") return "vm";
  if (t.includes("guest proxmox")) return "guest";
  if (t.includes("router")) return "router";
  if (t.includes("auditor")) return "this";
  if (t.includes("servidor")) return "guest";
  if (t.includes("cliente") || t.includes("iot")) return "iot";
  return "iot";
}

function shortType(type) {
  const t = String(type || "").toLowerCase();
  if (t.includes("nodo proxmox")) return "Proxmox";
  if (t.includes("guest proxmox")) return "LXC/VM?";
  if (t === "lxc") return "LXC";
  if (t === "vm") return "VM";
  if (t.includes("router")) return "Router";
  if (t.includes("auditor")) return "Auditor";
  if (t.includes("servidor")) return "Servidor";
  if (t.includes("cliente") || t.includes("iot")) return "Cliente";
  if (t.includes("dispositivo")) return "Desconoc.";
  return type ? String(type).slice(0, 14) : "—";
}

function effectiveType(host) {
  return host.type_override || host.type || "Desconocido";
}

function hostMatches(host, query) {
  if (!query) return true;
  const haystack = [
    host.ip, host.os, host.type, host.type_override, host.name, host.vendor,
    ...(host.hostnames || []),
  ].join(" ").toLowerCase();
  return haystack.includes(query);
}

function isProxmoxHost(host) {
  const auto = String(host.type || "").toLowerCase();
  const eff = String(effectiveType(host)).toLowerCase();
  return (
    auto.includes("proxmox") ||
    eff.includes("proxmox") ||
    eff === "lxc" ||
    eff === "vm" ||
    String(host.vendor || "").toLowerCase().includes("proxmox") ||
    /^bc:24:11/i.test(host.mac || "") ||
    (host.ip && host.ip === (state.data?.global?.proxmox?.source_ip || ""))
  );
}

function riskColor(cls) {
  return RISK_VAR[cls] || "var(--muted)";
}

function toast(message, isError = false) {
  toastEl.textContent = message;
  toastEl.classList.toggle("err", isError);
  toastEl.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2600);
}

/* --------------------------- hash routing -------------------------- */

function readHash() {
  const m = location.hash.match(/host=([^&]+)/);
  if (m) return decodeURIComponent(m[1]);
  if (location.hash.includes("global")) return "global";
  return null;
}

function setHash(ip) {
  if (ip && ip !== "global") {
    history.replaceState(null, "", `#host=${encodeURIComponent(ip)}`);
  } else {
    history.replaceState(null, "", "#global");
  }
}

/* ------------------------------ charts ----------------------------- */

function donutGradient(counts, total) {
  if (!total) return "var(--panel-3)";
  let acc = 0;
  const parts = [];
  for (const sev of SEV_ORDER) {
    const n = counts[sev] || 0;
    if (!n) continue;
    const pct = (n / total) * 100;
    parts.push(`${SEV_VAR[sev]} ${acc.toFixed(2)}% ${(acc + pct).toFixed(2)}%`);
    acc += pct;
  }
  return parts.length ? `conic-gradient(${parts.join(",")})` : "var(--panel-3)";
}

function donut(counts, total, label) {
  const legend = SEV_ORDER.map((sev) => {
    const n = counts[sev] || 0;
    return `<div class="legend-row">
      <span class="legend-dot" style="background:${SEV_VAR[sev]}"></span>
      <span>${sev}</span>
      <span class="count">${n}</span>
    </div>`;
  }).join("");
  return `<div class="donut-wrap">
    <div class="donut" style="background:${donutGradient(counts, total)}">
      <div class="donut-center"><div class="v">${total}</div><div class="l">${esc(label)}</div></div>
    </div>
    <div class="legend">${legend}</div>
  </div>`;
}

function bars(items, variant = "") {
  if (!items.length) return `<div class="muted small">Sin datos.</div>`;
  const max = Math.max(1, ...items.map((i) => i.count));
  return `<div class="bar-list">${items.map((item) => {
    const width = Math.max(2, Math.round((item.count / max) * 100));
    const cls = item.cls || variant;
    return `<div class="bar-row">
      <span class="bar-label" title="${esc(item.label)}">${esc(item.label)}</span>
      <span class="bar-track"><span class="bar-fill ${esc(cls)}" style="width:${width}%"></span></span>
      <span class="bar-val">${item.count}</span>
    </div>`;
  }).join("")}</div>`;
}

function sparkline(history) {
  if (!history || history.length < 2) {
    return `<div class="note">Todavía no hay suficiente histórico para dibujar la evolución. Se necesitan al menos 2 escaneos de esta IP.</div>`;
  }
  const w = 600, h = 130, pad = 26;
  const maxPorts = Math.max(1, ...history.map((x) => x.ports || 0));
  const step = (w - pad * 2) / (history.length - 1);
  const x = (i) => pad + i * step;
  const yRisk = (v) => h - pad - (Math.max(0, Math.min(100, v)) / 100) * (h - pad * 2);
  const yPorts = (v) => h - pad - (Math.min(v, maxPorts) / maxPorts) * (h - pad * 2);
  const riskPts = history.map((d, i) => `${x(i).toFixed(1)},${yRisk(d.risk).toFixed(1)}`).join(" ");
  const portPts = history.map((d, i) => `${x(i).toFixed(1)},${yPorts(d.ports).toFixed(1)}`).join(" ");
  const grid = [0, 25, 50, 75, 100].map((v) =>
    `<line class="grid" x1="${pad}" x2="${w - pad}" y1="${yRisk(v).toFixed(1)}" y2="${yRisk(v).toFixed(1)}"/>`
  ).join("");
  return `<div class="spark-wrap">
    <svg class="spark" viewBox="0 0 ${w} ${h}" role="img" aria-label="Evolución de riesgo y puertos">
      ${grid}
      <polyline class="line-ports" points="${portPts}"/>
      <polyline class="line-risk" points="${riskPts}"/>
      ${history.map((d, i) => `<circle class="dot-risk" cx="${x(i).toFixed(1)}" cy="${yRisk(d.risk).toFixed(1)}" r="3"/>`).join("")}
      <text class="axis" x="${pad}" y="${h - 6}">${esc(fmtShortDate(history[0].scanned_at))}</text>
      <text class="axis" x="${w - pad}" y="${h - 6}" text-anchor="end">${esc(fmtShortDate(history[history.length - 1].scanned_at))}</text>
      <text class="axis" x="${pad}" y="13">riesgo 100</text>
      <text class="axis" x="${pad}" y="${yRisk(0) - 4}">0</text>
    </svg>
    <div class="spark-legend"><span><i class="r"></i>riesgo</span><span><i class="p"></i>puertos (máx ${maxPorts})</span></div>
  </div>`;
}

/* ------------------------------ pieces ----------------------------- */

function findingCard(f, showHost) {
  const cls = sevClass(f.severity);
  const cves = (f.cves || []).length
    ? `<div class="cve-list">${f.cves.map((c) => `<span class="cve">${esc(c)}</span>`).join("")}</div>`
    : "";
  return `<article class="finding ${cls}">
    <div class="finding-head">
      <span class="badge ${cls}">${esc(f.severity)}</span>
      <span class="finding-title">${esc(f.title)}</span>
      ${showHost ? `<span class="finding-host">${esc(f.host || "")}</span>` : ""}
    </div>
    <div class="finding-evidence">${nl2br(f.evidence || "")}</div>
    <div class="finding-rec"><b>Recomendación:</b> ${nl2br(f.recommendation || "—")}</div>
    ${cves}
  </article>`;
}

function goodList(items) {
  if (!items.length) return `<div class="muted small">Sin comprobaciones positivas registradas.</div>`;
  return `<ul class="good-list">${items.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>`;
}

function annotationForm(host) {
  const current = host.type_override || "";
  const auto = host.type ? `Auto · ${host.type}` : "Auto (detectado)";
  const options = (state.data.type_options || []).filter(Boolean);
  const optionHtml = [
    `<option value="" ${current === "" ? "selected" : ""}>${esc(auto)}</option>`,
    ...options.map((t) => `<option value="${esc(t)}" ${current === t ? "selected" : ""}>${esc(t)}</option>`),
  ].join("");
  return `<form class="annot" data-annot="${esc(host.ip)}">
    <label for="annot-type">clasificar</label>
    <select id="annot-type" name="type">${optionHtml}</select>
    <input id="annot-name" name="name" maxlength="80" placeholder="nombre visible" value="${esc(host.name || "")}">
    <button class="save" type="submit">guardar</button>
    <span class="hint">LXC/VM se anota a mano</span>
  </form>`;
}

function riskGauge(meta) {
  const pct = Math.max(0, Math.min(100, meta.score || 0));
  return `<div class="hero-risk">
    <div class="risk-gauge" style="--pct:${pct};--gauge-color:${riskColor(meta.cls)}">
      <div class="val">${meta.score}</div>
      <div class="unit">riesgo</div>
    </div>
    <div class="risk-label ${meta.cls}">${esc(meta.label)}</div>
  </div>`;
}

function kpiCard(label, value, sub, cls) {
  return `<div class="kpi ${cls || ""}">
    <div class="l">${esc(label)}</div>
    <div class="v">${esc(value)}</div>
    ${sub ? `<div class="s">${esc(sub)}</div>` : ""}
  </div>`;
}

function portsTable(host) {
  if (!host.ports || !host.ports.length) {
    return `<div class="note">No se detectaron puertos TCP abiertos en este host.</div>`;
  }
  const rows = host.ports.map((p) => {
    const scripts = Object.entries(p.scripts || {})
      .filter(([, v]) => v && !String(v).startsWith("ERROR: Script execution failed"));
    const scriptHtml = scripts.length
      ? `<details><summary>${plural(scripts.length, "script", "scripts")}</summary>${scripts
          .map(([k, v]) => `<pre class="script">${esc(k)}:\n${esc(v)}</pre>`)
          .join("")}</details>`
      : `<span class="muted">—</span>`;
    const product = p.product || "";
    const version = [p.version, p.extrainfo].filter(Boolean).join(" ");
    return `<tr>
      <td class="port-num">${esc(p.port)}<span class="muted">/${esc(p.proto || "tcp")}</span></td>
      <td><div class="svc">${esc(p.name || "?")}</div></td>
      <td><div class="svc">${esc(product || "—")}</div>${version ? `<div class="svc-sub">${esc(version)}</div>` : ""}</td>
      <td>${scriptHtml}</td>
    </tr>`;
  }).join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>puerto</th><th>servicio</th><th>producto / versión</th><th>nse</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function proxmoxSection(px, full) {
  if (!px || (!px.cluster && !(px.guests || []).length)) {
    return `<div class="note">No hay datos de Proxmox en el último informe. El script los obtiene si encuentra <code>pve-exporter</code> en el puerto 9221.</div>`;
  }
  const guests = px.guests || [];
  const lxc = guests.filter((g) => g.type === "lxc").length;
  const vms = guests.filter((g) => g.type === "qemu").length;
  const nodes = px.nodes || [];
  const nodeRows = nodes.map((n) => `<tr>
    <td><b>${esc(n.name || "—")}</b></td>
    <td class="muted">${esc(n.id || "—")}</td>
    <td class="muted">${esc(n.nodeid || "—")}</td>
    <td class="muted">${esc(n.level || "—")}</td>
  </tr>`).join("");
  const shown = full ? guests : guests.slice(0, 10);
  const guestRows = shown.map((g) => {
    const gt = String(g.type || "").toLowerCase();
    const cls = gt === "qemu" ? "vm" : gt === "lxc" ? "lxc" : "guest";
    return `<tr>
      <td class="port-num">${esc(g.id || "—")}</td>
      <td><b>${esc(g.name || "—")}</b></td>
      <td class="muted">${esc(g.node || "—")}</td>
      <td><span class="type-badge ${cls}">${gt === "qemu" ? "VM" : gt.toUpperCase() || "—"}</span></td>
      <td class="muted">${esc(g.tags || "—")}</td>
    </tr>`;
  }).join("");
  return `<div class="panel" style="padding:14px 16px">
    <div class="section-title">proxmox</div>
    <div class="hero-tags" style="margin:0 0 11px">
      <span class="chip">cluster <b>${esc(px.cluster || "—")}</b></span>
      <span class="chip">versión <b>${esc(px.version || "—")}</b></span>
      <span class="chip">nodos <b>${esc(px.nodes_count || "—")}</b></span>
      <span class="chip">quórum <b>${px.quorate === "1" ? "sí" : esc(px.quorate || "—")}</b></span>
      <span class="chip">origen <b>${esc(px.source_ip || "—")}</b></span>
      <span class="chip">guests <b>${guests.length}</b> · LXC <b>${lxc}</b> · VM <b>${vms}</b></span>
    </div>
    ${nodeRows ? `<div class="table-wrap" style="margin-bottom:10px"><table>
      <thead><tr><th>nodo</th><th>id</th><th>nodeid</th><th>nivel</th></tr></thead>
      <tbody>${nodeRows}</tbody>
    </table></div>` : ""}
    ${guestRows ? `<div class="table-wrap" style="max-height:${full ? "420px" : "280px"}"><table>
      <thead><tr><th>id</th><th>nombre</th><th>nodo</th><th>tipo</th><th>tags</th></tr></thead>
      <tbody>${guestRows}</tbody>
    </table></div>` : `<div class="muted small">Sin guests definidos.</div>`}
    ${!full && guests.length > shown.length ? `<div class="muted small" style="margin-top:7px">+${guests.length - shown.length} guests más en el JSON.</div>` : ""}
  </div>`;
}

/* ---------------------------- global view -------------------------- */

function renderGlobal() {
  const g = state.data.global;
  if (!g || !state.data.hosts.length) return emptyState();

  const charts = `<div class="dash-grid">
    <div class="chart-card">
      <div class="chart-title">hallazgos por severidad <span>${g.total_findings}</span></div>
      ${donut(g.counts, g.total_findings, "hallazgos")}
    </div>
    <div class="chart-card">
      <div class="chart-title">tipos de host <span>${g.total_hosts}</span></div>
      ${bars(Object.entries(g.type_counts || {}).map(([k, v]) => ({ label: k, count: v, cls: typeClass(k) === "router" ? "blue" : typeClass(k) === "proxmox-node" ? "purple" : typeClass(k) === "guest" ? "blue" : typeClass(k) === "lxc" ? "green" : "" })))}
    </div>
    <div class="chart-card">
      <div class="chart-title">puertos más frecuentes</div>
      ${bars((g.top_ports || []).map((p) => ({ label: `${p.port}/${p.name || "?"}`, count: p.count, cls: "blue" })))}
    </div>
    <div class="chart-card">
      <div class="chart-title">servicios más frecuentes</div>
      ${bars((g.top_services || []).map((s) => ({ label: s.name, count: s.count, cls: "purple" })))}
    </div>
  </div>`;

  const topHosts = (g.top_hosts || []).length
    ? g.top_hosts.map((h) => `<button class="host-risk-row" data-host="${esc(h.ip)}">
        <span class="ip">${esc(h.ip)}</span>
        <span class="type-badge ${typeClass(h.type)}">${esc(shortType(h.type))}</span>
        <span class="os">${esc(h.os || "—")}</span>
        <span class="score" style="color:${riskColor(h.risk_meta.cls)}">${h.risk}</span>
      </button>`).join("")
    : `<div class="muted small" style="padding:8px 2px">Sin hosts con hallazgos.</div>`;

  const findings = (g.findings || []).length
    ? g.findings.map((f) => findingCard(f, true)).join("")
    : `<div class="note">El último escaneo no generó hallazgos.</div>`;

  const scans = (state.data.scans || []).slice().reverse().map((s) => `<div class="scan-row">
      <b>${fmtDate(s.scanned_at)}</b>
      <span>${esc(s.target)} · ${esc(fmtMode(s.mode))}</span>
      <span>${s.hosts} hosts</span>
      <span>${s.findings} hallazgos</span>
    </div>`).join("");

  return `<section class="detail-inner">
    <div class="hero panel">
      <div class="hero-main">
        <div class="kicker">network overview</div>
        <h2>OVERSEER <span class="thin">· ${esc(g.target || "sin objetivo")}</span></h2>
        <div class="hero-sub">Último escaneo ${fmtDate(g.scanned_at)} · modo ${esc(fmtMode(g.mode))} · ${plural(state.data.reports_count, "informe", "informes")} acumulados</div>
        <div class="hero-tags">
          <span class="chip">hosts <b>${g.total_hosts}</b></span>
          <span class="chip">puertos <b>${g.total_ports}</b></span>
          <span class="chip">hallazgos <b>${g.total_findings}</b></span>
          <span class="chip">servicios <b>${g.unique_services}</b></span>
        </div>
      </div>
      ${riskGauge(g.risk)}
    </div>

    <div class="kpis">
      ${kpiCard("hosts activos", g.total_hosts, `${g.hosts_with_ports} con puertos`, "ok")}
      ${kpiCard("hallazgos", g.total_findings, `${g.counts["CRÍTICO"] || 0} críticos`, "crit")}
      ${kpiCard("alto riesgo", (g.counts["ALTO"] || 0), `${g.counts["MEDIO"] || 0} medios`, "high")}
      ${kpiCard("puertos abiertos", g.total_ports, `${g.unique_services} servicios`, "info")}
    </div>

    ${charts}

    <div class="dash-grid">
      <div class="panel" style="padding:14px 16px">
        <div class="section-title">hosts con más riesgo</div>
        ${topHosts}
      </div>
      <div class="panel" style="padding:14px 16px">
        <div class="section-title">escaneos</div>
        <div class="scan-list">${scans || `<div class="muted small">Sin escaneos.</div>`}</div>
      </div>
    </div>

    <div class="panel" style="padding:14px 16px;margin-top:10px">
      <div class="section-title">hallazgos del último escaneo</div>
      ${findings}
    </div>

    <div style="margin-top:10px">${proxmoxSection(g.proxmox, true)}</div>

    <div class="panel" style="padding:14px 16px;margin-top:10px">
      <div class="section-title">comprobaciones positivas</div>
      ${goodList(g.good_checks || [])}
    </div>
  </section>`;
}

/* ----------------------------- host view --------------------------- */

function availableTabs(host) {
  const tabs = [
    ["resumen", "Resumen"],
    ["puertos", "Puertos", (host.ports || []).length],
    ["hallazgos", "Hallazgos", (host.findings || []).length],
    ["historial", "Historial", host.seen_count || 0],
  ];
  if (isProxmoxHost(host)) tabs.splice(3, 0, ["proxmox", "Proxmox"]);
  return tabs;
}

function renderSummaryTab(host) {
  const findings = host.findings || [];
  const top = findings.slice(0, 4);
  const good = (state.data.global.good_checks || []).filter((g) => {
    if (g.startsWith(host.ip + ":")) return true;
    return !/^\d{1,3}(\.\d{1,3}){3}:/.test(g);
  });
  const notes = `<div class="note" style="margin-top:12px">
    <b>Notas:</b> el SO y el tipo se infieren por banners y puertos (sin root no hay fingerprint <code>-O</code>).
    La asignación exacta IP → guest de Proxmox necesita DHCP o la API; usa <b>clasificar</b> para marcar LXC/VM.
  </div>`;
  return `<div class="tab-body">
    <div class="section-title">hallazgos principales</div>
    ${top.length ? top.map((f) => findingCard(f, false)).join("") : `<div class="note">Sin hallazgos para este host. Buen estado aparente.</div>`}
    ${findings.length > top.length ? `<button class="global-btn" data-tab="hallazgos" style="margin-bottom:12px">ver los ${findings.length} hallazgos →</button>` : ""}
    <div class="section-title" style="margin-top:16px">comprobaciones positivas</div>
    ${goodList(good)}
    ${notes}
  </div>`;
}

function renderPortsTab(host) {
  return `<div class="tab-body">${portsTable(host)}</div>`;
}

function renderFindingsTab(host) {
  const findings = host.findings || [];
  return `<div class="tab-body">
    ${findings.length ? findings.map((f) => findingCard(f, false)).join("") : `<div class="note">Sin hallazgos para este host.</div>`}
  </div>`;
}

function renderProxmoxTab(host) {
  const px = state.data.global.proxmox || {};
  const eff = String(effectiveType(host)).toLowerCase();
  const isGuest = String(host.type || "").toLowerCase().includes("guest proxmox") || eff === "lxc" || eff === "vm";
  const extra = isGuest
    ? `<div class="note" style="margin-top:10px">Este host es un guest de Proxmox. El escáner no puede saber desde la red si es <b>LXC</b> o <b>VM</b>; usa la clasificación manual del encabezado.</div>`
    : "";
  return `<div class="tab-body">${proxmoxSection(px, true)}${extra}</div>`;
}

function renderHistoryTab(host) {
  const history = host.history || [];
  const timeline = history.slice().reverse().map((x) => `<div class="tl-row">
    <span class="when">${fmtDate(x.scanned_at)}</span>
    <span class="ty">${esc(x.type || "—")} · ${esc(x.os || "")}</span>
    <span class="num">${x.ports} ptos</span>
    <span class="num">${x.risk} riesgo</span>
  </div>`).join("");
  return `<div class="tab-body">
    ${sparkline(history)}
    <div class="section-title">apariciones</div>
    <div class="timeline">${timeline || `<div class="muted small">Sin histórico.</div>`}</div>
  </div>`;
}

function renderHost(host) {
  const counts = host.severity_counts || {};
  const total = (host.findings || []).length;
  const risk = host.risk_meta || { score: 0, label: "Sin hallazgos", cls: "ok" };
  const type = effectiveType(host);
  const stale = state.data.global.scanned_at && host.last_seen !== state.data.global.scanned_at;
  const tabs = availableTabs(host);
  let tab = state.tab;
  if (!tabs.some((t) => t[0] === tab)) tab = "resumen";

  const tabButtons = tabs.map(([id, label, count]) => `<button class="tab ${tab === id ? "active" : ""}" data-tab="${id}">
    ${esc(label)}${count !== undefined ? `<span class="n">${count}</span>` : ""}
  </button>`).join("");

  const tabBody = tab === "resumen" ? renderSummaryTab(host)
    : tab === "puertos" ? renderPortsTab(host)
    : tab === "hallazgos" ? renderFindingsTab(host)
    : tab === "proxmox" ? renderProxmoxTab(host)
    : renderHistoryTab(host);

  const ports = host.ports || [];
  const ranges = [
    { label: "0–1023 · bien conocidos", count: ports.filter((p) => p.port <= 1023).length },
    { label: "1024–49151 · registrados", count: ports.filter((p) => p.port > 1023 && p.port <= 49151).length },
    { label: "49152–65535 · dinámicos", count: ports.filter((p) => p.port > 49151).length },
  ];
  const portChips = ports.length
    ? ports.map((p) => `<span class="chip"><b>${esc(p.port)}</b>/${esc(p.name || "?")}</span>`).join("")
    : `<span class="muted small">sin puertos abiertos</span>`;
  const services = new Set(ports.map((p) => p.name).filter(Boolean)).size;

  return `<section class="detail-inner">
    <div class="hero panel">
      <div class="hero-main">
        <div class="kicker">host · ${esc(host.ip)}</div>
        <h2>${esc(host.name || type)}${host.name ? `<span class="thin"> · ${esc(type)}</span>` : ""}</h2>
        <div class="hero-sub">${esc(host.os || "SO desconocido")}${host.vendor ? ` · ${esc(host.vendor)}` : ""}${host.mac ? ` · MAC ${esc(host.mac)}` : ""}</div>
        <div class="hero-tags">
          <span class="chip">visto <b>${plural(host.seen_count || 1, "vez", "veces")}</b></span>
          <span class="chip">último <b>${fmtDate(host.last_seen)}</b></span>
          ${(host.hostnames || []).length ? `<span class="chip">dns <b>${esc(host.hostnames.join(", "))}</b></span>` : ""}
          ${host.auditor ? `<span class="chip">equipo auditor</span>` : ""}
          ${host.type_override ? `<span class="chip">tipo anotado</span>` : ""}
          ${stale ? `<span class="chip" style="border-color:rgba(245,167,66,.45);color:var(--orange)">no visto en el último escaneo</span>` : ""}
        </div>
        ${annotationForm(host)}
      </div>
      ${riskGauge(risk)}
    </div>

    <div class="kpis">
      ${kpiCard("puertos", ports.length, `${services} servicios`, "info")}
      ${kpiCard("hallazgos", total, `${counts["CRÍTICO"] || 0} críticos`, total ? "crit" : "ok")}
      ${kpiCard("alto / medio", (counts["ALTO"] || 0) + (counts["MEDIO"] || 0), `${counts["ALTO"] || 0} altos`, "high")}
      ${kpiCard("riesgo", risk.score, risk.label, risk.cls)}
    </div>

    <div class="charts">
      <div class="chart-card">
        <div class="chart-title">hallazgos por severidad <span>${total}</span></div>
        ${donut(counts, total, "hallazgos")}
      </div>
      <div class="chart-card">
        <div class="chart-title">puertos por rango <span>${ports.length} abiertos</span></div>
        ${bars(ranges, "blue")}
        <div class="hero-tags" style="margin-top:12px">${portChips}</div>
      </div>
    </div>

    <div class="tabs">${tabButtons}</div>
    ${tabBody}
  </section>`;
}

/* ------------------------------ shell ------------------------------ */

function renderTopMeta() {
  const g = state.data?.global;
  if (!g) { topMeta.innerHTML = ""; return; }
  const risk = g.risk || { label: "—", cls: "ok", score: 0 };
  topMeta.innerHTML = `
    <span class="meta-pill">objetivo <b>${esc(g.target || "—")}</b></span>
    <span class="meta-pill">escaneo <b>${fmtDate(g.scanned_at)}</b></span>
    <span class="meta-pill">${g.total_hosts} activos · ${state.data.hosts.length} vistos</span>
    <span class="meta-pill">${g.total_findings} hallazgos</span>
    <span class="meta-pill risk ${risk.cls}">${esc(risk.label)} · ${risk.score}</span>`;
}

function renderSidebar() {
  const data = state.data;
  if (!data) { sidebar.innerHTML = ""; return; }
  const g = data.global || {};
  const counts = g.counts || {};
  const hosts = (data.hosts || []).filter((h) => hostMatches(h, state.filter));
  const okCount = (data.hosts || []).filter((h) => !(h.findings || []).length).length;

  const rows = hosts.map((h) => {
    const sev = h.max_severity ? SEV_CLASS[h.max_severity] : "ok";
    const active = state.selected === h.ip ? "active" : "";
    const stale = g.scanned_at && h.last_seen !== g.scanned_at;
    const type = effectiveType(h);
    const name = h.name ? `<span class="host-name">${esc(h.name)}</span>` : "";
    return `<button class="host-row ${active} ${stale ? "stale" : ""}" data-host="${esc(h.ip)}" title="${esc(h.os || "")}${stale ? " · no aparece en el último escaneo" : ""}">
      <span class="ip-line">
        <span class="sev-dot ${sev}"></span>
        <span class="host-ip">${esc(h.ip)}</span>
        ${name}
        <span class="type-badge ${typeClass(type)}">${esc(shortType(type))}</span>
      </span>
      <span class="host-os">${esc(h.os || "SO desconocido")}${stale ? " · histórico" : ""}</span>
    </button>`;
  }).join("");

  sidebar.innerHTML = `
    <div class="side-head">
      <button class="global-btn ${state.selected === "global" ? "active" : ""}" data-global="1">
        <span>Resumen general</span>
        <span class="count">${g.total_hosts} activos · ${data.hosts.length} vistos</span>
      </button>
      <div class="side-stats">
        <div class="side-stat"><div class="n">${data.hosts.length}</div><div class="l">vistos</div></div>
        <div class="side-stat crit"><div class="n">${counts["CRÍTICO"] || 0}</div><div class="l">crít.</div></div>
        <div class="side-stat high"><div class="n">${counts["ALTO"] || 0}</div><div class="l">altos</div></div>
        <div class="side-stat ok"><div class="n">${okCount}</div><div class="l">ok</div></div>
      </div>
    </div>
    <div class="host-list">
      ${rows || `<div class="side-empty">Ningún host coincide con “${esc(state.filter)}”.</div>`}
    </div>`;
}

function renderFoot() {
  const d = state.data;
  if (!d) { footMeta.textContent = ""; return; }
  footMeta.textContent = `${d.hosts.length} hosts · ${d.reports_count} informes · actualizado ${fmtDate(d.generated_at)}`;
}

function renderDetail() {
  if (!state.data) return;
  if (!state.data.hosts.length) {
    detail.innerHTML = emptyState();
    return;
  }
  if (state.selected === "global") {
    detail.innerHTML = renderGlobal();
    return;
  }
  const host = state.data.hosts.find((h) => h.ip === state.selected);
  if (!host) {
    state.selected = "global";
    detail.innerHTML = renderGlobal();
    return;
  }
  detail.innerHTML = renderHost(host);
}

function render() {
  if (!state.data) return;
  renderTopMeta();
  renderSidebar();
  renderDetail();
  renderFoot();
}

function emptyState() {
  return `<div class="empty">
    <div class="glyph">▚</div>
    <h2>OVERSEER</h2>
    <p>No hay informes JSON en <code>~/AUDITORIA_PLUS/informes</code>.</p>
    <pre>cd ~/AUDITORIA_PLUS
python3 auditoria_red2.py --range 192.168.1.0/24 --quick --no-browser</pre>
    <p>Después recarga esta página. El visor detecta los informes nuevos automáticamente.</p>
  </div>`;
}

function fileProtocolState() {
  return `<div class="empty">
    <div class="glyph">▚</div>
    <h2>OVERSEER</h2>
    <p>Este visor necesita su servidor local (no funciona abriendo el HTML con <code>file://</code>).</p>
    <pre>cd ~/AUDITORIA_PLUS/OVERSEER
./run.sh</pre>
    <p>Luego abre <code>http://127.0.0.1:8770</code>.</p>
  </div>`;
}

function errorState(message) {
  return `<div class="empty">
    <div class="glyph">!</div>
    <h2>Sin conexión con OVERSEER</h2>
    <p>${esc(message)}</p>
    <p>Arranca el servidor con:</p>
    <pre>cd ~/AUDITORIA_PLUS/OVERSEER
./run.sh</pre>
  </div>`;
}

/* ------------------------------ actions ---------------------------- */

function selectHost(ip) {
  state.selected = ip;
  setHash(ip);
  renderSidebar();
  renderDetail();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function selectGlobal() {
  state.selected = "global";
  setHash("global");
  renderSidebar();
  renderDetail();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function navigateHosts(delta) {
  const hosts = (state.data?.hosts || []).filter((h) => hostMatches(h, state.filter));
  if (!hosts.length) return;
  let idx = hosts.findIndex((h) => h.ip === state.selected);
  idx = idx < 0 ? 0 : (idx + delta + hosts.length) % hosts.length;
  selectHost(hosts[idx].ip);
}

function isTyping() {
  const el = document.activeElement;
  if (!el) return false;
  return el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable;
}

async function fetchData(opts = {}) {
  const silent = Boolean(opts.silent);
  const force = Boolean(opts.force);
  if (state.loading) return;
  state.loading = true;
  if (!silent) refreshBtn.classList.add("spin");
  try {
    const res = await fetch("/api/data", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.data = data;

    const hash = readHash();
    const validIps = new Set((data.hosts || []).map((h) => h.ip));
    if (hash && (hash === "global" || validIps.has(hash))) {
      state.selected = hash;
    } else if (state.selected !== "global" && !validIps.has(state.selected)) {
      state.selected = "global";
    }
    if (state.selected !== "global" && !validIps.has(state.selected)) {
      state.selected = "global";
    }

    const editing = document.activeElement?.closest?.(".annot");
    renderTopMeta();
    renderSidebar();
    if (!editing || force) renderDetail();
    renderFoot();
    if (!silent) toast(`Datos actualizados · ${plural(data.hosts.length, "host", "hosts")}`);
  } catch (err) {
    if (!silent) {
      detail.innerHTML = errorState(err.message || "error desconocido");
      toast("No se pudo cargar /api/data", true);
    }
  } finally {
    state.loading = false;
    refreshBtn.classList.remove("spin");
  }
}

/* ------------------------------ events ----------------------------- */

brand.addEventListener("click", selectGlobal);
brand.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectGlobal(); }
});

search.addEventListener("input", () => {
  state.filter = search.value.trim().toLowerCase();
  renderSidebar();
});

refreshBtn.addEventListener("click", () => fetchData());

sidebar.addEventListener("click", (e) => {
  if (e.target.closest("[data-global]")) { selectGlobal(); return; }
  const row = e.target.closest("[data-host]");
  if (row) selectHost(row.dataset.host);
});

detail.addEventListener("click", (e) => {
  const tab = e.target.closest("[data-tab]");
  if (tab) {
    state.tab = tab.dataset.tab;
    renderDetail();
    const tabsEl = detail.querySelector(".tabs");
    if (tabsEl) tabsEl.scrollIntoView({ block: "start", behavior: "smooth" });
    return;
  }
  const hostRow = e.target.closest("[data-host]");
  if (hostRow) selectHost(hostRow.dataset.host);
});

detail.addEventListener("submit", async (e) => {
  const form = e.target.closest("form[data-annot]");
  if (!form) return;
  e.preventDefault();
  const ip = form.dataset.annot;
  const type = form.querySelector("[name=type]").value;
  const name = form.querySelector("[name=name]").value.trim();
  try {
    const res = await fetch("/api/annotations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, type, name }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `HTTP ${res.status}`);
    }
    toast("Clasificación guardada");
    await fetchData({ silent: true, force: true });
  } catch (err) {
    toast(`No se pudo guardar: ${err.message}`, true);
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !isTyping()) {
    e.preventDefault();
    search.focus();
    search.select();
    return;
  }
  if (isTyping()) return;
  if (e.key === "r" || e.key === "R") {
    e.preventDefault();
    fetchData();
    return;
  }
  if (e.key === "Escape") {
    search.value = "";
    state.filter = "";
    renderSidebar();
    return;
  }
  if (e.key === "ArrowDown") { e.preventDefault(); navigateHosts(1); }
  if (e.key === "ArrowUp") { e.preventDefault(); navigateHosts(-1); }
});

window.addEventListener("hashchange", () => {
  const hash = readHash();
  if (hash && hash !== state.selected) {
    if (hash === "global") selectGlobal();
    else if ((state.data?.hosts || []).some((h) => h.ip === hash)) selectHost(hash);
  }
});

/* ------------------------------- boot ------------------------------ */

async function boot() {
  if (location.protocol === "file:") {
    sidebar.innerHTML = "";
    topMeta.innerHTML = "";
    detail.innerHTML = fileProtocolState();
    return;
  }
  renderTopMeta();
  await fetchData({ silent: true });
  setInterval(() => {
    if (document.visibilityState === "visible") fetchData({ silent: true });
  }, 20000);
}

boot();
