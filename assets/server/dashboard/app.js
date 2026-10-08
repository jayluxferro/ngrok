// ngrokd admin SPA (spec 15 §8). Vanilla ES2020, no framework, no build step:
// an admin surface is the last place to grow a node toolchain, and this file
// is served as-is by ngrokd's /static route.
//
// The load-bearing rule of the whole page: every dynamic node goes through
// el() below, which sets textContent and never innerHTML. The strings this
// page renders — tunnel URLs, event fields, validator error messages — are
// operator- and tenant-controlled text, and are never parsed as HTML, so a
// hostile <script> in a tunnel name is displayed, not executed. That property
// is structural (nothing here parses HTML at all), not a matter of escaping.

"use strict";

// ---- DOM helpers -----------------------------------------------------------

const $ = (id) => document.getElementById(id);

// el is the one way this file builds nodes. Routing every construction
// through it is what keeps the no-innerHTML rule from being eroded one
// "just this once" at a time.
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== null && text !== undefined) n.textContent = String(text);
  return n;
}

// clear empties a node; the polling renders replace their container's
// children wholesale each tick rather than diffing (500 rows rebuild in
// well under a frame, and diffing is where stale-row bugs live).
function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// nz substitutes a fallback for missing/empty values — every field read in
// this file may simply be absent when an older binary serves a newer page
// (spec §3: the snapshot enrichment is additive; this UI predates nothing).
const nz = (v, fb) => (v === undefined || v === null || v === "" ? fb : String(v));

// ---- formatting -------------------------------------------------------------

// Binary units (1024), matching what the tunnel actually carried; a byte
// count is also the one place "—" is a friendlier cell than a crash.
function fmtBytes(n) {
  if (typeof n !== "number" || !isFinite(n)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return (u === 0 ? v : v.toFixed(1)) + " " + units[u];
}

function fmtInt(n) {
  return typeof n === "number" && isFinite(n) ? n.toLocaleString("en-US") : "—";
}

function fmtRate(n) {
  return typeof n === "number" && isFinite(n) ? n.toFixed(2) + "/s" : "—";
}

// fmtDur renders seconds compactly ("3d 4h", "2m 07s"); it backs both the
// uptime card and the tunnels' age column.
function fmtDur(sec) {
  if (typeof sec !== "number" || !isFinite(sec) || sec < 0) return "—";
  let s = Math.floor(sec);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  if (m) return m + "m " + s + "s";
  return s + "s";
}

function fmtAge(iso) {
  const t = Date.parse(iso);
  return isNaN(t) ? "—" : fmtDur((Date.now() - t) / 1000);
}

// UTC wall clock, HH:MM:SS — the event timestamps are UTC on the wire
// (newEventHeader in server/observability.go) and stay UTC on screen.
function fmtHMS(iso) {
  const t = Date.parse(iso);
  return isNaN(t) ? "?" : new Date(t).toISOString().slice(11, 19) + "Z";
}

// ---- session / fetch ----------------------------------------------------------

// Latched on the first 401. The admin session cookie is never refreshed
// mid-session, so once it is dead every later call dies with it; polling and
// the SSE stream stop, and the banner (static HTML in index.html) offers the
// reload, which is the login flow's own post-auth target.
let sessionExpired = false;
function on401() {
  if (sessionExpired) return;
  sessionExpired = true;
  stopActiveTab();
  $("session-expired").hidden = false;
}

// fetchJSON is every call this page makes. Same-origin relative URLs, and
// credentials same-origin because the admin session rides a cookie. Non-200
// is surfaced, not thrown blindly: 401 latches the session banner, and every
// other failure carries the API's {"error": ...} body — the validate/render
// endpoints deliberately return JSON errors (400 envelope, 413 oversize,
// 422 vault refusal) whose text is the thing the operator needs to read.
async function fetchJSON(url, opts) {
  let res;
  try {
    res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts));
  } catch (err) {
    throw new Error("network error: " + (err && err.message ? err.message : "failed"));
  }
  if (res.status === 401) {
    on401();
    throw new Error("session expired");
  }
  const text = await res.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (_) {
    // non-JSON body: fall through, the !ok branch reports it as text
  }
  if (!res.ok) {
    const msg = body && body.error ? body.error : "HTTP " + res.status + (text ? ": " + text.slice(0, 200) : "");
    throw new Error(msg);
  }
  if (body === null) throw new Error("malformed JSON response");
  return body;
}

function postJSON(url, obj) {
  return fetchJSON(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj),
  });
}

// ---- tabs --------------------------------------------------------------------

// Each tab declares how to start and stop its live update, and only the
// active tab runs: polling a tab nobody watches spends the same per-IP
// admin rate budget that protects the auth path, and an idle SSE subscriber
// occupies an event-hub slot.
const TABS = {
  overview: { start: startOverview, stop: stopOverview },
  tunnels: { start: startTunnels, stop: stopTunnels },
  events: { start: startEvents, stop: stopEvents },
  workbench: { start: null, stop: null }, // static editors; nothing to poll
};
let activeTab = "overview";

function startActiveTab() {
  const t = TABS[activeTab];
  if (t && t.start) t.start();
}

function stopActiveTab() {
  const t = TABS[activeTab];
  if (t && t.stop) t.stop();
}

function activate(name) {
  stopActiveTab();
  activeTab = name;
  for (const btn of document.querySelectorAll(".tabbtn")) {
    const on = btn.dataset.tab === name;
    btn.classList.toggle("on", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
  }
  for (const sec of document.querySelectorAll(".tab")) {
    sec.hidden = sec.id !== "tab-" + name;
  }
  startActiveTab();
}

// Pausing on visibilitychange is not a nicety: a background tab left open
// for hours would otherwise keep the 2s polls and the SSE connection alive
// against a server that is rate-limiting and counting subscribers for them.
document.addEventListener("visibilitychange", () => {
  if (sessionExpired) return;
  if (document.visibilityState === "hidden") stopActiveTab();
  else startActiveTab();
});

// ---- overview ----------------------------------------------------------------

let ovTimer = null;

function startOverview() {
  fetchOverview();
  ovTimer = setInterval(fetchOverview, 2000);
}

function stopOverview() {
  if (ovTimer) {
    clearInterval(ovTimer);
    ovTimer = null;
  }
}

async function fetchOverview() {
  if (sessionExpired) return;
  let m;
  try {
    m = await fetchJSON("/metrics?window=" + encodeURIComponent($("ov-window").value));
  } catch (err) {
    // Stale cards with an error note beat a blank page: the last good
    // snapshot stays up and the status line says why it is not moving.
    $("ov-status").textContent = "metrics unavailable: " + err.message;
    return;
  }
  $("ov-status").textContent = "";
  renderOverview(m);
}

function addStat(parent, label, value) {
  const s = el("div", "stat");
  s.append(el("div", "statlabel", label), el("div", "statvalue", value));
  parent.append(s);
}

// renderOverview rebuilds the cards from one /metrics payload. Every field
// is read defensively (typeof + fallback) so an older binary missing a newer
// counter renders "—" instead of throwing mid-render.
function renderOverview(m) {
  m = m && typeof m === "object" ? m : {};
  const cards = $("ov-cards");
  clear(cards);

  const peak = typeof m.public_connections_peak === "number"
    ? " (peak " + fmtInt(m.public_connections_peak) + ")" : "";
  addStat(cards, "public connections", fmtInt(m.public_connections) + peak);
  addStat(cards, "control connections", fmtInt(m.control_connections));
  addStat(cards, "tunnels active", fmtInt(m.tunnels_active));
  addStat(cards, "connections opened", fmtInt(m.public_conn_open_total));
  addStat(cards, "auth rejects", fmtInt(m.auth_reject_count));
  addStat(cards, "rate-limit drops", fmtInt(m.rate_drop_count));
  addStat(cards, "events dropped",
    fmtInt(m.event_drop_count) +
    (typeof m.event_subscribers === "number" ? " (" + m.event_subscribers + " subscribers)" : ""));
  if (Array.isArray(m.event_destinations)) {
    addStat(cards, "export destinations", fmtInt(m.event_destinations.length));
  }
  addStat(cards, "uptime", fmtDur(m.uptime_seconds));

  const rates = $("ov-rates");
  clear(rates);
  const r = m.rates && typeof m.rates === "object" ? m.rates : null;
  // The rate rows are the inline dashboard's rateSummary numbers: per-second
  // slopes over the selected window.
  const rows = [
    ["public connections opened", r && r.public_conn_open_rate_per_sec],
    ["rate-limit drops", r && r.rate_drop_rate_per_sec],
    ["auth rejects", r && r.auth_reject_rate_per_sec],
  ];
  for (const [label, val] of rows) {
    const tr = el("tr");
    tr.append(el("td", null, label), el("td", "num", fmtRate(val)));
    rates.append(tr);
  }
  if (!r) {
    const tr = el("tr");
    const td = el("td", "muted", "rates unavailable (older server?)");
    td.colSpan = 2;
    tr.append(td);
    rates.append(tr);
  }
  $("ov-window-note").textContent =
    "(" + (typeof m.window_seconds === "number" ? m.window_seconds : "?") + "s window)";
}

// ---- tunnels -------------------------------------------------------------------

let tnTimer = null;

function startTunnels() {
  fetchTunnels();
  tnTimer = setInterval(fetchTunnels, 2000);
}

function stopTunnels() {
  if (tnTimer) {
    clearInterval(tnTimer);
    tnTimer = null;
  }
}

async function fetchTunnels() {
  if (sessionExpired) return;
  let payload;
  try {
    payload = await fetchJSON("/tunnels");
  } catch (err) {
    $("tn-count").textContent = "— " + err.message;
    return;
  }
  renderTunnels(payload);
}

function appendTag(cell, label) {
  cell.append(el("span", "tag", label));
}

// Flags render only when truthy: an older binary omits the enrichment fields
// entirely (spec §3 — additive JSON), and `undefined` is falsy, so the same
// code serves both without a version probe.
const TN_FLAGS = [
  ["internal", "internal"],
  ["agent_tls", "agent-tls"],
  ["pooling", "pool"],
  ["policy_attached", "policy"],
];

function tunnelRow(t) {
  t = t && typeof t === "object" ? t : {};
  const tr = el("tr");

  const urlTd = el("td");
  urlTd.append(el("code", null, nz(t.url, "—")));
  tr.append(urlTd);

  tr.append(el("td", null, nz(t.protocol, "?")));

  const own = el("td");
  if (typeof t.owner === "string" && t.owner !== "") own.append(el("span", "badge", t.owner));
  else own.append(el("span", "muted", "—"));
  tr.append(own);

  const flags = el("td");
  for (const [field, label] of TN_FLAGS) {
    if (t[field]) appendTag(flags, label);
  }
  // forward_to and claimed_port appear only when set — a blank tag cell for
  // every TCP tunnel would be noise, and absence is the common case.
  if (typeof t.forward_to === "string" && t.forward_to !== "") appendTag(flags, "→ " + t.forward_to);
  if (typeof t.claimed_port === "number" && t.claimed_port > 0) appendTag(flags, "port " + t.claimed_port);
  if (!flags.childNodes.length) flags.append(el("span", "muted", "—"));
  tr.append(flags);

  tr.append(el("td", "num", fmtInt(t.active_connections)));
  tr.append(el("td", "num", fmtInt(t.total_connections)));
  tr.append(el("td", "num", fmtBytes(t.bytes_in)));
  tr.append(el("td", "num", fmtBytes(t.bytes_out)));

  const age = el("td", null, fmtAge(t.started_at));
  if (typeof t.started_at === "string") age.title = t.started_at; // exact ISO on hover
  tr.append(age);
  return tr;
}

function renderTunnels(payload) {
  const body = $("tn-body");
  clear(body);
  const list = payload && Array.isArray(payload.tunnels) ? payload.tunnels : [];
  $("tn-count").textContent = list.length + " registered";
  // Sorted by URL so the table holds still between polls instead of
  // shuffling with the server's map iteration order.
  list.sort((a, b) => String((a && a.url) || "").localeCompare(String((b && b.url) || "")));
  if (list.length === 0) {
    const tr = el("tr");
    const td = el("td", "muted", "no tunnels registered");
    td.colSpan = 9;
    tr.append(td);
    body.append(tr);
    return;
  }
  for (const t of list) body.append(tunnelRow(t));
}

// ---- events --------------------------------------------------------------------

let es = null;
const EV_CAP = 500;

function setEvStatus(text) {
  $("ev-status").textContent = text;
}

function startEvents() {
  if (es) return;
  setEvStatus("connecting…");
  es = new EventSource("/events");
  es.onopen = () => setEvStatus("live");
  es.onmessage = (e) => addEventRow(e.data);
  es.onerror = () => {
    // EventSource reconnects on its own while open, so no manual retry here.
    // The status is all we can honestly show: an EventSource does not expose
    // the HTTP status, so a 401 looks like any other drop until one of the
    // polled endpoints (or the reload link) confirms the session died.
    setEvStatus("disconnected — retrying");
  };
}

function stopEvents() {
  if (!es) return;
  es.close();
  es = null;
  setEvStatus("paused");
}

// EV_RENDER maps each server event type to a color class and a one-line
// detail. Field names mirror the typed event structs in
// server/observability.go — that file is the API, this table is its view.
// tunnel_close carries only url today; the protocol is rendered if a future
// server adds it, and ignored otherwise.
const EV_RENDER = {
  tunnel_open: { cls: "ev-open", text: (e) => nz(e.url, "?") + " (" + nz(e.protocol, "?") + ")" },
  tunnel_close: {
    cls: "ev-close",
    text: (e) => nz(e.url, "?") + (e.protocol ? " (" + e.protocol + ")" : ""),
  },
  connection_open: { cls: "ev-open", text: (e) => nz(e.client_addr, "?") + " → " + nz(e.url, "?") },
  connection_close: {
    cls: "ev-close",
    text: (e) => nz(e.url, "?") + " — in " + fmtBytes(e.bytes_in) + ", out " + fmtBytes(e.bytes_out),
  },
  auth_reject: { cls: "ev-reject", text: (e) => "reason: " + nz(e.reason, "?") },
  rate_limit_drop: { cls: "ev-reject", text: (e) => nz(e.scope, "?") + " from " + nz(e.ip, "?") },
  connection_cap_drop: { cls: "ev-reject", text: (e) => nz(e.scope, "?") + " from " + nz(e.ip, "?") },
};

function addEventRow(raw) {
  let ev = null;
  try {
    ev = JSON.parse(raw);
  } catch (_) {
    // stays null: rendered as the raw payload below rather than dropped
  }
  const list = $("ev-list");
  const row = el("div", "evrow");
  row.append(el("span", "evtime", ev && typeof ev.at === "string" ? fmtHMS(ev.at) : "?"));

  const typ = ev && typeof ev.type === "string" ? ev.type : "unparseable";
  // Unknown types (a newer server talking to an older page) still render —
  // as the raw JSON — instead of being silently discarded.
  const spec = EV_RENDER[typ];
  row.classList.add(spec ? spec.cls : "ev-close");
  row.append(el("span", "badge", typ));

  const detail = el("span", "evdetail");
  detail.textContent = spec ? spec.text(ev) : String(raw).slice(0, 300);
  row.append(detail);

  list.insertBefore(row, list.firstChild); // newest top
  // The cap is a DOM budget: a busy server produces rows faster than a page
  // should keep them, so past 500 the oldest fall off the bottom.
  while (list.childNodes.length > EV_CAP) list.removeChild(list.lastChild);
  $("ev-count").textContent = list.childNodes.length + " rows (newest first)";
}

// ---- workbench -----------------------------------------------------------------

// setVerdict is the verdict line's single writer: state null hides the line,
// true/false/pending style it. The line is a <pre> fed with textContent —
// validator messages are multi-line, quote the operator's own document back
// at them, and are still never parsed as HTML.
function setVerdict(ed, state, text) {
  const v = ed.verdict;
  v.classList.remove("ok", "bad", "pending");
  if (state === null) {
    v.hidden = true;
    v.textContent = "";
    return;
  }
  v.classList.add(state === true ? "ok" : state === false ? "bad" : "pending");
  v.textContent = text;
  v.hidden = false;
}

// makeEditor binds one textarea to its validate/render endpoints. debounced
// validation runs only on non-empty text (an empty box is not an error, it
// is an empty box).
function makeEditor(kind, prefix) {
  const ed = {
    kind, // "config" | "policy" — also the /api/render kind value
    ta: $(prefix + "-text"),
    verdict: $(prefix + "-verdict"),
    timer: null,
    // seq orders responses: validation is async and the server makes no
    // ordering promise, so a slow reply to keystroke 3 must not overwrite
    // the verdict already shown for keystroke 5.
    seq: 0,
  };

  const cancelDebounce = () => {
    if (ed.timer) {
      clearTimeout(ed.timer);
      ed.timer = null;
    }
  };

  ed.ta.addEventListener("input", () => {
    cancelDebounce();
    if (ed.ta.value === "") {
      setVerdict(ed, null, null);
      return;
    }
    // 500 ms keystroke-idle, per spec §2: validate-as-you-type without
    // turning every keystroke into an API call.
    ed.timer = setTimeout(() => {
      ed.timer = null;
      validateDoc(ed);
    }, 500);
  });

  $(prefix + "-validate").addEventListener("click", () => {
    cancelDebounce();
    if (ed.ta.value === "") {
      setVerdict(ed, null, null);
      return;
    }
    validateDoc(ed);
  });

  $(prefix + "-render").addEventListener("click", () => renderDoc(ed));
  return ed;
}

async function validateDoc(ed) {
  if (sessionExpired) return;
  const n = ++ed.seq;
  setVerdict(ed, "pending", "validating…");
  try {
    const out = await postJSON("/api/validate/" + ed.kind, { content: ed.ta.value });
    if (n !== ed.seq) return; // a newer keystroke already spoke
    if (out.valid === true) setVerdict(ed, true, "valid");
    else if (out.valid === false) setVerdict(ed, false, out.error || "invalid (no detail given)");
    else setVerdict(ed, false, "unexpected response: " + JSON.stringify(out).slice(0, 300));
  } catch (err) {
    if (n !== ed.seq) return;
    // 4xx transport faults (400 envelope, 413 oversize, 422 vault refusal)
    // land here with the body's error text — rendered same as a verdict.
    setVerdict(ed, false, err.message);
  }
}

// renderDoc asks the server for the canonical re-marshal of the document and
// hands the bytes to the browser as a download. There is deliberately no
// "save": the server has no file-writing endpoint (spec non-goals), and a
// button that only pretended to save would be worse than none.
async function renderDoc(ed) {
  if (sessionExpired) return;
  if (ed.ta.value === "") {
    setVerdict(ed, null, null);
    return;
  }
  const n = ++ed.seq;
  setVerdict(ed, "pending", "rendering…");
  try {
    const out = await postJSON("/api/render", { kind: ed.kind, content: ed.ta.value });
    if (n !== ed.seq) return;
    if (out.valid === true && typeof out.rendered === "string") {
      download(out.rendered, ed.kind === "config" ? "ngrok-config.yaml" : "traffic-policy.yaml");
      setVerdict(ed, true, "rendered " + out.rendered.length + " bytes — download started");
    } else if (out.valid === false) {
      setVerdict(ed, false, out.error || "invalid (no detail given)");
    } else {
      setVerdict(ed, false, "unexpected response: " + JSON.stringify(out).slice(0, 300));
    }
  } catch (err) {
    if (n !== ed.seq) return;
    setVerdict(ed, false, err.message);
  }
}

function download(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
  const a = el("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  // Revoked on a delay rather than same-tick: the click has the bytes by
  // then in current engines, but a same-tick revoke has historically
  // cancelled in-flight downloads.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---- schema sidebar ------------------------------------------------------------

// Fetched once on first expand and cached; a failed fetch leaves the cache
// empty so closing and reopening the panel retries.
let schemaCache = null;

function toggleSchema() {
  const body = $("schema-body");
  const opening = body.hidden;
  body.hidden = !opening;
  $("schema-toggle").setAttribute("aria-expanded", opening ? "true" : "false");
  $("schema-toggle").textContent = opening ? "Schema ▾" : "Schema ▸";
  if (opening && !schemaCache) loadSchema();
}

async function loadSchema() {
  const body = $("schema-body");
  clear(body);
  body.append(el("div", "muted", "loading…"));
  try {
    schemaCache = await fetchJSON("/api/schema");
  } catch (err) {
    schemaCache = null; // retry on next open
    if (sessionExpired) return;
    clear(body);
    body.append(el("div", "verdict bad", err.message));
    return;
  }
  renderSchema(schemaCache);
}

// renderSchema shows the two config key groups and the policy action list.
// The policy "phases" map from the payload is not rendered separately: every
// action row already carries its phases, and the map is the same fact keyed
// the other way.
function renderSchema(s) {
  const body = $("schema-body");
  clear(body);
  const cfg = s && s.config && typeof s.config === "object" ? s.config : {};
  schemaGroup(body, "config — top level", cfg.top_level);
  schemaGroup(body, "config — per tunnel (tunnels.<name>.<key>)", cfg.tunnel);
  const pol = s && s.policy && typeof s.policy === "object" ? s.policy : {};
  policyActions(body, pol.actions);
}

// schemaGroup renders one table of {key, type, default, summary} rows.
// Defaults print via JSON.stringify so an empty-string default shows as ""
// instead of an innocent-looking blank cell.
function schemaGroup(parent, title, rows) {
  parent.append(el("h3", null, title));
  if (!Array.isArray(rows) || rows.length === 0) {
    parent.append(el("div", "muted", "unavailable (older server?)"));
    return;
  }
  const wrap = el("div", "tablewrap");
  const table = el("table");
  const tb = el("tbody");
  for (const r of rows) {
    const row = r && typeof r === "object" ? r : {};
    const tr = el("tr");
    const key = el("td");
    key.append(el("code", null, nz(row.key, "?")));
    tr.append(key);
    tr.append(el("td", "muted", nz(row.type, "?")));
    tr.append(el("td", "muted", "default" in row ? JSON.stringify(row.default) : "—"));
    tr.append(el("td", null, nz(row.summary, "")));
    tb.append(tr);
  }
  table.append(tb);
  wrap.append(table);
  parent.append(wrap);
}

function policyActions(parent, actions) {
  parent.append(el("h3", null, "policy — actions by phase"));
  if (!Array.isArray(actions) || actions.length === 0) {
    parent.append(el("div", "muted", "unavailable (older server?)"));
    return;
  }
  const wrap = el("div", "tablewrap");
  const table = el("table");
  const tb = el("tbody");
  for (const a of actions) {
    const row = a && typeof a === "object" ? a : {};
    const tr = el("tr");
    const name = el("td");
    name.append(el("code", null, nz(row.name, "?")));
    tr.append(name);
    const phases = el("td");
    const list = Array.isArray(row.phases) ? row.phases : [];
    for (const p of list) phases.append(el("span", "tag", String(p)));
    tr.append(phases);
    tr.append(el("td", null, nz(row.summary, "")));
    tb.append(tr);
  }
  table.append(tb);
  wrap.append(table);
  parent.append(wrap);
}

// ---- wiring ----------------------------------------------------------------

// Wiring runs at the bottom; the script tag is end-of-body, so the DOM is up
// and every handler above is defined before anything can be clicked.
for (const btn of document.querySelectorAll(".tabbtn")) {
  btn.addEventListener("click", () => activate(btn.dataset.tab));
}
$("ov-window").addEventListener("change", () => {
  if (activeTab === "overview" && !document.hidden) fetchOverview();
});
$("ev-clear").addEventListener("click", () => {
  clear($("ev-list"));
  $("ev-count").textContent = "0 rows (newest first)";
});
$("schema-toggle").addEventListener("click", toggleSchema);

makeEditor("config", "cfg");
makeEditor("policy", "pol");
activate("overview");
