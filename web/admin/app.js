/* piso-hotspot admin — the operator's phone is the primary screen.
   Three views (Dashboard, Devices, Settings) over /api/state +
   /api/control. No framework: one state object, re-rendered on change;
   /api/state is polled every 3s while the tab is visible. */
"use strict";

const app = document.getElementById("app");

// ------------------------------------------------------------- plumbing

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  let body = null;
  try { body = await res.json(); } catch (_) { /* empty body */ }
  return { res, body };
}

/** Tiny DOM helper: h("td", {class:"num"}, "12") */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (v === true) { el.setAttribute(k, ""); continue; }
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function fmtBytes(n) {
  if (n == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Number(n), u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return (u === 0 ? v : v.toFixed(1)) + " " + units[u];
}

function fmtMoney(minor, currency) {
  if (minor == null) return "—";
  return (minor / 100).toFixed(2) + " " + currency;
}

function fmtAgo(ts, now) {
  if (!ts) return "—";
  const s = Math.max(0, now - ts);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

function fmtLeft(expires, now) {
  if (!expires) return "—";
  let s = Math.round(expires - now);
  if (s <= 0) return "expired";
  const d = Math.floor(s / 86400); s %= 86400;
  const hh = Math.floor(s / 3600); s %= 3600;
  const mm = Math.floor(s / 60);
  if (d) return d + "d " + hh + "h";
  if (hh) return hh + "h " + mm + "m";
  return mm + "m " + (s % 60) + "s";
}

function fmtUp(started, now) {
  return fmtLeft(null, null) && (() => {
    let s = Math.max(0, now - started);
    const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60);
    return hh + "h " + mm + "m";
  })();
}

// ------------------------------------------------------------- app state

const S = {
  view: "dashboard",        // dashboard | devices | settings
  data: null,               // last /api/state payload
  now: Math.floor(Date.now() / 1000),
  flash: null,              // {kind:"ok"|"err", text}
  busy: false,              // a control request is in flight
};

function flash(kind, text) {
  S.flash = { kind, text };
  render();
  setTimeout(() => { if (S.flash?.text === text) { S.flash = null; render(); } }, 4000);
}

async function control(payload, okText) {
  if (S.busy) return;
  S.busy = true;
  render();
  try {
    const { res, body } = await api("/api/control", {
      method: "POST", body: JSON.stringify(payload),
    });
    if (res.ok) flash("ok", okText || "done");
    else flash("err", body?.error || "request failed (" + res.status + ")");
    await refresh();
  } finally {
    S.busy = false;
    render();
  }
}

async function refresh() {
  const { res, body } = await api("/api/state");
  if (res.status === 401) { renderLogin("session expired — log in again"); return; }
  if (res.ok && body) S.data = body;
  render();
}

// Poll only while visible; instant refresh when the tab returns.
let pollTimer = null;
function startPolling() {
  stopPolling();
  pollTimer = setInterval(() => {
    if (document.visibilityState === "visible") refresh();
  }, 3000);
}
function stopPolling() { clearInterval(pollTimer); pollTimer = null; }
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refresh();
});

// ------------------------------------------------------------- login

function renderLogin(error) {
  stopPolling();
  app.replaceChildren(
    h("div", { class: "card login" },
      h("h1", {}, "piso-hotspot"),
      h("p", { class: "muted" }, "admin panel"),
      error ? h("p", { class: "error" }, error) : "",
      h("form", { onsubmit: onLogin },
        h("input", {
          type: "password", name: "passphrase",
          autocomplete: "current-password", placeholder: "passphrase",
          required: "required", autofocus: "autofocus",
        }),
        h("button", { type: "submit", class: "primary wide" }, "log in"),
      ),
    ),
  );
}

async function onLogin(e) {
  e.preventDefault();
  const passphrase = new FormData(e.target).get("passphrase");
  const { res, body } = await api("/api/login", {
    method: "POST", body: JSON.stringify({ passphrase }),
  });
  if (res.ok) {
    S.view = "dashboard";
    await refresh();
    startPolling();
  } else {
    const retry = res.headers.get("Retry-After");
    renderLogin((body?.error || "wrong passphrase") + (retry ? ` — try again in ${retry}s` : ""));
  }
}

// ------------------------------------------------------------- shell

function nav(view, label) {
  return h("button", {
    class: "tab" + (S.view === view ? " active" : ""),
    onclick: () => { S.view = view; render(); },
  }, label);
}

function shell(content) {
  const d = S.data;
  app.replaceChildren(
    h("header", { class: "topbar" },
      h("span", { class: "brand" }, "piso-hotspot"),
      h("span", { class: "muted small" },
        d ? `${d.status.mode} · ${d.status.devices_seen} devices` : ""),
    ),
    S.flash ? h("div", { class: "flash " + S.flash.kind }, S.flash.text) : "",
    h("nav", { class: "tabs" },
      nav("dashboard", "Dashboard"),
      nav("devices", "Devices"),
      nav("settings", "Settings"),
    ),
    h("main", {}, content),
  );
}

// ------------------------------------------------------------- dashboard

function deviceName(dev) {
  return dev.label || dev.mac;
}

function dashboard() {
  const d = S.data;
  if (!d) return h("p", { class: "muted" }, "loading…");
  const s = d.status;
  const t = d.traffic;
  const paidDevices = d.devices.filter(x => x.state === "paid");
  const unpaid = d.devices.filter(x => x.state !== "paid" && !isFriendMac(d, x.mac));

  const cards = h("div", { class: "cards" },
    card("revenue today", fmtMoney(d.revenue_today.total_minor, d.currency),
      `${d.revenue_today.count} sold`),
    card("active passes", String(s.active_passes),
      `${paidDevices.length} paid now`),
    card("devices", String(s.devices_seen),
      `${unpaid.length} waiting`),
    card("traffic moved", fmtBytes((t.allowed?.bytes || 0) + (t.friends?.bytes || 0)),
      `${fmtBytes(t.blocked?.bytes || 0)} blocked`),
  );

  const passes = h("div", { class: "card" },
    h("h2", {}, "sell a pass"),
    d.devices.length === 0
      ? h("p", { class: "muted" }, "no devices yet — they appear when a client associates and gets a lease")
      : h("div", { class: "sellrow" },
          h("select", { id: "sell-mac" },
            d.devices.map(x =>
              h("option", { value: x.mac }, `${deviceName(x)} (${x.state})`))),
          d.passes.map(p =>
            h("button", {
              class: "primary",
              disabled: S.busy,
              onclick: () => control(
                { cmd: "grant", mac: document.getElementById("sell-mac").value, pass: p.id },
                `${p.name} granted`),
            }, `${p.name} · ${fmtMoney(p.price_minor, d.currency)}`)),
        ),
  );

  return h("div", {},
    cards,
    passes,
    h("div", { class: "card" },
      h("h2", {}, "live traffic"),
      h("table", { class: "kv" },
        trafficRow("paid (allowed set)", t.allowed),
        trafficRow("friends", t.friends),
        trafficRow("blocked / unpaid", t.blocked),
      ),
      h("p", { class: "muted small" }, "per-packet kernel counters, keyed by MAC — a payer cannot hide a friend's traffic"),
    ),
    h("div", { class: "card" },
      h("h2", {}, "hotspot"),
      h("table", { class: "kv" },
        kv("mode", `${s.mode} (${s.ap_iface}${s.uplink ? " → " + s.uplink : ""})`),
        kv("gateway", s.gateway),
        kv("uptime", fmtUp(s.started_at, S.now)),
        kv("panel", h("span", {},
          s.panel_urls.map((u, i) => [i ? " " : "", h("a", { href: u }, u.replace(/^http:\/\//, ""))])),
        ),
        kv("version", "v" + s.version),
      ),
    ),
  );
}

function trafficRow(label, t) {
  return h("tr", {},
    h("td", {}, label),
    h("td", { class: "num" }, fmtBytes(t?.bytes)),
    h("td", { class: "num muted" }, (t?.packets ?? 0) + " pkts"),
  );
}

function card(label, big, small) {
  return h("div", { class: "card stat" },
    h("div", { class: "muted small" }, label),
    h("div", { class: "big" }, big),
    h("div", { class: "muted small" }, small),
  );
}

function kv(k, v) {
  return h("tr", {}, h("td", {}, k), h("td", {}, v));
}

function isFriendMac(d, mac) {
  return d.friends.some(f => f.mac === mac);
}

// ------------------------------------------------------------- devices

function devices() {
  const d = S.data;
  if (!d) return h("p", { class: "muted" }, "loading…");
  const friendMacs = new Set(d.friends.map(f => f.mac));

  const rows = d.devices.map(dev => {
    const isFriend = friendMacs.has(dev.mac);
    const state =
      isFriend ? "friend" :
      dev.state === "paid" && dev.expires_at > S.now ? "paid · " + fmtLeft(dev.expires_at, S.now) :
      dev.state;
    return h("tr", {},
      h("td", {},
        h("div", { class: "devname" }, deviceName(dev)),
        h("div", { class: "muted small mono" }, dev.mac),
      ),
      h("td", {},
        h("span", { class: "pill " + (isFriend ? "friend" : dev.state) }, state),
        h("div", { class: "muted small" },
          "seen " + fmtAgo(dev.last_seen, S.now)),
      ),
      h("td", { class: "num" }, fmtBytes(d.traffic.by_mac?.[dev.mac]?.bytes)),
      h("td", { class: "actions" },
        isFriend
          ? h("button", { disabled: S.busy,
              onclick: () => control({ cmd: "unfriend", mac: dev.mac }, "unfriended") },
              "unfriend")
          : h("button", { disabled: S.busy,
              onclick: () => control({ cmd: "friend", mac: dev.mac, label: dev.label }, "friended — free access") },
              "friend"),
        h("button", { disabled: S.busy, class: "danger",
          onclick: () => control({ cmd: "revoke", mac: dev.mac }, "revoked") },
          "revoke"),
        h("button", { disabled: S.busy,
          onclick: () => renamePrompt(dev) }, "rename"),
      ),
    );
  });

  return h("div", {},
    h("div", { class: "card" },
      h("h2", {}, "devices"),
      rows.length === 0
        ? h("p", { class: "muted" }, "no devices seen yet")
        : h("table", { class: "devices" }, h("tbody", {}, rows)),
    ),
    h("div", { class: "card" },
      h("h2", {}, "friends"),
      d.friends.length === 0
        ? h("p", { class: "muted" }, "none — friends bypass the paywall entirely")
        : h("ul", {}, d.friends.map(f =>
            h("li", {}, h("span", { class: "mono" }, f.mac),
              f.label ? " — " + f.label : "",
              " ", h("button", { disabled: S.busy, class: "link",
                onclick: () => control({ cmd: "unfriend", mac: f.mac }, "unfriended") },
                "remove")))),
      h("p", { class: "muted small" },
        "add from the Devices table; friends cannot be revoked, only unfriended"),
    ),
  );
}

function renamePrompt(dev) {
  const name = prompt("Label for " + dev.mac, dev.label || "");
  if (name === null) return;
  control({ cmd: "rename", mac: dev.mac, label: name.trim() || null },
    name.trim() ? "renamed" : "label cleared");
}

// ------------------------------------------------------------- settings

function settings() {
  const d = S.data;
  if (!d) return h("p", { class: "muted" }, "loading…");
  const s = d.status;
  const theme = localStorage.getItem("piso-theme") || "auto";

  return h("div", {},
    h("div", { class: "card" },
      h("h2", {}, "appearance"),
      h("div", { class: "seg" },
        ["auto", "light", "dark"].map(t =>
          h("button", {
            class: theme === t ? "active" : "",
            onclick: () => setTheme(t),
          }, t)),
      ),
    ),
    h("div", { class: "card" },
      h("h2", {}, "passes"),
      h("table", { class: "kv" },
        d.passes.map(p => h("tr", {},
          h("td", {}, p.name),
          h("td", { class: "num" }, fmtMoney(p.price_minor, d.currency),
            h("div", { class: "muted small" }, p.id)),
        )),
      ),
      h("p", { class: "muted small" }, "configured in /etc/piso-hotspot/config.json — restart to apply"),
    ),
    h("div", { class: "card" },
      h("h2", {}, "limits"),
      h("table", { class: "kv" },
        kv("download cap", fmtBytes(d.caps?.max_down_bytes_per_sec) + "/s"),
        kv("upload cap", d.caps?.max_up_bytes_per_sec
          ? fmtBytes(d.caps.max_up_bytes_per_sec) + "/s" : "uncapped"),
        kv("max clients", d.caps?.max_clients ?? "—"),
      ),
      h("p", { class: "muted small" }, "from config.json; restart to apply"),
    ),
    h("div", { class: "card" },
      h("h2", {}, "session"),
      h("table", { class: "kv" },
        kv("passphrase", revealPass(),
          " ", h("button", { class: "link", onclick: copyPass }, "copy")),
        kv("source", s.passphrase_source),
        kv("active sessions", String(s.sessions)),
      ),
      h("button", { class: "danger wide", disabled: S.busy,
        onclick: () => {
          if (confirm("Shut the hotspot down? Every client loses the network.")) {
            control({ cmd: "shutdown" }, "shutting down…");
          }
        } },
        "shut down hotspot"),
    ),
  );
}

function setTheme(t) {
  localStorage.setItem("piso-theme", t);
  if (t === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  render();
}

/** The passphrase is fetched on demand, never carried in /api/state. */
let PASS_CACHE = null;

async function fetchPass() {
  if (PASS_CACHE) return PASS_CACHE;
  const { res, body } = await api("/api/passphrase");
  if (!res.ok) throw new Error(body?.error || `request failed (${res.status})`);
  PASS_CACHE = body.admin_passphrase;
  return PASS_CACHE;
}

function revealPass() {
  const out = h("span", { class: "mono" }, "••••••••");
  const button = h("button", {
    class: "link",
    onclick: async () => {
      try {
        out.textContent = await fetchPass();
        button.remove();
      } catch (e) { flash("err", String(e.message || e)); }
    },
  }, "reveal");
  return h("span", {}, out, " ", button);
}

async function copyPass() {
  try {
    await navigator.clipboard?.writeText(await fetchPass());
    flash("ok", "passphrase copied");
  } catch (e) {
    flash("err", "clipboard blocked by browser");
  }
}

// ------------------------------------------------------------- root render

function render() {
  if (!S.data) { return; } // login/loading owns the screen
  S.now = Math.floor(Date.now() / 1000);
  const body =
    S.view === "devices" ? devices() :
    S.view === "settings" ? settings() :
    dashboard();
  shell(body);
}

(async () => {
  const { body } = await api("/api/auth");
  if (body?.authenticated) {
    await refresh();
    startPolling();
  } else {
    renderLogin();
  }
})();
