/* piso-hotspot admin panel.
 *
 * One file, no framework: a state object, three views (dashboard,
 * devices, settings) rendered into #app, and /api/state polled every few
 * seconds while the tab is visible. Everything that changes who has
 * internet goes through the same control lane as the CLI, and every such
 * action asks for confirmation first.
 *
 * The numbers come from the daemon's last reconcile tick, not from a
 * fresh kernel dump per poll, so an open panel does not make the hotspot
 * do work.
 */
"use strict";

const app = document.getElementById("app");
const toasts = document.getElementById("toasts");

const POLL_MS = 4000;

/* ------------------------------------------------------------------ state */

const S = {
  data: null,        // last /api/state payload
  view: "dashboard",
  busy: false,
  edit: null,        // device whose rename dialog is open
  prevRates: null,   // {at, byMac, up, down} from the previous poll
  rates: {},         // mac -> {up, down} bytes per second
  totals: { up: 0, down: 0, blocked: 0, at: 0 },
  filter: "all",
  errors: [],        // validation messages from the last settings save
  drafts: {},        // settings fields the operator has touched but not saved
};

/* ------------------------------------------------------------- plumbing */

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

/** Tiny DOM helper: h("td", {class:"num"}, "12"). */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (value === true) { el.setAttribute(key, ""); continue; }
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el[key] = value;
    else el.setAttribute(key, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

/* ----------------------------------------------------------- formatting */

function fmtBytes(n) {
  if (n == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Number(n), unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return (unit === 0 ? value.toFixed(0) : value.toFixed(1)) + " " + units[unit];
}

function fmtRate(bytesPerSec) {
  if (bytesPerSec == null) return "—";
  if (bytesPerSec < 1) return "0 B/s";
  return fmtBytes(bytesPerSec) + "/s";
}

function fmtMoney(minor, currency) {
  if (minor == null) return "—";
  return (minor / 100).toFixed(2) + " " + (currency || "");
}

function fmtAgo(ts, now) {
  if (!ts) return "—";
  const seconds = Math.max(0, now - ts);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
}

function fmtClock(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function fmtDuration(seconds) {
  if (seconds == null) return "until midnight";
  if (seconds % 3600 === 0) return (seconds / 3600) + "h";
  if (seconds % 60 === 0) return (seconds / 60) + " min";
  return seconds + "s";
}

function humanAction(row) {
  const where = row.mac ? row.mac : "";
  const who = row.actor === "cli" ? "the command line" : "the panel (" + String(row.actor).replace(/^panel:/, "") + ")";
  switch (row.action) {
    case "grant": return `sold ${row.pass_id || "a pass"} to ${where} — ${row.detail || ""}`;
    case "revoke": return `cut off ${where}`;
    case "friend": return `gave ${where} free access`;
    case "unfriend": return `removed ${where} from friends`;
    case "rename": return `renamed ${where} to ${row.detail ? `"${row.detail}"` : "nothing"}`;
    case "shutdown": return "shut the hotspot down";
    case "settings": return `changed settings: ${row.detail || ""}`;
    default: return `${row.action} ${where}`.trim();
  }
}

/* ----------------------------------------------------------------- toasts */

function flash(kind, message, ttl = 4200) {
  const node = h("div", { class: "toast " + kind }, message);
  toasts.append(node);
  setTimeout(() => node.remove(), ttl);
}

function notesToToast(notes) {
  for (const note of notes || []) flash("warn", note, 7000);
}

/* ----------------------------------------------------------------- modal */

/** A promise-returning confirmation dialog: the panel never changes who
 *  has internet on a single stray tap. */
function ask({ title, body, choices, confirm, danger }) {
  return new Promise((resolve) => {
    const close = (result) => { backdrop.remove(); document.removeEventListener("keydown", onKey); resolve(result); };
    const onKey = (event) => { if (event.key === "Escape") close(null); };
    let content;
    if (choices) {
      content = h("div", { class: "choices" },
        choices.map((choice) =>
          h("button", {
            class: "ghost",
            onclick: () => close(choice),
          }, h("span", {}, choice.label), choice.price ? h("span", { class: "price" }, choice.price) : null)),
      );
    } else {
      content = h("div", { class: "actions" },
        h("button", {
          class: danger ? "danger" : "primary",
          onclick: () => close(true),
        }, confirm || "confirm"),
        h("button", { class: "ghost", onclick: () => close(null) }, "cancel"),
      );
    }
    const backdrop = h("div", {
      class: "modal-backdrop",
      onclick: (event) => { if (event.target === backdrop) close(null); },
    },
      h("div", { class: "modal", role: "dialog", "aria-modal": "true" },
        h("h3", {}, title),
        body ? h("p", {}, body) : null,
        content,
      ),
    );
    document.addEventListener("keydown", onKey);
    document.body.append(backdrop);
    const first = backdrop.querySelector("button");
    if (first) first.focus();
  });
}

/* --------------------------------------------------------------- actions */

async function control(request, successMessage) {
  if (S.busy) return null;
  S.busy = true;
  S.lastError = null;
  try {
    const { res, body } = await api("/api/control", { method: "POST", body: JSON.stringify(request) });
    if (!res.ok) {
      if (res.status === 401) { S.data = null; render(); return null; }
      S.lastError = (body && body.error) || `request failed (${res.status})`;
      flash("err", S.lastError);
      return null;
    }
    // A refused action answers 200 with ok:false and the reason: the
    // daemon explains itself, and the panel shows that explanation.
    if (body && body.error) { S.lastError = body.error; flash("err", body.error); return null; }
    if (successMessage) flash("ok", successMessage);
    await refresh();
    return body;
  } finally {
    S.busy = false;
  }
}

function deviceName(device) {
  return device.label || device.mac;
}

function devicePill(device, friends) {
  if (friends.some((f) => f.mac === device.mac)) return h("span", { class: "pill friend" }, "friend");
  if (device.state === "paid" && device.expires_at && device.expires_at > S.now) {
    return h("span", { class: "pill paid" }, "paid");
  }
  if (device.state === "expired") return h("span", { class: "pill expired" }, "expired");
  return h("span", { class: "pill unauthorized" }, "waiting");
}

async function sellPass(deviceMac, deviceLabel) {
  const passes = (S.data.passes || []);
  if (!passes.length) { flash("err", "no passes are configured"); return; }
  const choice = await ask({
    title: "sell a pass",
    body: `Which pass for ${deviceLabel || deviceMac}?`,
    choices: passes.map((pass) => ({
      id: pass.id,
      label: `${pass.name} · ${fmtDuration(pass.duration_secs)}`,
      price: fmtMoney(pass.price_minor, S.data.currency),
    })),
  });
  if (!choice) return;
  const pass = passes.find((p) => p.id === choice.id);
  const confirmed = await ask({
    title: "confirm sale",
    body: `${pass.name} for ${deviceLabel || deviceMac} at ${fmtMoney(pass.price_minor, S.data.currency)}? ` +
      `Internet starts as soon as you confirm.`,
    confirm: "sell it",
  });
  if (!confirmed) return;
  const body = await control({ cmd: "grant", mac: deviceMac, pass: pass.id },
    `sold ${pass.name} to ${deviceLabel || deviceMac}`);
  if (body && body.expires_at) flash("ok", `until ${fmtClock(body.expires_at)}`, 5000);
}

async function revoke(device) {
  const confirmed = await ask({
    title: "cut off",
    body: `Take internet away from ${deviceName(device)}? They keep their wifi connection.`,
    confirm: "cut them off",
    danger: true,
  });
  if (!confirmed) return;
  await control({ cmd: "revoke", mac: device.mac }, `${deviceName(device)} has no internet now`);
}

async function makeFriend(device) {
  const confirmed = await ask({
    title: "free access",
    body: `${deviceName(device)} would bypass the paywall forever — no pass, no expiry, ` +
      `no limit. You can undo it with "unfriend".`,
    confirm: "give free access",
    danger: true,
  });
  if (!confirmed) return;
  await control({ cmd: "friend", mac: device.mac, label: device.label || null },
    `${deviceName(device)} is now a friend`);
}

async function unfriend(device) {
  const confirmed = await ask({
    title: "remove free access",
    body: `${deviceName(device)} will need a pass again.`,
    confirm: "unfriend",
    danger: true,
  });
  if (!confirmed) return;
  await control({ cmd: "unfriend", mac: device.mac }, `${deviceName(device)} is no longer a friend`);
}

function rename(device) {
  const input = h("input", {
    type: "text",
    value: device.label || "",
    maxlength: 50,
    placeholder: "e.g. Juan's laptop",
  });
  const save = h("button", { class: "primary" }, "save label");
  const clear = h("button", { class: "ghost" }, "clear");
  const backdrop = h("div", { class: "modal-backdrop" },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true" },
      h("h3", {}, "name this device"),
      h("p", {}, "Up to 50 characters — it shows in the list, the panel and the CLI."),
      h("label", { class: "field" }, h("span", {}, "label"), input),
      h("div", { class: "actions" }, save, clear,
        h("button", { class: "ghost", onclick: () => backdrop.remove() }, "cancel")),
    ),
  );
  const submit = async (value) => {
    backdrop.remove();
    await control({ cmd: "rename", mac: device.mac, label: value },
      value ? `renamed to ${value}` : "label cleared");
  };
  save.onclick = () => submit(input.value.trim() || null);
  clear.onclick = () => submit(null);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit(input.value.trim() || null);
    if (event.key === "Escape") backdrop.remove();
  });
  document.body.append(backdrop);
  input.focus();
}

/* ------------------------------------------------------------------ views */

function healthBanner() {
  const status = S.data.status;
  const warnings = status.warnings || [];
  if (!warnings.length) return null;
  return h("div", { class: "banner bad" },
    h("strong", {}, warnings.length === 1 ? "one thing needs attention" : warnings.length + " things need attention"),
    h("ul", {}, warnings.map((warning) => h("li", {}, warning))),
  );
}

function dashboard() {
  const d = S.data, status = d.status;
  const traffic = d.traffic || { up: {}, down: {}, blocked: {}, by_mac: {} };
  const at = traffic.measured_at || 0;
  const rates = S.rates;

  const stat = (label, value, hint) =>
    h("div", { class: "stat" },
      h("div", { class: "label" }, label),
      h("div", { class: "value" }, value),
      hint ? h("div", { class: "hint" }, hint) : null,
    );

  const rateSum = (key) => Object.values(rates).reduce((sum, r) => sum + (r[key] || 0), 0);

  return [
    healthBanner(),
    h("div", { class: "card" },
      h("h2", {}, "right now"),
      h("div", { class: "stats" },
        stat("devices seen", String(status.devices_seen), (d.friends || []).length + " friends"),
        stat("active passes", String(status.active_passes), `${status.sessions} panel session(s)`),
        stat("sales today", fmtMoney(d.revenue_today ? d.revenue_today.total_minor : 0, d.currency), d.revenue_today ? `${d.revenue_today.count} sold` : ""),
        stat("uptime", fmtAgo(status.started_at, S.now).replace(" ago", ""), `started ${fmtClock(status.started_at)}`),
      ),
    ),
    h("div", { class: "card" },
      h("h2", {}, "traffic"),
      h("div", { class: "stats" },
        stat("download", fmtBytes(traffic.down.bytes), fmtRate(rateSum("down"))),
        stat("upload", fmtBytes(traffic.up.bytes), fmtRate(rateSum("up"))),
        stat("blocked", fmtBytes(traffic.blocked.bytes), "waiting devices, dropped"),
        stat("counted", at ? fmtAgo(at, S.now) : "—", "kernel counters, refreshed by the daemon"),
      ),
      h("p", { class: "hint" },
        "Counted in the kernel per device, both directions: uploads by the device's MAC, ",
        "downloads by the address it holds. Since the daemon's last restart."),
    ),
    sellCard(),
    activityCard(),
  ];
}

function sellCard() {
  const devices = S.data.devices;
  const input = h("input", {
    type: "text",
    placeholder: "device MAC, e.g. aa:bb:cc:dd:ee:ff",
    list: "device-macs",
    spellcheck: "false",
  });
  const datalist = h("datalist", { id: "device-macs" },
    devices.map((device) => h("option", { value: device.mac }, device.label || "")));
  const button = h("button", { class: "primary" }, "choose a pass");
  button.onclick = () => {
    const mac = input.value.trim().toLowerCase();
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
      flash("err", "that does not look like a MAC address");
      return;
    }
    const device = devices.find((row) => row.mac === mac);
    sellPass(mac, device ? device.label : null);
  };
  return h("div", { class: "card" },
    h("h2", {}, "sell a pass"),
    h("label", { class: "field" },
      h("span", {}, "device"),
      input,
    ),
    datalist,
    button,
    h("p", { class: "hint" }, "Devices appear here once they get a DHCP lease from the hotspot."),
  );
}

function activityCard() {
  const rows = (S.data.audit || []).slice(0, 8);
  return h("div", { class: "card" },
    h("h2", {}, "recent changes"),
    rows.length === 0
      ? h("p", { class: "muted" }, "Nothing yet. Grants, revokes, friends and logins show up here.")
      : h("ul", { class: "devices" },
        rows.map((row) =>
          h("li", {},
            h("div", { class: "device-head" },
              h("span", { class: "device-name" }, humanAction(row)),
              h("span", { class: "muted small nowrap" }, fmtAgo(row.ts, S.now)),
            ),
            h("div", { class: "device-meta" }, row.actor),
          ))),
  );
}

function devicesView() {
  const d = S.data;
  const friends = d.friends || [];
  const now = S.now;
  const wanted = d.devices.filter((device) => {
    const isFriend = friends.some((f) => f.mac === device.mac);
    const paid = device.state === "paid" && device.expires_at && device.expires_at > now;
    if (S.filter === "paid") return paid;
    if (S.filter === "waiting") return !paid && !isFriend;
    if (S.filter === "friends") return isFriend;
    return true;
  });

  const filterButton = (key, label) =>
    h("button", {
      class: S.filter === key ? "primary" : "ghost",
      onclick: () => { S.filter = key; render(); },
    }, label);

  return [
    h("div", { class: "card tight" },
      h("div", { class: "row" },
        filterButton("all", `all (${d.devices.length})`),
        filterButton("paid", "paying"),
        filterButton("waiting", "waiting"),
        filterButton("friends", `friends (${friends.length})`),
      ),
    ),
    h("div", { class: "card" },
      h("h2", {}, "devices"),
      wanted.length === 0
        ? h("p", { class: "muted" }, "No devices here. Clients show up after their first DHCP lease.")
        : h("ul", { class: "devices" }, wanted.map((device) => deviceRow(device, friends))),
    ),
  ];
}

function deviceRow(device, friends) {
  const now = S.now;
  const isFriend = friends.some((f) => f.mac === device.mac);
  const paid = device.state === "paid" && device.expires_at && device.expires_at > now;
  const traffic = (S.data.traffic.by_mac || {})[device.mac] || {};
  const rate = S.rates[device.mac] || {};

  const actions = [];
  if (!isFriend) {
    actions.push(h("button", {
      class: "primary",
      onclick: () => sellPass(device.mac, device.label),
    }, paid ? "extend" : "sell pass"));
  }
  if (paid && !isFriend) {
    actions.push(h("button", { class: "danger", onclick: () => revoke(device) }, "cut off"));
  }
  actions.push(isFriend
    ? h("button", { class: "ghost", onclick: () => unfriend(device) }, "unfriend")
    : h("button", { class: "ghost", onclick: () => makeFriend(device) }, "free access"));
  actions.push(h("button", { class: "ghost", onclick: () => rename(device) }, "rename"));

  return h("li", {},
    h("div", { class: "device-head" },
      h("span", { class: "device-name" }, deviceName(device)),
      devicePill(device, friends),
    ),
    h("div", { class: "device-meta" },
      device.mac,
      device.ip ? " · " + device.ip : "",
      " · seen " + fmtAgo(device.last_seen, now),
    ),
    h("div", { class: "device-stats" },
      paid ? h("span", {}, `pass ${device.pass_id} until ${fmtClock(device.expires_at)}`) : null,
      h("span", {}, "↓ " + fmtBytes(traffic.down_bytes || 0)),
      h("span", {}, "↑ " + fmtBytes(traffic.up_bytes || 0)),
      rate.down || rate.up ? h("span", {}, `now ${fmtRate(rate.down || 0)} ↓ ${fmtRate(rate.up || 0)} ↑`) : null,
      traffic.blocked_bytes ? h("span", {}, "dropped " + fmtBytes(traffic.blocked_bytes)) : null,
    ),
    h("div", { class: "actions device-actions" }, actions),
  );
}

/* --------------------------------------------------------------- settings */

function settingsDraft() {
  const settings = S.data.settings;
  return {
    ssid: settings.network.ssid,
    security: settings.network.security,
    passphrase: "",
    passphraseTouched: false,
    channel: String(settings.network.channel),
    max_clients: String(settings.network.max_clients),
    isolate_clients: settings.network.isolate_clients,
    country_code: settings.network.country_code || "",
    down_cap: settings.limits.max_down_bytes_per_sec,
    up_cap: settings.limits.max_up_bytes_per_sec,
    retention_days: String(settings.limits.retention_days),
    max_friends: String(settings.limits.max_friends),
    upstream_dns: (settings.dns.upstream || []).join(", "),
    portal_enabled: settings.portal.enabled,
    title: settings.portal.title,
    message: settings.portal.message,
    footer: settings.portal.footer,
    payment: settings.portal.payment_instructions,
    show_prices: settings.portal.show_prices,
    admin_passphrase: "",
    adminTouched: false,
    ...S.drafts,
  };
}

function capField(label, key, draft) {
  const unlimited = h("input", { type: "checkbox", checked: draft[key] == null });
  const number = h("input", {
    type: "number", min: "1", step: "1", inputmode: "numeric",
    value: draft[key] == null ? "" : String(Math.round(draft[key] / 1024)),
    disabled: draft[key] == null,
  });
  unlimited.onchange = () => {
    number.disabled = unlimited.checked;
    if (unlimited.checked) number.value = "";
    else if (!number.value) number.value = "1024";
    draft[key] = unlimited.checked ? null : Number(number.value) * 1024;
    S.drafts[key] = draft[key];
  };
  number.oninput = () => {
    draft[key] = number.value ? Number(number.value) * 1024 : null;
    S.drafts[key] = draft[key];
  };
  return h("label", { class: "field" },
    h("span", {}, label),
    h("div", { class: "row" },
      h("div", { class: "grow" }, number),
      h("div", { class: "grow check" }, unlimited, h("span", {}, "unlimited")),
    ),
    h("div", { class: "hint" }, "KiB/s. Applied in the kernel to every client."),
  );
}

function settingsView() {
  const d = S.data;
  const settings = d.settings;
  const draft = settingsDraft();
  const errors = S.errors;

  const bind = (key, event = "oninput") => ({
    [event]: (e) => {
      draft[key] = event === "onchange" && e.target.type === "checkbox" ? e.target.checked : e.target.value;
      S.drafts[key] = draft[key];
    },
  });

  const band = settings.network.band;
  const channelOptions = band === "5"
    ? [36, 40, 44, 48, 149, 153, 157, 161]
    : [1, 6, 11, 13];

  const save = h("button", { class: "primary" }, "save changes");
  save.onclick = () => saveSettings(draft);

  return [
    errors.length
      ? h("div", { class: "banner bad" },
        h("strong", {}, "the settings were not saved"),
        h("ul", {}, errors.map((error) => h("li", {}, error))))
      : null,
    h("div", { class: "grid two" },
      h("div", { class: "card" },
        h("h2", {}, "network"),
        h("label", { class: "field" },
          h("span", {}, "hotspot name (SSID)"),
          h("input", { type: "text", value: draft.ssid, maxlength: 32, ...bind("ssid") }),
        ),
        h("label", { class: "field" },
          h("span", {}, "encryption"),
          h("select", { ...bind("security", "onchange") },
            ["auto", "open", "wpa2", "wpa3"].map((mode) =>
              h("option", { value: mode, selected: draft.security === mode },
                mode === "auto" ? "auto — password decides" : mode.toUpperCase()))),
          h("div", { class: "hint" },
            settings.network.encrypted
              ? "Clients currently need the password to join. The paywall still gates the internet."
              : "The network is open right now. The paywall still gates the internet."),
        ),
        h("label", { class: "field" },
          h("span", {}, settings.network.passphrase_set ? "wifi password (leave blank to keep)" : "wifi password"),
          h("input", {
            type: "password", value: draft.passphrase, autocomplete: "new-password",
            oninput: (e) => {
              draft.passphrase = e.target.value;
              draft.passphraseTouched = true;
              S.drafts.passphrase = e.target.value;
              S.drafts.passphraseTouched = true;
            },
          }),
          h("div", { class: "hint" }, "8–63 characters. Everyone who knows it can join; only passes get internet."),
        ),
        h("div", { class: "row" },
          h("label", { class: "field" },
            h("span", {}, "band"),
            h("select", {
              onchange: (e) => {
                S.drafts.channel = e.target.value === "5" ? "36" : "6";
                render();
              },
            },
              h("option", { value: "2.4", selected: band === "2.4" }, "2.4 GHz"),
              h("option", { value: "5", selected: band === "5" }, "5 GHz")),
          ),
          h("label", { class: "field" },
            h("span", {}, "channel"),
            h("select", { ...bind("channel", "onchange") },
              channelOptions.map((value) =>
                h("option", { value: String(value), selected: String(value) === String(draft.channel) }, String(value)))),
          ),
        ),
        settings.network.channel_follows_station
          ? h("p", { class: "hint" },
            `In --wifi-uplink mode the access point follows the station, which is on channel ` +
            `${settings.network.beacon_channel}. The channel setting is ignored.`)
          : null,
        h("div", { class: "row" },
          h("label", { class: "field" },
            h("span", {}, "max clients"),
            h("input", { type: "number", min: "1", max: "255", value: draft.max_clients, ...bind("max_clients") }),
          ),
          h("label", { class: "field" },
            h("span", {}, "country code"),
            h("input", { type: "text", value: draft.country_code, maxlength: 2, placeholder: "PH", ...bind("country_code") }),
          ),
        ),
        h("label", { class: "check" },
          h("input", {
            type: "checkbox", checked: draft.isolate_clients,
            ...bind("isolate_clients", "onchange"),
          }),
          h("span", {}, "keep clients from talking to each other"),
        ),
        h("p", { class: "hint" }, "Changing any of this restarts the access point: every client has to rejoin."),
      ),

      h("div", {},
        h("div", { class: "card" },
          h("h2", {}, "speed limits"),
          capField("download cap", "down_cap", draft),
          capField("upload cap", "up_cap", draft),
        ),
        h("div", { class: "card" },
          h("h2", {}, "portal"),
          h("label", { class: "check" },
            h("input", { type: "checkbox", checked: draft.portal_enabled, ...bind("portal_enabled", "onchange") }),
            h("span", {}, "show the captive portal to unpaid devices"),
          ),
          h("label", { class: "field" },
            h("span", {}, "title"),
            h("input", { type: "text", value: draft.title, ...bind("title") }),
          ),
          h("label", { class: "field" },
            h("span", {}, "message"),
            h("input", { type: "text", value: draft.message, ...bind("message") }),
          ),
          h("label", { class: "field" },
            h("span", {}, "how to pay"),
            h("textarea", { ...bind("payment") }, draft.payment),
          ),
          h("label", { class: "field" },
            h("span", {}, "footnote"),
            h("input", { type: "text", value: draft.footer, ...bind("footer") }),
          ),
          h("label", { class: "check" },
            h("input", { type: "checkbox", checked: draft.show_prices, ...bind("show_prices", "onchange") }),
            h("span", {}, "list pass prices"),
          ),
        ),
        h("div", { class: "card" },
          h("h2", {}, "housekeeping"),
          h("div", { class: "row" },
            h("label", { class: "field" },
              h("span", {}, "forget devices after (days)"),
              h("input", { type: "number", min: "1", value: draft.retention_days, ...bind("retention_days") }),
            ),
            h("label", { class: "field" },
              h("span", {}, "max friends"),
              h("input", { type: "number", min: "0", value: draft.max_friends, ...bind("max_friends") }),
            ),
          ),
          h("label", { class: "field" },
            h("span", {}, "dns servers (blank = the host's own)"),
            h("input", { type: "text", value: draft.upstream_dns, placeholder: "1.1.1.1, 9.9.9.9", ...bind("upstream_dns") }),
          ),
        ),
        h("div", { class: "card" },
          h("h2", {}, "panel"),
          h("table", { class: "kv" },
            h("tr", {}, h("th", {}, "serving"), h("td", {}, settings.panel && settings.panel.serving_tls ? "https (encrypted)" : "http (not encrypted)")),
            h("tr", {}, h("th", {}, "bound to"), h("td", { class: "mono" }, `${settings.panel.bind}:${settings.panel.port}`)),
            h("tr", {}, h("th", {}, "urls"), h("td", {},
              h("ul", { style: "margin:0;padding-left:16px" },
                settings.panel.urls.map((url) => h("li", { class: "mono small" }, url))))),
          ),
          h("label", { class: "field" },
            h("span", {}, "admin passphrase (leave blank to keep)"),
            h("input", {
              type: "password", value: draft.admin_passphrase, autocomplete: "new-password",
              oninput: (e) => {
                draft.admin_passphrase = e.target.value;
                draft.adminTouched = true;
                S.drafts.admin_passphrase = e.target.value;
                S.drafts.adminTouched = true;
              },
            }),
            h("div", { class: "hint" },
              `Currently from ${d.status.passphrase_source === "generated" ? "this run (generated)" : "config.json"}. ` +
              "At least 8 characters."),
          ),
        ),
      ),
    ),
    h("div", { class: "actions" },
      save,
      h("button", {
        class: "ghost",
        onclick: () => { S.drafts = {}; S.errors = []; render(); },
      }, "discard"),
    ),
    h("p", { class: "hint" }, "Settings are written to config.json and applied where they can be, live."),
  ];
}

async function saveSettings(draft) {
  const settings = S.data.settings;
  const patch = {};
  const changed = (a, b) => String(a) !== String(b);

  if (changed(draft.ssid, settings.network.ssid)) patch.ssid = draft.ssid;
  if (changed(draft.security, settings.network.security)) patch.security = draft.security;
  if (draft.passphraseTouched) patch.passphrase = draft.passphrase;
  if (changed(draft.channel, settings.network.channel)) patch.channel = Number(draft.channel);
  if (changed(draft.max_clients, settings.network.max_clients)) patch.max_clients = Number(draft.max_clients);
  if (draft.isolate_clients !== settings.network.isolate_clients) patch.isolate_clients = draft.isolate_clients;
  const country = draft.country_code.trim().toUpperCase();
  if (changed(country, settings.network.country_code || "")) patch.country_code = country || null;
  if (draft.down_cap !== settings.limits.max_down_bytes_per_sec) patch.max_down_bytes_per_sec = draft.down_cap;
  if (draft.up_cap !== settings.limits.max_up_bytes_per_sec) patch.max_up_bytes_per_sec = draft.up_cap;
  if (changed(draft.retention_days, settings.limits.retention_days)) patch.retention_days = Number(draft.retention_days);
  if (changed(draft.max_friends, settings.limits.max_friends)) patch.max_friends = Number(draft.max_friends);
  const dns = draft.upstream_dns.split(",").map((s) => s.trim()).filter(Boolean);
  if (changed(dns.join(","), (settings.dns.upstream || []).join(","))) patch.upstream_dns = dns;
  if (draft.portal_enabled !== settings.portal.enabled) patch.portal_enabled = draft.portal_enabled;
  if (changed(draft.title, settings.portal.title) || changed(draft.message, settings.portal.message) ||
      changed(draft.payment, settings.portal.payment_instructions) || changed(draft.footer, settings.portal.footer) ||
      draft.show_prices !== settings.portal.show_prices) {
    patch.blocked_page = {
      title: draft.title,
      message: draft.message,
      footer: draft.footer,
      payment_instructions: draft.payment,
      show_prices: draft.show_prices,
    };
  }
  if (draft.adminTouched) patch.admin_passphrase = draft.admin_passphrase;

  if (Object.keys(patch).length === 0) { flash("warn", "nothing changed"); return; }

  if (patch.ssid || patch.passphrase !== undefined || patch.channel || patch.security) {
    const confirmed = await ask({
      title: "restart the access point?",
      body: "Radio settings change in hostapd, which means every connected client is dropped " +
        "and has to rejoin the wifi.",
      confirm: "apply and restart",
    });
    if (!confirmed) return;
  }

  S.errors = [];
  const body = await control({ cmd: "set_config", patch });
  if (body) {
    S.drafts = {};
    S.errors = [];
    flash("ok", "settings saved");
    notesToToast(body.notes);
  } else if (S.lastError) {
    S.errors = String(S.lastError).split("; ");
    render();
  }
}

/* ------------------------------------------------------------------ shell */

function shell(body) {
  const status = S.data.status;
  const warnings = (status.warnings || []).length;

  const themeButton = h("button", {
    class: "ghost",
    title: "Appearance: auto, light, dark",
    onclick: () => {
      const order = ["auto", "light", "dark"];
      const current = localStorage.getItem("piso-theme") || "auto";
      const next = order[(order.indexOf(current) + 1) % order.length];
      localStorage.setItem("piso-theme", next);
      applyTheme();
      render();
    },
  }, { auto: "◐ auto", light: "☀ light", dark: "☾ dark" }[localStorage.getItem("piso-theme") || "auto"]);

  const logout = h("button", {
    class: "ghost",
    onclick: async () => {
      await api("/api/logout", { method: "POST" });
      S.data = null;
      stopPolling();
      render();
    },
  }, "log out");

  return [
    h("div", { class: "topbar" },
      h("div", { class: "brand" },
        h("div", { class: "dino" }),
        h("div", {},
          h("h1", {}, "piso-hotspot"),
          h("div", { class: "sub" },
            status.mode,
            " · ",
            warnings ? `${warnings} warning(s)` : "all good",
          ),
        ),
      ),
      h("div", { class: "grow" }),
      themeButton,
      logout,
    ),
    h("nav", { class: "tabs" },
      [["dashboard", "dashboard"], ["devices", "devices"], ["settings", "settings"]].map(([key, label]) =>
        h("button", {
          class: "tab" + (S.view === key ? " active" : ""),
          onclick: () => { S.view = key; render(); },
        }, label)),
    ),
    h("main", {}, body),
    h("footer", { class: "site" },
      h("a", { href: S.data.settings.repository }, "piso-hotspot on github"),
      h("span", { class: "muted" }, "· version " + status.version),
      h("span", { class: "muted" }, S.data.settings.panel && S.data.settings.panel.serving_tls ? "· https" : "· http"),
    ),
  ];
}

function applyTheme() {
  const mode = localStorage.getItem("piso-theme") || "auto";
  if (mode === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = mode;
}

/* ------------------------------------------------------------------ auth */

function renderLogin(error) {
  stopPolling();
  app.replaceChildren(
    h("div", { class: "login card" },
      h("div", { class: "dino" }),
      h("h1", {}, "piso-hotspot"),
      h("p", { class: "muted" }, "admin panel"),
      error ? h("p", { class: "banner bad" }, error) : null,
      h("form", {
        onsubmit: async (event) => {
          event.preventDefault();
          const passphrase = new FormData(event.target).get("passphrase");
          const { res, body } = await api("/api/login", {
            method: "POST", body: JSON.stringify({ passphrase }),
          });
          if (res.ok) {
            await refresh();
            startPolling();
          } else {
            const retry = res.headers.get("Retry-After");
            renderLogin((body && body.error ? body.error : "wrong passphrase") +
              (retry ? ` — try again in ${retry}s` : ""));
          }
        },
      },
        h("label", { class: "field" },
          h("span", {}, "passphrase"),
          h("input", {
            type: "password", name: "passphrase", autocomplete: "current-password",
            required: true, autofocus: true,
          }),
        ),
        h("button", { type: "submit", class: "primary wide" }, "log in"),
      ),
      h("p", { class: "hint" },
        "The passphrase is in config.json, or printed by ",
        h("span", { class: "mono" }, "piso-hotspot status"),
        " when it is generated."),
    ),
  );
}

/* --------------------------------------------------------------- refresh */

async function refresh() {
  const { res, body } = await api("/api/state");
  if (res.status === 401 || (body && body.error && !body.status)) {
    S.data = null;
    render();
    return;
  }
  if (!res.ok || !body || !body.status) return;

  const previous = S.prevRates;
  S.data = body;
  S.now = Math.floor(Date.now() / 1000);
  S.lastError = null;

  // Rates: the kernel counters are cumulative, so the change since the
  // last poll is what "right now" means. A counter that went backwards
  // means the set was rebuilt (a device re-joined), which is not traffic.
  const traffic = body.traffic || { by_mac: {}, measured_at: 0 };
  const at = traffic.measured_at || S.now;
  const rates = {};
  if (previous && at > previous.at) {
    const seconds = at - previous.at;
    for (const [mac, current] of Object.entries(traffic.by_mac || {})) {
      const before = previous.byMac[mac] || {};
      const delta = (key) => Math.max(0, (current[key] || 0) - (before[key] || 0)) / seconds;
      rates[mac] = { up: delta("up_bytes"), down: delta("down_bytes") };
    }
  }
  S.rates = rates;
  S.prevRates = { at, byMac: traffic.by_mac || {} };

  render();
}

let pollTimer = null;
function startPolling() {
  stopPolling();
  pollTimer = setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
}
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
document.addEventListener("visibilitychange", () => { if (!document.hidden && pollTimer) refresh(); });

/* ---------------------------------------------------------------- render */

function render() {
  if (!S.data) { return; }
  const body =
    S.view === "devices" ? devicesView() :
    S.view === "settings" ? settingsView() :
    dashboard();
  app.replaceChildren(...shell(body));
}

async function start() {
  applyTheme();
  const { res, body } = await api("/api/auth");
  if (res.ok && body && body.authenticated) {
    await refresh();
    startPolling();
  } else {
    renderLogin();
  }
}

start();
