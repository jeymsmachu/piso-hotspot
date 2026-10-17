/* piso-hotspot admin — boot logic.
   P3a: working login gate + state view; the full Dashboard/Devices/
   Settings UI lands in P3d on top of these exact endpoints. */
"use strict";

const app = document.getElementById("app");

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  let body = null;
  try { body = await res.json(); } catch (_) { /* no body */ }
  return { res, body };
}

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "onclick") el.onclick = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function renderLogin(error) {
  app.replaceChildren(
    h("h1", {}, "piso-hotspot"),
    h("p", {}, "admin panel"),
    error ? h("p", { class: "error" }, error) : "",
    h("form", {},
      h("input", {
        type: "password", name: "passphrase", autocomplete: "current-password",
        placeholder: "passphrase", required: "required", autofocus: "autofocus",
      }),
      h("button", { type: "submit" }, "log in"),
    ),
  );
  app.querySelector("form").onsubmit = async (e) => {
    e.preventDefault();
    const passphrase = new FormData(e.target).get("passphrase");
    const { res, body } = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ passphrase }),
    });
    if (res.ok) renderState();
    else {
      const retry = res.headers.get("Retry-After");
      renderLogin(body?.error || "wrong passphrase" + (retry ? ` (${retry}s)` : ""));
    }
  };
}

async function renderState() {
  const { res, body } = await api("/api/state");
  if (!res.ok) return renderLogin("session expired");
  const s = body.status;
  app.replaceChildren(
    h("h1", {}, "piso-hotspot"),
    h("p", { class: "muted" },
      `${s.mode} · ${s.ap_iface}` + (s.uplink ? ` → ${s.uplink}` : ""),
      " · ", `${s.devices_seen} devices · ${s.active_passes} active passes`),
    h("h2", {}, "panel"),
    h("ul", {}, s.panel_urls.map((u) => h("li", {}, h("a", { href: u }, u)))),
    h("h2", {}, "state (raw)"),
    h("pre", {}, JSON.stringify(body, null, 2)),
    h("button", {
      onclick: async () => { await api("/api/logout", { method: "POST" }); renderLogin(); },
    }, "log out"),
  );
}

(async () => {
  const { body } = await api("/api/auth");
  if (body?.authenticated) renderState();
  else renderLogin();
})();
