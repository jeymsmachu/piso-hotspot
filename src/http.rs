//! Admin panel HTTP surface.
//!
//! An axum server on a dedicated thread inside the daemon; the rest of
//! the daemon stays on plain std threads. Handlers hold the shared
//! `Daemon` mutex only for quick store/firewall work, so a panel request
//! never stalls enforcement, and nothing runs when no browser is open.
//!
//! The captive portal is a separate server — see [`crate::portal`].

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{LoginError, SESSION_IDLE};
use crate::control::Request as CtlRequest;
use crate::daemon::Daemon;
use crate::{log_info, log_warn};

const SESSION_COOKIE: &str = "piso_session";

pub type Shared = Arc<Mutex<Daemon>>;

/// Serve the panel until the process dies.
///
/// With `tls` the port speaks HTTPS using that certificate; without it,
/// plain HTTP. Returns an error string when the socket cannot be bound or
/// the certificate cannot be read (the hotspot itself keeps running; the
/// CLI remains fully usable, and `status` reports why the panel is down).
pub fn spawn_panel(
    state: Shared,
    bind: Ipv4Addr,
    port: u16,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    runtime.block_on(async move {
        let address = SocketAddr::from((bind, port));
        let service = panel_router(state).into_make_service_with_connect_info::<SocketAddr>();
        match tls {
            Some((cert, key)) => {
                let config = crate::tls::rustls_config(&cert, &key).await?;
                axum_server::bind_rustls(address, config)
                    .serve(service)
                    .await
                    .map_err(|e| format!("panel server (tls): {e}"))
            }
            None => {
                let listener = tokio::net::TcpListener::bind(address)
                    .await
                    .map_err(|e| format!("cannot bind panel on {address}: {e}"))?;
                axum::serve(listener, service)
                    .await
                    .map_err(|e| format!("panel server: {e}"))
            }
        }
    })
}

fn panel_router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/api/auth", get(auth_check))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/state", get(state_payload))
        .route("/api/passphrase", get(passphrase_payload))
        .route("/api/control", post(control))
        // Every panel request is a small JSON blob; a hard cap means no
        // request body can be a memory or bandwidth problem, whatever
        // the client claims its content-length is.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Largest accepted panel request body. The settings form is the big
/// one, and it is a few hundred bytes.
const MAX_BODY_BYTES: usize = 16 * 1024;

// ------------------------------------------------------------- static files

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/admin/index.html"))
}

async fn app_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../web/admin/app.css"),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../web/admin/app.js"),
    )
}

// ---------------------------------------------------------------------- auth

#[derive(Deserialize)]
struct LoginBody {
    passphrase: String,
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn token_from(headers: &HeaderMap) -> Option<&str> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').map(str::trim).find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == SESSION_COOKIE).then_some(value)
    })
}

/// The session cookie. `Secure` is set whenever the panel is serving
/// TLS: a browser would refuse an insecure cookie otherwise, and setting
/// it on plain HTTP would silently break logging in.
fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
        SESSION_IDLE.as_secs(),
        if secure { "; Secure" } else { "" }
    )
}

/// Is this request carrying a valid session, issued to this address?
///
/// Binding the session to the address it was issued to is what makes a
/// sniffed cookie useless to a different device (the panel is plain
/// LAN-reachable, and the uplink can be somebody else's network).
fn session_valid(state: &Shared, headers: &HeaderMap, ip: &str) -> bool {
    token_from(headers)
        .map(|token| {
            state
                .lock()
                .map(|mut d| d.auth.validate(token, ip))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Returns the 401 response when the caller has no valid session.
fn auth_error(state: &Shared, headers: &HeaderMap, ip: &str) -> Option<Response> {
    (!session_valid(state, headers, ip)).then(|| error(StatusCode::UNAUTHORIZED, "not logged in"))
}

async fn auth_check(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let authenticated = session_valid(&state, &headers, &addr.ip().to_string());
    Json(json!({ "authenticated": authenticated })).into_response()
}

async fn login(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = addr.ip().to_string();
    let (result, secure) = match state.lock() {
        Ok(mut d) => {
            let secure = d.panel_tls.is_some();
            (d.auth.login(&ip, &body.passphrase), secure)
        }
        Err(_) => (Err(LoginError::BadPassphrase), false),
    };
    match result {
        Ok(token) => {
            log_info!("panel login ok from {ip}");
            (
                [(header::SET_COOKIE, session_cookie(&token, secure))],
                Json(json!({ "ok": true })),
            )
                .into_response()
        }
        Err(LoginError::BadPassphrase) => {
            log_warn!("panel login failed from {ip} (wrong passphrase)");
            error(StatusCode::UNAUTHORIZED, "wrong passphrase")
        }
        Err(LoginError::LockedOut(secs)) => {
            log_warn!("panel login refused from {ip}: locked out for {secs}s");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, secs.to_string())],
                Json(json!({ "error": format!("too many attempts; try again in {secs}s") })),
            )
                .into_response()
        }
    }
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let mut secure = false;
    if let Some(token) = token_from(&headers)
        && let Ok(mut d) = state.lock()
    {
        d.auth.logout(token);
        secure = d.panel_tls.is_some();
        log_info!("panel logout");
    }
    (
        [(
            header::SET_COOKIE,
            format!(
                "{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0{}",
                if secure { "; Secure" } else { "" }
            ),
        )],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

// ------------------------------------------------------------------ api data

/// Everything the panel needs for one render, under one authed request.
///
/// The numbers come from the daemon's last reconciler tick, never from a
/// fresh `nft` call: a dashboard open on three phones must not run the
/// kernel's rule dump three times every three seconds.
async fn state_payload(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = auth_error(&state, &headers, &addr.ip().to_string()) {
        return resp;
    }
    let d = match state.lock() {
        Ok(d) => d,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    };
    let now = crate::daemon::now();
    let today_start = crate::store::next_midnight(now) - 86_400;
    let revenue = crate::store::revenue_since(&d.conn, today_start).unwrap_or((0, 0));
    let devices = crate::store::list_devices(&d.conn).unwrap_or_default();
    let friends = crate::store::list_friends(&d.conn).unwrap_or_default();
    let audit = crate::store::recent_actions(&d.conn, 25).unwrap_or_default();

    // Per-device traffic, up and down, from the kernel's own counters.
    let mut by_mac = serde_json::Map::new();
    let mut up = (0u64, 0u64);
    let mut down = (0u64, 0u64);
    let mut blocked = (0u64, 0u64);
    for (mac, t) in &d.traffic {
        by_mac.insert(
            mac.clone(),
            json!({
                "up_packets": t.up_packets,
                "up_bytes": t.up_bytes,
                "down_packets": t.down_packets,
                "down_bytes": t.down_bytes,
                "blocked_packets": t.blocked_packets,
                "blocked_bytes": t.blocked_bytes,
            }),
        );
        up = (up.0 + t.up_packets, up.1 + t.up_bytes);
        down = (down.0 + t.down_packets, down.1 + t.down_bytes);
        blocked = (blocked.0 + t.blocked_packets, blocked.1 + t.blocked_bytes);
    }
    let counter = |(packets, bytes): (u64, u64)| json!({ "packets": packets, "bytes": bytes });

    Json(json!({
        "status": {
            "mode": d.mode,
            "ap_iface": d.fw.ap_iface,
            "uplink": d.fw.uplink,
            "gateway": d.fw.gateway.to_string(),
            "started_at": d.started_at,
            "devices_seen": devices.len(),
            "active_passes": crate::store::count_active_passes(&d.conn, now).unwrap_or(0),
            "panel_urls": d.panel_urls,
            "sessions": d.auth.session_count(),
            "passphrase_source": if d.passphrase_generated { "generated" } else { "config" },
            "version": env!("CARGO_PKG_VERSION"),
            "warnings": d.health,
            "health_at": d.health_at,
            "last_reconcile": d.last_reconcile.as_ref().map(|note| json!({
                "at": note.at,
                "summary": note.summary,
                "error": note.error,
            })),
        },
        "devices": devices,
        "friends": friends,
        "audit": audit,
        "settings": settings_view(&d),
        "passes": d.cfg.passes,
        "currency": d.cfg.currency,
        "theme": serde_json::to_value(d.cfg.ui.theme).unwrap_or_default(),
        "revenue_today": { "total_minor": revenue.0, "count": revenue.1 },
        "caps": d.cfg.bandwidth,
        "traffic": {
            "up": counter(up),
            "down": counter(down),
            "blocked": counter(blocked),
            "by_mac": by_mac,
            // When the kernel numbers were read: a panel that shows
            // rates has to know.
            "measured_at": d.traffic_at,
        },
    }))
    .into_response()
}

/// The settings the panel may see.
///
/// Everything except the two passphrases: the wifi password is shown as
/// "set / not set", and the admin passphrase has its own endpoint. This
/// is the shape the settings form is built from, and the reason the form
/// can never echo a secret back into the browser.
fn settings_view(d: &Daemon) -> serde_json::Value {
    let cfg = &d.cfg;
    let security = cfg.ap.security.resolve(&cfg.ap.passphrase);
    json!({
        "network": {
            "ssid": cfg.ap.ssid,
            "security": cfg.ap.security.label(),
            "effective_security": security.label(),
            "encrypted": security.is_encrypted(),
            "passphrase_set": !cfg.ap.passphrase.is_empty(),
            "channel": cfg.ap.channel,
            "band": if cfg.ap.channel <= 14 { "2.4" } else { "5" },
            "max_clients": cfg.ap.max_clients,
            "isolate_clients": cfg.ap.isolate_clients,
            "country_code": cfg.ap.country_code,
            "channel_follows_station": d.mode == "wifi-uplink",
            "beacon_channel": d.ap_channel,
        },
        "limits": {
            "max_down_bytes_per_sec": cfg.bandwidth.max_down_bytes_per_sec,
            "max_up_bytes_per_sec": cfg.bandwidth.max_up_bytes_per_sec,
            "retention_days": cfg.retention_days,
            "max_friends": cfg.max_friends,
        },
        "portal": {
            "enabled": cfg.portal.enabled,
            "title": cfg.blocked_page.title,
            "message": cfg.blocked_page.message,
            "footer": cfg.blocked_page.footer,
            "payment_instructions": cfg.blocked_page.payment_instructions,
            "show_prices": cfg.blocked_page.show_prices,
        },
        "panel": {
            "bind": cfg.admin.bind.to_string(),
            "port": cfg.ap.port,
            "tls": cfg.admin.tls.label(),
            "serving_tls": d.panel_tls.is_some(),
            "urls": d.panel_urls,
        },
        "dns": {
            "upstream": cfg.upstream_dns,
            "uses_system_resolvers": cfg.upstream_dns.is_empty(),
        },
        "currency": cfg.currency,
        "theme": serde_json::to_value(cfg.ui.theme).unwrap_or_default(),
        "mode": d.mode,
        "repository": "https://github.com/jeymsmachu/piso-hotspot",
    })
}

/// The admin passphrase, on demand only.
///
/// It is the durable login secret: shipping it in the 3-second state
/// poll would scatter it through browser history, devtools and any
/// screenshot of the dashboard. The CLI (`piso-hotspot status`) and an
/// explicit click here are the only ways to read it back.
async fn passphrase_payload(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = auth_error(&state, &headers, &addr.ip().to_string()) {
        return resp;
    }
    match state.lock() {
        Ok(d) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "admin_passphrase": d.auth.passphrase(),
                "passphrase_source": if d.passphrase_generated { "generated" } else { "config" },
            })),
        )
            .into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    }
}

/// The panel's command lane: same protocol as the root-only control
/// socket, gated by the session instead.
async fn control(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CtlRequest>,
) -> Response {
    if let Some(resp) = auth_error(&state, &headers, &addr.ip().to_string()) {
        return resp;
    }
    // The audit trail names the lane that asked: the root socket is
    // `cli`, this one carries the address the request came from.
    let actor = format!("panel:{}", addr.ip());
    Json(crate::daemon::dispatch_actor(&state, req, &actor)).into_response()
}
