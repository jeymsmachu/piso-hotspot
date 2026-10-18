//! Admin panel HTTP surface.
//!
//! An axum server on a dedicated thread inside the daemon; the rest of
//! the daemon stays on plain std threads. Handlers hold the shared
//! `Daemon` mutex only for quick store/firewall work, so a panel request
//! never stalls enforcement, and nothing runs when no browser is open.
//!
//! The captive portal is a separate server — see [`crate::portal`].

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

/// Serve the panel on `0.0.0.0:port` until the process dies.
/// Returns an error string when the socket cannot be bound (the
/// hotspot itself keeps running; the CLI remains fully usable).
pub fn spawn_panel(state: Shared, port: u16) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| format!("cannot bind panel on port {port}: {e}"))?;
        let router = panel_router(state);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .map_err(|e| format!("panel server: {e}"))
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

fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_IDLE.as_secs()
    )
}

/// Returns the 401 response when the caller has no valid session.
fn auth_error(state: &Shared, headers: &HeaderMap) -> Option<Response> {
    let valid = token_from(headers)
        .map(|token| {
            state
                .lock()
                .map(|mut d| d.auth.validate(token))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    (!valid).then(|| error(StatusCode::UNAUTHORIZED, "not logged in"))
}

async fn auth_check(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let authenticated = token_from(&headers)
        .map(|token| {
            state
                .lock()
                .map(|mut d| d.auth.validate(token))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    Json(json!({ "authenticated": authenticated })).into_response()
}

async fn login(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = addr.ip().to_string();
    let result = state
        .lock()
        .map(|mut d| d.auth.login(&ip, &body.passphrase));
    match result {
        Ok(Ok(token)) => {
            log_info!("panel login ok from {ip}");
            (
                [(header::SET_COOKIE, session_cookie(&token))],
                Json(json!({ "ok": true })),
            )
                .into_response()
        }
        Ok(Err(LoginError::BadPassphrase)) => {
            log_warn!("panel login failed from {ip} (wrong passphrase)");
            error(StatusCode::UNAUTHORIZED, "wrong passphrase")
        }
        Ok(Err(LoginError::LockedOut(secs))) => {
            log_warn!("panel login refused from {ip}: locked out for {secs}s");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, secs.to_string())],
                Json(json!({ "error": format!("too many attempts; try again in {secs}s") })),
            )
                .into_response()
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    }
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(token) = token_from(&headers)
        && let Ok(mut d) = state.lock()
    {
        d.auth.logout(token);
        log_info!("panel logout");
    }
    (
        [(
            header::SET_COOKIE,
            format!("{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0"),
        )],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

// ------------------------------------------------------------------ api data

/// Everything the panel needs for one render, under one authed request.
async fn state_payload(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(resp) = auth_error(&state, &headers) {
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

    // Live kernel counters: aggregate per set plus per-MAC, so the
    // dashboard can derive rates client-side between polls.
    let allowed_elems =
        d.fw.set_members(crate::nft::SET_ALLOWED)
            .unwrap_or_default();
    let friend_elems =
        d.fw.set_members(crate::nft::SET_FRIENDS)
            .unwrap_or_default();
    let blocked_elems =
        d.fw.set_members(crate::nft::SET_BLOCKED)
            .unwrap_or_default();
    let mut by_mac = serde_json::Map::new();
    for set in [&allowed_elems, &friend_elems, &blocked_elems] {
        for el in set {
            by_mac.insert(
                el.mac.to_string(),
                json!({ "packets": el.packets, "bytes": el.bytes }),
            );
        }
    }
    let totals = |v: &[crate::nft::SetElement]| {
        json!({
            "packets": v.iter().map(|e| e.packets).sum::<u64>(),
            "bytes": v.iter().map(|e| e.bytes).sum::<u64>(),
        })
    };

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
        },
        "devices": devices,
        "friends": friends,
        "passes": d.cfg.passes,
        "currency": d.cfg.currency,
        "theme": serde_json::to_value(d.cfg.ui.theme).unwrap_or_default(),
        "revenue_today": { "total_minor": revenue.0, "count": revenue.1 },
        "caps": d.cfg.bandwidth,
        "traffic": {
            "allowed": totals(&allowed_elems),
            "friends": totals(&friend_elems),
            "blocked": totals(&blocked_elems),
            "by_mac": by_mac,
        },
    }))
    .into_response()
}

/// The admin passphrase, on demand only.
///
/// It is the durable login secret: shipping it in the 3-second state
/// poll would scatter it through browser history, devtools and any
/// screenshot of the dashboard. The CLI (`piso-hotspot status`) and an
/// explicit click here are the only ways to read it back.
async fn passphrase_payload(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(resp) = auth_error(&state, &headers) {
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
    if let Some(resp) = auth_error(&state, &headers) {
        return resp;
    }
    // The audit trail names the lane that asked: the root socket is
    // `cli`, this one carries the address the request came from.
    let actor = format!("panel:{}", addr.ip());
    Json(crate::daemon::dispatch_actor(&state, req, &actor)).into_response()
}
