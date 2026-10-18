//! The captive portal: what a student sees at any HTTP URL before they
//! pay (and what the operator sees when checking from a client device).
//!
//! Server-rendered, one request one response: no JavaScript runs for
//! unpaid clients at all, and paid clients get a single tiny countdown
//! tick. The nft `prerouting` redirect (see [`crate::nft`]) brings
//! unpaid HTTP here — DNS is never tampered with.

use std::net::Ipv4Addr;

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use crate::http::Shared;
use crate::store;
use crate::{log_info, neigh};

const TEMPLATE: &str = include_str!("../web/portal/portal.html");
const CSS: &str = include_str!("../web/portal/portal.css");

/// One priced line on the unpaid page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriceRow {
    pub name: String,
    /// Duration hint, e.g. "15 min" or "until midnight".
    pub detail: String,
    pub price: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PortalKind {
    Unpaid {
        mac: Option<String>,
    },
    Paid {
        mac: String,
        pass_name: String,
        expires_at: i64,
    },
    Friend {
        mac: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct PortalData {
    pub title: String,
    pub message: String,
    pub footnote: String,
    pub payment: String,
    pub show_prices: bool,
    pub prices: Vec<PriceRow>,
    /// `auto`, `light`, or `dark`.
    pub theme: String,
    pub kind: PortalKind,
    pub now: i64,
}

/// Escape text interpolated into HTML — operator config and device
/// data are attacker-influenced in the general case.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Format a minor-unit price for humans (assumes a 100-subunit major
/// unit — centavos, cents, etc.).
fn format_price(currency: &str, minor: u32) -> String {
    let symbol = match currency {
        "PHP" => "₱",
        "USD" => "$",
        "EUR" => "€",
        "GBP" => "£",
        "JPY" => "¥",
        other => return format!("{other} {}.{}", minor / 100, minor % 100),
    };
    if minor.is_multiple_of(100) {
        format!("{symbol}{}", minor / 100)
    } else {
        format!("{symbol}{}.{}", minor / 100, minor % 100)
    }
}

pub fn price_rows(passes: &[crate::passes::PassDef], currency: &str) -> Vec<PriceRow> {
    passes
        .iter()
        .map(|p| PriceRow {
            name: p.name.clone(),
            detail: match p.duration_secs {
                Some(s) if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
                Some(s) if s >= 60 && s % 60 == 0 => format!("{} min", s / 60),
                Some(s) => format!("{s}s"),
                None => "until midnight".to_string(),
            },
            price: format_price(currency, p.price_minor),
        })
        .collect()
}

fn hhmm(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .with_timezone(&chrono::Local)
        .format("%H:%M")
        .to_string()
}

/// Render the full portal page. Pure: same inputs, same bytes.
pub fn render(data: &PortalData) -> String {
    let theme_attr = match data.theme.as_str() {
        "light" => " data-theme=\"light\"",
        "dark" => " data-theme=\"dark\"",
        _ => "",
    };

    let (content, script) = match &data.kind {
        PortalKind::Unpaid { mac } => {
            let mut html = format!(
                "<section class=\"card\">\n\
                   <h1>{title}</h1>\n\
                   <p class=\"msg\">{message}</p>\n\
                   <p class=\"device\">this device · {mac}</p>\n\
                 </section>\n",
                title = escape(&data.title),
                message = escape(&data.message),
                mac = escape(mac.as_deref().unwrap_or("(unknown — rejoin the wifi)")),
            );
            if data.show_prices && !data.prices.is_empty() {
                html.push_str("<section class=\"card\">\n<h2>passes</h2>\n<ul class=\"prices\">\n");
                for row in &data.prices {
                    html.push_str(&format!(
                        "  <li><span>{} · {}</span><span class=\"p\">{}</span></li>\n",
                        escape(&row.name),
                        escape(&row.detail),
                        escape(&row.price),
                    ));
                }
                html.push_str("</ul>\n</section>\n");
            }
            if !data.payment.trim().is_empty() {
                html.push_str(&format!(
                    "<section class=\"card\">\n<h2>how to pay</h2>\n\
                     <div class=\"payment\">{}</div>\n</section>\n",
                    escape(&data.payment)
                ));
            }
            if !data.footnote.trim().is_empty() {
                html.push_str(&format!(
                    "<p class=\"footnote\">{}</p>\n",
                    escape(&data.footnote)
                ));
            }
            (html, String::new())
        }
        PortalKind::Paid {
            mac,
            pass_name,
            expires_at,
        } => {
            let html = format!(
                "<section class=\"card online\">\n\
                   <h1>You're online</h1>\n\
                   <p class=\"big\"><span id=\"remaining\">{left}</span> left</p>\n\
                   <p class=\"pass\">{pass} pass</p>\n\
                   <p class=\"until\">until {until}</p>\n\
                   <p class=\"device\">this device · {mac}</p>\n\
                 </section>\n",
                left = time_left(*expires_at, data.now),
                pass = escape(pass_name),
                until = hhmm(*expires_at),
                mac = escape(mac),
            );
            // The only script in the portal: one countdown, browser-side,
            // seeded with server time so a wrong phone clock cannot lie.
            let script = format!(
                "<script>(function(){{\
                   var el=document.getElementById('remaining');\
                   if(!el)return;\
                   var expires={expires_at},skew=(Date.now()/1000)-{now};\
                   function fmt(s){{\
                     s=Math.max(0,Math.round(s));\
                     var h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;\
                     return h?h+'h '+m+'m':(m?m+'m '+x+'s':x+'s');\
                   }}\
                   function tick(){{\
                     if(document.hidden)return;\
                     var left=expires-(Date.now()/1000)+skew;\
                     el.textContent=fmt(left);\
                     if(left<=0)location.reload();\
                   }}\
                   setInterval(tick,1000);\
                   document.addEventListener('visibilitychange',tick);\
                   tick();\
                 }})();</script>",
                expires_at = *expires_at,
                now = data.now,
            );
            (html, script)
        }
        PortalKind::Friend { mac } => {
            let html = format!(
                "<section class=\"card online\">\n\
                   <h1>You're online</h1>\n\
                   <p class=\"big\">unlimited</p>\n\
                   <p class=\"pass\">friend access — no pass needed</p>\n\
                   <p class=\"device\">this device · {mac}</p>\n\
                 </section>\n",
                mac = escape(mac.as_deref().unwrap_or("(unknown — rejoin the wifi)")),
            );
            (html, String::new())
        }
    };

    TEMPLATE
        .replace("{{THEME_ATTR}}", theme_attr)
        .replace("{{TITLE}}", &escape(&data.title))
        .replace("{{CONTENT}}", &content)
        .replace("{{SCRIPT}}", &script)
}

fn time_left(expires_at: i64, now: i64) -> String {
    let s = (expires_at - now).max(0);
    let (h, m) = (s / 3600, (s % 3600) / 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{s}s")
    }
}

// ------------------------------------------------------------------ server

/// Serve the portal on the gateway address, port 80, until the process
/// dies. Failure to bind logs and returns; the hotspot keeps running.
pub fn spawn(state: Shared, gateway: Ipv4Addr) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((gateway, 80u16))
            .await
            .map_err(|e| format!("cannot bind portal on {gateway}:80: {e}"))?;
        let router = Router::new()
            .route("/portal", get(page))
            .route("/portal.css", get(css))
            .route("/assets/offline-sprite-1x.png", get(sprite_1x))
            .route("/assets/offline-sprite-2x.png", get(sprite_2x))
            .route("/assets/press-start-2p.woff2", get(font))
            .fallback(page)
            .with_state(state);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .map_err(|e| format!("portal server: {e}"))
    })
}

async fn css() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/css")], CSS)
}

async fn sprite_1x() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, crate::assets::PNG_TYPE)],
        crate::assets::SPRITE_1X,
    )
}

async fn sprite_2x() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, crate::assets::PNG_TYPE)],
        crate::assets::SPRITE_2X,
    )
}

/// The pixel display face, served from the binary: a captive portal has
/// no internet to fetch fonts from.
async fn font() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, crate::assets::FONT_TYPE)],
        crate::assets::FONT_PRESS_START_2P,
    )
}

/// Paths that are the portal itself: those render the page instead of
/// bouncing the visitor to it.
fn is_portal_path(path: &str) -> bool {
    matches!(path, "/" | "/portal") || path.starts_with("/portal.") || path.starts_with("/assets/")
}

/// A redirect, which is the answer an operating system reads as
/// "captive": no caching, and no page in the place of what was asked for.
fn redirect_to(url: &str) -> Response {
    let mut response = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The page itself: never cached, so an expired pass cannot keep showing
/// a paid page out of the browser's cache.
fn page_response(html: String) -> Response {
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Any path: the client's state page.
///
/// Unpaid visitors are *redirected* to the page rather than handed it in
/// place of whatever they asked for. That distinction is what makes an
/// operating system offer "sign in to this network" again after a pass
/// expires: captive-portal probes are matched against the answer they
/// expect, and a redirect is the answer that means "captive" — a 200
/// carrying somebody else's page means "online", and the notice never
/// comes back (#25).
async fn page(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    uri: Uri,
) -> Response {
    let now = crate::daemon::now();
    let ip = addr.ip();

    // Who is asking: the kernel's neighbour table, not the DHCP lease
    // file, so a device that took somebody else's address is described as
    // itself (#22). A v6 or malformed source simply has no entry.
    let device_mac = match ip {
        std::net::IpAddr::V4(v4) => neigh::holder(v4).map(|mac| mac.to_string()),
        std::net::IpAddr::V6(_) => None,
    };

    let (data, gateway, unpaid) = {
        let d = match state.lock() {
            Ok(d) => d,
            Err(_) => {
                return Html("<h1>temporarily unavailable</h1>").into_response();
            }
        };

        let kind = match &device_mac {
            None => PortalKind::Unpaid { mac: None },
            Some(mac) => {
                let is_friend = store::is_friend(&d.conn, mac).unwrap_or(false);
                let device = store::get_device(&d.conn, mac).ok().flatten();
                if is_friend {
                    PortalKind::Friend {
                        mac: Some(mac.clone()),
                    }
                } else if let Some(dev) = device
                    && dev.state == "paid"
                    && dev.expires_at.is_some_and(|e| e > now)
                {
                    let pass_id = dev.pass_id.unwrap_or_default();
                    let pass_name = d
                        .cfg
                        .passes
                        .iter()
                        .find(|p| p.id == pass_id)
                        .map(|p| p.name.clone())
                        .unwrap_or(pass_id);
                    PortalKind::Paid {
                        mac: mac.clone(),
                        pass_name,
                        expires_at: dev.expires_at.unwrap_or(now),
                    }
                } else {
                    PortalKind::Unpaid {
                        mac: Some(mac.clone()),
                    }
                }
            }
        };
        let unpaid = matches!(kind, PortalKind::Unpaid { .. });

        let data = PortalData {
            title: d.cfg.blocked_page.title.clone(),
            message: d.cfg.blocked_page.message.clone(),
            footnote: d.cfg.blocked_page.footer.clone(),
            payment: d.cfg.blocked_page.payment_instructions.clone(),
            show_prices: d.cfg.blocked_page.show_prices,
            prices: price_rows(&d.cfg.passes, &d.cfg.currency),
            theme: match d.cfg.ui.theme {
                crate::config::Theme::Auto => "auto".into(),
                crate::config::Theme::Light => "light".into(),
                crate::config::Theme::Dark => "dark".into(),
            },
            kind,
            now,
        };
        (data, d.fw.gateway, unpaid)
    };

    let described = match &data.kind {
        PortalKind::Unpaid { mac } => format!("unpaid mac={}", mac.as_deref().unwrap_or("?")),
        PortalKind::Paid { mac, .. } => format!("paid mac={mac}"),
        PortalKind::Friend { mac } => format!("friend mac={}", mac.as_deref().unwrap_or("?")),
    };

    if unpaid && !is_portal_path(uri.path()) {
        // Send them to the page, and say so: this is also the evidence
        // that a device which was online before is being asked to sign in
        // again.
        log_info!("portal redirect from {ip} ({described}) for {}", uri.path());
        return redirect_to(&format!("http://{gateway}/portal"));
    }
    log_info!("portal page for {ip} ({described})");
    page_response(render(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unpaid() -> PortalData {
        PortalData {
            title: "No internet yet".into(),
            message: "See the operator.".into(),
            footnote: "Quick ₱3".into(),
            payment: String::new(),
            show_prices: true,
            prices: price_rows(&crate::passes::default_passes(), "PHP"),
            theme: "auto".into(),
            kind: PortalKind::Unpaid {
                mac: Some("42:61:7e:6c:ee:d2".into()),
            },
            now: 1_700_000_000,
        }
    }

    #[test]
    fn unpaid_page_shows_message_and_mac() {
        let html = render(&unpaid());
        assert!(html.contains("See the operator."));
        assert!(html.contains("42:61:7e:6c:ee:d2"));
        assert!(html.contains("github.com/jeymsmachu/piso-hotspot"));
        // The configured title is the document title too.
        assert!(html.contains("<title>No internet yet</title>"));
    }

    #[test]
    fn unpaid_page_lists_prices_with_currency() {
        let html = render(&unpaid());
        assert!(html.contains("Quick · 15 min"));
        assert!(html.contains("₱3"));
        assert!(html.contains("Extended · 45 min"));
        assert!(html.contains("Day · until midnight"));
        assert!(html.contains("₱15"));
    }

    #[test]
    fn prices_and_payment_toggle() {
        let mut d = unpaid();
        d.show_prices = false;
        d.payment = "GCash 0917 123 4567".into();
        let html = render(&d);
        assert!(!html.contains("class=\"prices\""));
        assert!(html.contains("GCash 0917 123 4567"));

        let mut d = unpaid();
        d.prices.clear();
        d.show_prices = true;
        let html = render(&d);
        assert!(!html.contains("class=\"prices\""), "empty list hidden");
    }

    #[test]
    fn paid_page_counts_down_without_http_requests() {
        let mut d = unpaid();
        d.kind = PortalKind::Paid {
            mac: "42:61:7e:6c:ee:d2".into(),
            pass_name: "Quick".into(),
            expires_at: d.now + 900,
        };
        let html = render(&d);
        assert!(html.contains("You're online"));
        assert!(html.contains(">15m</span> left"), "{html}");
        assert!(html.contains("Quick pass"));
        assert!(html.contains("id=\"remaining\""));
        // The countdown is the only script doing work, it is inline, and
        // nothing here talks to the network: no external files, no fetch.
        assert!(html.contains("setInterval"), "the countdown runs locally");
        assert!(!html.contains("<script src="));
        assert!(!html.contains("fetch("));
    }

    #[test]
    fn unpaid_and_friend_pages_only_carry_the_theme_toggle() {
        // The theme toggle is the one script on an unpaid page: no
        // countdown, no timers, nothing that keeps a visitor's browser
        // talking to the gateway.
        let html = render(&unpaid());
        assert!(!html.contains("setInterval"));
        assert!(!html.contains("remaining"));
        assert!(!html.contains("<script src="));
        let mut d = unpaid();
        d.kind = PortalKind::Friend {
            mac: Some("42:61:7e:6c:ee:d2".into()),
        };
        let html = render(&d);
        assert!(html.contains("unlimited"));
        assert!(html.contains("friend access"));
        assert!(!html.contains("setInterval"));
    }

    #[test]
    fn theme_attribute_follows_config() {
        let mut d = unpaid();
        d.theme = "dark".into();
        assert!(render(&d).contains("<html lang=\"en\" data-theme=\"dark\">"));
        d.theme = "auto".into();
        assert!(render(&d).contains("<html lang=\"en\">"));
    }

    #[test]
    fn hostile_text_is_escaped() {
        let mut d = unpaid();
        d.message = "<script>alert('x')</script>".into();
        d.title = "a\"b<c>".into();
        let html = render(&d);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(html.contains("a&quot;b&lt;c&gt;"));
    }

    #[test]
    fn price_formatting() {
        assert_eq!(format_price("PHP", 300), "₱3");
        assert_eq!(format_price("PHP", 1250), "₱12.50");
        assert_eq!(format_price("USD", 500), "$5");
        assert_eq!(format_price("XXX", 250), "XXX 2.50");
    }

    #[test]
    fn time_left_scales() {
        assert_eq!(time_left(1_700_000_900, 1_700_000_000), "15m");
        assert_eq!(time_left(1_700_003_600, 1_700_000_000), "1h 0m");
        assert_eq!(time_left(1_700_000_005, 1_700_000_000), "5s");
        assert_eq!(time_left(1_699_999_999, 1_700_000_000), "0s");
    }
}
