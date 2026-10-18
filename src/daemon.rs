//! The daemon: owns the radio, hostapd, dnsmasq, the paywall, and the
//! control socket for as long as the hotspot runs.
//!
//! `piso-hotspot start` re-executes this binary as `daemon` (detached,
//! setsid), waits until the control socket answers, and exits. Everything
//! that must survive a closed terminal or terminal-less operation lives
//! here.
//!
//! Ordering on bring-up is deliberate: the paywall table is installed
//! *before* forwarding is enabled, and the gateway address exists before
//! DHCP does — at no point does a client see working-but-ungated internet.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{self, Config};
use crate::control::{self, Request, Response, StatusInfo};
use crate::doctor;
use crate::nft::Firewall;
use crate::paywall;
use crate::radio;
use crate::store;
use crate::{leases, shaper, ufw, wireless};
use crate::{log_error, log_info, log_warn};

const PID_FILE: &str = "/run/piso-hotspot/daemon.pid";
const LOG_FILE: &str = "/run/piso-hotspot/daemon.log";
const RUNNING_FILE: &str = "/run/piso-hotspot/running.json";

const RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

/// Set by signals and by "a child died"; the main loop watches it.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Which supervised process died first, if that is why we are shutting down.
static CHILD_DEATH: Mutex<Option<String>> = Mutex::new(None);

extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug)]
pub struct Opts {
    /// No uplink: exercise AP + DHCP + paywall without NAT.
    pub offline: bool,
    /// Keep the station associated and beacon the AP beside it on a
    /// virtual interface (needs driver station+AP concurrency).
    pub wifi_uplink: bool,
    /// Point the AP at a second radio while the first stays a wifi
    /// station (two radios required).
    pub dual_radio: bool,
}

/// What `stop` needs if the daemon dies without cleaning up.
#[derive(Serialize, Deserialize, Debug)]
pub struct RunningRecord {
    pub mode: String,
    pub ap_iface: String,
    pub uplink: Option<String>,
    pub gateway: String,
    /// `/proc/sys/net/ipv4/ip_forward` before we touched it.
    pub ip_forward_prev: Option<String>,
    pub started_at: i64,
    /// UFW rules added at start (removed at stop).
    #[serde(default)]
    pub portal_enabled: bool,
    #[serde(default = "default_panel_port")]
    pub panel_port: u16,
}

fn default_panel_port() -> u16 {
    8080
}

// ------------------------------------------------------------- parent side

/// Detach a daemon and wait until it answers on the control socket.
pub fn spawn(opts: Opts) -> Result<(), String> {
    if control::alive() {
        return Err("piso-hotspot is already running (`piso-hotspot status`)".into());
    }
    // The daemon would normally create this; the log lives here too.
    fs::create_dir_all("/run/piso-hotspot").map_err(|e| format!("cannot create run dir: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    // A new run rotates the log instead of truncating it: the previous
    // run's lines are what an operator needs after a crash (#30).
    if let Err(e) = crate::log::rotate(Path::new(LOG_FILE)) {
        eprintln!("piso-hotspot: {e}");
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .map_err(|e| format!("cannot open {LOG_FILE}: {e}"))?;
    let err_log = log.try_clone().map_err(|e| e.to_string())?;

    let mut cmd = Command::new(exe);
    cmd.arg("daemon");
    if opts.offline {
        cmd.arg("--offline");
    }
    if opts.wifi_uplink {
        cmd.arg("--wifi-uplink");
    }
    if opts.dual_radio {
        cmd.arg("--dual-radio");
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err_log));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn daemon: {e}"))?;

    for _ in 0..75 {
        std::thread::sleep(Duration::from_millis(200));
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!(
                "daemon exited during startup ({status}); log tail:\n{}",
                log_tail()
            ));
        }
        if control::alive() {
            return Ok(());
        }
    }
    Err(format!(
        "daemon did not become ready in 15s; log tail:\n{}",
        log_tail()
    ))
}

fn log_tail() -> String {
    let text = fs::read_to_string(LOG_FILE).unwrap_or_default();
    let chars: Vec<char> = text.chars().collect();
    let start = chars.len().saturating_sub(1500);
    chars[start..].iter().collect()
}

/// Orderly shutdown, with emergency cleanup when the daemon cannot do
/// it itself. Never touches interfaces it has no record of.
pub fn stop() -> Result<(), String> {
    if control::alive() {
        control::request(&Request::Shutdown).map_err(|e| e.to_string())?;
        for _ in 0..50 {
            if !control::alive() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        return Err("daemon accepted shutdown but is still answering after 10s".into());
    }

    // No live daemon: recover what a record says was started.
    if let Some(pid) = read_pid() {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        std::thread::sleep(Duration::from_millis(500));
        cleanup_from_record();
        return Err("daemon was not responding; cleaned up from the running record".into());
    }

    if Path::new(RUNNING_FILE).exists() {
        cleanup_from_record();
        println!("piso-hotspot: no daemon; cleaned up from the running record");
        return Ok(());
    }

    // Nothing recorded: at most a stale paywall table (ours by name).
    let stale_fw = Firewall {
        ap_iface: String::new(),
        uplink: None,
        gateway: Ipv4Addr::UNSPECIFIED,
        panel_port: 0,
        portal_enabled: false,
    };
    if stale_fw.table_exists() {
        let _ = stale_fw.uninstall();
        println!("piso-hotspot: removed a stale paywall table; interfaces untouched");
    } else {
        println!("piso-hotspot: not running");
    }
    Ok(())
}

fn read_pid() -> Option<u32> {
    fs::read_to_string(PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn cleanup_from_record() {
    let Ok(text) = fs::read_to_string(RUNNING_FILE) else {
        return;
    };
    let Ok(record) = serde_json::from_str::<RunningRecord>(&text) else {
        return;
    };
    let fw = Firewall {
        ap_iface: record.ap_iface.clone(),
        uplink: record.uplink.clone(),
        gateway: record.gateway.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
        // Uninstall never renders; ports are irrelevant here.
        panel_port: 0,
        portal_enabled: false,
    };
    let _ = fw.uninstall();
    ufw::close(&record.ap_iface, record.portal_enabled, record.panel_port);
    let _ = shaper::clear(&record.ap_iface);
    let _ = radio::set_gateway(&record.ap_iface, &record.gateway, false);
    if let Some(prev) = &record.ip_forward_prev
        && let Ok(current) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        && current.trim() != prev
    {
        let _ = radio::set_ip_forward(prev == "1");
    }
    if record.mode == "wifi-uplink" {
        // The station was never ours to touch; only remove the virtual AP.
        crate::viface::remove(&record.ap_iface);
    } else {
        radio::release(&record.ap_iface);
    }
    let _ = fs::remove_file(RUNNING_FILE);
    let _ = fs::remove_file(PID_FILE);
}

// -------------------------------------------------------------- daemon side

/// Shared between the control socket, reconciler, child watcher, and
/// the HTTP panel. Fields are `pub(crate)` because the panel handlers
/// read them; the mutex keeps every access serialized.
pub(crate) struct Daemon {
    pub(crate) cfg: Config,
    pub(crate) conn: rusqlite::Connection,
    pub(crate) fw: Firewall,
    pub(crate) mode: String,
    pub(crate) started_at: i64,
    /// Panel login state (sessions, lockout, effective passphrase).
    pub(crate) auth: crate::auth::AuthState,
    /// URLs the panel answers on, computed once after bring-up.
    pub(crate) panel_urls: Vec<String>,
    /// True when the passphrase was generated (not from config).
    pub(crate) passphrase_generated: bool,
    ip_forward_prev: Option<String>,
    hostapd: Option<Child>,
    dnsmasq: Option<Child>,
}

/// Entry point for the hidden `daemon` subcommand.
pub fn run(opts: Opts) -> ! {
    if let Err(e) = run_inner(opts) {
        // Never leave a stale pid file behind a failed start.
        let _ = fs::remove_file(PID_FILE);
        log_error!("exiting: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run_inner(opts: Opts) -> Result<(), String> {
    fs::create_dir_all("/run/piso-hotspot").map_err(|e| e.to_string())?;
    // Root-only from here: the daemon log and run files may hold
    // operational detail, the control socket holds power.
    let _ = fs::set_permissions(
        "/run/piso-hotspot",
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    );
    // From here on, operational messages are timestamped and leveled —
    // and land in the same file as hostapd's and dnsmasq's output.
    crate::log::init(Path::new(LOG_FILE));
    if !doctor::is_root() {
        return Err("must run as root".into());
    }

    unsafe {
        let handler = on_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGHUP, handler);
    }
    fs::write(PID_FILE, format!("{}\n", std::process::id())).map_err(|e| e.to_string())?;

    // Leftovers from a crashed previous run: finish their teardown first.
    if !control::alive() && Path::new(RUNNING_FILE).exists() {
        cleanup_from_record();
    }

    let cfg = Config::load(&config::config_path()).map_err(|e| e.to_string())?;
    let conn = store::open(&config::state_path()).map_err(|e| e.to_string())?;

    let plan = plan(opts, &cfg)?;
    log_info!(
        "mode={} ap={} uplink={:?} gateway={}",
        plan.mode,
        plan.ap_iface,
        plan.uplink,
        plan.gateway
    );

    let record = RunningRecord {
        mode: plan.mode.clone(),
        ap_iface: plan.ap_iface.clone(),
        uplink: plan.uplink.clone(),
        gateway: plan.gateway.to_string(),
        ip_forward_prev: None,
        started_at: now(),
        portal_enabled: cfg.portal.enabled,
        panel_port: cfg.ap.port,
    };
    fs::write(
        RUNNING_FILE,
        serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let fw = Firewall {
        ap_iface: plan.ap_iface.clone(),
        uplink: plan.uplink.clone(),
        gateway: plan.gateway,
        panel_port: cfg.ap.port,
        portal_enabled: cfg.portal.enabled,
    };

    let (passphrase, passphrase_generated) = if cfg.admin.passphrase.is_empty() {
        (crate::auth::new_passphrase(), true)
    } else {
        (cfg.admin.passphrase.clone(), false)
    };

    let mut daemon = Daemon {
        cfg,
        conn,
        fw,
        mode: plan.mode.clone(),
        started_at: now(),
        auth: crate::auth::AuthState::new(passphrase),
        panel_urls: Vec::new(),
        passphrase_generated,
        ip_forward_prev: None,
        hostapd: None,
        dnsmasq: None,
    };

    if let Err(e) = bring_up(&mut daemon, &plan) {
        log_error!("bring-up failed: {e}");
        teardown(&mut daemon);
        return Err(e);
    }
    daemon.panel_urls = panel_urls(
        daemon.fw.gateway,
        daemon.cfg.ap.port,
        daemon.fw.uplink.as_deref(),
    );
    log_info!("hotspot up; panel: {:?}", daemon.panel_urls);

    let port = daemon.cfg.ap.port;
    let (portal_enabled, portal_gateway) = (daemon.cfg.portal.enabled, daemon.fw.gateway);
    let daemon = Arc::new(Mutex::new(daemon));
    serve(Arc::clone(&daemon));
    spawn_reconciler(Arc::clone(&daemon));
    spawn_child_watch(Arc::clone(&daemon));
    {
        let panel_state = Arc::clone(&daemon);
        std::thread::spawn(move || {
            if let Err(e) = crate::http::spawn_panel(panel_state, port) {
                // The paywall and CLI keep working without the panel.
                log_error!("panel unavailable: {e}");
            }
        });
    }
    if portal_enabled {
        let portal_state = Arc::clone(&daemon);
        std::thread::spawn(move || {
            if let Err(e) = crate::portal::spawn(portal_state, portal_gateway) {
                // Clients still get internet; they just get no notice page.
                log_error!("portal unavailable: {e}");
            }
        });
    }

    while !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(250));
    }

    let death = CHILD_DEATH.lock().ok().and_then(|d| d.clone());
    let mut d = daemon.lock().map_err(|_| "state poisoned".to_string())?;
    teardown(&mut d);
    match death {
        Some(what) => Err(format!("{what} died; hotspot shut down")),
        None => Ok(()),
    }
}

#[derive(Debug)]
struct Plan {
    mode: String,
    ap_iface: String,
    uplink: Option<String>,
    gateway: Ipv4Addr,
    /// Channel the AP must use because the radio has no channel of its
    /// own to give (`--wifi-uplink`: the station's current channel).
    station_channel: Option<u8>,
}

/// Every address the panel answers on: localhost, the AP gateway, and
/// the uplink side (so a tethered phone or a LAN device can reach it).
fn panel_urls(gateway: Ipv4Addr, port: u16, uplink: Option<&str>) -> Vec<String> {
    let mut urls = vec![
        format!("http://127.0.0.1:{port}"),
        format!("http://{gateway}:{port}"),
    ];
    if let Some(iface) = uplink
        && let Some(ip) = iface_ipv4(iface)
    {
        urls.push(format!("http://{ip}:{port}"));
    }
    urls
}

/// First IPv4 address of an interface, from `ip -o -4 addr show`.
fn iface_ipv4(iface: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "3: wlan0    inet 192.168.100.176/24 brd ..."
    text.split_whitespace()
        .skip_while(|t| *t != "inet")
        .nth(1)
        .map(|addr| addr.split('/').next().unwrap_or(addr).to_string())
}

/// Decide what to run from what doctor found. Pure inspection — no
/// side effects before this returns.
fn plan(opts: Opts, cfg: &Config) -> Result<Plan, String> {
    if opts.offline && opts.wifi_uplink {
        return Err("--offline and --wifi-uplink are mutually exclusive".into());
    }
    let report = doctor::inspect();
    let missing: Vec<String> = report
        .dependencies
        .iter()
        .filter(|d| d.path.is_none() && d.name != "bluetoothctl")
        .map(|d| d.name.clone())
        .collect();
    if !missing.is_empty() {
        return Err(format!("missing required tools: {}", missing.join(", ")));
    }

    if opts.wifi_uplink {
        return wifi_uplink_plan(&report, cfg);
    }
    if opts.dual_radio {
        return dual_radio_plan(&report, cfg);
    }

    let gateway = cfg.gateway;
    // Which radio becomes the AP: the operator's explicit choice wins
    // (multi-radio hosts), else the first AP-capable one.
    let ap_iface = match cfg.ap.interface.as_deref() {
        Some(want) => {
            let usable = report
                .radios
                .iter()
                .any(|r| r.supports_ap && r.interfaces.iter().any(|i| i == want));
            if !usable {
                return Err(format!(
                    "ap.interface {want:?}: not found or the radio lacks AP mode \
                     (`piso-hotspot doctor` lists candidates)"
                ));
            }
            want.to_string()
        }
        None => report
            .radios
            .iter()
            .find(|r| r.supports_ap)
            .and_then(|r| r.interfaces.first().cloned())
            .ok_or("no wifi radio supports AP mode")?,
    };
    let uplink = if opts.offline {
        None
    } else if let Some(want) = cfg.ap.uplink.as_deref() {
        let known = report.uplinks.iter().any(|u| u.iface == want);
        let is_station = report
            .radios
            .iter()
            .any(|r| r.interfaces.iter().any(|i| i == want));
        if !known && !is_station {
            return Err(format!("ap.uplink {want:?}: no such interface"));
        }
        Some(want.to_string())
    } else {
        let found = report
            .uplinks
            .iter()
            .find(|u| u.is_default_route && u.kind != crate::doctor::UplinkKind::Wifi)
            .map(|u| u.iface.clone());
        match found {
            Some(iface) => Some(iface),
            None => {
                return Err("no uplink: plug in a USB-tethered phone or ethernet cable \
                     (or use `start --offline` to test without internet)"
                    .into());
            }
        }
    };

    Ok(Plan {
        mode: if opts.offline { "offline" } else { "hotspot" }.to_string(),
        ap_iface,
        uplink,
        gateway,
        station_channel: None,
    })
}

/// `--wifi-uplink`: the radio stays associated with the operator's
/// network and beacons the hotspot beside it — but only if the driver
/// advertises station+AP concurrency *and* the station side is
/// actually connected, because there the uplink is the association.
fn wifi_uplink_plan(report: &doctor::Report, cfg: &Config) -> Result<Plan, String> {
    let radio = report.radios.iter().find(|r| r.concurrent_ap_sta).ok_or(
        "no radio advertises station+AP interface combinations; \
         `piso-hotspot doctor` shows what the driver supports \
         (some cards need a driver patch)",
    )?;
    let station_iface = radio
        .interfaces
        .first()
        .ok_or("the concurrent-capable radio has no interface")?
        .clone();
    let station = radio.station.as_ref().filter(|s| s.connected).ok_or(
        "wifi-uplink needs the station side connected first — its wifi \
         connection is what the hotspot sells (connect, then start again)",
    )?;
    let channel = station
        .channel
        .ok_or("could not read the station's channel; is the connection stable?")?;

    Ok(Plan {
        mode: "wifi-uplink".to_string(),
        ap_iface: crate::viface::AP_IFACE.to_string(),
        uplink: Some(station_iface),
        gateway: cfg.gateway,
        station_channel: Some(channel),
    })
}

/// Pick the beaconing interface: the configured `ap.interface` if it is
/// AP-capable on a radio that is neither the uplink nor another live
/// station, else the first such interface.
fn pick_ap_radio(
    report: &doctor::Report,
    cfg: &Config,
    exclude_phy: &str,
) -> Result<String, String> {
    let is_free = |r: &doctor::Radio| {
        r.phy != exclude_phy && !r.station.as_ref().is_some_and(|s| s.connected)
    };
    let candidates: Vec<&doctor::Radio> = report
        .radios
        .iter()
        .filter(|r| r.supports_ap && is_free(r))
        .collect();
    match cfg.ap.interface.as_deref() {
        Some(want) => {
            let usable = candidates
                .iter()
                .any(|r| r.interfaces.iter().any(|i| i == want));
            if !usable {
                return Err(format!(
                    "ap.interface {want:?}: not an AP-capable radio free of the \
                     uplink and other stations (`piso-hotspot doctor` lists candidates)"
                ));
            }
            Ok(want.to_string())
        }
        None => candidates
            .iter()
            .find_map(|r| r.interfaces.first().cloned())
            .ok_or_else(|| {
                "no radio available to beacon: every other AP-capable radio is \
                 busy as a station"
                    .to_string()
            }),
    }
}

/// `--dual-radio`: internet arrives over one radio as a station while a
/// second radio beacons the AP. Both radios stay in their natural mode,
/// so no driver concurrency is needed — just two radios.
fn dual_radio_plan(report: &doctor::Report, cfg: &Config) -> Result<Plan, String> {
    let default_routes = doctor::default_route_ifaces();
    dual_radio_plan_with_routes(report, cfg, &default_routes)
}

/// Route table injected: the pure decision, exercisable in tests.
fn dual_radio_plan_with_routes(
    report: &doctor::Report,
    cfg: &Config,
    default_routes: &std::collections::BTreeSet<String>,
) -> Result<Plan, String> {
    // An explicit `ap.uplink` names the internet egress. Warn when the
    // default route points elsewhere: NAT is pinned to that interface,
    // so client traffic would otherwise leave unmasked on another link.
    if let Some(want) = cfg.ap.uplink.as_deref() {
        let radio = report
            .radios
            .iter()
            .find(|r| r.interfaces.iter().any(|i| i == want))
            .ok_or_else(|| format!("ap.uplink {want:?}: no such wifi interface"))?;
        if !default_routes.contains(want) {
            log_warn!(
                "ap.uplink {want} does not hold the default route; \
                 client traffic only follows it if a route says so"
            );
        }
        return Ok(Plan {
            mode: "dual-radio".to_string(),
            ap_iface: pick_ap_radio(report, cfg, &radio.phy)?,
            uplink: Some(want.to_string()),
            gateway: cfg.gateway,
            station_channel: None,
        });
    }

    // Auto-selection: the uplink must be the station actually carrying
    // internet (default route), never merely "some connected station".
    let station_radio = report
        .radios
        .iter()
        .filter(|r| r.station.as_ref().is_some_and(|s| s.connected))
        .find(|r| r.interfaces.iter().any(|i| default_routes.contains(i)))
        .ok_or_else(|| {
            let roaming: Vec<&str> = report
                .radios
                .iter()
                .filter(|r| r.station.as_ref().is_some_and(|s| s.connected))
                .filter_map(|r| r.interfaces.first().map(String::as_str))
                .collect();
            match roaming.as_slice() {
                [] => "dual-radio needs a connected wifi station as its uplink \
                       (connect to wifi first)"
                    .to_string(),
                stations => format!(
                    "connected station(s) {} do not hold the default route; set \
                     ap.uplink to choose one explicitly",
                    stations.join(", ")
                ),
            }
        })?;
    let uplink = station_radio
        .interfaces
        .iter()
        .find(|i| default_routes.contains(*i))
        .expect("station_radio was selected by this test")
        .clone();

    // A second associated station would let NetworkManager move the
    // default route mid-sale; only the chosen uplink may be connected.
    let stray: Vec<&String> = report
        .radios
        .iter()
        .filter(|r| r.phy != station_radio.phy)
        .filter(|r| r.station.as_ref().is_some_and(|s| s.connected))
        .flat_map(|r| r.interfaces.iter())
        .collect();
    if !stray.is_empty() {
        return Err(format!(
            "more than one wifi station is connected ({}); disconnect {} or set \
             ap.uplink to choose the uplink explicitly",
            stray
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            uplink
        ));
    }

    Ok(Plan {
        mode: "dual-radio".to_string(),
        ap_iface: pick_ap_radio(report, cfg, &station_radio.phy)?,
        uplink: Some(uplink),
        gateway: cfg.gateway,
        station_channel: None,
    })
}

fn bring_up(d: &mut Daemon, plan: &Plan) -> Result<(), String> {
    if plan.mode == "wifi-uplink" {
        // The station keeps its association and NetworkManager keeps
        // the device; the AP lives on a virtual interface beside it.
        crate::viface::create(&plan.uplink.clone().unwrap_or_default())
            .map_err(|e| format!("creating the virtual AP interface: {e}"))?;
    } else {
        radio::take(&plan.ap_iface).map_err(|e| e.to_string())?;
    }

    // Paywall first: installed before forwarding exists.
    d.fw.install()
        .map_err(|e| format!("installing paywall: {e}"))?;
    // UFW's INPUT chain registers before any nft rule we write — if it
    // is active, our ports must be opened there too or DHCP/portal/panel
    // die silently. Failing here is deliberate: half-working is worse.
    ufw::open(&plan.ap_iface, d.cfg.portal.enabled, d.cfg.ap.port)
        .map_err(|e| format!("opening UFW ports for hotspot clients: {e}"))?;

    radio::set_gateway(&plan.ap_iface, &plan.gateway.to_string(), true)
        .map_err(|e| format!("setting gateway address: {e}"))?;

    // Client bandwidth caps: in-kernel, applied before anything serves
    // traffic. A cap that cannot be enforced fails the start loudly —
    // silently unlimited is worse than refusing to run.
    let caps = shaper::Caps {
        down: d.cfg.bandwidth.max_down_bytes_per_sec,
        up: d.cfg.bandwidth.max_up_bytes_per_sec,
    };
    if !caps.is_unlimited() {
        shaper::apply(&plan.ap_iface, caps).map_err(|e| format!("applying bandwidth caps: {e}"))?;
    }

    d.ip_forward_prev =
        Some(radio::set_ip_forward(true).map_err(|e| format!("enabling ip_forward: {e}"))?);
    // Record the previous value for `stop` recovery.
    if let Ok(text) = fs::read_to_string(RUNNING_FILE)
        && let Ok(mut rec) = serde_json::from_str::<RunningRecord>(&text)
    {
        rec.ip_forward_prev = d.ip_forward_prev.clone();
        if let Ok(text) = serde_json::to_string_pretty(&rec) {
            let _ = fs::write(RUNNING_FILE, text);
        }
    }

    fs::write(
        wireless::DNSMASQ_CONF,
        wireless::dnsmasq_config(&d.cfg, &plan.ap_iface),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        wireless::HOSTAPD_CONF,
        wireless::hostapd_config_on_channel(
            &d.cfg,
            &plan.ap_iface,
            plan.station_channel.unwrap_or(d.cfg.ap.channel),
        ),
    )
    .map_err(|e| e.to_string())?;

    d.dnsmasq = Some(
        supervise(
            "dnsmasq",
            &[
                "--keep-in-foreground",
                &format!("--conf-file={}", wireless::DNSMASQ_CONF),
            ],
        )
        .map_err(|e| format!("starting dnsmasq: {e}"))?,
    );
    expect_alive(&mut d.dnsmasq, "dnsmasq")?;

    d.hostapd = Some(
        supervise("hostapd", &[wireless::HOSTAPD_CONF])
            .map_err(|e| format!("starting hostapd: {e}"))?,
    );
    expect_alive(&mut d.hostapd, "hostapd")?;

    // Everything is in place: bring the firewall in step with the store.
    match paywall::reconcile(&d.conn, &d.fw, now()) {
        Ok(r) if r.changed() => log_info!("initial reconcile: {r:?}"),
        Ok(_) => {}
        Err(e) => log_error!("initial reconcile failed: {e}"),
    }
    Ok(())
}

fn supervise(program: &str, args: &[&str]) -> std::io::Result<Child> {
    Command::new(program).args(args).spawn()
}

fn expect_alive(child: &mut Option<Child>, name: &str) -> Result<(), String> {
    std::thread::sleep(Duration::from_millis(400));
    match child {
        Some(c) => match c.try_wait() {
            Ok(Some(status)) => Err(format!("{name} exited immediately: {status}")),
            Ok(None) => Ok(()),
            Err(e) => Err(format!("{name}: {e}")),
        },
        None => Err(format!("{name} not running")),
    }
}

/// Kill children, disable forwarding, remove the paywall, hand the radio
/// back. Every step tolerates "not done" so it doubles as the failure
/// path. Order matters: stop the AP before the address, the address
/// before handing the card to NetworkManager.
fn teardown(d: &mut Daemon) {
    for (child, name) in [(&mut d.hostapd, "hostapd"), (&mut d.dnsmasq, "dnsmasq")] {
        if let Some(mut c) = child.take() {
            let _ = c.kill();
            let _ = c.wait();
            log_info!("stopped {name}");
        }
    }
    let _ = d.fw.uninstall();
    ufw::close(&d.fw.ap_iface, d.cfg.portal.enabled, d.cfg.ap.port);
    let _ = shaper::clear(&d.fw.ap_iface);
    let gateway = d.fw.gateway.to_string();
    let _ = radio::set_gateway(&d.fw.ap_iface, &gateway, false);
    if let Some(prev) = d.ip_forward_prev.take() {
        let _ = radio::set_ip_forward(prev == "1");
    }
    if d.mode == "wifi-uplink" {
        // The station and NetworkManager were never touched; only the
        // virtual AP interface goes away.
        crate::viface::remove(&d.fw.ap_iface);
    } else {
        radio::release(&d.fw.ap_iface);
    }
    for file in [
        PID_FILE,
        RUNNING_FILE,
        control::SOCKET_PATH,
        wireless::HOSTAPD_CONF,
        wireless::DNSMASQ_CONF,
        wireless::LEASE_FILE,
    ] {
        let _ = fs::remove_file(file);
    }
    log_info!("teardown complete");
}

// --------------------------------------------------------------- serving

fn serve(d: Arc<Mutex<Daemon>>) {
    std::thread::spawn(move || {
        let listener = match control::bind() {
            Ok(l) => l,
            Err(e) => {
                log_error!("control socket: {e}");
                SHUTDOWN.store(true, Ordering::SeqCst);
                return;
            }
        };
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let d = Arc::clone(&d);
            // Requests are cheap and rare; serial handling keeps the
            // store single-writer without ceremony.
            handle(&d, stream);
        }
    });
}

fn handle(d: &Arc<Mutex<Daemon>>, stream: std::os::unix::net::UnixStream) {
    // A request is one small JSON line; cap what we are willing to
    // buffer for it so a stuck client cannot grow the daemon's memory.
    let mut reader = BufReader::new(stream.take(MAX_CONTROL_REQUEST));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let response = match serde_json::from_str::<Request>(line.trim()) {
        Err(e) => Response::err(format!("bad request: {e}")),
        Ok(req) => dispatch(d, req),
    };
    let mut stream = reader.into_inner().into_inner();
    if let Ok(mut text) = serde_json::to_string(&response) {
        text.push('\n');
        let _ = stream.write_all(text.as_bytes());
    }
}

/// Largest control-socket request we will read (the socket is root-only;
/// this is a guard against a buggy caller, not against an attacker).
const MAX_CONTROL_REQUEST: u64 = 64 * 1024;

pub(crate) fn dispatch(d: &Arc<Mutex<Daemon>>, req: Request) -> Response {
    dispatch_actor(d, req, "cli")
}

/// Dispatch a request, attributing it to `actor` in the audit trail.
///
/// The root socket reports as `cli`; the panel reports as
/// `panel:<address>`. Every action that changes who has internet is
/// recorded *and* logged before the response is built, so the record
/// exists even if the caller never sees the answer. Failures change
/// nothing, so they are not recorded — but they are logged.
pub(crate) fn dispatch_actor(d: &Arc<Mutex<Daemon>>, req: Request, actor: &str) -> Response {
    let result = (|| -> Result<Response, String> {
        let d = d.lock().map_err(|_| "state poisoned".to_string())?;
        let now_ts = now();
        match req {
            Request::Status => Ok(Response {
                ok: true,
                error: None,
                expires_at: None,
                status: Some(status_info(&d, now_ts)?),
            }),
            Request::Grant { mac, pass } => {
                let mac: crate::mac::MacAddr = mac.parse().map_err(|e| format!("bad mac: {e}"))?;
                let pass = d
                    .cfg
                    .passes
                    .iter()
                    .find(|p| p.id == pass)
                    .ok_or_else(|| {
                        let ids: Vec<&str> = d.cfg.passes.iter().map(|p| p.id.as_str()).collect();
                        format!("unknown pass {:?}; configured: {}", pass, ids.join(", "))
                    })?
                    .clone();
                let expires =
                    store::grant(&d.conn, &mac, &pass, now_ts, &d.cfg.currency).map_err(err_str)?;
                store::record_action(
                    &d.conn,
                    now_ts,
                    "grant",
                    Some(&mac),
                    Some(&pass.id),
                    actor,
                    Some(&format!(
                        "{} ({} minor) until {expires}",
                        pass.name, pass.price_minor
                    )),
                )
                .map_err(err_str)?;
                paywall::apply_device(&d.conn, &d.fw, mac, now_ts).map_err(err_str)?;
                log_info!("grant {mac} pass={} by {actor} until {expires}", pass.id);
                Ok(Response {
                    ok: true,
                    error: None,
                    status: None,
                    expires_at: Some(expires),
                })
            }
            Request::Revoke { mac } => {
                let mac: crate::mac::MacAddr = mac.parse().map_err(|e| format!("bad mac: {e}"))?;
                store::revoke(&d.conn, &mac, now_ts).map_err(err_str)?;
                store::record_action(&d.conn, now_ts, "revoke", Some(&mac), None, actor, None)
                    .map_err(err_str)?;
                paywall::apply_device(&d.conn, &d.fw, mac, now_ts).map_err(err_str)?;
                log_info!("revoke {mac} by {actor}");
                Ok(Response::ok_empty())
            }
            Request::Friend { mac, label } => {
                let mac: crate::mac::MacAddr = mac.parse().map_err(|e| format!("bad mac: {e}"))?;
                let label = crate::text::clean_label(label.as_deref())?;
                store::friend(&d.conn, &mac, label.as_deref(), now_ts).map_err(err_str)?;
                store::record_action(
                    &d.conn,
                    now_ts,
                    "friend",
                    Some(&mac),
                    None,
                    actor,
                    label.as_deref(),
                )
                .map_err(err_str)?;
                paywall::apply_device(&d.conn, &d.fw, mac, now_ts).map_err(err_str)?;
                log_info!(
                    "friend {mac} label={:?} by {actor} (unlimited, free)",
                    label.as_deref().unwrap_or("-")
                );
                Ok(Response::ok_empty())
            }
            Request::Unfriend { mac } => {
                let mac: crate::mac::MacAddr = mac.parse().map_err(|e| format!("bad mac: {e}"))?;
                store::unfriend(&d.conn, &mac).map_err(err_str)?;
                store::record_action(&d.conn, now_ts, "unfriend", Some(&mac), None, actor, None)
                    .map_err(err_str)?;
                paywall::apply_device(&d.conn, &d.fw, mac, now_ts).map_err(err_str)?;
                log_info!("unfriend {mac} by {actor}");
                Ok(Response::ok_empty())
            }
            Request::Rename { mac, label } => {
                let mac: crate::mac::MacAddr = mac.parse().map_err(|e| format!("bad mac: {e}"))?;
                let label = crate::text::clean_label(label.as_deref())?;
                store::set_device_label(&d.conn, &mac, label.as_deref(), now_ts)
                    .map_err(err_str)?;
                store::record_action(
                    &d.conn,
                    now_ts,
                    "rename",
                    Some(&mac),
                    None,
                    actor,
                    label.as_deref(),
                )
                .map_err(err_str)?;
                log_info!(
                    "rename {mac} to {:?} by {actor}",
                    label.as_deref().unwrap_or("(cleared)")
                );
                Ok(Response::ok_empty())
            }
            Request::Shutdown => {
                store::record_action(&d.conn, now_ts, "shutdown", None, None, actor, None)
                    .map_err(err_str)?;
                log_info!("shutdown requested by {actor}");
                SHUTDOWN.store(true, Ordering::SeqCst);
                Ok(Response::ok_empty())
            }
        }
    })();
    match result {
        Ok(resp) => resp,
        Err(e) => {
            log_warn!("request refused: {e}");
            Response::err(e)
        }
    }
}

/// The snapshot `status` and the panel report. Kept in one place so both
/// lanes answer the same way.
fn status_info(d: &Daemon, now_ts: i64) -> Result<StatusInfo, String> {
    Ok(StatusInfo {
        mode: d.mode.clone(),
        ap_iface: d.fw.ap_iface.clone(),
        uplink: d.fw.uplink.clone(),
        gateway: d.fw.gateway.to_string(),
        started_at: d.started_at,
        devices_seen: store::count_devices(&d.conn).map_err(err_str)?,
        active_passes: store::count_active_passes(&d.conn, now_ts).map_err(err_str)?,
        panel_urls: d.panel_urls.clone(),
        admin_passphrase: d.auth.passphrase().to_string(),
        sessions: d.auth.session_count(),
    })
}

fn err_str(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The loop that keeps the kernel honest: expire passes, sync sets,
/// notice new devices via our own DHCP leases.
fn spawn_reconciler(d: Arc<Mutex<Daemon>>) {
    std::thread::spawn(move || {
        while !SHUTDOWN.load(Ordering::SeqCst) {
            std::thread::sleep(RECONCILE_INTERVAL);
            if SHUTDOWN.load(Ordering::SeqCst) {
                return;
            }
            let Ok(d) = d.lock() else { return };
            let now_ts = now();
            match paywall::reconcile(&d.conn, &d.fw, now_ts) {
                Ok(r) if r.changed() => log_info!("reconcile: {r:?}"),
                Ok(_) => {}
                Err(e) => log_error!("reconcile failed: {e}"),
            }
            for lease in leases::read(Path::new(wireless::LEASE_FILE)) {
                if let Err(e) =
                    store::touch_leased_device(&d.conn, &lease.mac, Some(&lease.ip), now_ts)
                {
                    log_warn!("lease touch failed: {e}");
                }
            }
            // Retention: forget strangers, keep payers and friends, and
            // let the next tick sync the firewall sets accordingly.
            let retention = i64::from(d.cfg.retention_days) * 86_400;
            match store::prune_devices(&d.conn, now_ts, retention) {
                Ok(0) => {}
                Ok(n) => log_info!(
                    "retention: forgot {n} device(s) not seen in {}d",
                    d.cfg.retention_days
                ),
                Err(e) => log_warn!("prune failed: {e}"),
            }
        }
    });
}

/// If hostapd or dnsmasq dies, the hotspot is a lie — shut down.
fn spawn_child_watch(d: Arc<Mutex<Daemon>>) {
    std::thread::spawn(move || {
        while !SHUTDOWN.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
            let mut death: Option<String> = None;
            {
                let Ok(mut guard) = d.lock() else { return };
                if let Some(status) = guard
                    .hostapd
                    .as_mut()
                    .and_then(|c| c.try_wait().ok().flatten())
                {
                    death = Some(format!("hostapd ({status})"));
                } else if let Some(status) = guard
                    .dnsmasq
                    .as_mut()
                    .and_then(|c| c.try_wait().ok().flatten())
                {
                    death = Some(format!("dnsmasq ({status})"));
                }
            }
            if let Some(what) = death {
                if SHUTDOWN.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(mut slot) = CHILD_DEATH.lock() {
                    *slot = Some(what);
                }
                SHUTDOWN.store(true, Ordering::SeqCst);
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::{Radio, Station};
    use std::collections::BTreeSet;

    fn radio(iface: &str, phy: &str, ap: bool, station: Option<&str>) -> Radio {
        Radio {
            interfaces: vec![iface.to_string()],
            phy: phy.to_string(),
            driver: None,
            bands: vec!["2.4".to_string()],
            supports_ap: ap,
            concurrent_ap_sta: false,
            concurrent_shares_channel: false,
            station: station.map(|ssid| Station {
                connected: true,
                ssid: Some(ssid.to_string()),
                channel: Some(6),
            }),
        }
    }

    fn report(radios: Vec<Radio>) -> doctor::Report {
        doctor::Report {
            host: doctor::Host {
                hostname: "test".into(),
                kernel: "test".into(),
                is_root: true,
            },
            dependencies: vec![],
            radios,
            uplinks: vec![],
            modes: vec![],
            state: doctor::State {
                config_path: "/dev/null".into(),
                config_exists: false,
                config_error: None,
                state_path: "/dev/null".into(),
                state_exists: false,
                schema_version: None,
            },
            conflicts: vec![],
            ok: true,
        }
    }

    fn routes(ifaces: &[&str]) -> BTreeSet<String> {
        ifaces.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dual_radio_picks_the_default_route_station_as_uplink() {
        let r = report(vec![
            radio("wlan0", "phy0", true, Some("home")),
            radio("wlan1", "phy1", true, None),
        ]);
        let plan =
            dual_radio_plan_with_routes(&report_clone(&r), &Config::default(), &routes(&["wlan0"]))
                .expect("plan");
        assert_eq!(plan.mode, "dual-radio");
        assert_eq!(plan.uplink.as_deref(), Some("wlan0"));
        assert_eq!(plan.ap_iface, "wlan1");
    }

    #[test]
    fn dual_radio_refuses_two_connected_stations_without_an_explicit_uplink() {
        let r = report(vec![
            radio("wlan0", "phy0", true, Some("home")),
            radio("wlan1", "phy1", true, Some("other")),
            radio("wlan2", "phy2", true, None),
        ]);
        let err =
            dual_radio_plan_with_routes(&r, &Config::default(), &routes(&["wlan0"])).unwrap_err();
        assert!(err.contains("more than one wifi station"), "{err}");
    }

    #[test]
    fn dual_radio_explicit_uplink_wins_over_ambiguity() {
        let mut cfg = Config::default();
        cfg.ap.uplink = Some("wlan1".into());
        let r = report(vec![
            radio("wlan0", "phy0", true, Some("home")),
            radio("wlan1", "phy1", true, Some("other")),
            radio("wlan2", "phy2", true, None),
        ]);
        // No default-route entry needed: explicit choice is authoritative.
        let plan = dual_radio_plan_with_routes(&r, &cfg, &routes(&[])).expect("plan");
        assert_eq!(plan.uplink.as_deref(), Some("wlan1"));
        assert_eq!(plan.ap_iface, "wlan2");
    }

    #[test]
    fn dual_radio_never_beacons_on_the_uplink_radio() {
        let mut cfg = Config::default();
        cfg.ap.interface = Some("wlan0".into()); // same phy as the uplink
        let r = report(vec![
            radio("wlan0", "phy0", true, Some("home")),
            radio("wlan1", "phy1", true, None),
        ]);
        let err = dual_radio_plan_with_routes(&r, &cfg, &routes(&["wlan0"])).unwrap_err();
        assert!(err.contains("not an AP-capable radio free of"), "{err}");
    }

    #[test]
    fn dual_radio_needs_a_second_radio() {
        let r = report(vec![radio("wlan0", "phy0", true, Some("home"))]);
        let err =
            dual_radio_plan_with_routes(&r, &Config::default(), &routes(&["wlan0"])).unwrap_err();
        assert!(err.contains("no radio available to beacon"), "{err}");
    }

    #[test]
    fn dual_radio_without_a_default_route_names_the_station() {
        let r = report(vec![
            radio("wlan0", "phy0", true, Some("home")),
            radio("wlan1", "phy1", true, None),
        ]);
        let err = dual_radio_plan_with_routes(&r, &Config::default(), &routes(&[])).unwrap_err();
        assert!(err.contains("do not hold the default route"), "{err}");
        assert!(err.contains("ap.uplink"), "{err}");
    }

    fn report_clone(r: &doctor::Report) -> doctor::Report {
        // Report owns no interior state worth deep-copying; rebuild it.
        report(
            r.radios
                .iter()
                .map(|x| Radio {
                    interfaces: x.interfaces.clone(),
                    phy: x.phy.clone(),
                    driver: x.driver.clone(),
                    bands: x.bands.clone(),
                    supports_ap: x.supports_ap,
                    concurrent_ap_sta: x.concurrent_ap_sta,
                    concurrent_shares_channel: x.concurrent_shares_channel,
                    station: x.station.as_ref().map(|s| Station {
                        connected: s.connected,
                        ssid: s.ssid.clone(),
                        channel: s.channel,
                    }),
                })
                .collect(),
        )
    }

    /// A daemon state good enough to exercise `dispatch` without a radio:
    /// temp database, default config, and a firewall that is never asked
    /// to run anything.
    fn offline_daemon(name: &str) -> Arc<Mutex<Daemon>> {
        let dir = std::env::temp_dir().join(format!("piso-dispatch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conn = crate::store::open(&dir.join("state.db")).unwrap();
        Arc::new(Mutex::new(Daemon {
            cfg: Config::default(),
            conn,
            fw: Firewall {
                ap_iface: "wlan0".into(),
                uplink: None,
                gateway: Ipv4Addr::new(10, 10, 0, 1),
                panel_port: 8080,
                portal_enabled: true,
            },
            mode: "offline".into(),
            started_at: 0,
            auth: crate::auth::AuthState::new("test-passphrase".into()),
            panel_urls: Vec::new(),
            passphrase_generated: true,
            ip_forward_prev: None,
            hostapd: None,
            dnsmasq: None,
        }))
    }

    #[test]
    fn labels_are_validated_where_both_lanes_meet() {
        let d = offline_daemon("labels");
        let mac = "aa:bb:cc:dd:ee:ff".to_string();

        // Blank means "clear", and normal labels are stored trimmed.
        let resp = dispatch(
            &d,
            Request::Rename {
                mac: mac.clone(),
                label: Some("  Juan's laptop  ".into()),
            },
        );
        assert!(resp.ok, "{:?}", resp.error);
        let stored: Option<String> = d
            .lock()
            .unwrap()
            .conn
            .query_row("SELECT label FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored.as_deref(), Some("Juan's laptop"));
        assert!(
            dispatch(
                &d,
                Request::Rename {
                    mac: mac.clone(),
                    label: Some("  ".into())
                }
            )
            .ok
        );
        let stored: Option<String> = d
            .lock()
            .unwrap()
            .conn
            .query_row("SELECT label FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, None, "blank clears the label");

        // Oversized and control-character labels are refused, not stored.
        let too_long = "a".repeat(crate::text::MAX_LABEL_CHARS + 1);
        for bad in [too_long, "evil\nlabel".into(), "\u{1b}[2Jpwned".into()] {
            let resp = dispatch(
                &d,
                Request::Friend {
                    mac: mac.clone(),
                    label: Some(bad.clone()),
                },
            );
            assert!(!resp.ok, "{bad:?} must be refused");
            let err = resp.error.unwrap_or_default();
            assert!(
                err.contains("at most 50 characters") || err.contains("control characters"),
                "{err}"
            );
        }
        let friends: i64 = d
            .lock()
            .unwrap()
            .conn
            .query_row("SELECT COUNT(*) FROM friends", [], |r| r.get(0))
            .unwrap();
        assert_eq!(friends, 0, "nothing was stored");
    }
}
