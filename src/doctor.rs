//! `piso-hotspot doctor`: inspect this machine and report what the
//! hotspot could do. Read-only — never changes anything.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;

use crate::iwlist;

#[derive(Serialize)]
pub struct Report {
    pub host: Host,
    pub dependencies: Vec<Dependency>,
    pub radios: Vec<Radio>,
    pub uplinks: Vec<Uplink>,
    pub modes: Vec<Mode>,
    pub state: State,
    /// True when at least one real hotspot mode is available.
    pub ok: bool,
}

#[derive(Serialize)]
pub struct Host {
    pub hostname: String,
    pub kernel: String,
    pub is_root: bool,
}

#[derive(Serialize)]
pub struct Dependency {
    pub name: String,
    pub required_for: Vec<String>,
    pub path: Option<PathBuf>,
}

#[derive(Serialize)]
pub struct Radio {
    /// Network interfaces on this phy.
    pub interfaces: Vec<String>,
    pub phy: String,
    pub driver: Option<String>,
    /// Distinct bands in GHz (`"2.4"`, `"5"`, `"6"`).
    pub bands: Vec<String>,
    pub supports_ap: bool,
    /// Can be a station and an AP at the same time (single-radio uplink).
    pub concurrent_ap_sta: bool,
    /// Every station+AP combination shares one channel.
    pub concurrent_shares_channel: bool,
    /// Station-side association state, from `iw dev <iface> link`.
    pub station: Option<Station>,
}

#[derive(Serialize)]
pub struct Station {
    pub connected: bool,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UplinkKind {
    Ethernet,
    UsbTether,
    Wifi,
    Bluetooth,
    Other,
}

#[derive(Serialize)]
pub struct Uplink {
    pub iface: String,
    pub kind: UplinkKind,
    pub is_default_route: bool,
    pub operstate: Option<String>,
}

#[derive(Serialize)]
pub struct Mode {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct State {
    pub config_path: PathBuf,
    pub config_exists: bool,
    pub state_path: PathBuf,
    pub state_exists: bool,
    pub schema_version: Option<i64>,
}

/// Which tools are installed. Passed around as plain data so mode
/// derivation stays a pure, testable function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tools {
    pub iw: bool,
    pub hostapd: bool,
    pub dnsmasq: bool,
    pub nft: bool,
    pub bluetoothctl: bool,
}

impl Tools {
    /// Missing tools required by every AP-based mode.
    fn missing_ap_deps(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.iw {
            missing.push("iw");
        }
        if !self.hostapd {
            missing.push("hostapd");
        }
        if !self.dnsmasq {
            missing.push("dnsmasq");
        }
        if !self.nft {
            missing.push("nft");
        }
        missing
    }
}

pub fn inspect() -> Report {
    let tools = Tools {
        iw: which("iw").is_some(),
        hostapd: which("hostapd").is_some(),
        dnsmasq: which("dnsmasq").is_some(),
        nft: which("nft").is_some(),
        bluetoothctl: which("bluetoothctl").is_some(),
    };

    let phy_caps: BTreeMap<String, iwlist::Phy> = which("iw")
        .and_then(|iw| run_ok(&iw, &["list"]))
        .map(|out| {
            iwlist::parse(&out)
                .into_iter()
                .map(|p| (p.name.clone(), p))
                .collect()
        })
        .unwrap_or_default();

    let default_routes = default_route_ifaces();

    let radios = collect_radios(&phy_caps);
    let uplinks = collect_uplinks(&default_routes);
    let modes = derive_modes(&radios, &uplinks, tools);
    let ok = modes
        .iter()
        .filter(|m| m.name != "offline")
        .any(|m| m.available);

    let config_path = crate::config::config_path();
    let state_path = crate::config::state_path();
    let (state_exists, schema_version) = match store_info(&state_path) {
        Some(v) => (true, v),
        None => (false, None),
    };

    Report {
        host: Host {
            hostname: read_trimmed("/etc/hostname").unwrap_or_else(|| "unknown".to_string()),
            kernel: read_trimmed("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|| "unknown".to_string()),
            is_root: is_root(),
        },
        dependencies: vec![
            dep("iw", tools.iw, &["hotspot", "dual-radio", "wifi-uplink"]),
            dep(
                "hostapd",
                tools.hostapd,
                &["hotspot", "dual-radio", "wifi-uplink"],
            ),
            dep(
                "dnsmasq",
                tools.dnsmasq,
                &["hotspot", "dual-radio", "wifi-uplink"],
            ),
            dep("nft", tools.nft, &["hotspot", "dual-radio", "wifi-uplink"]),
            dep("bluetoothctl", tools.bluetoothctl, &["bluetooth"]),
        ],
        radios,
        uplinks,
        modes,
        state: State {
            config_exists: config_path.exists(),
            config_path,
            state_exists,
            state_path,
            schema_version,
        },
        ok,
    }
}

fn dep(name: &'static str, found: bool, required_for: &[&'static str]) -> Dependency {
    Dependency {
        name: name.to_string(),
        required_for: required_for.iter().map(|s| s.to_string()).collect(),
        path: if found { which(name) } else { None },
    }
}

fn collect_radios(phy_caps: &BTreeMap<String, iwlist::Phy>) -> Vec<Radio> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for iface in net_ifaces() {
        if let Some(phy) = symlink_name(&format!("/sys/class/net/{iface}/phy80211")) {
            groups.entry(phy).or_default().push(iface);
        }
    }

    let mut radios: Vec<Radio> = groups
        .into_iter()
        .map(|(phy, interfaces)| {
            let caps = phy_caps.get(&phy);
            let driver = interfaces.iter().find_map(|i| driver_name(i));
            let station = interfaces.iter().find_map(|i| station_link(i));
            Radio {
                bands: caps
                    .map(|p| p.bands.iter().cloned().collect())
                    .unwrap_or_default(),
                supports_ap: caps.is_some_and(|p| p.supports_ap()),
                concurrent_ap_sta: caps.is_some_and(|p| p.supports_concurrent_station_and_ap()),
                concurrent_shares_channel: caps
                    .is_some_and(|p| p.concurrent_combos_share_channel()),
                interfaces,
                phy,
                driver,
                station,
            }
        })
        .collect();
    radios.sort_by(|a, b| a.interfaces.cmp(&b.interfaces));
    radios
}

fn collect_uplinks(default_routes: &BTreeSet<String>) -> Vec<Uplink> {
    let mut uplinks: Vec<Uplink> = net_ifaces()
        .into_iter()
        .filter(|i| i != "lo")
        .filter(|i| !is_wifi(i))
        .map(|iface| {
            let kind = classify_uplink(&iface);
            let is_default_route = default_routes.contains(&iface);
            let operstate = read_trimmed(&format!("/sys/class/net/{iface}/operstate"));
            Uplink {
                iface,
                kind,
                is_default_route,
                operstate,
            }
        })
        .collect();
    uplinks.sort_by_key(|u| (!u.is_default_route, u.iface.clone()));
    uplinks
}

/// Pure mode derivation from inspected facts, so it can be tested
/// without hardware.
pub fn derive_modes(radios: &[Radio], uplinks: &[Uplink], tools: Tools) -> Vec<Mode> {
    let mut modes = Vec::new();
    let missing = tools.missing_ap_deps();
    let ap_radios: Vec<&Radio> = radios.iter().filter(|r| r.supports_ap).collect();
    let wired_uplink: Option<&Uplink> = uplinks
        .iter()
        .find(|u| matches!(u.kind, UplinkKind::Ethernet | UplinkKind::UsbTether));
    let wifi_is_default = uplinks
        .iter()
        .any(|u| u.kind == UplinkKind::Wifi && u.is_default_route);

    // hotspot: one radio becomes the AP, internet comes from elsewhere
    let hotspot = if !missing.is_empty() {
        Mode::unavailable("hotspot", format!("missing tools: {}", missing.join(", ")))
    } else if ap_radios.is_empty() {
        Mode::unavailable("hotspot", "no radio supports AP mode".to_string())
    } else if let Some(uplink) = wired_uplink {
        Mode::available(
            "hotspot",
            format!("uplink {} ({:?})", uplink.iface, uplink.kind),
        )
    } else if wifi_is_default && radios.len() < 2 {
        Mode::unavailable(
            "hotspot",
            "the only radio would be spent on the AP; plug in a USB-tethered \
             phone or ethernet for the uplink"
                .to_string(),
        )
    } else {
        Mode::unavailable(
            "hotspot",
            "no uplink found; plug in a USB-tethered phone or ethernet cable".to_string(),
        )
    };
    modes.push(hotspot);

    // dual-radio: one radio uplinks, another beacons
    let dual = if !missing.is_empty() {
        Mode::unavailable(
            "dual-radio",
            format!("missing tools: {}", missing.join(", ")),
        )
    } else if radios.len() < 2 {
        Mode::unavailable("dual-radio", "only one radio present".to_string())
    } else if !wifi_is_default {
        Mode::unavailable(
            "dual-radio",
            "no wifi station to uplink from (connect to wifi first)".to_string(),
        )
    } else if ap_radios.is_empty() {
        Mode::unavailable("dual-radio", "no radio supports AP mode".to_string())
    } else {
        Mode::available(
            "dual-radio",
            "uplinks over wifi, beacons on a second radio".to_string(),
        )
    };
    modes.push(dual);

    // wifi-uplink: one radio does both, needs a driver advertising the
    // combination (patched or dual-band-concurrency capable)
    let wifi_uplink = if !missing.is_empty() {
        Mode::unavailable(
            "wifi-uplink",
            format!("missing tools: {}", missing.join(", ")),
        )
    } else {
        match radios.iter().find(|r| r.concurrent_ap_sta) {
            None => Mode::unavailable(
                "wifi-uplink",
                "no radio advertises station+AP interface combinations".to_string(),
            ),
            Some(radio) => {
                let mut notes = vec![];
                if radio.concurrent_shares_channel {
                    notes.push("the AP follows the station's channel and band");
                }
                match &radio.station {
                    Some(s) if s.connected => notes.push("station connected"),
                    Some(_) => notes.push("station not connected (uplink would have no internet)"),
                    None => {}
                }
                Mode::available(
                    "wifi-uplink",
                    format!(
                        "single radio {} does both{}",
                        radio.interfaces.first().map(String::as_str).unwrap_or("?"),
                        if notes.is_empty() {
                            String::new()
                        } else {
                            format!("; {}", notes.join("; "))
                        }
                    ),
                )
            }
        }
    };
    modes.push(wifi_uplink);

    // bluetooth: paired phone with Bluetooth tethering
    modes.push(if tools.bluetoothctl {
        Mode::available(
            "bluetooth",
            "phone must be paired with Bluetooth tethering switched on".to_string(),
        )
    } else {
        Mode::unavailable("bluetooth", "bluetoothctl not installed".to_string())
    });

    // offline: no uplink; exercises the paywall and the panel
    modes.push(Mode::available(
        "offline",
        "no internet; paywall and panel can be tested".to_string(),
    ));

    modes
}

impl Mode {
    fn available(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            available: true,
            detail,
        }
    }
    fn unavailable(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            available: false,
            detail,
        }
    }
}

pub fn print_human(report: &Report) {
    println!("piso-hotspot doctor");
    println!();
    println!("Host");
    println!("  hostname   {}", report.host.hostname);
    println!("  kernel     {}", report.host.kernel);
    println!(
        "  root       {}",
        if report.host.is_root {
            "yes"
        } else {
            "no (starting the hotspot will need sudo)"
        }
    );
    println!();
    println!("Dependencies");
    for dep in &report.dependencies {
        match &dep.path {
            Some(p) => println!("  {:<14} ok       {}", dep.name, p.display()),
            None => println!(
                "  {:<14} missing  required by: {}",
                dep.name,
                dep.required_for.join(", ")
            ),
        }
    }
    println!();
    println!("Radios");
    if report.radios.is_empty() {
        println!("  no wifi radios found");
    }
    for radio in &report.radios {
        let primary = radio.interfaces.first().map(String::as_str).unwrap_or("?");
        let driver = radio.driver.as_deref().unwrap_or("unknown driver");
        println!("  {}  ({}, {})", primary, radio.phy, driver);
        if !radio.bands.is_empty() {
            let bands: Vec<String> = radio.bands.iter().map(|b| format!("{b} GHz")).collect();
            println!("         bands: {}", bands.join(", "));
        }
        println!(
            "         AP mode: {}   station+AP: {}{}",
            yes_no(radio.supports_ap),
            yes_no(radio.concurrent_ap_sta),
            if radio.concurrent_ap_sta && radio.concurrent_shares_channel {
                " (shares one channel)"
            } else {
                ""
            }
        );
        if let Some(st) = &radio.station {
            if st.connected {
                println!(
                    "         station: connected to {}{}",
                    st.ssid
                        .as_deref()
                        .map(|s| format!("\"{s}\""))
                        .unwrap_or_else(|| "(unknown ssid)".to_string()),
                    st.channel
                        .map(|c| format!(" on channel {c}"))
                        .unwrap_or_default()
                );
            } else {
                println!("         station: not connected");
            }
        }
    }
    println!();
    println!("Uplinks");
    if report.uplinks.is_empty() {
        println!("  no non-wifi interfaces found");
    }
    for uplink in &report.uplinks {
        println!(
            "  {:<12} {:<11} {}{}",
            uplink.iface,
            kind_label(uplink.kind),
            if uplink.is_default_route {
                "default route"
            } else {
                ""
            },
            uplink
                .operstate
                .as_deref()
                .filter(|s| *s != "up")
                .map(|s| format!(" ({s})"))
                .unwrap_or_default()
        );
    }
    println!();
    println!("Modes");
    for mode in &report.modes {
        println!(
            "  {:<12} {:<11} {}",
            mode.name,
            if mode.available {
                "available"
            } else {
                "unavailable"
            },
            mode.detail
        );
    }
    println!();
    println!("State");
    println!(
        "  config     {}{}",
        report.state.config_path.display(),
        if report.state.config_exists {
            ""
        } else {
            " (not created yet; defaults apply)"
        }
    );
    println!(
        "  state.db   {}{}",
        report.state.state_path.display(),
        match (report.state.state_exists, report.state.schema_version) {
            (false, _) => " (not created yet)".to_string(),
            (true, Some(v)) => format!(" (schema v{v})"),
            (true, None) => " (unreadable)".to_string(),
        }
    );
    println!();
    if report.ok {
        println!("verdict: ok — at least one hotspot mode is available");
    } else {
        println!("verdict: no hotspot mode is available (see modes above)");
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn kind_label(kind: UplinkKind) -> &'static str {
    match kind {
        UplinkKind::Ethernet => "ethernet",
        UplinkKind::UsbTether => "usb-tether",
        UplinkKind::Wifi => "wifi",
        UplinkKind::Bluetooth => "bluetooth",
        UplinkKind::Other => "other",
    }
}

// ---------------------------------------------------------------- host probes

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if let Ok(meta) = fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Some(candidate);
        }
    }
    None
}

fn run_ok(program: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn is_root() -> bool {
    read_trimmed("/proc/self/status")
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(str::to_string)
            })
        })
        .is_some_and(|uid| uid == "0")
}

fn net_ifaces() -> Vec<String> {
    let mut ifaces: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|dir| {
            dir.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect()
        })
        .unwrap_or_default();
    ifaces.sort();
    ifaces
}

fn is_wifi(iface: &str) -> bool {
    PathBuf::from(format!("/sys/class/net/{iface}/phy80211")).exists()
}

/// Basename of a symlink target, e.g. `.../phy80211` → `phy0`.
fn symlink_name(link: &str) -> Option<String> {
    fs::read_link(link)
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()))
}

fn driver_name(iface: &str) -> Option<String> {
    symlink_name(&format!("/sys/class/net/{iface}/device/driver"))
}

fn classify_uplink(iface: &str) -> UplinkKind {
    if iface.starts_with("bnep") {
        return UplinkKind::Bluetooth;
    }
    // USB devices expose vendor/product ids under their device node.
    if PathBuf::from(format!("/sys/class/net/{iface}/device/idVendor")).exists() {
        return UplinkKind::UsbTether;
    }
    // ARPHRD_ETHER (1) and no wifi phy: plain ethernet-like link.
    if read_trimmed(&format!("/sys/class/net/{iface}/type")).as_deref() == Some("1") {
        return UplinkKind::Ethernet;
    }
    UplinkKind::Other
}

/// Interfaces currently holding the default IPv4 route, from /proc/net/route.
fn default_route_ifaces() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(text) = fs::read_to_string("/proc/net/route") else {
        return out;
    };
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(iface), Some(dest), Some(_gw), Some(flags)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        // Destination 00000000, RTF_UP (0x1) set.
        if dest == "00000000"
            && let Ok(flags) = u32::from_str_radix(flags, 16)
            && flags & 0x1 != 0
        {
            out.insert(iface.to_string());
        }
    }
    out
}

/// Association state of an interface via `iw dev <iface> link`.
fn station_link(iface: &str) -> Option<Station> {
    let iw = which("iw")?;
    let out = run_ok(&iw, &["dev", iface, "link"])?;
    if out.trim_start().starts_with("Not connected") {
        return Some(Station {
            connected: false,
            ssid: None,
            channel: None,
        });
    }
    if !out.trim_start().starts_with("Connected to") {
        return None;
    }
    let ssid = out.lines().find_map(|l| {
        l.trim()
            .strip_prefix("SSID: ")
            .map(|s| s.trim().to_string())
    });
    let channel = out.lines().find_map(|l| {
        // `freq: 5745.0` — iw prints a float.
        let rest = l.trim().strip_prefix("freq: ")?;
        let mhz: f64 = rest.split_whitespace().next()?.parse().ok()?;
        iwlist::channel_for_frequency(mhz.round() as u32)
    });
    Some(Station {
        connected: true,
        ssid,
        channel,
    })
}

fn store_info(path: &std::path::Path) -> Option<Option<i64>> {
    if !path.exists() {
        return None;
    }
    match crate::store::open_readonly(path) {
        Ok(conn) => Some(crate::store::schema_version(&conn).ok()),
        Err(_) => Some(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn radio(ap: bool, concurrent: bool) -> Radio {
        Radio {
            interfaces: vec!["wlan0".to_string()],
            phy: "phy0".to_string(),
            driver: None,
            bands: vec!["2.4".to_string()],
            supports_ap: ap,
            concurrent_ap_sta: concurrent,
            concurrent_shares_channel: concurrent,
            station: None,
        }
    }

    fn uplink(kind: UplinkKind, default: bool) -> Uplink {
        Uplink {
            iface: "usb0".to_string(),
            kind,
            is_default_route: default,
            operstate: Some("up".to_string()),
        }
    }

    const FULL_TOOLS: Tools = Tools {
        iw: true,
        hostapd: true,
        dnsmasq: true,
        nft: true,
        bluetoothctl: true,
    };

    fn mode<'a>(modes: &'a [Mode], name: &str) -> &'a Mode {
        modes.iter().find(|m| m.name == name).unwrap()
    }

    #[test]
    fn hotspot_needs_ap_radio_and_wired_uplink() {
        let radios = vec![radio(true, false)];
        let uplinks = vec![uplink(UplinkKind::UsbTether, true)];
        let modes = derive_modes(&radios, &uplinks, FULL_TOOLS);
        assert!(mode(&modes, "hotspot").available);
        assert!(!mode(&modes, "dual-radio").available);
        assert!(!mode(&modes, "wifi-uplink").available);
    }

    #[test]
    fn single_wifi_radio_cannot_hotspot_over_itself() {
        let radios = vec![radio(true, false)];
        let uplinks = vec![uplink(UplinkKind::Wifi, true)];
        let modes = derive_modes(&radios, &uplinks, FULL_TOOLS);
        assert!(!mode(&modes, "hotspot").available);
        assert!(mode(&modes, "hotspot").detail.contains("only radio"));
    }

    #[test]
    fn two_radios_enable_hotspot_even_with_wifi_uplink_default() {
        let mut second = radio(true, false);
        second.interfaces = vec!["wlan1".to_string()];
        let radios = vec![radio(false, false), second];
        let uplinks = vec![uplink(UplinkKind::Wifi, true)];
        let modes = derive_modes(&radios, &uplinks, FULL_TOOLS);
        // wifi uplink on wlan0, AP on wlan1: hotspot works via dual radios,
        // and dual-radio mode itself is available.
        assert!(mode(&modes, "dual-radio").available);
    }

    #[test]
    fn concurrent_radio_enables_wifi_uplink() {
        let radios = vec![radio(true, true)];
        let uplinks = vec![uplink(UplinkKind::Wifi, true)];
        let modes = derive_modes(&radios, &uplinks, FULL_TOOLS);
        assert!(mode(&modes, "wifi-uplink").available);
        assert!(mode(&modes, "wifi-uplink").detail.contains("channel"));
    }

    #[test]
    fn missing_tools_block_all_ap_modes() {
        let tools = Tools {
            hostapd: false,
            ..FULL_TOOLS
        };
        let radios = vec![radio(true, true)];
        let uplinks = vec![uplink(UplinkKind::Ethernet, true)];
        let modes = derive_modes(&radios, &uplinks, tools);
        assert!(!mode(&modes, "hotspot").available);
        assert!(!mode(&modes, "dual-radio").available);
        assert!(!mode(&modes, "wifi-uplink").available);
        assert!(mode(&modes, "hotspot").detail.contains("hostapd"));
        assert!(mode(&modes, "offline").available);
        assert!(mode(&modes, "bluetooth").available);
    }

    #[test]
    fn offline_is_always_available() {
        let modes = derive_modes(&[], &[], FULL_TOOLS);
        assert!(mode(&modes, "offline").available);
    }

    #[test]
    fn no_wifi_uplink_combination_reports_reason() {
        let radios = vec![radio(true, false)];
        let uplinks = vec![uplink(UplinkKind::Ethernet, true)];
        let modes = derive_modes(&radios, &uplinks, FULL_TOOLS);
        assert!(!mode(&modes, "wifi-uplink").available);
        assert!(
            mode(&modes, "wifi-uplink")
                .detail
                .contains("interface combinations")
        );
    }
}
