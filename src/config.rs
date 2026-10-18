//! Operator settings: `/etc/piso-hotspot/config.json`.
//!
//! The file is human-edited JSON; anything omitted falls back to defaults.
//! Program-owned state (passes, friends, revenue) lives in SQLite instead —
//! see [`crate::store`].

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::passes::{self, PassDef};

pub const CONFIG_FILE: &str = "config.json";
pub const STATE_FILE: &str = "state.db";

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Directory holding config.json and state.db.
///
/// `/etc/piso-hotspot` by default; `$PISO_HOTSPOT_CONFIG_DIR` overrides
/// (used for tests and sandboxes).
pub fn config_dir() -> PathBuf {
    match std::env::var_os("PISO_HOTSPOT_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from("/etc/piso-hotspot"),
    }
}

pub fn config_path() -> PathBuf {
    config_dir().join(CONFIG_FILE)
}

pub fn state_path() -> PathBuf {
    config_dir().join(STATE_FILE)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ap: ApSettings,
    pub gateway: Ipv4Addr,
    pub currency: String,
    pub passes: Vec<PassDef>,
    pub blocked_page: BlockedPage,
    pub admin: AdminSettings,
    pub portal: PortalSettings,
    pub ui: UiSettings,
    pub bandwidth: BandwidthSettings,
    /// How long to remember devices that never paid and are not friends.
    /// Sales and audit rows are kept forever.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_retention_days() -> u32 {
    30
}

/// Panel login. Empty passphrase = a fresh random one per start,
/// printed by `piso-hotspot status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSettings {
    pub passphrase: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortalSettings {
    /// Serve the captive portal (DNS hijack + notice pages).
    pub enabled: bool,
}

impl Default for PortalSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the device (prefers-color-scheme).
    #[default]
    Auto,
    Light,
    Dark,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    pub theme: Theme,
}

/// Client-facing traffic caps, in bytes per second (1 MB/s = 1_000_000).
/// Applied in-kernel with `tc`; the host machine keeps full speed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BandwidthSettings {
    pub max_down_bytes_per_sec: Option<u64>,
    pub max_up_bytes_per_sec: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApSettings {
    /// Network name students see. 1–32 bytes.
    pub ssid: String,
    /// WPA2 passphrase, or empty for an open network. 8–63 characters when set.
    pub passphrase: String,
    /// Radio channel. Ignored in single-radio uplink modes, where the
    /// access point follows the station's channel.
    pub channel: u8,
    /// Maximum number of associated stations.
    pub max_clients: u8,
    /// Port the admin panel binds to.
    pub port: u16,
    /// Keep associated clients from talking directly to each other.
    pub isolate_clients: bool,
    /// Ask for 802.11n rates so the radio is not the bottleneck.
    pub ieee80211n: bool,
    /// Regulatory domain advertised to clients, e.g. `"PH"`. Omitted
    /// from hostapd config when unset (the kernel's default applies).
    pub country_code: Option<String>,
    /// Force the hotspot onto this wifi interface (hosts with several
    /// radios). Unset: the first AP-capable radio is used.
    pub interface: Option<String>,
    /// Force the internet-bound interface (hosts with several uplinks).
    /// Unset: the interface holding the default route is used.
    pub uplink: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedPage {
    pub title: String,
    pub message: String,
    pub footer: String,
    /// How to pay: free text shown on the portal (e.g. GCash details).
    pub payment_instructions: String,
    /// List the configured passes and prices on the portal.
    pub show_prices: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ap: ApSettings::default(),
            gateway: Ipv4Addr::new(10, 10, 0, 1),
            currency: "PHP".to_string(),
            passes: passes::default_passes(),
            blocked_page: BlockedPage::default(),
            admin: AdminSettings::default(),
            portal: PortalSettings::default(),
            ui: UiSettings::default(),
            bandwidth: BandwidthSettings::default(),
            retention_days: default_retention_days(),
        }
    }
}

impl Default for ApSettings {
    fn default() -> Self {
        Self {
            ssid: "piso-hotspot".to_string(),
            passphrase: String::new(),
            channel: 6,
            max_clients: 12,
            port: 8080,
            isolate_clients: true,
            ieee80211n: true,
            country_code: None,
            interface: None,
            uplink: None,
        }
    }
}

impl Default for BlockedPage {
    fn default() -> Self {
        Self {
            title: "No internet yet".to_string(),
            message: "See the operator to buy a pass.".to_string(),
            footer: String::new(),
            payment_instructions: String::new(),
            show_prices: true,
        }
    }
}

/// Write `cfg` to `path` (atomically, root-only).
///
/// The file holds the wifi and admin passphrases, so it is written 0600
/// into a 0700 directory, through a temporary file in the same
/// directory: a half-written config would take the hotspot down.
pub fn save(path: &Path, cfg: &Config) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|source| ConfigError::Read {
        path: dir.to_path_buf(),
        source,
    })?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    let mut text = serde_json::to_string_pretty(cfg).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    text.push('\n');
    let temp = path.with_extension("json.new");
    fs::write(&temp, text).map_err(|source| ConfigError::Read {
        path: temp.clone(),
        source,
    })?;
    let _ = fs::set_permissions(&temp, fs::Permissions::from_mode(0o600));
    fs::rename(&temp, path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })
}

impl Config {
    /// Load from `path`, falling back to defaults when the file does not
    /// exist. Returns every problem found, not just the first.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let cfg = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if self.ap.ssid.is_empty() || self.ap.ssid.len() > 32 {
            problems.push(format!(
                "ap.ssid must be 1-32 bytes, got {}",
                self.ap.ssid.len()
            ));
        }
        // The SSID is written verbatim into hostapd's line-oriented
        // config; a newline or control byte would inject directives.
        if self
            .ap
            .ssid
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            problems.push(
                "ap.ssid must not contain control characters, quotes, or backslashes".to_string(),
            );
        }
        if !self.ap.passphrase.is_empty() && !(8..=63).contains(&self.ap.passphrase.len()) {
            problems.push(format!(
                "ap.passphrase must be empty (open network) or 8-63 characters, got {}",
                self.ap.passphrase.len()
            ));
        }
        // Same line-oriented config, plus WPA2 PSKs are printable ASCII.
        if self
            .ap
            .passphrase
            .chars()
            .any(|c| c.is_control() || !c.is_ascii())
        {
            problems.push(
                "ap.passphrase must be printable ASCII (no control or non-ASCII characters)"
                    .to_string(),
            );
        }
        if self.ap.channel == 0 || self.ap.channel > 165 {
            problems.push(format!("ap.channel must be 1-165, got {}", self.ap.channel));
        }
        if self.ap.max_clients == 0 {
            problems.push("ap.max_clients must be at least 1".to_string());
        }
        if self.ap.port == 0 {
            problems.push("ap.port must be a valid port".to_string());
        }
        if self.gateway.is_loopback()
            || self.gateway.is_broadcast()
            || self.gateway.is_unspecified()
        {
            problems.push(format!("gateway {} is not a usable address", self.gateway));
        }
        if let Some(country) = &self.ap.country_code
            && !(country.len() == 2 && country.bytes().all(|b| b.is_ascii_uppercase()))
        {
            problems.push(format!(
                "ap.country_code must be a 2-letter ISO code like \"PH\", got {country:?}"
            ));
        }
        // Interface names reach nft/hostapd/ip command lines and the
        // ruleset text; apply the kernel's own alphabet up front.
        let valid_iface = |name: &str| {
            !name.is_empty()
                && name.len() <= 15
                // A leading dash would be parsed as a flag by tools we
                // invoke (ufw, ip, iw); the kernel never needs one.
                && !name.starts_with('-')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        };
        if let Some(want) = &self.ap.interface
            && !valid_iface(want)
        {
            problems.push(format!(
                "ap.interface must be a real interface name (letters, digits, _ - .), got {want:?}"
            ));
        }
        if let Some(want) = &self.ap.uplink
            && !valid_iface(want)
        {
            problems.push(format!(
                "ap.uplink must be a real interface name (letters, digits, _ - .), got {want:?}"
            ));
        }
        if !self.admin.passphrase.is_empty() && self.admin.passphrase.len() < 8 {
            problems.push(
                "admin.passphrase must be empty (random per start) or at least 8 characters"
                    .to_string(),
            );
        }
        for (name, cap) in [
            (
                "bandwidth.max_down_bytes_per_sec",
                self.bandwidth.max_down_bytes_per_sec,
            ),
            (
                "bandwidth.max_up_bytes_per_sec",
                self.bandwidth.max_up_bytes_per_sec,
            ),
        ] {
            if cap == Some(0) {
                problems.push(format!("{name}: set null for unlimited, not 0"));
            }
        }
        if self.retention_days == 0 {
            problems.push("retention_days must be at least 1".to_string());
        }
        if self.passes.is_empty() {
            problems.push("at least one pass must be configured".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in &self.passes {
            if p.id.is_empty() {
                problems.push("every pass needs a non-empty id".to_string());
            } else if !seen.insert(p.id.as_str()) {
                problems.push(format!("duplicate pass id {:?}", p.id));
            }
            if p.price_minor == 0 {
                problems.push(format!("pass {:?} has price 0", p.id));
            }
            if let Some(0) = p.duration_secs {
                problems.push(format!("pass {:?} has a zero duration", p.id));
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn documented_example_config_parses_and_validates() {
        // docs/config.example.json is the reference operators copy;
        // it must never drift from the real schema or defaults.
        let cfg: Config =
            serde_json::from_str(include_str!("../docs/config.example.json")).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn ap_uplink_defaults_to_none() {
        let cfg = Config::default();
        assert!(cfg.ap.uplink.is_none());
        assert!(cfg.ap.interface.is_none());
    }

    #[test]
    fn ap_uplink_parses_from_json() {
        let cfg: Config = serde_json::from_str(r#"{"ap":{"uplink":"wlan2"}}"#).unwrap();
        assert_eq!(cfg.ap.uplink.as_deref(), Some("wlan2"));
    }

    #[test]
    fn ssid_with_newline_is_rejected() {
        let mut cfg = Config::default();
        cfg.ap.ssid = "school\nieee80211w=0".to_string();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("ap.ssid"), "{err}");
    }

    #[test]
    fn passphrase_with_control_bytes_is_rejected() {
        let mut cfg = Config::default();
        cfg.ap.passphrase = "password\twith-tab".to_string();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("ap.passphrase"), "{err}");
    }

    #[test]
    fn iface_names_are_alphabet_checked() {
        for bad in ["wlan0\nip link", "wlan 0", "wlan0;", ""] {
            let mut cfg = Config::default();
            cfg.ap.interface = Some(bad.to_string());
            assert!(cfg.validate().is_err(), "accepted interface {bad:?}");
            let mut cfg = Config::default();
            cfg.ap.uplink = Some(bad.to_string());
            assert!(cfg.validate().is_err(), "accepted uplink {bad:?}");
        }
        let mut cfg = Config::default();
        cfg.ap.interface = Some("wlan0".to_string());
        cfg.ap.uplink = Some("wlan1".to_string());
        cfg.validate().unwrap();
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load(Path::new("/nonexistent/piso/config.json")).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn invalid_json_reports_position() {
        let dir = std::env::temp_dir().join(format!("piso-cfg-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        fs::write(&path, "{ not json").unwrap();
        let err = Config::load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not valid JSON"), "msg was: {msg}");
        assert!(msg.contains("line"), "msg was: {msg}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn partial_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir().join(format!("piso-cfg-partial-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        fs::write(&path, r#"{"ap": {"ssid": "MySchool"}}"#).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.ap.ssid, "MySchool");
        assert_eq!(cfg.ap.channel, 6);
        assert_eq!(cfg.gateway, Ipv4Addr::new(10, 10, 0, 1));
        assert_eq!(cfg.passes, passes::default_passes());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn short_passphrase_is_rejected() {
        let mut cfg = Config::default();
        cfg.ap.passphrase = "short".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_passphrase_is_open_network() {
        let mut cfg = Config::default();
        cfg.ap.passphrase = String::new();
        cfg.validate().unwrap();
    }

    #[test]
    fn duplicate_pass_ids_are_rejected() {
        let mut cfg = Config::default();
        cfg.passes.push(PassDef {
            id: "quick".into(),
            name: "Another quick".into(),
            price_minor: 100,
            duration_secs: Some(60),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn bad_channel_is_rejected() {
        let mut cfg = Config::default();
        cfg.ap.channel = 0;
        assert!(cfg.validate().is_err());
        cfg.ap.channel = 166;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn new_sections_parse_from_partial_file() {
        let dir = std::env::temp_dir().join(format!("piso-cfg-p3-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        fs::write(
            &path,
            r#"{"admin":{"passphrase":"hunter22"},"ui":{"theme":"dark"},
                "bandwidth":{"max_down_bytes_per_sec":20000000},
                "blocked_page":{"payment_instructions":"GCash 0917..."}}"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.admin.passphrase, "hunter22");
        assert_eq!(cfg.ui.theme, Theme::Dark);
        assert_eq!(cfg.bandwidth.max_down_bytes_per_sec, Some(20_000_000));
        assert_eq!(cfg.bandwidth.max_up_bytes_per_sec, None);
        assert!(cfg.portal.enabled);
        assert!(cfg.blocked_page.show_prices);
        assert_eq!(cfg.blocked_page.payment_instructions, "GCash 0917...");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn short_admin_passphrase_is_rejected() {
        let mut cfg = Config::default();
        cfg.admin.passphrase = "short".into();
        assert!(cfg.validate().is_err());
        cfg.admin.passphrase = String::new(); // random-per-start
        cfg.validate().unwrap();
    }

    #[test]
    fn zero_bandwidth_cap_is_rejected() {
        let mut cfg = Config::default();
        cfg.bandwidth.max_down_bytes_per_sec = Some(0);
        assert!(cfg.validate().is_err());
        cfg.bandwidth.max_down_bytes_per_sec = None; // unlimited
        cfg.validate().unwrap();
    }

    #[test]
    fn theme_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Theme::Auto).unwrap(), r#""auto""#);
        assert_eq!(serde_json::to_string(&Theme::Dark).unwrap(), r#""dark""#);
        let t: Theme = serde_json::from_str(r#""light""#).unwrap();
        assert_eq!(t, Theme::Light);
    }
}
