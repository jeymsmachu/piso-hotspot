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
    /// How many friends the list may hold; `0` means no limit. Friends
    /// bypass the paywall forever, so a cap is the difference between
    /// "my friends' phones" and "the whole barangay".
    #[serde(default = "default_max_friends")]
    pub max_friends: u32,
    /// DNS servers handed to clients, e.g. `["1.1.1.1", "9.9.9.9"]`.
    /// Empty (the default) uses the host's own resolvers, which is what a
    /// `--wifi-uplink` hotspot needs.
    #[serde(default)]
    pub upstream_dns: Vec<Ipv4Addr>,
}

fn default_retention_days() -> u32 {
    30
}

fn default_max_friends() -> u32 {
    50
}

/// Panel login. Empty passphrase = a fresh random one per start,
/// printed by `piso-hotspot status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSettings {
    pub passphrase: String,
    /// How the panel is served. HTTPS by default: the panel grants and
    /// revokes access and shows the login secret, and on a shared uplink
    /// LAN plain HTTP hands all of that to anyone listening.
    pub tls: TlsMode,
    /// Certificate and key to use when `tls` is `file`.
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Address the panel binds. `0.0.0.0` (the default) is reachable
    /// from the hotspot and, when there is an uplink, from that network
    /// too — which is how a phone on either side can run it. Narrow it on
    /// a network you do not trust.
    pub bind: Ipv4Addr,
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            passphrase: String::new(),
            tls: TlsMode::default(),
            cert_file: None,
            key_file: None,
            bind: Ipv4Addr::UNSPECIFIED,
        }
    }
}

/// How the admin panel is served.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Generate a self-signed certificate once and keep it: encrypted,
    /// with a one-time browser warning per device.
    #[default]
    Auto,
    /// Serve plain HTTP (for setups that terminate TLS in front of us).
    Off,
    /// Use the certificate and key named in `cert_file`/`key_file`.
    File,
}

impl TlsMode {
    /// True when the panel is meant to be encrypted.
    pub fn is_tls(self) -> bool {
        !matches!(self, TlsMode::Off)
    }

    pub fn label(self) -> &'static str {
        match self {
            TlsMode::Auto => "auto",
            TlsMode::Off => "off",
            TlsMode::File => "file",
        }
    }
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
    /// Wireless encryption. `auto` (the default) follows the passphrase:
    /// open when there is none, WPA2 when there is. Betting on
    /// encryption is a choice, so it is explicit here, not implied.
    pub security: WifiSecurity,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// A settings change coming from the panel or the API.
///
/// Every field is optional: what is left out keeps its current value, so
/// the panel can submit a form without reloading everything it did not
/// touch. Unknown fields are refused rather than ignored, so a typo is an
/// error the operator sees instead of a setting that silently did not
/// happen.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsPatch {
    // --- the network ---
    pub ssid: Option<String>,
    pub security: Option<WifiSecurity>,
    pub passphrase: Option<String>,
    pub channel: Option<u8>,
    pub max_clients: Option<u8>,
    pub isolate_clients: Option<bool>,
    /// `Some(None)` clears it, `Some(Some(code))` sets it, `None` leaves
    /// it alone.
    #[serde(default, deserialize_with = "double_option")]
    pub country_code: Option<Option<String>>,
    // --- limits and housekeeping ---
    #[serde(default, deserialize_with = "double_option")]
    pub max_down_bytes_per_sec: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    pub max_up_bytes_per_sec: Option<Option<u64>>,
    pub retention_days: Option<u32>,
    pub max_friends: Option<u32>,
    pub upstream_dns: Option<Vec<Ipv4Addr>>,
    // --- portal and panel ---
    pub portal_enabled: Option<bool>,
    pub blocked_page: Option<BlockedPage>,
    pub theme: Option<Theme>,
    pub admin_passphrase: Option<String>,
}

/// Tell "field absent" from "field explicitly null".
///
/// Without this, serde maps a bare `null` in an `Option<Option<T>>` to
/// the *outer* `None`, which is the same as leaving the field out — so
/// "unlimited" and "leave my cap alone" would be indistinguishable.
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

impl SettingsPatch {
    /// Overlay this patch onto a configuration. The caller validates the
    /// result before anything is written or applied.
    pub fn apply(&self, cfg: &mut Config) {
        if let Some(value) = &self.ssid {
            cfg.ap.ssid = value.clone();
        }
        if let Some(value) = self.security {
            cfg.ap.security = value;
        }
        if let Some(value) = &self.passphrase {
            cfg.ap.passphrase = value.clone();
        }
        if let Some(value) = self.channel {
            cfg.ap.channel = value;
        }
        if let Some(value) = self.max_clients {
            cfg.ap.max_clients = value;
        }
        if let Some(value) = self.isolate_clients {
            cfg.ap.isolate_clients = value;
        }
        if let Some(value) = &self.country_code {
            cfg.ap.country_code = value.clone();
        }
        if let Some(value) = self.max_down_bytes_per_sec {
            cfg.bandwidth.max_down_bytes_per_sec = value;
        }
        if let Some(value) = self.max_up_bytes_per_sec {
            cfg.bandwidth.max_up_bytes_per_sec = value;
        }
        if let Some(value) = self.retention_days {
            cfg.retention_days = value;
        }
        if let Some(value) = self.max_friends {
            cfg.max_friends = value;
        }
        if let Some(value) = &self.upstream_dns {
            cfg.upstream_dns = value.clone();
        }
        if let Some(value) = self.portal_enabled {
            cfg.portal.enabled = value;
        }
        if let Some(value) = &self.blocked_page {
            cfg.blocked_page = value.clone();
        }
        if let Some(value) = self.theme {
            cfg.ui.theme = value;
        }
        if let Some(value) = &self.admin_passphrase {
            cfg.admin.passphrase = value.clone();
        }
    }

    /// True when the patch would change anything at all.
    pub fn touches_anything(&self) -> bool {
        *self != SettingsPatch::default()
    }

    /// Which settings this patch touches, by name.
    ///
    /// Names only, never values: this goes into the audit trail and the
    /// log, and one of the fields is a passphrase.
    pub fn describe(&self) -> String {
        let mut names: Vec<&str> = Vec::new();
        let note = |set: bool, name: &'static str, names: &mut Vec<&'static str>| {
            if set {
                names.push(name);
            }
        };
        note(self.ssid.is_some(), "ssid", &mut names);
        note(self.security.is_some(), "security", &mut names);
        note(self.passphrase.is_some(), "wifi passphrase", &mut names);
        note(self.channel.is_some(), "channel", &mut names);
        note(self.max_clients.is_some(), "max_clients", &mut names);
        note(
            self.isolate_clients.is_some(),
            "isolate_clients",
            &mut names,
        );
        note(self.country_code.is_some(), "country_code", &mut names);
        note(
            self.max_down_bytes_per_sec.is_some(),
            "download cap",
            &mut names,
        );
        note(
            self.max_up_bytes_per_sec.is_some(),
            "upload cap",
            &mut names,
        );
        note(self.retention_days.is_some(), "retention_days", &mut names);
        note(self.max_friends.is_some(), "max_friends", &mut names);
        note(self.upstream_dns.is_some(), "upstream_dns", &mut names);
        note(self.portal_enabled.is_some(), "portal", &mut names);
        note(self.blocked_page.is_some(), "portal text", &mut names);
        note(self.theme.is_some(), "theme", &mut names);
        note(
            self.admin_passphrase.is_some(),
            "admin passphrase",
            &mut names,
        );
        if names.is_empty() {
            "nothing".to_string()
        } else {
            names.join(", ")
        }
    }
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
            max_friends: default_max_friends(),
            upstream_dns: Vec::new(),
        }
    }
}

/// What the radio uses to protect the association.
///
/// Encryption protects the *link*, not the internet: everyone still has
/// to pass the paywall. An open network is easier to join (a captive
/// portal is the whole product), an encrypted one keeps a neighbour from
/// reading a paying client's traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiSecurity {
    /// Open when there is no passphrase, WPA2 when there is one.
    #[default]
    Auto,
    Open,
    Wpa2,
    Wpa3,
}

impl WifiSecurity {
    /// What the radio will actually do, given the configured passphrase.
    pub fn resolve(self, passphrase: &str) -> WifiSecurity {
        match self {
            WifiSecurity::Auto if passphrase.is_empty() => WifiSecurity::Open,
            WifiSecurity::Auto => WifiSecurity::Wpa2,
            other => other,
        }
    }

    /// True when the resolved choice protects the association.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, WifiSecurity::Open)
    }

    pub fn label(self) -> &'static str {
        match self {
            WifiSecurity::Auto => "auto",
            WifiSecurity::Open => "open",
            WifiSecurity::Wpa2 => "wpa2",
            WifiSecurity::Wpa3 => "wpa3",
        }
    }
}

impl Default for ApSettings {
    fn default() -> Self {
        Self {
            ssid: "piso-hotspot".to_string(),
            passphrase: String::new(),
            security: WifiSecurity::Auto,
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
    /// The settings that only take effect when the access point is
    /// restarted: comparing this before and after an edit is how the
    /// daemon knows whether clients are about to be dropped.
    pub fn ap_signature(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{:?}",
            self.ap.ssid,
            self.ap.passphrase,
            self.ap.security.resolve(&self.ap.passphrase).label(),
            self.ap.channel,
            self.ap.max_clients,
            self.ap.isolate_clients,
            self.ap.country_code
        )
    }

    /// The settings the panel server reads once, at start.
    pub fn panel_signature(&self) -> String {
        format!(
            "{}|{}|{}|{:?}|{:?}",
            self.ap.port,
            self.admin.bind,
            self.admin.tls.label(),
            self.admin.cert_file,
            self.admin.key_file
        )
    }

    /// The settings the captive portal server reads once, at start.
    pub fn portal_signature(&self) -> String {
        format!("{}", self.portal.enabled)
    }

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
        match self.ap.security.resolve(&self.ap.passphrase) {
            WifiSecurity::Open => {
                if !self.ap.passphrase.is_empty() {
                    problems.push(
                        "ap.security is \"open\", so ap.passphrase must be empty — \
                         choose \"wpa2\" or \"wpa3\" to use a password"
                            .to_string(),
                    );
                }
            }
            WifiSecurity::Wpa2 | WifiSecurity::Wpa3 => {
                if self.ap.passphrase.is_empty() {
                    problems.push(format!(
                        "ap.security is \"{}\", which needs an ap.passphrase of 8-63 characters",
                        self.ap.security.label()
                    ));
                }
            }
            // `resolve` never returns Auto.
            WifiSecurity::Auto => {}
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
        if self.admin.tls == TlsMode::File {
            match (&self.admin.cert_file, &self.admin.key_file) {
                (Some(_), Some(_)) => {}
                _ => problems.push(
                    "admin.tls = \"file\" needs admin.cert_file and admin.key_file".to_string(),
                ),
            }
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
        if self.upstream_dns.len() > 4 {
            problems.push("upstream_dns: at most 4 servers".to_string());
        }
        for server in &self.upstream_dns {
            if server.is_unspecified() || server.is_loopback() || server.is_broadcast() {
                problems.push(format!(
                    "upstream_dns {server} is not a usable DNS server address"
                ));
            }
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
    fn security_and_passphrase_have_to_agree() {
        let mut c = Config::default();
        // The shipped default: auto with no passphrase means an open
        // network, which is what the project has always started.
        c.validate().unwrap();
        assert_eq!(c.ap.security.resolve(&c.ap.passphrase), WifiSecurity::Open);

        // Asking for WPA2 without a passphrase is a mistake worth naming.
        c.ap.security = WifiSecurity::Wpa2;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("needs an ap.passphrase"), "{err}");

        c.ap.passphrase = "printed-on-a-sign".to_string();
        c.validate().unwrap();
        assert_eq!(c.ap.security.resolve(&c.ap.passphrase), WifiSecurity::Wpa2);

        // An open network with a leftover password is contradictory.
        c.ap.security = WifiSecurity::Open;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("must be empty"), "{err}");

        // `auto` follows the passphrase.
        c.ap.security = WifiSecurity::Auto;
        c.validate().unwrap();
    }

    #[test]
    fn settings_patches_overlay_and_are_strict() {
        let mut c = Config::default();
        let patch: SettingsPatch =
            serde_json::from_str(r#"{"ssid":"Kanto Net","max_friends":3}"#).unwrap();
        patch.apply(&mut c);
        assert_eq!(c.ap.ssid, "Kanto Net");
        assert_eq!(c.max_friends, 3);
        assert_eq!(c.ap.passphrase, "", "untouched fields keep their value");

        // A typo is an error, not a setting that silently did not happen.
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"ssdi":"oops"}"#).is_err());

        // "absent" and "explicitly null" are different: one leaves the
        // cap alone, the other makes it unlimited.
        let untouched: SettingsPatch = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(untouched.max_down_bytes_per_sec, None);
        let cleared: SettingsPatch =
            serde_json::from_str(r#"{"max_down_bytes_per_sec":null}"#).unwrap();
        assert_eq!(cleared.max_down_bytes_per_sec, Some(None));
        let limited: SettingsPatch =
            serde_json::from_str(r#"{"max_down_bytes_per_sec":1000000}"#).unwrap();
        assert_eq!(limited.max_down_bytes_per_sec, Some(Some(1_000_000)));

        let mut c = Config::default();
        c.bandwidth.max_down_bytes_per_sec = Some(5_000);
        cleared.apply(&mut c);
        assert_eq!(c.bandwidth.max_down_bytes_per_sec, None);
        limited.apply(&mut c);
        assert_eq!(c.bandwidth.max_down_bytes_per_sec, Some(1_000_000));
    }

    #[test]
    fn signatures_notice_what_needs_a_restart() {
        let base = Config::default();
        let mut renamed = base.clone();
        renamed.ap.ssid = "Kanto Net".to_string();
        assert_ne!(
            base.ap_signature(),
            renamed.ap_signature(),
            "a new SSID restarts the AP"
        );

        let mut capped = base.clone();
        capped.bandwidth.max_down_bytes_per_sec = Some(1_000_000);
        assert_eq!(
            base.ap_signature(),
            capped.ap_signature(),
            "caps apply live"
        );

        let mut ported = base.clone();
        ported.ap.port = 9090;
        assert_ne!(base.panel_signature(), ported.panel_signature());
        assert_eq!(base.ap_signature(), ported.ap_signature());
    }

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
