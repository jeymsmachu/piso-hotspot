//! piso-hotspot: pay-per-usage wifi hotspot.

mod auth;
mod config;
mod control;
mod daemon;
mod doctor;
mod http;
mod iwlist;
mod keepalive;
mod leases;
mod log;
mod mac;
mod neigh;
mod netns;
mod nft;
mod passes;
mod paywall;
mod portal;
mod radio;
mod shaper;
mod store;
mod text;
mod tls;
mod ufw;
mod viface;
mod wireless;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use config::Config;
use control::Request;

/// Where the packaged systemd unit lives, for `wipe-data`.
const SYSTEMD_UNIT: &str = "/etc/systemd/system/piso-hotspot.service";

#[derive(Parser)]
#[command(name = "piso-hotspot", version, about = "Pay-per-usage wifi hotspot")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect this machine and report what could work. Changes nothing.
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Start the hotspot (root).
    Start {
        /// Bring up AP, DHCP, and paywall without an uplink — for tests.
        #[arg(long, conflicts_with_all = ["wifi_uplink", "dual_radio"])]
        offline: bool,
        /// Keep the wifi connection and beacon the AP beside it on a
        /// virtual interface (needs driver station+AP concurrency).
        #[arg(long, conflicts_with = "dual_radio")]
        wifi_uplink: bool,
        /// Beacon the AP on a second radio while the first stays a
        /// wifi station (two radios required).
        #[arg(long)]
        dual_radio: bool,
    },
    /// Stop the hotspot and restore the machine (root).
    Stop,
    /// Show what the daemon is doing right now.
    Status,
    /// List devices seen on the hotspot.
    List,
    /// List friends (unlimited, free access).
    Friends,
    /// Show recent privileged actions (grants, revokes, friends, logins).
    Audit {
        /// How many entries to show.
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
    /// Create the configuration file with the current defaults.
    Init {
        /// Overwrite an existing configuration file.
        #[arg(long)]
        force: bool,
    },
    /// Delete everything this program created: configuration, state,
    /// systemd unit, run files. Asks for confirmation first.
    WipeData {
        /// Skip the confirmation prompt (for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Sell a pass: grant <mac> <quick|extended|...>.
    Grant { mac: String, pass: String },
    /// Cut a device off (keeps its wifi association).
    Revoke { mac: String },
    /// Give unlimited free access: friend <mac> [label].
    Friend { mac: String, label: Option<String> },
    /// Remove a device from the friend list.
    Unfriend { mac: String },
    /// Internal: the daemon started by `start`.
    #[command(hide = true)]
    Daemon {
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        wifi_uplink: bool,
        #[arg(long)]
        dual_radio: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Doctor { json } => return cmd_doctor(json),
        Command::Start {
            offline,
            wifi_uplink,
            dual_radio,
        } => cmd_start(offline, wifi_uplink, dual_radio),
        Command::Stop => cmd_stop(),
        Command::Status => cmd_status(),
        Command::List => cmd_list(),
        Command::Friends => cmd_friends(),
        Command::Audit { limit } => cmd_audit(limit),
        Command::Init { force } => cmd_init(force),
        Command::WipeData { yes } => cmd_wipe_data(yes),
        Command::Grant { mac, pass } => cmd_grant(mac, pass),
        Command::Revoke { mac } => cmd_revoke(mac),
        Command::Friend { mac, label } => cmd_friend(mac, label),
        Command::Unfriend { mac } => cmd_unfriend(mac),
        Command::Daemon {
            offline,
            wifi_uplink,
            dual_radio,
        } => daemon::run(daemon::Opts {
            offline,
            wifi_uplink,
            dual_radio,
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("piso-hotspot: {msg}");
            ExitCode::FAILURE
        }
    }
}

type CmdResult = Result<(), String>;

fn cmd_doctor(json: bool) -> ExitCode {
    let report = doctor::inspect();
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("piso-hotspot: cannot render the report: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        doctor::print_human(&report);
    }
    // 0: usable. 1: this machine cannot run a hotspot. 2: the machine is
    // fine but config.json is not — scripts can tell the two apart.
    if !report.ok {
        return ExitCode::FAILURE;
    }
    if report.state.config_error.is_some() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn cmd_start(offline: bool, wifi_uplink: bool, dual_radio: bool) -> CmdResult {
    if !doctor::is_root() {
        return Err("start must run as root (try: sudo piso-hotspot start)".into());
    }
    daemon::spawn(daemon::Opts {
        offline,
        wifi_uplink,
        dual_radio,
    })?;
    let status = control::request(&Request::Status).map_err(|e| e.to_string())?;
    if let Some(s) = status.status {
        println!("piso-hotspot is running");
        println!("  mode     {}", s.mode);
        println!("  access point {}  gateway {}", s.ap_iface, s.gateway);
        match &s.uplink {
            Some(u) => println!("  uplink   {u}"),
            None => println!("  uplink   none (offline test mode)"),
        }
        println!();
        println!("next: `piso-hotspot list` shows connected devices;");
        println!("      `piso-hotspot grant <mac> quick` sells internet.");
    }
    Ok(())
}

fn cmd_stop() -> CmdResult {
    if !doctor::is_root() {
        return Err("stop must run as root (try: sudo piso-hotspot stop)".into());
    }
    daemon::stop()
}

fn cmd_status() -> CmdResult {
    let resp = control::request(&Request::Status).map_err(|e| e.to_string())?;
    let Some(s) = resp.status else {
        return Err(resp.error.unwrap_or_else(|| "empty status".into()));
    };
    println!("piso-hotspot is running");
    println!("  mode       {}", s.mode);
    println!("  access point  {}  gateway {}", s.ap_iface, s.gateway);
    match &s.uplink {
        Some(u) => println!("  uplink     {u}"),
        None => println!("  uplink     none (offline test mode)"),
    }
    println!("  started    {}", fmt_ts(s.started_at));
    println!(
        "  devices    {} seen, {} with active passes",
        s.devices_seen, s.active_passes
    );
    println!("  panel:");
    for url in &s.panel_urls {
        println!("    {url}");
    }
    if s.sessions > 0 {
        println!("  sessions:  {} active", s.sessions);
    }
    println!(
        "  admin passphrase: {}",
        text::sanitize(&s.admin_passphrase)
    );
    if s.warnings.is_empty() {
        println!("  health:     ok");
    } else {
        println!("  health:");
        for warning in &s.warnings {
            // Warnings quote interfaces and error text: escape them too.
            println!("    - {}", text::sanitize(warning));
        }
    }
    Ok(())
}

fn cmd_list() -> CmdResult {
    let devices = with_store(store::list_devices)?;
    if devices.is_empty() {
        println!("no devices seen yet (clients appear once they get a DHCP lease)");
        return Ok(());
    }
    println!(
        "{:<18} {:<12} {:<10} {:<17} {:<15} {:<10} LABEL",
        "MAC", "STATE", "PASS", "EXPIRES", "IP", "SEEN"
    );
    let now = daemon::now();
    for d in devices {
        // Labels are operator-controlled free text: escape before they
        // reach a terminal (see `text::sanitize`).
        let label = d.label.as_deref().map(text::sanitize).unwrap_or_default();
        let expires = d.expires_at.map(fmt_ts).unwrap_or_default();
        let ip = d.ip.clone().unwrap_or_default();
        println!(
            "{:<18} {:<12} {:<10} {:<17} {:<15} {:<10} {}",
            d.mac,
            d.state,
            d.pass_id.as_deref().unwrap_or("-"),
            if expires.is_empty() { "-" } else { &expires },
            if ip.is_empty() { "-" } else { &ip },
            fmt_ago(now - d.last_seen),
            if label.is_empty() { "-" } else { &label }
        );
    }
    Ok(())
}

/// "just now", "5m ago", "3h ago", "2d ago": lease age at a glance.
fn fmt_ago(seconds: i64) -> String {
    let seconds = seconds.max(0);
    match seconds {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

fn cmd_friends() -> CmdResult {
    let friends = with_store(store::list_friends)?;
    if friends.is_empty() {
        println!("no friends");
        return Ok(());
    }
    println!("{:<18} LABEL", "MAC");
    for f in friends {
        println!(
            "{:<18} {}",
            f.mac,
            f.label
                .as_deref()
                .map(text::sanitize)
                .unwrap_or_else(|| "-".into())
        );
    }
    Ok(())
}

fn cmd_audit(limit: u32) -> CmdResult {
    let actions = with_store(|conn| store::recent_actions(conn, limit))?;
    if actions.is_empty() {
        println!("no privileged actions recorded yet");
        return Ok(());
    }
    println!(
        "{:<17} {:<9} {:<18} {:<10} {:<18} DETAIL",
        "WHEN", "ACTION", "MAC", "PASS", "ACTOR"
    );
    for a in actions {
        println!(
            "{:<17} {:<9} {:<18} {:<10} {:<18} {}",
            fmt_ts(a.ts),
            text::sanitize(&a.action),
            a.mac.as_deref().unwrap_or("-"),
            a.pass_id.as_deref().unwrap_or("-"),
            text::sanitize(&a.actor),
            a.detail.as_deref().map(text::sanitize).unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_init(force: bool) -> CmdResult {
    if !doctor::is_root() {
        return Err("init writes into the config directory (try: sudo piso-hotspot init)".into());
    }
    let path = config::config_path();
    if path.exists() && !force {
        return Err(format!(
            "{} already exists — edit it, or pass --force to replace it with the defaults",
            path.display()
        ));
    }
    let cfg = Config::default();
    config::save(&path, &cfg).map_err(|e| e.to_string())?;
    println!("wrote {}", path.display());
    println!();
    println!("next:");
    println!("  edit it (name, passwords, prices, caps)");
    println!("  `piso-hotspot doctor` checks it without changing anything");
    println!("  `sudo piso-hotspot start` runs the hotspot");
    Ok(())
}

/// What `wipe-data` deletes, in the order it deletes it.
///
/// Separate from the deletion so the list can be printed before anything
/// happens, and so a test can prove what is *not* on it: the binary, the
/// repository, and anything the operator put in the config directory.
fn wipe_paths(config_dir: &Path, unit: &Path, run_dir: &Path) -> Vec<PathBuf> {
    let state = config_dir.join(config::STATE_FILE);
    let mut paths = vec![config_dir.join(config::CONFIG_FILE), state.clone()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = state.clone().into_os_string();
        sidecar.push(suffix);
        paths.push(PathBuf::from(sidecar));
    }
    paths.push(unit.to_path_buf());
    paths.push(run_dir.to_path_buf());
    paths
}

/// Delete what exists, and report exactly that.
fn remove_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for path in paths {
        let outcome = if path.is_dir() {
            // The run directory holds only what the daemon wrote.
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        if outcome.is_ok() {
            removed.push(path.clone());
        }
    }
    removed
}

fn cmd_wipe_data(yes: bool) -> CmdResult {
    if !doctor::is_root() {
        return Err("wipe-data must run as root (try: sudo piso-hotspot wipe-data)".into());
    }
    if control::alive() {
        return Err(
            "the hotspot is running — `sudo piso-hotspot stop` first, so the radio and the \
             firewall are handed back before the state is gone"
                .into(),
        );
    }
    let config_dir = config::config_dir();
    let paths = wipe_paths(
        &config_dir,
        Path::new(SYSTEMD_UNIT),
        Path::new(daemon::RUN_DIR),
    );

    println!("this deletes:");
    for path in &paths {
        println!("  {}", path.display());
    }
    println!();
    println!("it does not touch the binary, the repository, or other packages' files.");
    if !yes {
        println!("if the hotspot was active recently, run `sudo piso-hotspot stop` first.");
        print!("type `wipe` to confirm: ");
        std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| e.to_string())?;
        if answer.trim() != "wipe" {
            return Err("nothing was deleted".into());
        }
    }

    let removed = remove_paths(&paths);
    for path in &removed {
        println!("removed {}", path.display());
    }
    // The config directory itself goes only if nothing else lives there.
    if config_dir.exists() && std::fs::read_dir(&config_dir).is_ok_and(|d| d.count() == 0) {
        let _ = std::fs::remove_dir(&config_dir);
    }
    if removed.is_empty() {
        println!("nothing was there to delete");
    }
    println!();
    println!("note: a package-managed unit in /usr/lib/systemd/system belongs to the");
    println!("package manager — remove it with your package manager, not here.");
    println!("`sudo systemctl daemon-reload` forgets the unit we did remove.");
    Ok(())
}

fn cmd_grant(mac: String, pass: String) -> CmdResult {
    let resp = control::request(&Request::Grant {
        mac: mac.clone(),
        pass: pass.clone(),
    })
    .map_err(|e| e.to_string())?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "grant failed".into()));
    }
    let expires = resp.expires_at.unwrap_or(0);
    let remaining = expires - daemon::now();
    println!(
        "granted {pass} to {mac} until {} ({}m left)",
        fmt_ts(expires),
        remaining.max(0) / 60
    );
    Ok(())
}

fn cmd_revoke(mac: String) -> CmdResult {
    let resp =
        control::request(&Request::Revoke { mac: mac.clone() }).map_err(|e| e.to_string())?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "revoke failed".into()));
    }
    println!("revoked {mac} — no internet until granted again");
    Ok(())
}

fn cmd_friend(mac: String, label: Option<String>) -> CmdResult {
    let resp = control::request(&Request::Friend {
        mac: mac.clone(),
        label,
    })
    .map_err(|e| e.to_string())?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "friend failed".into()));
    }
    println!("{mac} is now a friend (unlimited, free)");
    Ok(())
}

fn cmd_unfriend(mac: String) -> CmdResult {
    let resp =
        control::request(&Request::Unfriend { mac: mac.clone() }).map_err(|e| e.to_string())?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "unfriend failed".into()));
    }
    println!("{mac} is no longer a friend");
    Ok(())
}

/// Read-only store access for listing commands; no daemon needed.
fn with_store<T>(
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, store::StoreError>,
) -> Result<T, String> {
    let path = config::state_path();
    if !path.exists() {
        return Err(format!(
            "no state yet at {} (run `sudo piso-hotspot start` first)",
            path.display()
        ));
    }
    let conn = store::open_readonly(&path).map_err(|e| e.to_string())?;
    f(&conn).map_err(|e| e.to_string())
}

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_leaves_the_binary_the_repo_and_siblings_alone() {
        let config_dir = Path::new("/etc/piso-hotspot");
        let run_dir = Path::new("/run/piso-hotspot");
        let unit = Path::new("/etc/systemd/system/piso-hotspot.service");
        let paths = wipe_paths(config_dir, unit, run_dir);

        // Exactly what we created: config, state and its SQLite sidecars,
        // the unit, the run directory.
        for expected in [
            "/etc/piso-hotspot/config.json",
            "/etc/piso-hotspot/state.db",
            "/etc/piso-hotspot/state.db-wal",
            "/etc/piso-hotspot/state.db-shm",
            "/etc/piso-hotspot/state.db-journal",
            "/etc/systemd/system/piso-hotspot.service",
            "/run/piso-hotspot",
        ] {
            assert!(
                paths.contains(&PathBuf::from(expected)),
                "missing {expected} from {paths:?}"
            );
        }
        assert_eq!(paths.len(), 7, "nothing else is on the list: {paths:?}");
        // Nothing under the binary's own location, and no directories we
        // do not own.
        for path in &paths {
            let text = path.display().to_string();
            for forbidden in [
                "/usr/bin",
                "/usr/lib",
                "/etc/systemd/system/network",
                "/home/",
            ] {
                assert!(!text.starts_with(forbidden), "{text} must not be wiped");
            }
        }
    }

    #[test]
    fn removal_reports_what_it_deleted_and_touches_nothing_else() {
        let dir = std::env::temp_dir().join(format!("piso-wipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config_dir = dir.join("etc");
        let run_dir = dir.join("run");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(config_dir.join("config.json"), "{}").unwrap();
        std::fs::write(config_dir.join("state.db"), "").unwrap();
        std::fs::write(config_dir.join("notes.txt"), "the operator's own file").unwrap();
        std::fs::write(run_dir.join("daemon.log"), "log").unwrap();
        let unit = dir.join("piso-hotspot.service");
        std::fs::write(&unit, "unit").unwrap();

        let paths = wipe_paths(&config_dir, &unit, &run_dir);
        let removed = remove_paths(&paths);
        assert!(removed.contains(&config_dir.join("config.json")));
        assert!(removed.contains(&config_dir.join("state.db")));
        assert!(removed.contains(&unit));
        assert!(removed.contains(&run_dir), "the run directory goes whole");
        assert!(!run_dir.exists());
        assert!(
            config_dir.join("notes.txt").exists(),
            "files we did not create survive"
        );
        assert!(!paths.contains(&config_dir.join("notes.txt")));

        // Nothing left to delete the second time around.
        assert!(remove_paths(&paths).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_written_config_loads_back_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("piso-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.json");

        let defaults = Config::default();
        config::save(&path, &defaults).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded, defaults, "what we write is what we read back");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the file holds passphrases"
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // The written file must be accepted by the same validation the
        // daemon applies.
        loaded.validate().unwrap();
        // A second write replaces it without leaving the temporary behind.
        config::save(&path, &loaded).unwrap();
        assert!(!path.with_extension("json.new").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
