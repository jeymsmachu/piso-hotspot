//! piso-hotspot: pay-per-usage wifi hotspot.

mod auth;
mod config;
mod control;
mod daemon;
mod doctor;
mod http;
mod iwlist;
mod leases;
mod mac;
mod nft;
mod passes;
mod paywall;
mod portal;
mod radio;
mod shaper;
mod store;
mod ufw;
mod viface;
mod wireless;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use control::Request;

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
        Command::Doctor { json } => cmd_doctor(json),
        Command::Start {
            offline,
            wifi_uplink,
            dual_radio,
        } => cmd_start(offline, wifi_uplink, dual_radio),
        Command::Stop => cmd_stop(),
        Command::Status => cmd_status(),
        Command::List => cmd_list(),
        Command::Friends => cmd_friends(),
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

fn cmd_doctor(json: bool) -> CmdResult {
    let report = doctor::inspect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        doctor::print_human(&report);
    }
    if !report.ok {
        return Err("no hotspot mode is available (see doctor output)".into());
    }
    Ok(())
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
    println!("  admin passphrase: {}", s.admin_passphrase);
    Ok(())
}

fn cmd_list() -> CmdResult {
    let devices = with_store(store::list_devices)?;
    if devices.is_empty() {
        println!("no devices seen yet (clients appear once they get a DHCP lease)");
        return Ok(());
    }
    println!(
        "{:<18} {:<12} {:<10} {:<17} LABEL",
        "MAC", "STATE", "PASS", "EXPIRES"
    );
    for d in devices {
        let label = d.label.clone().unwrap_or_default();
        let expires = d.expires_at.map(fmt_ts).unwrap_or_default();
        println!(
            "{:<18} {:<12} {:<10} {:<17} {}",
            d.mac,
            d.state,
            d.pass_id.as_deref().unwrap_or("-"),
            if expires.is_empty() { "-" } else { &expires },
            if label.is_empty() { "-" } else { &label }
        );
    }
    Ok(())
}

fn cmd_friends() -> CmdResult {
    let friends = with_store(store::list_friends)?;
    if friends.is_empty() {
        println!("no friends");
        return Ok(());
    }
    println!("{:<18} LABEL", "MAC");
    for f in friends {
        println!("{:<18} {}", f.mac, f.label.as_deref().unwrap_or("-"));
    }
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
