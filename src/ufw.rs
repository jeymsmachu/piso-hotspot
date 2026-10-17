//! Cooperation with UFW.
//!
//! UFW (when active) installs an `INPUT` chain via the iptables-compat
//! table, whose hook entry registers *before* any nft-native chain. Its
//! default `deny (incoming)` therefore silently eats every portal,
//! panel, and DHCP packet addressed to hotspot clients — before our
//! paywall rules ever run. That was the field bug behind "the portal
//! never loads" on a correctly configured hotspot.
//!
//! We do not weaken the user's firewall: we open exactly the ports the
//! hotspot needs, scoped to the AP interface, for as long as the
//! hotspot runs. Everything is removed on stop.

use std::process::Command;

/// Which ports the hotspot needs from the *client-facing* side.
/// Pure: unit-testable mapping from config to required ports.
pub fn needed_ports(portal: bool, panel_port: u16) -> (Vec<u16>, Vec<u16>) {
    let mut tcp: Vec<u16> = Vec::new();
    let mut udp: Vec<u16> = vec![53, 67]; // dnsmasq: DNS + DHCP
    if portal {
        tcp.extend([80, 443]); // portal + HTTPS-first fast-fail
        udp.push(443); // QUIC fast-fail
    }
    if panel_port != 0 && !tcp.contains(&panel_port) {
        tcp.push(panel_port);
    }
    tcp.sort_unstable();
    udp.sort_unstable();
    (tcp, udp)
}

fn spec(iface: &str, proto: &str, ports: &[u16]) -> Vec<String> {
    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "allow".into(),
        "in".into(),
        "on".into(),
        iface.to_string(),
        "proto".into(),
        proto.into(),
        "to".into(),
        "any".into(),
        "port".into(),
        list,
    ]
}

fn ufw(args: &[&str]) -> Result<String, String> {
    let out = Command::new("ufw")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        return Err(if stderr.is_empty() { stdout } else { stderr });
    }
    Ok(stdout)
}

fn have_ufw() -> bool {
    which("ufw").is_some()
}

fn active() -> bool {
    ufw(&["status"])
        .map(|s| s.contains("Status: active"))
        .unwrap_or(false)
}

/// Allow the hotspot's ports through UFW, scoped to the AP interface.
/// Returns `Err` only when UFW is active and refuses — silently
/// continuing would recreate the bug this module exists to fix.
pub fn open(iface: &str, portal: bool, panel_port: u16) -> Result<(), String> {
    if !have_ufw() || !active() {
        return Ok(());
    }
    let (tcp, udp) = needed_ports(portal, panel_port);
    if !tcp.is_empty() {
        run_spec(spec(iface, "tcp", &tcp), false)?;
    }
    if !udp.is_empty() {
        run_spec(spec(iface, "udp", &udp), false)?;
    }
    Ok(())
}

/// Remove exactly what [`open`] added. Best-effort: a leftover rule on
/// a now-deleted interface is inert.
pub fn close(iface: &str, portal: bool, panel_port: u16) {
    if !have_ufw() || !active() {
        return;
    }
    let (tcp, udp) = needed_ports(portal, panel_port);
    for (proto, list) in [("tcp", &tcp), ("udp", &udp)] {
        if list.is_empty() {
            continue;
        }
        let _ = run_spec(spec(iface, proto, list), true);
    }
}

fn run_spec(args: Vec<String>, delete: bool) -> Result<String, String> {
    let mut all: Vec<String> = Vec::new();
    if delete {
        all.push("--force".to_string());
        all.push("delete".to_string());
    }
    all.extend(args);
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    ufw(&refs)
}

fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(program);
            let executable = std::fs::metadata(&candidate)
                .map(|m| {
                    use std::os::unix::fs::PermissionsExt;
                    m.is_file() && m.permissions().mode() & 0o111 != 0
                })
                .unwrap_or(false);
            executable.then_some(candidate)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_and_panel_ports_are_all_covered() {
        let (tcp, udp) = needed_ports(true, 8080);
        assert_eq!(tcp, vec![80, 443, 8080]);
        assert_eq!(udp, vec![53, 67, 443]);
    }

    #[test]
    fn no_portal_still_opens_dns_dhcp_and_panel() {
        let (tcp, udp) = needed_ports(false, 8080);
        assert_eq!(tcp, vec![8080]);
        assert_eq!(udp, vec![53, 67]);
    }

    #[test]
    fn panel_port_zero_or_duplicate_is_handled() {
        let (tcp, udp) = needed_ports(false, 0);
        assert!(tcp.is_empty());
        assert_eq!(udp, vec![53, 67]);
        // Panel already in the portal list → not duplicated.
        let (tcp, _) = needed_ports(true, 80);
        assert_eq!(tcp.iter().filter(|p| **p == 80).count(), 1);
    }

    #[test]
    fn rule_specs_are_scoped_to_the_iface() {
        let tcp = spec("wlan2", "tcp", &[80, 443, 8080]);
        assert_eq!(
            tcp.join(" "),
            "allow in on wlan2 proto tcp to any port 80,443,8080"
        );
        let udp = spec("ap0", "udp", &[53, 67]);
        assert_eq!(udp.join(" "), "allow in on ap0 proto udp to any port 53,67");
    }
}
