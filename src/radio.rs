//! Radio ownership: hand the wifi card from NetworkManager to hostapd
//! and back.
//!
//! Everything here is best-effort by design: NetworkManager may be
//! absent, and the goal on release is "NM can manage this card again",
//! not a specific sequence of commands.

use std::process::Command;
use std::time::Duration;

fn nmcli(args: &[&str]) -> bool {
    Command::new("nmcli")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Is the interface still associated with a network?
fn associated(iface: &str) -> bool {
    Command::new("iw")
        .args(["dev", iface, "link"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim_start()
                .starts_with("Connected to")
        })
        .unwrap_or(false)
}

/// Claim `iface` for the access point: tell NetworkManager to let go
/// and make sure the card is not still associated (create_ap-style
/// hostapd refuses otherwise).
pub fn take(iface: &str) -> Result<(), RadioError> {
    // Best-effort: nmcli may not exist.
    nmcli(&["device", "set", iface, "managed", "no"]);
    nmcli(&["device", "disconnect", iface]);

    for _ in 0..10 {
        if !associated(iface) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Still associated — cycle the link. This also clears the odd
    // "firmware failed to leave lps state" the RTL chips show.
    let _ = link_set(iface, false);
    std::thread::sleep(Duration::from_millis(300));
    let _ = link_set(iface, true);
    std::thread::sleep(Duration::from_millis(300));

    if associated(iface) {
        return Err(RadioError::StillAssociated(iface.to_string()));
    }
    Ok(())
}

/// Hand `iface` back so NetworkManager can manage (and reconnect) it.
pub fn release(iface: &str) {
    nmcli(&["device", "set", iface, "managed", "yes"]);
}

fn link_set(iface: &str, up: bool) -> bool {
    Command::new("ip")
        .args(["link", "set", iface, if up { "up" } else { "down" }])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Set/clear the gateway address on the AP interface.
pub fn set_gateway(iface: &str, gateway: &str, up: bool) -> Result<(), RadioError> {
    let addr = format!("{gateway}/24");
    let args: Vec<&str> = if up {
        vec!["addr", "replace", &addr, "dev", iface]
    } else {
        vec!["addr", "del", &addr, "dev", iface]
    };
    let status = Command::new("ip")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| RadioError::Command("ip", e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(RadioError::Command(
            "ip",
            format!("exit {status} for args {args:?}"),
        ))
    }
}

pub fn set_ip_forward(enabled: bool) -> Result<String, RadioError> {
    let path = "/proc/sys/net/ipv4/ip_forward";
    let previous = std::fs::read_to_string(path)
        .map_err(|e| RadioError::Command("ip_forward", e.to_string()))?;
    std::fs::write(path, if enabled { "1\n" } else { "0\n" })
        .map_err(|e| RadioError::Command("ip_forward", e.to_string()))?;
    Ok(previous.trim().to_string())
}

#[derive(thiserror::Error, Debug)]
pub enum RadioError {
    #[error("interface {0} is still associated with a network")]
    StillAssociated(String),
    #[error("{0} failed: {1}")]
    Command(&'static str, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the error formatting and side-effect-free paths are
    // unit-testable; take/release are exercised by the live smoke test.

    #[test]
    fn still_associated_error_names_the_iface() {
        let err = RadioError::StillAssociated("wlan0".into());
        assert_eq!(
            err.to_string(),
            "interface wlan0 is still associated with a network"
        );
    }

    #[test]
    fn command_error_names_the_tool() {
        let err = RadioError::Command("ip", "exit status 2".into());
        assert!(err.to_string().starts_with("ip failed:"));
    }
}
