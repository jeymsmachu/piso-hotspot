//! Virtual access-point interfaces (`ap0`) beside a station interface.
//!
//! The `--wifi-uplink` primitive: the station keeps its association and
//! the AP beacons beside it on the same radio, which requires a driver
//! station+AP interface combination (`piso-hotspot doctor` reports it).
//!
//! Two kernel quirks shape the implementation:
//! - a new virtual interface can briefly borrow the station's MAC, and
//!   hostapd misbehaves on a duplicate, so wait for a distinct one;
//! - `iw dev … interface add` exits 0 even when it changed nothing, so
//!   read the interface type back instead of trusting the exit code.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use thiserror::Error;

pub const AP_IFACE: &str = "ap0";

#[derive(Error, Debug)]
pub enum VifaceError {
    #[error("cannot create {name} beside {station}: {detail}")]
    Create {
        name: String,
        station: String,
        detail: String,
    },
    #[error("{0} was created but is not an AP interface")]
    NotAnAp(String),
    #[error("{0} kept the station's MAC for 2s; refusing to run hostapd on a duplicate")]
    MacRace(String),
    #[error("interface {0} does not exist")]
    Missing(String),
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn mac_of(iface: &str) -> Option<String> {
    read_trimmed(&format!("/sys/class/net/{iface}/address"))
}

fn link_exists(iface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{iface}")).exists()
}

fn iw(args: &[&str]) -> Result<String, String> {
    let out = Command::new("iw")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(if stderr.trim().is_empty() {
            format!("iw {args:?} exited {}", out.status)
        } else {
            stderr.trim().to_string()
        });
    }
    Ok(stdout)
}

/// Create `name` (default `ap0`) beside `station` as an AP interface.
pub fn create(station: &str) -> Result<String, VifaceError> {
    // A leftover from an earlier run is ours to replace.
    remove(AP_IFACE);

    iw(&["dev", station, "interface", "add", AP_IFACE, "type", "__ap"]).map_err(|detail| {
        VifaceError::Create {
            name: AP_IFACE.to_string(),
            station: station.to_string(),
            detail,
        }
    })?;

    // Wait for the interface to appear and carry a MAC distinct from
    // the station's (the kernel may briefly clone it).
    let deadline = Instant::now() + Duration::from_secs(2);
    let station_mac = mac_of(station);
    loop {
        if let Some(ap_mac) = mac_of(AP_IFACE)
            && station_mac.as_deref() != Some(ap_mac.as_str())
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(VifaceError::MacRace(AP_IFACE.to_string()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // A freshly created virtual interface can come up `managed` even
    // though it was created `type __ap`, and hostapd then fails with
    // "Device or resource busy". Force the type the way the interface
    // must be down first, and read it back — `iw` exits 0 whether or
    // not the change happened.
    set_type_ap()?;

    // Final truth from the kernel, not from exit codes.
    let info =
        iw(&["dev", AP_IFACE, "info"]).map_err(|_| VifaceError::Missing(AP_IFACE.to_string()))?;
    if !info.contains("type AP") {
        return Err(VifaceError::NotAnAp(AP_IFACE.to_string()));
    }
    Ok(AP_IFACE.to_string())
}

fn set_type_ap() -> Result<(), VifaceError> {
    let _ = Command::new("ip")
        .args(["link", "set", AP_IFACE, "down"])
        .output();
    iw(&["dev", AP_IFACE, "set", "type", "__ap"]).map_err(|detail| VifaceError::Create {
        name: AP_IFACE.to_string(),
        station: "(forcing type)".to_string(),
        detail,
    })?;
    Ok(())
}

/// Remove the virtual AP interface. Tolerates "already gone".
pub fn remove(name: &str) {
    if link_exists(name) {
        let _ = iw(&["dev", name, "del"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_interface_error_names_it() {
        assert_eq!(
            VifaceError::Missing("ap0".into()).to_string(),
            "interface ap0 does not exist"
        );
    }

    #[test]
    fn mac_race_error_is_explanatory() {
        let msg = VifaceError::MacRace("ap0".into()).to_string();
        assert!(msg.contains("duplicate"), "{msg}");
    }

    #[test]
    fn remove_tolerates_absent_interface() {
        // No root needed: nothing exists, nothing happens, no panic.
        remove("definitely-not-an-interface");
    }

    #[test]
    fn mac_of_nonexistent_is_none() {
        assert_eq!(mac_of("definitely-not-an-interface"), None);
        assert!(!link_exists("definitely-not-an-interface"));
    }
}
