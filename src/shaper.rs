//! Client bandwidth caps, enforced entirely in-kernel with `tc`.
//!
//! Two independent token-bucket filters, both living only on the AP
//! interface so the host's own traffic on the uplink is never touched:
//!
//! * **Download cap** — TBF as the AP's root qdisc: every byte going
//!   out to clients passes the bucket.
//! * **Upload cap** — client traffic arrives on the AP *ingress*, which
//!   cannot be shaped directly, so it is mirrored to a software `ifb`
//!   device *before* routing/NAT and shaped there. The uplink never
//!   carries a qdisc of ours, which keeps teardown trivially safe.
//!
//! Once installed, the kernel does all the work: no userspace loops,
//! no battery cost.

use std::process::Command;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShapeError {
    #[error("{0} failed: {1}")]
    Command(&'static str, String),
    #[error("upload cap needs the ifb kernel module: {0}")]
    Ifb(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    pub down: Option<u64>,
    pub up: Option<u64>,
}

impl Caps {
    pub fn is_unlimited(&self) -> bool {
        self.down.is_none() && self.up.is_none()
    }
}

/// tc rate string for bytes/second (tc wants bits: 20 MB/s ->160000000bit).
pub fn rate_bits(bytes_per_sec: u64) -> String {
    format!("{}bit", bytes_per_sec.saturating_mul(8))
}

/// Bucket size: ~125 ms of traffic, floor64 KiB (bursty apps stay
/// smooth, a cap cannot be leapt over in one burst).
pub fn burst_bytes(bytes_per_sec: u64) -> u64 {
    (bytes_per_sec / 8).max(64 * 1024)
}

/// Queue ceiling: ~250 ms of traffic, floor128 KiB.
pub fn limit_bytes(bytes_per_sec: u64) -> u64 {
    (bytes_per_sec / 2).max(128 * 1024)
}

fn run(cmd: &'static str, args: &[&str]) -> Result<(), ShapeError> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| ShapeError::Command(cmd, e.to_string()))?;
    if !out.status.success() {
        return Err(ShapeError::Command(
            cmd,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

/// Like `run`, but "it wasn't there" counts as success — used for
/// teardown and for clearing a cap that was never set.
fn run_tolerant(cmd: &'static str, args: &[&str], absent_ok: &[&str]) -> Result<(), ShapeError> {
    match run(cmd, args) {
        Ok(()) => Ok(()),
        Err(ShapeError::Command(_, msg)) if absent_ok.iter().any(|pat| msg.contains(pat)) => Ok(()),
        Err(e) => Err(e),
    }
}

fn tbf_replace(iface: &str, bytes_per_sec: u64) -> Result<(), ShapeError> {
    run(
        "tc",
        &[
            "qdisc",
            "replace",
            "dev",
            iface,
            "root",
            "tbf",
            "rate",
            &rate_bits(bytes_per_sec),
            "burst",
            &burst_bytes(bytes_per_sec).to_string(),
            "limit",
            &limit_bytes(bytes_per_sec).to_string(),
        ],
    )
}

fn ensure_ifb() -> Result<(), ShapeError> {
    // Best effort: the module may already be loaded (modprobe then
    // just succeeds); if it cannot load, the link add below reports it.
    let _ = Command::new("modprobe").arg("ifb").output();
    if run("ip", &["link", "show", "ifb0"]).is_err() {
        run("ip", &["link", "add", "ifb0", "type", "ifb"])
            .map_err(|e| ShapeError::Ifb(e.to_string()))?;
    }
    run("ip", &["link", "set", "ifb0", "up"]).map_err(|e| ShapeError::Ifb(e.to_string()))
}

fn apply_upload(ap_iface: &str, bytes_per_sec: u64) -> Result<(), ShapeError> {
    ensure_ifb()?;
    // Mirror everything arriving at the AP into ifb0 (pre-routing, so
    // client source addresses are still intact), then shape it there.
    run_tolerant(
        "tc",
        &["qdisc", "del", "dev", ap_iface, "ingress"],
        &["Cannot", "No such", "Failed"],
    )?;
    run("tc", &["qdisc", "add", "dev", ap_iface, "ingress"])?;
    run(
        "tc",
        &[
            "filter", "add", "dev", ap_iface, "parent", "ffff:", "protocol", "all", "u32", "match",
            "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", "ifb0",
        ],
    )?;
    tbf_replace("ifb0", bytes_per_sec)
}

fn clear_upload(ap_iface: &str) -> Result<(), ShapeError> {
    run_tolerant(
        "tc",
        &["qdisc", "del", "dev", ap_iface, "ingress"],
        &["Cannot", "No such", "Failed"],
    )?;
    run_tolerant(
        "ip",
        &["link", "del", "ifb0"],
        &["Cannot", "No such", "does not exist"],
    )
}

/// Install (or remove, when both caps are absent) client shaping.
/// The AP interface must already exist.
pub fn apply(ap_iface: &str, caps: Caps) -> Result<(), ShapeError> {
    if let Some(down) = caps.down {
        tbf_replace(ap_iface, down)?;
    } else {
        run_tolerant(
            "tc",
            &["qdisc", "del", "dev", ap_iface, "root"],
            &["Cannot", "No such", "Failed"],
        )?;
    }
    if let Some(up) = caps.up {
        apply_upload(ap_iface, up)?;
    } else {
        clear_upload(ap_iface)?;
    }
    Ok(())
}

/// Remove everything this module installed. Idempotent.
pub fn clear(ap_iface: &str) -> Result<(), ShapeError> {
    run_tolerant(
        "tc",
        &["qdisc", "del", "dev", ap_iface, "root"],
        &["Cannot", "No such", "Failed"],
    )?;
    clear_upload(ap_iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_conversion_is_bits() {
        // The user's example:20 MB/s client download cap.
        assert_eq!(rate_bits(20_000_000), "160000000bit");
        assert_eq!(rate_bits(1), "8bit");
    }

    #[test]
    fn burst_and_limit_scale_with_floors() {
        assert_eq!(burst_bytes(20_000_000), 2_500_000); //125 ms
        assert_eq!(burst_bytes(1), 64 * 1024); // floor
        assert_eq!(limit_bytes(20_000_000), 10_000_000); //250 ms
        assert_eq!(limit_bytes(1), 128 * 1024); // floor
    }

    #[test]
    fn caps_detection() {
        assert!(Caps::default().is_unlimited());
        assert!(
            !Caps {
                down: Some(1),
                up: None
            }
            .is_unlimited()
        );
        assert!(
            !Caps {
                down: None,
                up: Some(1)
            }
            .is_unlimited()
        );
    }

    #[test]
    fn errors_name_the_command() {
        let e = ShapeError::Command("tc", "Cannot find device".into());
        assert!(e.to_string().starts_with("tc failed"));
        let e = ShapeError::Ifb("no module".into());
        assert!(e.to_string().contains("ifb kernel module"));
    }
}
