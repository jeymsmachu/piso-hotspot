//! The control protocol: CLI ⇄ daemon over a root-only unix socket.
//!
//! One JSON request per connection, one JSON response, close. The
//! socket lives at `/run/piso-hotspot/control.sock` with mode 0600:
//! every command on it changes who has internet or who administers
//! things, so only root talks to it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SOCKET_PATH: &str = "/run/piso-hotspot/control.sock";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Liveness + current state.
    Status,
    /// Sell a pass: `pass` is a configured pass id.
    Grant {
        mac: String,
        pass: String,
    },
    /// Cut a device off.
    Revoke {
        mac: String,
    },
    /// Unlimited free access, e.g. staff.
    Friend {
        mac: String,
        label: Option<String>,
    },
    Unfriend {
        mac: String,
    },
    /// Set (or clear with null) the operator's device label.
    Rename {
        mac: String,
        label: Option<String>,
    },
    /// Orderly shutdown (used by `piso-hotspot stop`).
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StatusInfo {
    pub mode: String,
    pub ap_iface: String,
    pub uplink: Option<String>,
    pub gateway: String,
    pub started_at: i64,
    pub devices_seen: i64,
    pub active_passes: i64,
    /// Every URL the panel answers on right now.
    pub panel_urls: Vec<String>,
    /// The passphrase that works this run (chosen or generated).
    pub admin_passphrase: String,
    /// Live panel sessions.
    pub sessions: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusInfo>,
    /// Expiry timestamp for a successful grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Response {
    pub fn ok_empty() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            expires_at: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            status: None,
            expires_at: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum ControlError {
    #[error("cannot reach the daemon at {SOCKET_PATH}: {0}")]
    Unreachable(String),
    #[error("bad response from daemon: {0}")]
    BadResponse(String),
}

/// Send one request to the daemon.
pub fn request(req: &Request) -> Result<Response, ControlError> {
    let path = PathBuf::from(SOCKET_PATH);
    let mut stream = connect(&path)?;
    let mut line =
        serde_json::to_string(req).map_err(|e| ControlError::BadResponse(e.to_string()))?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| ControlError::Unreachable(e.to_string()))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| ControlError::Unreachable(e.to_string()))?;
    serde_json::from_str(response.trim()).map_err(|e| ControlError::BadResponse(e.to_string()))
}

fn connect(path: &Path) -> Result<UnixStream, ControlError> {
    UnixStream::connect(path)
        .map_err(|e| ControlError::Unreachable(format!("{}: {e}", path.display())))
}

/// Is a daemon answering?
pub fn alive() -> bool {
    request(&Request::Status).is_ok()
}

/// Bind the control socket with mode 0600, replacing any stale one
/// (reachable only when no daemon holds it).
pub fn bind() -> std::io::Result<UnixListener> {
    let path = PathBuf::from(SOCKET_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialization_roundtrip() {
        let cases = vec![
            Request::Status,
            Request::Grant {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                pass: "quick".into(),
            },
            Request::Revoke {
                mac: "aa:bb:cc:dd:ee:ff".into(),
            },
            Request::Friend {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                label: Some("Sir Tony".into()),
            },
            Request::Friend {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                label: None,
            },
            Request::Unfriend {
                mac: "aa:bb:cc:dd:ee:ff".into(),
            },
            Request::Rename {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                label: Some("Redmi".into()),
            },
            Request::Rename {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                label: None,
            },
            Request::Shutdown,
        ];
        for req in cases {
            let json = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(req, back, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn responses_skip_absent_fields() {
        let r = Response::ok_empty();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"ok":true}"#);
        let r = Response::err("nope");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""error":"nope""#));
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(!back.ok);
    }

    #[test]
    fn status_info_roundtrips() {
        let s = StatusInfo {
            mode: "hotspot".into(),
            ap_iface: "wlan0".into(),
            uplink: Some("usb0".into()),
            gateway: "10.10.0.1".into(),
            started_at: 1_700_000_000,
            devices_seen: 3,
            active_passes: 1,
            panel_urls: vec!["http://10.10.0.1:8080".into()],
            admin_passphrase: "ABCD-EFGH".into(),
            sessions: 1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: StatusInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn unreachable_socket_reports_helpfully() {
        // No daemon in tests; the error names the socket path.
        let err = request(&Request::Status).unwrap_err();
        assert!(err.to_string().contains("control.sock"), "{err}");
    }
}
