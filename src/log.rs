//! The daemon's log: append-only, timestamped, leveled.
//!
//! Children (hostapd, dnsmasq) inherit the daemon's stdout/stderr, which
//! the parent points at this same file, so their output and the daemon's
//! own lines end up together — that is the file the troubleshooting
//! docs tell operators to read.
//!
//! A new run rotates instead of truncating: `daemon.log` becomes
//! `daemon.log.1`, older runs age out, and the last few restarts stay
//! readable after an incident. Log lines are the operational record, so
//! nothing here is ever truncated in place.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// How many rotated files to keep besides the live one.
pub const KEEP_ROTATIONS: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

struct Logger {
    file: Mutex<Option<File>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Rotate `path` (and its older siblings) and start a fresh log.
///
/// Called by the parent before it spawns a daemon, so the previous run's
/// file is preserved rather than truncated by the redirect.
pub fn rotate(path: &Path) -> Result<(), String> {
    let rotated = |n: usize| -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    };
    // Age the oldest out first, then shift each file up by one.
    let _ = fs::remove_file(rotated(KEEP_ROTATIONS));
    for n in (1..KEEP_ROTATIONS).rev() {
        if rotated(n).exists() {
            let _ = fs::rename(rotated(n), rotated(n + 1));
        }
    }
    if path.exists() {
        fs::rename(path, rotated(1)).map_err(|e| format!("cannot rotate {path:?}: {e}"))?;
    }
    Ok(())
}

/// Start logging to `path` (append). Falls back to stderr when the file
/// cannot be opened: losing the file is better than losing the daemon.
pub fn init(path: &Path) {
    let file = OpenOptions::new().create(true).append(true).open(path).ok();
    if file.is_none() {
        eprintln!("cannot append to {path:?}; logging to stderr only");
    }
    let _ = LOGGER.set(Logger {
        file: Mutex::new(file),
    });
}

/// One line: `2026-10-18 18:22:01 [INFO] message`.
pub fn write(level: Level, message: &str) {
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let line = format!("{stamp} [{}] {message}\n", level.label());
    match LOGGER.get() {
        Some(logger) => {
            let mut guard = match logger.file.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match guard.as_mut() {
                Some(file) => {
                    // Timestamps are the point of this file; a failed
                    // write to a full disk must not take the daemon down.
                    if file.write_all(line.as_bytes()).is_err() {
                        *guard = None;
                        eprint!("{line}");
                    } else {
                        let _ = file.flush();
                    }
                }
                None => eprint!("{line}"),
            }
        }
        None => eprint!("{line}"),
    }
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, &format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piso-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rotation_keeps_the_previous_runs() {
        let dir = temp_dir("rotate");
        let log = dir.join("daemon.log");
        for run in 1..=6 {
            fs::write(&log, format!("run {run}\n")).unwrap();
            rotate(&log).unwrap();
        }
        // The live file is gone until the new run writes to it; the
        // previous run is `.1`, and only KEEP_ROTATIONS files survive.
        assert!(!log.exists());
        assert_eq!(
            fs::read_to_string(dir.join("daemon.log.1")).unwrap(),
            "run 6\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("daemon.log.2")).unwrap(),
            "run 5\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("daemon.log.3")).unwrap(),
            "run 4\n"
        );
        assert!(!dir.join("daemon.log.4").exists(), "older runs are pruned");
    }

    #[test]
    fn rotation_of_a_missing_file_is_not_an_error() {
        let dir = temp_dir("missing");
        assert!(rotate(&dir.join("daemon.log")).is_ok());
    }

    #[test]
    fn appending_survives_rotation_and_never_truncates() {
        let dir = temp_dir("append");
        let log = dir.join("daemon.log");
        fs::write(&log, "older line\n").unwrap();
        // The parent rotates, then both sides append.
        rotate(&log).unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        file.write_all(b"new line\n").unwrap();
        drop(file);
        assert_eq!(
            fs::read_to_string(dir.join("daemon.log.1")).unwrap(),
            "older line\n"
        );
        assert_eq!(fs::read_to_string(&log).unwrap(), "new line\n");
    }
}
