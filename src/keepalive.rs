//! Staying up: helper supervision, interface verification, and resume.
//!
//! Bring-up is the easy half. The promises that matter afterwards are:
//!
//! - a helper that dies is restarted with backoff rather than buried (#6);
//! - the access point and the uplink are re-checked every tick, because
//!   NetworkManager, a driver reset, or a roam can take them away
//!   silently (#8, #9);
//! - waking from suspend re-asserts the hotspot instead of pretending
//!   nothing happened (#4).
//!
//! All of it runs on the daemon's threads. Nothing here blocks on a lock
//! while sleeping: a restart that waits does not hold the panel hostage.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::daemon::{Daemon, supervise};
use crate::{log_error, log_info, log_warn};

/// How many times one helper may be restarted before the daemon gives up
/// and lets systemd bring the whole hotspot back cleanly.
pub const MAX_RESTARTS: usize = 5;
/// Restarts older than this do not count against the budget: a helper
/// that fails once a week is not in a crash loop.
pub const RESTART_WINDOW: Duration = Duration::from_secs(300);
/// Longest wait between restart attempts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(16);

/// Exponential backoff for restart attempt `attempt` (1-based).
pub fn backoff(attempt: usize) -> Duration {
    let seconds = 1u64 << (attempt.saturating_sub(1)).min(4);
    Duration::from_secs(seconds).min(MAX_BACKOFF)
}

/// The channel a connected station is on, from `iw dev <if> link`.
pub fn station_channel(link_output: &str) -> Option<u8> {
    // `iw link` prints "channel: 6": the colon is part of the token.
    link_output
        .split_whitespace()
        .skip_while(|token| token.trim_end_matches(':') != "channel")
        .nth(1)
        .and_then(|value| value.parse().ok())
}

/// Is the station in `link_output` associated?
pub fn station_connected(link_output: &str) -> bool {
    link_output.trim_start().starts_with("Connected to")
}

/// Is `info_output` (from `iw dev <if> info`) an access point?
pub fn is_ap_mode(info_output: &str) -> bool {
    info_output.contains("type AP")
}

// ----------------------------------------------------------------- helpers

fn start_helper(name: &str) -> std::io::Result<std::process::Child> {
    match name {
        "hostapd" => supervise("hostapd", &[crate::wireless::HOSTAPD_CONF]),
        "dnsmasq" => supervise(
            "dnsmasq",
            &[
                "--keep-in-foreground",
                &format!("--conf-file={}", crate::wireless::DNSMASQ_CONF),
            ],
        ),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown helper {other}"),
        )),
    }
}

/// Which supervised helper has died, with its exit status.
fn dead_helper(d: &mut Daemon) -> Option<(String, String)> {
    for name in ["hostapd", "dnsmasq"] {
        let child = match name {
            "hostapd" => d.hostapd.as_mut(),
            _ => d.dnsmasq.as_mut(),
        };
        if let Some(process) = child
            && let Ok(Some(status)) = process.try_wait()
        {
            return Some((name.to_string(), status.to_string()));
        }
    }
    None
}

fn slot<'a>(d: &'a mut Daemon, name: &str) -> &'a mut Option<std::process::Child> {
    match name {
        "hostapd" => &mut d.hostapd,
        _ => &mut d.dnsmasq,
    }
}

fn note(d: &mut Daemon, message: String) {
    log_warn!("{message}");
    // The newest few restarts are what an operator needs to see.
    if d.restart_notes.len() >= 5 {
        d.restart_notes.remove(0);
    }
    d.restart_notes.push(message);
}

/// Supervise the helpers forever: restart with backoff, and give up —
/// loudly, and with a reason `status` can report — when a helper is in a
/// crash loop, because a hotspot that keeps dying is worse than one that
/// admits it.
pub(crate) fn watch_children(d: Arc<Mutex<Daemon>>) {
    let mut restarts: Vec<(String, std::time::Instant)> = Vec::new();
    while !crate::daemon::shutting_down() {
        std::thread::sleep(Duration::from_millis(500));
        if crate::daemon::shutting_down() {
            return;
        }

        let dead = match d.lock() {
            Ok(mut guard) => dead_helper(&mut guard),
            Err(_) => return,
        };
        let Some((name, status)) = dead else { continue };

        // Only recent failures count against the budget.
        let now_instant = std::time::Instant::now();
        restarts.retain(|(_, at)| now_instant.duration_since(*at) < RESTART_WINDOW);
        let attempts = restarts.iter().filter(|(n, _)| *n == name).count() + 1;

        if attempts > MAX_RESTARTS {
            let reason = format!(
                "{name} exited ({status}) and was restarted {MAX_RESTARTS} times in {}s; \
                 giving up so the service can be restarted cleanly",
                RESTART_WINDOW.as_secs()
            );
            if let Ok(mut guard) = d.lock() {
                note(&mut guard, reason.clone());
            }
            log_error!("{reason}");
            crate::daemon::shutdown_with(reason);
            return;
        }

        let wait = backoff(attempts);
        log_warn!(
            "{name} exited ({status}); restarting in {}s (attempt {attempts}/{MAX_RESTARTS})",
            wait.as_secs()
        );
        std::thread::sleep(wait);
        if crate::daemon::shutting_down() {
            return;
        }

        let outcome = match d.lock() {
            Ok(mut guard) => {
                let started = start_helper(&name).map(|child| {
                    *slot(&mut guard, &name) = Some(child);
                });
                match started {
                    Ok(()) => {
                        // Give it a moment: a helper that cannot start at
                        // all should count as a failure, not as a restart.
                        std::thread::sleep(Duration::from_millis(400));
                        let alive = slot(&mut guard, &name)
                            .as_mut()
                            .and_then(|c| c.try_wait().ok().flatten())
                            .is_none();
                        if alive {
                            Ok(format!(
                                "{name} restarted (attempt {attempts}) after {status}"
                            ))
                        } else {
                            Err(format!("{name} exited immediately after restart"))
                        }
                    }
                    Err(e) => Err(format!("cannot restart {name}: {e}")),
                }
            }
            Err(_) => return,
        };

        match outcome {
            Ok(message) => {
                log_info!("{message}");
                restarts.push((name.clone(), std::time::Instant::now()));
                if let Ok(mut guard) = d.lock() {
                    note(&mut guard, message);
                    // Bring the firewall back in step: a restarted dnsmasq
                    // re-reads the lease file, and a restarted hostapd may
                    // have missed a device.
                    guard.needs_reconcile = true;
                }
            }
            Err(message) => {
                log_error!("{message}");
                if let Ok(mut guard) = d.lock() {
                    note(&mut guard, message);
                }
                restarts.push((name, std::time::Instant::now()));
            }
        }
    }
}

// ------------------------------------------------------------ interface check

/// The state of the access point, as the kernel has it right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApState {
    Fine,
    /// The interface is not in AP mode any more: something took it.
    ModeLost {
        iface: String,
        detail: String,
    },
    /// The interface is gone entirely.
    Missing {
        iface: String,
    },
}

/// Check the access point with real commands (`iw`, `ip`).
pub(crate) fn ap_state(iface: &str) -> ApState {
    if !std::path::Path::new(&format!("/sys/class/net/{iface}")).exists() {
        return ApState::Missing {
            iface: iface.to_string(),
        };
    }
    match crate::daemon::cmd_out("iw", &["dev", iface, "info"]) {
        Some(info) if is_ap_mode(&info) => ApState::Fine,
        Some(info) => ApState::ModeLost {
            iface: iface.to_string(),
            detail: info
                .lines()
                .find(|line| line.trim_start().starts_with("type"))
                .unwrap_or("no interface type reported")
                .trim()
                .to_string(),
        },
        None => ApState::ModeLost {
            iface: iface.to_string(),
            detail: "iw could not read the interface".to_string(),
        },
    }
}

/// Is the gateway address still on the interface?
pub(crate) fn gateway_present(iface: &str, gateway: &str) -> bool {
    crate::daemon::cmd_out("ip", &["-o", "-4", "addr", "show", "dev", iface])
        .is_some_and(|addrs| addrs.contains(gateway))
}

/// The station's view of its link, when this mode has one.
pub(crate) fn station_link(iface: &str) -> Option<String> {
    crate::daemon::cmd_out("iw", &["dev", iface, "link"])
}

/// Which way a roaming station went, when the AP must follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UplinkChange {
    Fine,
    /// The station is no longer associated: nothing to sell.
    Disconnected {
        iface: String,
    },
    /// The station moved to another channel and the AP went deaf.
    ChannelChanged {
        from: u8,
        to: u8,
    },
}

/// Compare the channel the AP beacons on with the one the station is on.
pub(crate) fn uplink_change(iface: &str, ap_channel: u8, link: &str) -> UplinkChange {
    if !station_connected(link) {
        return UplinkChange::Disconnected {
            iface: iface.to_string(),
        };
    }
    match station_channel(link) {
        Some(channel) if channel != ap_channel => UplinkChange::ChannelChanged {
            from: ap_channel,
            to: channel,
        },
        _ => UplinkChange::Fine,
    }
}

/// Re-assert the access point after something took it away: claim the
/// interface back, put the gateway address on it, reinstall the paywall,
/// and bring hostapd up again on the current channel.
pub(crate) fn reassert_ap(d: &mut Daemon) -> Result<(), String> {
    let iface = d.fw.ap_iface.clone();
    log_warn!("re-asserting the access point on {iface}");
    if d.mode != "wifi-uplink" {
        crate::radio::take(&iface).map_err(|e| e.to_string())?;
    }
    crate::radio::set_gateway(&iface, &d.fw.gateway.to_string(), true)
        .map_err(|e| format!("re-adding the gateway address: {e}"))?;
    // hostapd cannot survive its interface being re-typed under it.
    if let Some(mut child) = d.hostapd.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let child = supervise("hostapd", &[crate::wireless::HOSTAPD_CONF])
        .map_err(|e| format!("restarting hostapd: {e}"))?;
    d.hostapd = Some(child);
    crate::daemon::expect_alive(&mut d.hostapd, "hostapd")?;
    d.fw.install()
        .map_err(|e| format!("reinstalling the paywall: {e}"))?;
    d.needs_reconcile = true;
    d.panel_urls = d.compute_panel_urls();
    Ok(())
}

/// Restart hostapd so it beacons on a different channel (a station that
/// roamed, in `--wifi-uplink`).
pub(crate) fn follow_channel(d: &mut Daemon, channel: u8) -> Result<(), String> {
    let iface = d.fw.ap_iface.clone();
    log_warn!("station moved to channel {channel}; restarting hostapd there");
    std::fs::write(
        crate::wireless::HOSTAPD_CONF,
        crate::wireless::hostapd_config_on_channel(&d.cfg, &iface, channel),
    )
    .map_err(|e| format!("writing the hostapd config: {e}"))?;
    if let Some(mut child) = d.hostapd.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    d.hostapd = Some(
        supervise("hostapd", &[crate::wireless::HOSTAPD_CONF])
            .map_err(|e| format!("restarting hostapd: {e}"))?,
    );
    crate::daemon::expect_alive(&mut d.hostapd, "hostapd")?;
    d.ap_channel = channel;
    Ok(())
}

/// What a resumed machine needs: the radio was almost certainly reset,
/// and every client association is gone. Nothing here is fatal — the goal
/// is that the hotspot is working again before the first client notices.
pub(crate) fn resume_recovery(d: &mut Daemon) {
    log_warn!("resumed from suspend; re-arming the hotspot");
    match ap_state(&d.fw.ap_iface) {
        ApState::Fine if gateway_present(&d.fw.ap_iface, &d.fw.gateway.to_string()) => {
            log_info!("the access point survived the suspend");
        }
        _ => {
            if let Err(e) = reassert_ap(d) {
                log_error!("could not re-assert the access point: {e}");
                d.restart_notes
                    .push(format!("after suspend: could not re-assert the AP: {e}"));
                return;
            }
        }
    }
    if d.mode == "wifi-uplink"
        && let Some(uplink) = d.fw.uplink.clone()
    {
        match station_link(&uplink) {
            Some(link) if station_connected(&link) => {
                if let Some(channel) = station_channel(&link)
                    && channel != d.ap_channel
                    && let Err(e) = follow_channel(d, channel)
                {
                    log_error!("could not follow the station's channel: {e}");
                }
            }
            _ => log_error!(
                "the uplink station {uplink} is not associated after resume; \
                 reconnect the wifi to sell internet again"
            ),
        }
    }
    d.needs_reconcile = true;
    d.panel_urls = d.compute_panel_urls();
    log_info!("resume recovery finished");
}

/// A wall-clock jump is the only reliable sign that the machine slept:
/// monotonic time does not advance while suspended, the wall clock does.
pub fn slept_through(gap_seconds: i64, interval: Duration) -> bool {
    gap_seconds > (interval.as_secs() as i64) * 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_stops_at_the_cap() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(4), Duration::from_secs(8));
        assert_eq!(backoff(5), Duration::from_secs(16));
        assert_eq!(backoff(9), MAX_BACKOFF, "no unbounded growth");
        assert_eq!(backoff(0), Duration::from_secs(1), "defensive");
    }

    #[test]
    fn station_link_is_parsed() {
        let connected = "Connected to 8c:3b:ad:00:11:22 (on wlan1)\n\tSSID: home\n\
                         \tfreq: 2437\n\tRX: 1234 bytes\n\tTX: 4321 bytes\n\t\
                         signal: -45 dBm\n\ttx bitrate: 72.2 MBit/s\n\tbss flags: short-preamble\n\
                         \tdtim period: 2\n\tbeacon int: 100\n\tchannel: 6\n";
        assert!(station_connected(connected));
        assert_eq!(station_channel(connected), Some(6));

        let disconnected = "Not connected.";
        assert!(!station_connected(disconnected));
        assert_eq!(station_channel(disconnected), None);
        assert_eq!(station_channel(""), None);
    }

    #[test]
    fn ap_mode_is_recognised_from_iw_output() {
        assert!(is_ap_mode(
            "Interface ap0\n\tifindex 7\n\ttype AP\n\twiphy 0\n"
        ));
        assert!(!is_ap_mode(
            "Interface wlan0\n\tifindex 3\n\ttype managed\n\twiphy 0\n"
        ));
        assert!(!is_ap_mode(""));
    }

    #[test]
    fn uplink_change_reports_disconnects_and_roams() {
        assert_eq!(
            uplink_change("wlan1", 6, "Not connected."),
            UplinkChange::Disconnected {
                iface: "wlan1".into()
            }
        );
        let roamed = "Connected to aa:bb:cc:dd:ee:ff (on wlan1)\n\tchannel: 11\n";
        assert_eq!(
            uplink_change("wlan1", 6, roamed),
            UplinkChange::ChannelChanged { from: 6, to: 11 }
        );
        let same = "Connected to aa:bb:cc:dd:ee:ff (on wlan1)\n\tchannel: 6\n";
        assert_eq!(uplink_change("wlan1", 6, same), UplinkChange::Fine);
        // A station that reports no channel is not treated as a roam.
        let silent = "Connected to aa:bb:cc:dd:ee:ff (on wlan1)\n";
        assert_eq!(uplink_change("wlan1", 6, silent), UplinkChange::Fine);
    }

    #[test]
    fn suspend_is_noticed_by_the_clock_jump() {
        let interval = Duration::from_secs(15);
        assert!(
            !slept_through(15, interval),
            "a normal tick is not a resume"
        );
        assert!(!slept_through(45, interval), "a slow tick is still a tick");
        assert!(slept_through(46, interval));
        assert!(slept_through(3600, interval), "a nap is a nap");
    }
}
