//! Reconciliation: the store is the truth, the firewall is a cache.
//!
//! `reconcile` makes the kernel match the database: make sure the table
//! is still loaded and still ours, expire what is due, then diff each
//! nft set against the store. Idempotent — safe to call from a loop,
//! after every mutation, and after someone hand-edits nftables.
//!
//! Everything a tick needs from the kernel comes from one `nft list
//! table`, and everything it changes goes back in one `nft -f` script,
//! so a tick that touches a hundred devices is still two processes.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use rusqlite::Connection;

use crate::mac::MacAddr;
use crate::nft::{Firewall, SetChange, SetName, TableSnapshot, diff};
use crate::store;

#[derive(thiserror::Error, Debug)]
pub enum PaywallError {
    #[error(transparent)]
    Nft(#[from] crate::nft::NftError),
    #[error("state database: {0}")]
    Store(#[from] store::StoreError),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The table was missing, flushed, or foreign, and has been reloaded.
    pub reinstalled: bool,
    /// Passes flipped to expired this tick.
    pub expired: usize,
    pub allowed_added: usize,
    pub allowed_removed: usize,
    pub friends_added: usize,
    pub friends_removed: usize,
    pub blocked_added: usize,
    pub blocked_removed: usize,
    pub addresses_added: usize,
    pub addresses_removed: usize,
}

impl Report {
    pub fn changed(&self) -> bool {
        self.reinstalled
            || self.expired > 0
            || self.allowed_added > 0
            || self.allowed_removed > 0
            || self.friends_added > 0
            || self.friends_removed > 0
            || self.blocked_added > 0
            || self.blocked_removed > 0
            || self.addresses_added > 0
            || self.addresses_removed > 0
    }
}

/// A device's address, as last seen in the lease file. Download
/// accounting is keyed by address (see [`crate::nft`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseAddress {
    pub mac: MacAddr,
    pub addr: Ipv4Addr,
}

/// What one reconcile did, plus the kernel view it read along the way —
/// callers get the traffic snapshot without a second `nft` call.
#[derive(Debug)]
pub struct Outcome {
    pub report: Report,
    pub snapshot: TableSnapshot,
}

/// Bring the firewall in line with the store.
pub fn reconcile(
    conn: &Connection,
    fw: &Firewall,
    now: i64,
    leases: &[LeaseAddress],
) -> Result<Outcome, PaywallError> {
    let mut report = Report::default();

    // Enforcement first, and from the same read the sets below use: a
    // table that is missing, flushed or foreign is rebuilt from scratch
    // rather than trusted, and a healthy tick still costs one `nft list`.
    let snapshot = match fw.inspect()? {
        Some(snapshot) => snapshot,
        None => {
            fw.install()?;
            report.reinstalled = true;
            fw.inspect()?.ok_or_else(|| {
                crate::nft::NftError::Rejected(
                    "the paywall was reinstalled but does not read back".to_string(),
                )
            })?
        }
    };
    report.expired = store::expire_due(conn, now)?;

    let want_allowed = store::paid_macs(conn, now)?;
    let want_friends = store::friend_macs(conn)?;
    // Every known device without access gets attributed drop counters.
    let want_blocked: Vec<MacAddr> = store::all_device_macs(conn)?
        .into_iter()
        .filter(|m| !want_allowed.contains(m) && !want_friends.contains(m))
        .collect();

    // Address sets: what a client is *currently* using. Allowed
    // addresses are counted, blocked ones are dropped, and nothing here
    // ever grants access — the MAC sets above do that.
    let mut want_allowed_v4 = Vec::new();
    let mut want_blocked_v4 = Vec::new();
    for lease in leases {
        if want_allowed.contains(&lease.mac) || want_friends.contains(&lease.mac) {
            want_allowed_v4.push(lease.addr);
        } else if want_blocked.contains(&lease.mac) {
            want_blocked_v4.push(lease.addr);
        }
    }

    let changes = plan(
        &snapshot,
        &want_allowed,
        &want_friends,
        &want_blocked,
        &want_allowed_v4,
        &want_blocked_v4,
        &mut report,
    );
    fw.apply_batch(&changes)?;
    Ok(Outcome { report, snapshot })
}

/// The set operations that turn the kernel's picture into the store's.
/// Pure: the whole reconcile decision is testable without a kernel.
#[allow(clippy::too_many_arguments)]
fn plan(
    snapshot: &TableSnapshot,
    want_allowed: &[MacAddr],
    want_friends: &[MacAddr],
    want_blocked: &[MacAddr],
    want_allowed_v4: &[Ipv4Addr],
    want_blocked_v4: &[Ipv4Addr],
    report: &mut Report,
) -> Vec<SetChange> {
    let mut changes = Vec::new();
    let sets: [(SetName, &[MacAddr]); 3] = [
        (SetName::Allowed, want_allowed),
        (SetName::Friends, want_friends),
        (SetName::Blocked, want_blocked),
    ];
    for (set, want) in sets {
        let have: Vec<MacAddr> = snapshot.macs(set).iter().map(|e| e.mac).collect();
        let d = diff(want, &have);
        for mac in &d.add {
            changes.push(SetChange::AddMac(set, *mac));
        }
        for mac in &d.remove {
            changes.push(SetChange::DelMac(set, *mac));
        }
        match set {
            SetName::Allowed => {
                report.allowed_added = d.add.len();
                report.allowed_removed = d.remove.len();
            }
            SetName::Friends => {
                report.friends_added = d.add.len();
                report.friends_removed = d.remove.len();
            }
            _ => {
                report.blocked_added = d.add.len();
                report.blocked_removed = d.remove.len();
            }
        }
    }

    let v4_sets: [(SetName, &[Ipv4Addr]); 2] = [
        (SetName::AllowedV4, want_allowed_v4),
        (SetName::BlockedV4, want_blocked_v4),
    ];
    for (set, want) in v4_sets {
        let have: Vec<Ipv4Addr> = snapshot.addresses(set).iter().map(|e| e.addr).collect();
        let d = diff(want, &have);
        for addr in &d.add {
            changes.push(SetChange::AddV4(set, *addr));
        }
        for addr in &d.remove {
            changes.push(SetChange::DelV4(set, *addr));
        }
        report.addresses_added += d.add.len();
        report.addresses_removed += d.remove.len();
    }
    changes
}

/// Apply one grant/revoke immediately instead of waiting for the tick.
pub fn apply_device(
    conn: &Connection,
    fw: &Firewall,
    mac: MacAddr,
    now: i64,
) -> Result<(), PaywallError> {
    let paid = store::paid_macs(conn, now)?.contains(&mac);
    let friend = store::friend_macs(conn)?.contains(&mac);
    let mut changes = Vec::new();
    if paid {
        changes.push(SetChange::AddMac(SetName::Allowed, mac));
        changes.push(SetChange::DelMac(SetName::Blocked, mac));
    } else {
        changes.push(SetChange::DelMac(SetName::Allowed, mac));
    }
    if friend {
        changes.push(SetChange::AddMac(SetName::Friends, mac));
        changes.push(SetChange::DelMac(SetName::Blocked, mac));
    } else {
        changes.push(SetChange::DelMac(SetName::Friends, mac));
    }
    if !paid && !friend {
        // The device row exists by now (grant/revoke/touch created it),
        // so attribute its future drops to it.
        changes.push(SetChange::AddMac(SetName::Blocked, mac));
    }
    fw.apply_batch(&changes)?;
    Ok(())
}

/// Per-device traffic, as the kernel counts it.
///
/// Uploads come from the MAC sets (the rules that gate uploads carry the
/// client's MAC); downloads come from the address sets, mapped back to
/// the device that holds the address. All of them are cumulative
/// counters, so the panel derives rates between polls.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub up_bytes: u64,
    pub up_packets: u64,
    pub down_bytes: u64,
    pub down_packets: u64,
    /// Dropped while blocked (uploads by MAC, downloads by address).
    pub blocked_bytes: u64,
    pub blocked_packets: u64,
}

/// Fold one snapshot into per-MAC traffic using the current leases.
pub fn traffic(snapshot: &TableSnapshot, leases: &[LeaseAddress]) -> HashMap<String, Traffic> {
    let mut out: HashMap<String, Traffic> = HashMap::new();
    for (set, blocked) in [
        (SetName::Allowed, false),
        (SetName::Friends, false),
        (SetName::Blocked, true),
    ] {
        for element in snapshot.macs(set) {
            let entry = out.entry(element.mac.to_string()).or_default();
            if blocked {
                entry.blocked_bytes += element.bytes;
                entry.blocked_packets += element.packets;
            } else {
                entry.up_bytes += element.bytes;
                entry.up_packets += element.packets;
            }
        }
    }
    for (set, blocked) in [(SetName::AllowedV4, false), (SetName::BlockedV4, true)] {
        for element in snapshot.addresses(set) {
            // An address nobody holds any more cannot be attributed.
            let Some(lease) = leases.iter().find(|l| l.addr == element.addr) else {
                continue;
            };
            let entry = out.entry(lease.mac.to_string()).or_default();
            if blocked {
                entry.blocked_bytes += element.bytes;
                entry.blocked_packets += element.packets;
            } else {
                entry.down_bytes += element.bytes;
                entry.down_packets += element.packets;
            }
        }
    }
    out
}

/// Kernel-side tests for the reconciler, over a fake `nft`.
///
/// The paywall is where a bug becomes either open or closed internet, so
/// it is tested against an in-memory stand-in that behaves like the real
/// thing at the level this code cares about: a ruleset that can be
/// installed, flushed or deleted, and sets that hold elements with
/// counters. The kernel itself is exercised by
/// `tests/netns_enforcement.rs`, which needs root.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use rusqlite::Connection;

    use super::*;
    use crate::nft::{FakeNft, NftBackend, NftError};

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn firewall(fake: &Arc<FakeNft>, uplink: Option<&str>) -> Firewall {
        Firewall::with_backend(
            Arc::clone(fake) as Arc<dyn NftBackend>,
            "wlan0",
            uplink.map(str::to_string),
            Ipv4Addr::new(10, 10, 0, 1),
            8080,
            true,
        )
    }

    fn db(name: &str) -> Connection {
        let dir = std::env::temp_dir().join(format!("piso-paywall-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::store::open(&dir.join("state.db")).unwrap()
    }

    fn pass(id: &str) -> crate::passes::PassDef {
        crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == id)
            .unwrap()
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn reconcile_installs_the_table_when_it_is_missing() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("install");
        assert!(!fake.installed());

        let outcome = reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert!(outcome.report.reinstalled);
        assert!(fake.installed());
        assert!(outcome.report.changed());
    }

    #[test]
    fn reconcile_reinstalls_a_flushed_table() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("flush");
        crate::store::grant(&conn, &mac("aa:bb:cc:dd:ee:01"), &pass("quick"), NOW, "PHP").unwrap();
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(fake.members(SetName::Allowed), vec!["aa:bb:cc:dd:ee:01"]);

        // Someone runs `nft flush table inet piso`: the table is still
        // there, so a mere existence check saw nothing wrong, and
        // enforcement stayed off forever.
        fake.flush();
        let outcome = reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert!(outcome.report.reinstalled, "a flushed table is not intact");
        // The device is back in the allowed set: the flush was repaired,
        // not just noticed.
        assert_eq!(fake.members(SetName::Allowed), vec!["aa:bb:cc:dd:ee:01"]);
    }

    #[test]
    fn an_intact_table_is_left_alone() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("intact");
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        let runs_after_install = fake.runs();
        let outcome = reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert!(!outcome.report.reinstalled);
        assert!(!outcome.report.changed());
        // One read, and no write at all when nothing changed.
        assert_eq!(fake.runs(), runs_after_install + 1);
    }

    #[test]
    fn grants_and_revocations_move_devices_between_sets() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("grants");
        let device = mac("aa:bb:cc:dd:ee:01");
        reconcile(&conn, &fw, NOW, &[]).unwrap();

        // A grant: paid, allowed, no longer merely blocked.
        crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(fake.members(SetName::Allowed), vec![device.to_string()]);
        assert!(fake.members(SetName::Blocked).is_empty());

        // Revoked mid-pass: out of allowed, back to blocked.
        crate::store::revoke(&conn, &device, NOW + 10).unwrap();
        let outcome = reconcile(&conn, &fw, NOW + 10, &[]).unwrap();
        assert!(outcome.report.changed());
        assert!(fake.members(SetName::Allowed).is_empty());
        assert_eq!(fake.members(SetName::Blocked), vec![device.to_string()]);
    }

    #[test]
    fn expiry_is_exact_at_the_boundary() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("boundary");
        let device = mac("aa:bb:cc:dd:ee:01");
        let expires = crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(fake.members(SetName::Allowed).len(), 1);

        // At the expiry second the pass is over, not one tick later.
        reconcile(&conn, &fw, expires, &[]).unwrap();
        assert!(
            fake.members(SetName::Allowed).is_empty(),
            "expires_at == now must be expired"
        );
        assert_eq!(fake.members(SetName::Blocked), vec![device.to_string()]);
    }

    #[test]
    fn a_friend_is_allowed_even_without_a_pass() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("friend");
        let device = mac("aa:bb:cc:dd:ee:01");
        crate::store::friend(&conn, &device, Some("Nena"), NOW).unwrap();
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(fake.members(SetName::Friends), vec![device.to_string()]);
        assert!(fake.members(SetName::Blocked).is_empty());
    }

    #[test]
    fn a_paying_friend_stays_in_both_sets() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("friend-paid");
        let device = mac("aa:bb:cc:dd:ee:01");
        crate::store::friend(&conn, &device, None, NOW).unwrap();
        crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(fake.members(SetName::Friends), vec![device.to_string()]);
        assert_eq!(fake.members(SetName::Allowed), vec![device.to_string()]);
    }

    #[test]
    fn addresses_follow_the_leases_and_never_grant_access() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("addresses");
        let paid = mac("aa:bb:cc:dd:ee:01");
        let blocked = mac("aa:bb:cc:dd:ee:02");
        crate::store::grant(&conn, &paid, &pass("quick"), NOW, "PHP").unwrap();
        crate::store::touch_leased_device(&conn, &blocked, Some("10.10.0.9"), NOW).unwrap();

        let leases = vec![
            LeaseAddress {
                mac: paid,
                addr: Ipv4Addr::new(10, 10, 0, 5),
            },
            LeaseAddress {
                mac: blocked,
                addr: Ipv4Addr::new(10, 10, 0, 9),
            },
        ];
        reconcile(&conn, &fw, NOW, &leases).unwrap();
        assert_eq!(fake.members(SetName::AllowedV4), vec!["10.10.0.5"]);
        assert_eq!(fake.members(SetName::BlockedV4), vec!["10.10.0.9"]);

        // The device loses its pass: its address moves with it.
        crate::store::revoke(&conn, &paid, NOW + 5).unwrap();
        reconcile(&conn, &fw, NOW + 5, &leases).unwrap();
        assert!(fake.members(SetName::AllowedV4).is_empty());
        assert!(
            fake.members(SetName::BlockedV4)
                .contains(&"10.10.0.5".to_string())
        );

        // A device that leaves the network takes its address with it.
        reconcile(&conn, &fw, NOW + 10, &[]).unwrap();
        assert!(fake.members(SetName::AllowedV4).is_empty());
        assert!(fake.members(SetName::BlockedV4).is_empty());
    }

    #[test]
    fn traffic_is_attributed_up_and_down() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("traffic");
        let device = mac("aa:bb:cc:dd:ee:01");
        crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();
        let leases = vec![LeaseAddress {
            mac: device,
            addr: Ipv4Addr::new(10, 10, 0, 5),
        }];
        reconcile(&conn, &fw, NOW, &leases).unwrap();

        // Counters as the kernel reports them, in `nft list table` shape.
        let listed = "\
table inet piso {
\tset allowed {
\t\ttype ether_addr
\t\tcounter
\t\telements = { aa:bb:cc:dd:ee:01 counter packets 10 bytes 1000 }
\t}
\tset allowed_v4 {
\t\ttype ipv4_addr
\t\tcounter
\t\telements = { 10.10.0.5 counter packets 40 bytes 90000 }
\t}
}
";
        let snapshot = crate::nft::parse_table_listing(listed);
        let traffic = traffic(&snapshot, &leases);
        let entry = traffic.get(&device.to_string()).expect("device reported");
        assert_eq!(entry.up_bytes, 1000, "uploads come from the MAC set");
        assert_eq!(entry.up_packets, 10);
        assert_eq!(entry.down_bytes, 90_000, "downloads come from the IPv4 set");
        assert_eq!(entry.down_packets, 40);
    }

    #[test]
    fn a_failing_kernel_is_reported_and_retried_next_tick() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("failure");
        let device = mac("aa:bb:cc:dd:ee:01");
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();

        // The write fails: the caller hears about it, and nothing is
        // half-applied behind its back.
        *fake.fail_next.lock().unwrap() = Some("Netlink error: busy".to_string());
        let err = reconcile(&conn, &fw, NOW, &[]).unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
        assert!(fake.members(SetName::Allowed).is_empty());

        // The next tick converges.
        reconcile(&conn, &fw, NOW + 15, &[]).unwrap();
        assert_eq!(fake.members(SetName::Allowed), vec![device.to_string()]);
    }

    #[test]
    fn a_stale_element_does_not_lose_the_rest_of_the_batch() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("stale");
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        for (i, id) in ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
            .iter()
            .enumerate()
        {
            crate::store::grant(&conn, &mac(id), &pass("quick"), NOW + i as i64, "PHP").unwrap();
        }
        // The first device is already in the kernel, but our read of the
        // table did not see it (it arrived between the read and the
        // write): the batch add fails with "File exists", and the second
        // device must still get through.
        fake.sets
            .lock()
            .unwrap()
            .entry(SetName::Allowed.name().to_string())
            .or_default()
            .insert("aa:bb:cc:dd:ee:01".to_string());
        fake.hidden
            .lock()
            .unwrap()
            .insert("aa:bb:cc:dd:ee:01".to_string());

        let outcome = reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(
            outcome.report.allowed_added, 2,
            "both devices looked missing"
        );
        let members = fake.members(SetName::Allowed);
        assert!(members.contains(&"aa:bb:cc:dd:ee:01".to_string()));
        assert!(members.contains(&"aa:bb:cc:dd:ee:02".to_string()));
        // Once the listing shows everything again, the next tick is quiet.
        fake.hidden.lock().unwrap().clear();
        let outcome = reconcile(&conn, &fw, NOW + 1, &[]).unwrap();
        assert!(!outcome.report.changed(), "{:?}", outcome.report);
    }

    #[test]
    fn batch_writes_are_single_runs() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("batching");
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        let before = fake.runs();
        // Twenty new devices: one read, one write.
        for i in 0..20 {
            let id = format!("aa:bb:cc:dd:{i:02x}:01");
            crate::store::touch_leased_device(&conn, &mac(&id), None, NOW).unwrap();
        }
        reconcile(&conn, &fw, NOW, &[]).unwrap();
        assert_eq!(
            fake.runs() - before,
            2,
            "a tick should cost one read and one write"
        );
        assert_eq!(fake.members(SetName::Blocked).len(), 20);
    }

    #[test]
    fn apply_device_is_immediate_and_never_waits_for_the_tick() {
        let fake = FakeNft::new();
        let fw = firewall(&fake, None);
        let conn = db("apply");
        let device = mac("aa:bb:cc:dd:ee:01");
        reconcile(&conn, &fw, NOW, &[]).unwrap();

        crate::store::grant(&conn, &device, &pass("quick"), NOW, "PHP").unwrap();
        apply_device(&conn, &fw, device, NOW).unwrap();
        assert_eq!(fake.members(SetName::Allowed), vec![device.to_string()]);
        assert!(fake.members(SetName::Blocked).is_empty());

        crate::store::revoke(&conn, &device, NOW + 1).unwrap();
        apply_device(&conn, &fw, device, NOW + 1).unwrap();
        assert!(fake.members(SetName::Allowed).is_empty());
        assert_eq!(fake.members(SetName::Blocked), vec![device.to_string()]);
    }
}
