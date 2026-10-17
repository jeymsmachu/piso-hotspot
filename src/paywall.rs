//! Reconciliation: the store is the truth, the firewall is a cache.
//!
//! `reconcile` makes the kernel match the database: expire what is due,
//! then diff each nft set against the store. Idempotent — safe to call
//! from a loop, after every mutation, and after someone hand-edits
//! nftables.

use rusqlite::Connection;

use crate::nft::{Firewall, SET_ALLOWED, SET_BLOCKED, SET_FRIENDS, diff};
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
    /// Passes flipped to expired this tick.
    pub expired: usize,
    pub allowed_added: usize,
    pub allowed_removed: usize,
    pub friends_added: usize,
    pub friends_removed: usize,
    pub blocked_added: usize,
    pub blocked_removed: usize,
}

impl Report {
    pub fn changed(&self) -> bool {
        self.expired > 0
            || self.allowed_added > 0
            || self.allowed_removed > 0
            || self.friends_added > 0
            || self.friends_removed > 0
            || self.blocked_added > 0
            || self.blocked_removed > 0
    }
}

/// Bring the firewall in line with the store.
///
/// If the table itself is missing (hand-deleted, flushed), it is
/// reinstalled first — the paywall must fail closed, not stay open
/// until the next full restart.
pub fn reconcile(conn: &Connection, fw: &Firewall, now: i64) -> Result<Report, PaywallError> {
    if !fw.table_exists() {
        fw.install()?;
    }

    let mut report = Report {
        expired: store::expire_due(conn, now)?,
        ..Report::default()
    };

    let want_allowed = store::paid_macs(conn, now)?;
    let want_friends = store::friend_macs(conn)?;

    let (n_add, n_rem) = sync_set(fw, SET_ALLOWED, &want_allowed, fw.set_members(SET_ALLOWED)?)?;
    report.allowed_added = n_add;
    report.allowed_removed = n_rem;

    let (n_add, n_rem) = sync_set(fw, SET_FRIENDS, &want_friends, fw.set_members(SET_FRIENDS)?)?;
    report.friends_added = n_add;
    report.friends_removed = n_rem;

    // Every known device without access gets attributed drop counters.
    let want_blocked: Vec<crate::mac::MacAddr> = store::all_device_macs(conn)?
        .into_iter()
        .filter(|m| !want_allowed.contains(m) && !want_friends.contains(m))
        .collect();
    let (n_add, n_rem) = sync_set(fw, SET_BLOCKED, &want_blocked, fw.set_members(SET_BLOCKED)?)?;
    report.blocked_added = n_add;
    report.blocked_removed = n_rem;

    Ok(report)
}

fn sync_set(
    fw: &Firewall,
    set: &str,
    want: &[crate::mac::MacAddr],
    have: Vec<crate::nft::SetElement>,
) -> Result<(usize, usize), PaywallError> {
    let have: Vec<crate::mac::MacAddr> = have.into_iter().map(|e| e.mac).collect();
    let d = diff(want, &have);
    for mac in &d.add {
        fw.set_add(set, mac)?;
    }
    for mac in &d.remove {
        fw.set_remove(set, mac)?;
    }
    Ok((d.add.len(), d.remove.len()))
}

/// Apply one grant/revoke immediately instead of waiting for the tick.
pub fn apply_device(
    conn: &Connection,
    fw: &Firewall,
    mac: crate::mac::MacAddr,
    now: i64,
) -> Result<(), PaywallError> {
    let paid = store::paid_macs(conn, now)?.contains(&mac);
    let friend = store::friend_macs(conn)?.contains(&mac);
    if paid {
        fw.set_add(SET_ALLOWED, &mac)?;
        fw.set_remove(SET_BLOCKED, &mac)?;
    } else {
        fw.set_remove(SET_ALLOWED, &mac)?;
    }
    if friend {
        fw.set_add(SET_FRIENDS, &mac)?;
        fw.set_remove(SET_BLOCKED, &mac)?;
    } else {
        fw.set_remove(SET_FRIENDS, &mac)?;
    }
    if !paid && !friend {
        // The device row exists by now (grant/revoke/touch created it),
        // so attribute its future drops to it.
        fw.set_add(SET_BLOCKED, &mac)?;
    }
    Ok(())
}
