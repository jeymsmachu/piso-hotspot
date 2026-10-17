//! Reconciliation: the store is the truth, the firewall is a cache.
//!
//! `reconcile` makes the kernel match the database: expire what is due,
//! then diff each nft set against the store. Idempotent — safe to call
//! from a loop, after every mutation, and after someone hand-edits
//! nftables.

use rusqlite::Connection;

use crate::nft::{Firewall, SET_ALLOWED, SET_FRIENDS, diff};
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
}

impl Report {
    pub fn changed(&self) -> bool {
        self.expired > 0
            || self.allowed_added > 0
            || self.allowed_removed > 0
            || self.friends_added > 0
            || self.friends_removed > 0
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
    let have_allowed = fw.set_members(SET_ALLOWED)?;
    let d = diff(&want_allowed, &have_allowed);
    for mac in &d.add {
        fw.set_add(SET_ALLOWED, mac)?;
    }
    for mac in &d.remove {
        fw.set_remove(SET_ALLOWED, mac)?;
    }
    report.allowed_added = d.add.len();
    report.allowed_removed = d.remove.len();

    let want_friends = store::friend_macs(conn)?;
    let have_friends = fw.set_members(SET_FRIENDS)?;
    let d = diff(&want_friends, &have_friends);
    for mac in &d.add {
        fw.set_add(SET_FRIENDS, mac)?;
    }
    for mac in &d.remove {
        fw.set_remove(SET_FRIENDS, mac)?;
    }
    report.friends_added = d.add.len();
    report.friends_removed = d.remove.len();

    Ok(report)
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
    } else {
        fw.set_remove(SET_ALLOWED, &mac)?;
    }
    if friend {
        fw.set_add(SET_FRIENDS, &mac)?;
    } else {
        fw.set_remove(SET_FRIENDS, &mac)?;
    }
    Ok(())
}
