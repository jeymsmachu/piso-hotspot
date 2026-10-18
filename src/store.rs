//! Program-owned state: `/etc/piso-hotspot/state.db`.
//!
//! The database is the source of truth for passes, friends, and sales.
//! The firewall is a cache reconciled against it. Settings do not live
//! here — see [`crate::config`].

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use thiserror::Error;

/// Current schema version, tracked in SQLite's `user_version` pragma.
pub const SCHEMA_VERSION: i64 = 2;

const SCHEMA_V1: &str = "
CREATE TABLE devices (
    mac        TEXT PRIMARY KEY,
    label      TEXT,
    state      TEXT NOT NULL DEFAULT 'unauthorized',
    pass_id    TEXT,
    expires_at INTEGER,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
CREATE TABLE friends (
    mac        TEXT PRIMARY KEY,
    label      TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE sales (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac         TEXT NOT NULL,
    pass_id     TEXT NOT NULL,
    price_minor INTEGER NOT NULL,
    currency    TEXT NOT NULL,
    sold_at     INTEGER NOT NULL,
    expires_at  INTEGER
);
CREATE INDEX idx_sales_sold_at ON sales (sold_at);
";

/// v2 adds the append-only audit trail and the address a device was
/// last seen on (the panel, `list`, and the portal all report it).
const SCHEMA_V2: &str = "
CREATE TABLE actions (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    action  TEXT NOT NULL,
    mac     TEXT,
    pass_id TEXT,
    actor   TEXT NOT NULL,
    detail  TEXT
);
CREATE INDEX idx_actions_ts ON actions (ts);
ALTER TABLE devices ADD COLUMN ip TEXT;
";

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("cannot open state database {path}: {source}")]
    Open {
        path: std::path::PathBuf,
        source: rusqlite::Error,
    },
    #[error("state database error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Open (creating if needed) and migrate the state database at `path`.
///
/// The database records who connected, what they were called, and what
/// they paid; it is created 0600 inside a 0700 directory, and existing
/// files are tightened too (older versions created them world-readable).
pub fn open(path: &Path) -> Result<Connection, StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Open {
            path: path.to_path_buf(),
            source: rusqlite::Error::ToSqlConversionFailure(Box::new(e)),
        })?;
        set_mode(parent, 0o700);
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|source| StoreError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    // Before WAL mode: SQLite copies the database's mode onto the
    // sidecars it creates, so restricting the database now also covers
    // files that do not exist yet.
    restrict_db_files(path);
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

/// chmod, ignoring failure: an exotic filesystem must not stop the
/// hotspot from running.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// The database and its SQLite sidecars, all root-only.
fn restrict_db_files(path: &Path) {
    set_mode(path, 0o600);
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        if sidecar.exists() {
            set_mode(&sidecar, 0o600);
        }
    }
}

/// Open read-only for inspection. Does not create the file.
pub fn open_readonly(path: &Path) -> Result<Connection, StoreError> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|source| {
        StoreError::Open {
            path: path.to_path_buf(),
            source,
        }
    })
}

pub fn schema_version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let version = schema_version(conn)?;
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        conn.execute_batch(SCHEMA_V2)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

// ------------------------------------------------------------------ queries

/// A device row as shown by `piso-hotspot list`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DeviceRow {
    pub mac: String,
    pub label: Option<String>,
    pub state: String,
    pub pass_id: Option<String>,
    pub expires_at: Option<i64>,
    /// Last DHCP address seen for this device, when it ever had one.
    pub ip: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FriendRow {
    pub mac: String,
    pub label: Option<String>,
    pub created_at: i64,
}

/// Local midnight following `now`, as a unix timestamp. Passes sold
/// "until dismissal" end there — the revenue day rolls over.
pub fn next_midnight(now: i64) -> i64 {
    let local = chrono::DateTime::from_timestamp(now, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .with_timezone(&chrono::Local);
    (local.date_naive() + chrono::Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_local_timezone(chrono::Local)
        .single()
        .expect("midnight is unambiguous")
        .timestamp()
}

/// Grant a pass: the device becomes `paid` until `pass` expires, and the
/// sale is recorded in the same transaction.
///
/// Renewal extends, it never truncates: a live pass keeps whatever time
/// it has left and the purchased pass is added on top. Buying a 15-minute
/// pass on top of a day pass means "day pass plus 15 minutes", and buying
/// a day pass twice before midnight does not shorten the first one.
pub fn grant(
    conn: &Connection,
    mac: &crate::mac::MacAddr,
    pass: &crate::passes::PassDef,
    now: i64,
    currency: &str,
) -> Result<i64, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT expires_at FROM devices WHERE mac = ?1 AND state = 'paid'",
            [mac.to_string()],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    // Time already paid for counts from its own expiry, not from now.
    let base = current.unwrap_or(now).max(now);
    let expires = match pass.duration_secs {
        Some(secs) => base + secs as i64,
        None => next_midnight(base),
    };
    tx.execute(
        "INSERT INTO devices (mac, state, pass_id, expires_at, first_seen, last_seen)
         VALUES (?1, 'paid', ?2, ?3, ?4, ?4)
         ON CONFLICT(mac) DO UPDATE SET
            state = 'paid', pass_id = ?2, expires_at = ?3, last_seen = ?4",
        rusqlite::params![mac.to_string(), pass.id, expires, now],
    )?;
    tx.execute(
        "INSERT INTO sales (mac, pass_id, price_minor, currency, sold_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            mac.to_string(),
            pass.id,
            pass.price_minor,
            currency,
            now,
            expires
        ],
    )?;
    tx.commit()?;
    Ok(expires)
}

/// Cut a device off. Friends are untouched — their access does not come
/// from a pass.
pub fn revoke(conn: &Connection, mac: &crate::mac::MacAddr, now: i64) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE devices SET state = 'unauthorized', pass_id = NULL, expires_at = NULL,
            last_seen = ?2
         WHERE mac = ?1",
        rusqlite::params![mac.to_string(), now],
    )?;
    Ok(())
}

/// Mark every pass past its expiry as `expired`. Returns rows changed.
pub fn expire_due(conn: &Connection, now: i64) -> Result<usize, StoreError> {
    Ok(conn.execute(
        "UPDATE devices SET state = 'expired'
         WHERE state = 'paid' AND expires_at IS NOT NULL AND expires_at <= ?1",
        [now],
    )?)
}

pub fn friend(
    conn: &Connection,
    mac: &crate::mac::MacAddr,
    label: Option<&str>,
    now: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO friends (mac, label, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(mac) DO UPDATE SET label = COALESCE(?2, friends.label)",
        rusqlite::params![mac.to_string(), label, now],
    )?;
    Ok(())
}

pub fn unfriend(conn: &Connection, mac: &crate::mac::MacAddr) -> Result<(), StoreError> {
    conn.execute("DELETE FROM friends WHERE mac = ?1", [mac.to_string()])?;
    Ok(())
}

pub fn list_devices(conn: &Connection) -> Result<Vec<DeviceRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT mac, label, state, pass_id, expires_at, ip, first_seen, last_seen
         FROM devices ORDER BY last_seen DESC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(DeviceRow {
                mac: r.get(0)?,
                label: r.get(1)?,
                state: r.get(2)?,
                pass_id: r.get(3)?,
                expires_at: r.get(4)?,
                ip: r.get(5)?,
                first_seen: r.get(6)?,
                last_seen: r.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn list_friends(conn: &Connection) -> Result<Vec<FriendRow>, StoreError> {
    let mut stmt =
        conn.prepare("SELECT mac, label, created_at FROM friends ORDER BY created_at")?;
    let rows = stmt
        .query_map([], |r| {
            Ok(FriendRow {
                mac: r.get(0)?,
                label: r.get(1)?,
                created_at: r.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// MACs with a live pass, for the firewall's `allowed` set.
pub fn paid_macs(conn: &Connection, now: i64) -> Result<Vec<crate::mac::MacAddr>, StoreError> {
    let mut stmt =
        conn.prepare("SELECT mac FROM devices WHERE state = 'paid' AND expires_at > ?1")?;
    let macs = stmt
        .query_map([now], |r| r.get::<_, String>(0))?
        .filter_map(|s| s.ok())
        .filter_map(|s| s.parse().ok())
        .collect();
    Ok(macs)
}

/// Every MAC the store knows about (seen, granted, or renamed).
pub fn all_device_macs(conn: &Connection) -> Result<Vec<crate::mac::MacAddr>, StoreError> {
    let mut stmt = conn.prepare("SELECT mac FROM devices")?;
    let macs = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|s| s.ok())
        .filter_map(|s| s.parse().ok())
        .collect();
    Ok(macs)
}

/// MACs with unlimited access, for the firewall's `friends` set.
pub fn friend_macs(conn: &Connection) -> Result<Vec<crate::mac::MacAddr>, StoreError> {
    let mut stmt = conn.prepare("SELECT mac FROM friends")?;
    let macs = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|s| s.ok())
        .filter_map(|s| s.parse().ok())
        .collect();
    Ok(macs)
}

/// Record that a device was seen on the network (DHCP lease). Never
/// touches an existing pass state or the operator's label.
pub fn touch_leased_device(
    conn: &Connection,
    mac: &crate::mac::MacAddr,
    ip: Option<&str>,
    now: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO devices (mac, ip, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(mac) DO UPDATE SET last_seen = ?3, ip = COALESCE(?2, devices.ip)",
        rusqlite::params![mac.to_string(), ip, now],
    )?;
    Ok(())
}

pub fn count_devices(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?)
}

pub fn count_active_passes(conn: &Connection, now: i64) -> Result<i64, StoreError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE state = 'paid' AND expires_at > ?1",
        [now],
        |r| r.get(0),
    )?)
}

/// Set (or clear, with `None`) the operator's label for a device.
/// Creates the row if the device has never been seen.
pub fn set_device_label(
    conn: &Connection,
    mac: &crate::mac::MacAddr,
    label: Option<&str>,
    now: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO devices (mac, label, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(mac) DO UPDATE SET label = ?2, last_seen = ?3",
        rusqlite::params![mac.to_string(), label, now],
    )?;
    Ok(())
}

/// One device by MAC, when known to the store.
pub fn get_device(conn: &Connection, mac: &str) -> Result<Option<DeviceRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT mac, label, state, pass_id, expires_at, ip, first_seen, last_seen
         FROM devices WHERE mac = ?1",
    )?;
    let mut rows = stmt.query_map([mac], |r| {
        Ok(DeviceRow {
            mac: r.get(0)?,
            label: r.get(1)?,
            state: r.get(2)?,
            pass_id: r.get(3)?,
            expires_at: r.get(4)?,
            ip: r.get(5)?,
            first_seen: r.get(6)?,
            last_seen: r.get(7)?,
        })
    })?;
    rows.next().transpose().map_err(Into::into)
}

/// Is this MAC on the friend list?
pub fn is_friend(conn: &Connection, mac: &str) -> Result<bool, StoreError> {
    let n: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM friends WHERE mac = ?1)",
        [mac],
        |r| r.get(0),
    )?;
    Ok(n == 1)
}

/// Revenue since `since` (unix ts): total in the minor unit and count.
pub fn revenue_since(conn: &Connection, since: i64) -> Result<(i64, i64), StoreError> {
    conn.query_row(
        "SELECT COALESCE(SUM(price_minor), 0), COUNT(*) FROM sales WHERE sold_at >= ?1",
        [since],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(Into::into)
}

// ---------------------------------------------------------------- audit

/// One privileged action, as recorded in the append-only `actions` table.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ActionRow {
    pub ts: i64,
    pub action: String,
    pub mac: Option<String>,
    pub pass_id: Option<String>,
    pub actor: String,
    pub detail: Option<String>,
}

/// Append one privileged action. Rows are only ever inserted: this is
/// the answer to "who gave away internet, and when was it cut".
pub fn record_action(
    conn: &Connection,
    now: i64,
    action: &str,
    mac: Option<&crate::mac::MacAddr>,
    pass_id: Option<&str>,
    actor: &str,
    detail: Option<&str>,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO actions (ts, action, mac, pass_id, actor, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            now,
            action,
            mac.map(|m| m.to_string()),
            pass_id,
            actor,
            detail
        ],
    )?;
    Ok(())
}

/// Most recent audit rows, newest first.
pub fn recent_actions(conn: &Connection, limit: u32) -> Result<Vec<ActionRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT ts, action, mac, pass_id, actor, detail FROM actions
         ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt
        .query_map([limit], |r| {
            Ok(ActionRow {
                ts: r.get(0)?,
                action: r.get(1)?,
                mac: r.get(2)?,
                pass_id: r.get(3)?,
                actor: r.get(4)?,
                detail: r.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Forget devices nobody paid for, that are not friends, and that have
/// not been seen for `retention_secs`. Keeps the table (and the nft
/// sets reconciled from it) from growing with every MAC that ever
/// walked past. Sales and audit rows are never pruned.
pub fn prune_devices(
    conn: &Connection,
    now: i64,
    retention_secs: i64,
) -> Result<usize, StoreError> {
    Ok(conn.execute(
        "DELETE FROM devices
         WHERE last_seen < ?1
           AND state != 'paid'
           AND mac NOT IN (SELECT mac FROM friends)",
        [now - retention_secs],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("piso-store-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.db")
    }

    #[test]
    fn open_creates_and_migrates() {
        let path = temp_db("create");
        let conn = open(&path).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn schema_has_expected_tables() {
        let path = temp_db("tables");
        let conn = open(&path).unwrap();
        for table in ["devices", "friends", "sales"] {
            let found: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(found, 1, "missing table {table}");
        }
    }

    #[test]
    fn reopen_is_idempotent() {
        let path = temp_db("reopen");
        {
            let conn = open(&path).unwrap();
            conn.execute(
                "INSERT INTO devices (mac, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:ff', 1, 1)",
                [],
            )
            .unwrap();
        }
        let conn = open(&path).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn readonly_does_not_create() {
        let path = temp_db("readonly");
        assert!(open_readonly(&path).is_err());
    }

    #[test]
    fn devices_default_to_unauthorized() {
        let path = temp_db("unauth");
        let conn = open(&path).unwrap();
        conn.execute(
            "INSERT INTO devices (mac, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:ff', 1, 1)",
            [],
        )
        .unwrap();
        let state: String = conn
            .query_row("SELECT state FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "unauthorized");
    }

    fn mac(s: &str) -> crate::mac::MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn grant_marks_paid_records_sale_and_expiry() {
        let path = temp_db("grant");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        let expires = grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &quick, now, "PHP").unwrap();
        assert_eq!(expires, now + 15 * 60);

        let devices = list_devices(&conn).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].state, "paid");
        assert_eq!(devices[0].pass_id.as_deref(), Some("quick"));
        assert_eq!(devices[0].expires_at, Some(expires));

        let sales: i64 = conn
            .query_row("SELECT COUNT(*) FROM sales", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sales, 1);
        let price: i64 = conn
            .query_row("SELECT price_minor FROM sales", [], |r| r.get(0))
            .unwrap();
        assert_eq!(price, 300);
    }

    #[test]
    fn day_pass_ends_at_next_midnight() {
        let path = temp_db("day");
        let conn = open(&path).unwrap();
        // 2023-11-14 22:13:20 UTC
        let now = 1_700_000_000;
        let day = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "day")
            .unwrap();
        let expires = grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &day, now, "PHP").unwrap();
        let expected = next_midnight(now);
        assert_eq!(expires, expected);
        // Sometime between 1 and 25 hours out.
        assert!(expected - now > 3600 && expected - now <= 86_400);
    }

    #[test]
    fn expire_due_flips_paid_to_expired() {
        let path = temp_db("expire");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &quick, now, "PHP").unwrap();
        assert_eq!(expire_due(&conn, now + 60).unwrap(), 0);
        assert_eq!(expire_due(&conn, now + 901).unwrap(), 1);
        let paid = paid_macs(&conn, now + 901).unwrap();
        assert!(paid.is_empty());
    }

    #[test]
    fn revoke_clears_pass_but_keeps_history() {
        let path = temp_db("revoke");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &quick, now, "PHP").unwrap();
        revoke(&conn, &mac("aa:bb:cc:dd:ee:ff"), now + 10).unwrap();
        let devices = list_devices(&conn).unwrap();
        assert_eq!(devices[0].state, "unauthorized");
        assert_eq!(devices[0].pass_id, None);
        assert_eq!(devices[0].expires_at, None);
        // The sale survives for revenue history.
        let sales: i64 = conn
            .query_row("SELECT COUNT(*) FROM sales", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sales, 1);
    }

    #[test]
    fn friends_survive_revocation() {
        let path = temp_db("friend-revoke");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        friend(&conn, &mac("aa:bb:cc:dd:ee:ff"), Some("Sir Tony"), now).unwrap();
        revoke(&conn, &mac("aa:bb:cc:dd:ee:ff"), now).unwrap();
        let friends = list_friends(&conn).unwrap();
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].label.as_deref(), Some("Sir Tony"));
    }

    #[test]
    fn friend_label_updates_only_when_provided() {
        let path = temp_db("friend-label");
        let conn = open(&path).unwrap();
        friend(&conn, &mac("aa:bb:cc:dd:ee:ff"), Some("Sir Tony"), 1).unwrap();
        friend(&conn, &mac("aa:bb:cc:dd:ee:ff"), None, 2).unwrap();
        let friends = list_friends(&conn).unwrap();
        assert_eq!(friends[0].label.as_deref(), Some("Sir Tony"));
        friend(&conn, &mac("aa:bb:cc:dd:ee:ff"), Some("Renamed"), 3).unwrap();
        let friends = list_friends(&conn).unwrap();
        assert_eq!(friends[0].label.as_deref(), Some("Renamed"));
    }

    #[test]
    fn unfriend_removes_only_friend_not_device() {
        let path = temp_db("unfriend");
        let conn = open(&path).unwrap();
        friend(&conn, &mac("aa:bb:cc:dd:ee:ff"), None, 1).unwrap();
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:ff"), Some("10.10.0.9"), 2).unwrap();
        unfriend(&conn, &mac("aa:bb:cc:dd:ee:ff")).unwrap();
        assert!(list_friends(&conn).unwrap().is_empty());
        assert_eq!(list_devices(&conn).unwrap().len(), 1);
    }

    #[test]
    fn touch_never_wakes_dormant_pass_or_state() {
        let path = temp_db("touch");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &quick, now, "PHP").unwrap();
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:ff"), None, now + 5).unwrap();
        let devices = list_devices(&conn).unwrap();
        assert_eq!(devices[0].state, "paid");
        assert_eq!(devices[0].last_seen, now + 5);
        assert_eq!(devices[0].first_seen, now);
    }

    #[test]
    fn paid_and_friend_macs_feed_the_firewall() {
        let path = temp_db("macsets");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:01"), &quick, now, "PHP").unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:02"), &quick, now, "PHP").unwrap();
        friend(&conn, &mac("aa:bb:cc:dd:ee:03"), None, now).unwrap();

        let mut paid = paid_macs(&conn, now).unwrap();
        paid.sort();
        assert_eq!(paid.len(), 2);
        assert_eq!(paid[0].to_string(), "aa:bb:cc:dd:ee:01");
        assert_eq!(paid[1].to_string(), "aa:bb:cc:dd:ee:02");
        let friends = friend_macs(&conn).unwrap();
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].to_string(), "aa:bb:cc:dd:ee:03");

        // After expiry only friends remain allowed.
        let mut paid = paid_macs(&conn, now + 901).unwrap();
        paid.sort();
        assert!(paid.is_empty());
    }

    #[test]
    fn counting_helpers() {
        let path = temp_db("counts");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:01"), &quick, now, "PHP").unwrap();
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:02"), Some("10.10.0.42"), now).unwrap();
        assert_eq!(count_devices(&conn).unwrap(), 2);
        assert_eq!(count_active_passes(&conn, now).unwrap(), 1);
        assert_eq!(count_active_passes(&conn, now + 901).unwrap(), 0);
    }

    #[test]
    fn set_device_label_creates_updates_clears() {
        let path = temp_db("label");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        set_device_label(&conn, &mac("aa:bb:cc:dd:ee:99"), Some("TestDevice"), now).unwrap();
        let rows = list_devices(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label.as_deref(), Some("TestDevice"));
        // Timestamps must be real timestamps, not the mac string.
        assert_eq!(rows[0].first_seen, now);

        set_device_label(&conn, &mac("aa:bb:cc:dd:ee:99"), None, now + 5).unwrap();
        let rows = list_devices(&conn).unwrap();
        assert_eq!(rows.len(), 1, "update must not duplicate");
        assert_eq!(
            rows[0].label, None,
            "clearing falls back to device-reported"
        );
        assert_eq!(rows[0].last_seen, now + 5);
    }

    #[test]
    fn revenue_since_counts_sales() {
        let path = temp_db("revenue");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let quick = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "quick")
            .unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:01"), &quick, now, "PHP").unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:02"), &quick, now + 60, "PHP").unwrap();
        let (total, count) = revenue_since(&conn, now).unwrap();
        assert_eq!((total, count), (600, 2));
        let (total, count) = revenue_since(&conn, now + 30).unwrap();
        assert_eq!((total, count), (300, 1));
        let (total, count) = revenue_since(&conn, now + 600).unwrap();
        assert_eq!((total, count), (0, 0));
    }

    fn pass(id: &str) -> crate::passes::PassDef {
        crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == id)
            .unwrap()
    }

    #[test]
    fn renewal_extends_a_live_pass_instead_of_truncating_it() {
        let path = temp_db("renew");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        // A live day pass, then a quick pass sold on top of it.
        let day_expiry = grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &pass("day"), now, "PHP").unwrap();
        assert_eq!(day_expiry, next_midnight(now));
        let renewed = grant(
            &conn,
            &mac("aa:bb:cc:dd:ee:ff"),
            &pass("quick"),
            now + 60,
            "PHP",
        )
        .unwrap();
        assert_eq!(
            renewed,
            day_expiry + 900,
            "the day pass must keep its time and gain the quick pass"
        );

        // Reverse order: a live quick pass survives a day pass on top.
        let path = temp_db("renew-reverse");
        let conn = open(&path).unwrap();
        grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &pass("quick"), now, "PHP").unwrap();
        let after = grant(
            &conn,
            &mac("aa:bb:cc:dd:ee:ff"),
            &pass("day"),
            now + 10,
            "PHP",
        )
        .unwrap();
        assert_eq!(after, next_midnight(now));
        assert!(after > now + 900 - 1 || next_midnight(now) >= now + 900);

        // Both sales are booked.
        let (_, count) = revenue_since(&conn, now).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn renewal_after_expiry_starts_from_now() {
        let path = temp_db("renew-expired");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        grant(&conn, &mac("aa:bb:cc:dd:ee:ff"), &pass("quick"), now, "PHP").unwrap();
        let later = now + 10_000; // long past the 15-minute pass
        let expires = grant(
            &conn,
            &mac("aa:bb:cc:dd:ee:ff"),
            &pass("quick"),
            later,
            "PHP",
        )
        .unwrap();
        assert_eq!(expires, later + 900);
    }

    #[test]
    fn schema_migration_from_v1_preserves_data() {
        let path = temp_db("migrate-v1");
        {
            // A database exactly as version 1 created it.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO devices (mac, state, expires_at, first_seen, last_seen)
                 VALUES ('aa:bb:cc:dd:ee:ff', 'paid', 9999999999, 1, 1)",
                [],
            )
            .unwrap();
        }
        let conn = open(&path).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let devices = list_devices(&conn).unwrap();
        assert_eq!(devices.len(), 1, "existing rows survive the migration");
        assert_eq!(devices[0].state, "paid");
        assert_eq!(devices[0].ip, None, "the new column starts empty");
        // The audit table exists and accepts rows.
        record_action(&conn, 5, "grant", None, Some("quick"), "cli", None).unwrap();
        assert_eq!(recent_actions(&conn, 10).unwrap().len(), 1);
    }

    #[test]
    fn state_files_are_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db("perms");
        {
            let conn = open(&path).unwrap();
            conn.execute(
                "INSERT INTO devices (mac, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:ff', 1, 1)",
                [],
            )
            .unwrap();
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the database is not world-readable"
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn audit_rows_append_newest_first() {
        let path = temp_db("audit");
        let conn = open(&path).unwrap();
        let m = mac("aa:bb:cc:dd:ee:ff");
        record_action(&conn, 1, "grant", Some(&m), Some("quick"), "cli", None).unwrap();
        record_action(&conn, 2, "revoke", Some(&m), None, "panel:10.10.0.2", None).unwrap();
        let rows = recent_actions(&conn, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "revoke");
        assert_eq!(rows[0].actor, "panel:10.10.0.2");
        assert_eq!(rows[1].action, "grant");
        assert_eq!(rows[1].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(recent_actions(&conn, 1).unwrap().len(), 1);
    }

    #[test]
    fn pruning_forgets_strangers_but_keeps_payers_and_friends() {
        let path = temp_db("prune");
        let conn = open(&path).unwrap();
        let now = 1_700_000_000;
        let stale = now - 30 * 86_400;
        let stranger = mac("aa:bb:cc:dd:ee:01");
        let paying = mac("aa:bb:cc:dd:ee:02");
        let friend_mac = mac("aa:bb:cc:dd:ee:03");
        touch_leased_device(&conn, &stranger, None, stale).unwrap();
        touch_leased_device(&conn, &paying, None, stale).unwrap();
        touch_leased_device(&conn, &friend_mac, None, stale).unwrap();
        grant(&conn, &paying, &pass("day"), stale, "PHP").unwrap();
        friend(&conn, &friend_mac, None, stale).unwrap();

        assert_eq!(prune_devices(&conn, now, 7 * 86_400).unwrap(), 1);
        assert_eq!(get_device(&conn, &stranger.to_string()).unwrap(), None);
        assert!(get_device(&conn, &paying.to_string()).unwrap().is_some());
        assert!(
            get_device(&conn, &friend_mac.to_string())
                .unwrap()
                .is_some()
        );
        // Fresh strangers are kept.
        let fresh = mac("aa:bb:cc:dd:ee:04");
        touch_leased_device(&conn, &fresh, None, now).unwrap();
        assert_eq!(prune_devices(&conn, now, 7 * 86_400).unwrap(), 0);
    }
}
