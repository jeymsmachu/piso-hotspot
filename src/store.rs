//! Program-owned state: `/etc/piso-hotspot/state.db`.
//!
//! The database is the source of truth for passes, friends, and sales.
//! The firewall is a cache reconciled against it. Settings do not live
//! here — see [`crate::config`].

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;

/// Current schema version, tracked in SQLite's `user_version` pragma.
pub const SCHEMA_VERSION: i64 = 1;

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
pub fn open(path: &Path) -> Result<Connection, StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Open {
            path: path.to_path_buf(),
            source: rusqlite::Error::ToSqlConversionFailure(Box::new(e)),
        })?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|source| StoreError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
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
pub fn grant(
    conn: &Connection,
    mac: &crate::mac::MacAddr,
    pass: &crate::passes::PassDef,
    now: i64,
    currency: &str,
) -> Result<i64, StoreError> {
    let expires = match pass.duration_secs {
        Some(secs) => now + secs as i64,
        None => next_midnight(now),
    };
    let tx = conn.unchecked_transaction()?;
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
        "SELECT mac, label, state, pass_id, expires_at, first_seen, last_seen
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
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
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
    now: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO devices (mac, first_seen, last_seen) VALUES (?1, ?2, ?2)
         ON CONFLICT(mac) DO UPDATE SET last_seen = ?2",
        rusqlite::params![mac.to_string(), now],
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

/// Revenue since `since` (unix ts): total in the minor unit and count.
pub fn revenue_since(conn: &Connection, since: i64) -> Result<(i64, i64), StoreError> {
    conn.query_row(
        "SELECT COALESCE(SUM(price_minor), 0), COUNT(*) FROM sales WHERE sold_at >= ?1",
        [since],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(Into::into)
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
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:ff"), 2).unwrap();
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
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:ff"), now + 5).unwrap();
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
        touch_leased_device(&conn, &mac("aa:bb:cc:dd:ee:02"), now).unwrap();
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
}
