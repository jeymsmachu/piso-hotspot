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
// No production consumer until the daemon lands in P1; exercised by tests.
#[allow(dead_code)]
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
}
