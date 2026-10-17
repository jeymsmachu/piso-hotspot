//! Our dnsmasq's lease file: who is on the network right now.
//!
//! This is the device-discovery source — the daemon reads it every
//! reconcile tick and records seen devices in the store. paidspot
//! declared a "lease watcher" it never built; here there is exactly one
//! reader, the reconcile loop.

use std::path::Path;

use crate::mac::MacAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Expiry epoch from dnsmasq (informational).
    pub expires_at: i64,
    pub mac: MacAddr,
    pub ip: String,
    pub hostname: Option<String>,
}

/// Parse a dnsmasq lease file: `<expiry> <mac> <ip> <hostname> <client-id>`.
///
/// Unparseable lines are skipped — a half-written line mid-rename
/// should not stop discovery.
pub fn parse(content: &str) -> Vec<Lease> {
    content
        .lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let expires_at: i64 = cols.next()?.parse().ok()?;
            let mac: MacAddr = cols.next()?.parse().ok()?;
            let ip = cols.next()?.to_string();
            let hostname = cols
                .next()
                .map(|h| h.to_string())
                .filter(|h| h != "*" && !h.is_empty());
            Some(Lease {
                expires_at,
                mac,
                ip,
                hostname,
            })
        })
        .collect()
}

/// Read and parse the live lease file. Missing file = no clients yet.
pub fn read(path: &Path) -> Vec<Lease> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_lease_file() {
        let text = "\
1760000000 1c:ce:51:a2:ff:9f 10.10.0.23 student-phone *
1760000300 aa:bb:cc:dd:ee:ff 10.10.0.24 * 01:aa:bb:cc:dd:ee:ff
";
        let leases = parse(text);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac.to_string(), "1c:ce:51:a2:ff:9f");
        assert_eq!(leases[0].ip, "10.10.0.23");
        assert_eq!(leases[0].hostname.as_deref(), Some("student-phone"));
        // Star hostnames from unregistered clients become None.
        assert_eq!(leases[1].hostname, None);
    }

    #[test]
    fn skips_malformed_lines() {
        let text = "\
not a lease
1760000000 gg:not:a:mac 10.10.0.25 x *
1760000000 aa:bb:cc:dd:ee:ff 10.10.0.26 ok *
";
        let leases = parse(text);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, "10.10.0.26");
    }

    #[test]
    fn empty_or_missing_file_is_no_clients() {
        assert!(parse("").is_empty());
        assert!(read(Path::new("/nonexistent/leases")).is_empty());
    }

    #[test]
    fn extra_columns_are_ignored() {
        let text = "1760000000 aa:bb:cc:dd:ee:ff 10.10.0.27 host 01:aa:bb extra junk\n";
        let leases = parse(text);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname.as_deref(), Some("host"));
    }
}
