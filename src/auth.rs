//! Panel login: sessions, lockout, and the effective passphrase.
//!
//! Everything here lives in the daemon's memory: sessions vanish on
//! restart, and a randomly generated passphrase never touches disk.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A session dies after this long without activity.
pub const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// ...and after this long *with* activity. A cookie that leaks (a
/// screenshot, a browser profile, a shared device) must not be a
/// permanent key to the money.
pub const SESSION_ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
/// Failures from one address before it is locked out for [`LOCKOUT`].
pub const MAX_FAILURES: u32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(300);
/// Failures across *all* addresses in [`GLOBAL_WINDOW`] before logins
/// stop being accepted at all. Per-address limits alone are defeated by
/// adding addresses (measured: 30 attempts in 0.21s with six source
/// addresses); this is the wall a rotating attacker actually hits.
pub const GLOBAL_FAILURES: u32 = 20;
pub const GLOBAL_WINDOW: Duration = Duration::from_secs(60);
/// Most lockout records to keep. Beyond this, entries that are not
/// currently locking anybody out are dropped.
const MAX_LOCKOUT_ENTRIES: usize = 512;

/// Constant-time-ish string equality. Leaks only the length, never
/// position of the first difference.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (*a.get(i).unwrap_or(&0)) as usize ^ (*b.get(i).unwrap_or(&0)) as usize;
    }
    diff == 0
}

/// 256-bit token, hex encoded.
pub fn new_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Human-typable passphrase for the config-less case: unambiguous
/// characters only, ~100 bits in 20 characters.
pub fn new_passphrase() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I
    let mut out = String::with_capacity(20);
    for _ in 0..20 {
        let mut buf = [0u8; 1];
        getrandom::fill(&mut buf).expect("system RNG unavailable");
        out.push(ALPHABET[buf[0] as usize % ALPHABET.len()] as char);
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    BadPassphrase,
    /// Too many attempts; retry after the given seconds.
    LockedOut(u64),
}

struct LockoutEntry {
    failures: u32,
    locked_until: Option<Instant>,
}

struct Session {
    /// The address the session was issued to.
    addr: String,
    /// Last activity, for the idle timeout.
    seen: Instant,
    /// When the session was issued, for the absolute timeout.
    created: Instant,
}

pub struct AuthState {
    /// The passphrase that actually works this run.
    passphrase: String,
    /// token -> session
    sessions: HashMap<String, Session>,
    /// client address -> failure bookkeeping
    locked: HashMap<String, LockoutEntry>,
    /// When each recent failure happened, across all addresses: the
    /// shared budget that address rotation cannot escape.
    failures: Vec<Instant>,
}

impl AuthState {
    pub fn new(passphrase: String) -> Self {
        Self {
            passphrase,
            sessions: HashMap::new(),
            locked: HashMap::new(),
            failures: Vec::new(),
        }
    }

    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Change the passphrase that works from now on.
    ///
    /// Sessions already issued keep working: locking the operator out of
    /// the panel that just changed the password would be a trap.
    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = passphrase;
        self.locked.clear();
        self.failures.clear();
    }

    /// Attempt a login from `addr`. On success, issues a fresh token.
    ///
    /// Two limits protect the passphrase: the per-address lockout, and a
    /// shared budget of failures across every address, which is what
    /// stops an attacker from resetting the first limit by rotating
    /// source addresses.
    pub fn login(&mut self, addr: &str, attempt: &str) -> Result<String, LoginError> {
        let now = Instant::now();
        self.prune(now);

        if let Some(wait) = self.global_cooldown(now) {
            return Err(LoginError::LockedOut(wait.as_secs().saturating_add(1)));
        }
        if let Some(wait) = self.address_cooldown(addr, now) {
            return Err(LoginError::LockedOut(wait.as_secs().saturating_add(1)));
        }

        if ct_eq(attempt, &self.passphrase) {
            self.locked.remove(addr);
            let token = new_token();
            self.sessions.insert(
                token.clone(),
                Session {
                    addr: addr.to_string(),
                    seen: now,
                    created: now,
                },
            );
            return Ok(token);
        }

        let entry = self.locked.entry(addr.to_string()).or_insert(LockoutEntry {
            failures: 0,
            locked_until: None,
        });
        entry.failures += 1;
        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(now + LOCKOUT);
            entry.failures = 0;
        }
        self.failures.push(now);
        Err(LoginError::BadPassphrase)
    }

    /// How long this address must wait, when it is locked out.
    fn address_cooldown(&self, addr: &str, now: Instant) -> Option<Duration> {
        self.locked
            .get(addr)?
            .locked_until
            .filter(|until| now < *until)
            .map(|until| until - now)
    }

    /// How long the *shared* budget must recover for, when the recent
    /// failure rate is over the limit. This bounds guessing no matter how
    /// many addresses the attacker has: the worst case for the operator
    /// is a short wait, not a permanent lockout.
    fn global_cooldown(&self, now: Instant) -> Option<Duration> {
        let failures: Vec<Instant> = self
            .failures
            .iter()
            .copied()
            .filter(|at| now.duration_since(*at) < GLOBAL_WINDOW)
            .collect();
        if failures.len() < GLOBAL_FAILURES as usize {
            return None;
        }
        let oldest = failures.first()?;
        Some(GLOBAL_WINDOW - now.duration_since(*oldest))
    }

    /// Drop bookkeeping nobody needs any more: expired lockouts with no
    /// failures behind them, and (if the map is still huge) the oldest
    /// entries that are not locking anybody out.
    fn prune(&mut self, now: Instant) {
        self.failures
            .retain(|at| now.duration_since(*at) < GLOBAL_WINDOW);
        self.locked.retain(|_, entry| {
            entry.failures > 0 || entry.locked_until.is_some_and(|until| now < until)
        });
        if self.locked.len() > MAX_LOCKOUT_ENTRIES {
            let mut idle: Vec<String> = self
                .locked
                .iter()
                .filter(|(_, entry)| entry.locked_until.is_none_or(|until| now >= until))
                .map(|(addr, _)| addr.clone())
                .collect();
            idle.sort();
            for addr in idle {
                if self.locked.len() <= MAX_LOCKOUT_ENTRIES {
                    break;
                }
                self.locked.remove(&addr);
            }
        }
    }

    /// Sliding-idle validation bound to the address the session was
    /// issued to.
    ///
    /// A token that arrives from somewhere else is not accepted, so a
    /// cookie copied off the network (or a screenshot) is not a login.
    pub fn validate(&mut self, token: &str, addr: &str) -> bool {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.seen) < SESSION_IDLE
                && now.duration_since(session.created) < SESSION_ABSOLUTE
        });
        match self.sessions.get_mut(token) {
            Some(session) if session.addr == addr => {
                session.seen = now;
                true
            }
            _ => false,
        }
    }

    pub fn logout(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> AuthState {
        AuthState::new("correct-horse".into())
    }

    #[test]
    fn good_passphrase_issues_a_token() {
        let mut a = auth();
        let token = a.login("10.10.0.7", "correct-horse").unwrap();
        assert!(a.validate(&token, "10.10.0.7"));
    }

    #[test]
    fn bad_passphrase_is_rejected_and_counted() {
        let mut a = auth();
        assert_eq!(
            a.login("10.10.0.7", "wrong"),
            Err(LoginError::BadPassphrase)
        );
        assert_eq!(
            a.login("10.10.0.7", "wrong"),
            Err(LoginError::BadPassphrase)
        );
    }

    #[test]
    fn lockout_after_max_failures() {
        let mut a = auth();
        for _ in 0..MAX_FAILURES {
            let _ = a.login("10.10.0.7", "wrong");
        }
        match a.login("10.10.0.7", "correct-horse") {
            Err(LoginError::LockedOut(secs)) => assert!(secs > 0),
            other => panic!("expected lockout, got {other:?}"),
        }
        // A different address is unaffected by that address's lockout.
        assert!(a.login("10.10.0.8", "correct-horse").is_ok());
    }

    #[test]
    fn rotating_addresses_hit_the_shared_budget() {
        let mut a = auth();
        // Five different addresses, one failure each: no single address
        // is locked out, but the guesses are still bounded.
        for i in 0..GLOBAL_FAILURES {
            let addr = format!("10.10.0.{i}");
            match a.login(&addr, "wrong") {
                Err(LoginError::BadPassphrase) => {}
                other => panic!("attempt {i} should be a plain failure: {other:?}"),
            }
        }
        // The next attempt, from a brand-new address, waits.
        match a.login("192.168.99.99", "correct-horse") {
            Err(LoginError::LockedOut(secs)) => {
                assert!(secs > 0 && secs <= GLOBAL_WINDOW.as_secs() + 1, "{secs}s");
            }
            other => panic!("the shared budget must apply: {other:?}"),
        }
        // And the operator is not permanently out: the budget is a wait,
        // not a lock, once the window passes.
        a.failures.clear();
        assert!(a.login("192.168.99.99", "correct-horse").is_ok());
    }

    #[test]
    fn successful_login_clears_the_counter() {
        let mut a = auth();
        for _ in 0..MAX_FAILURES - 1 {
            let _ = a.login("10.10.0.7", "wrong");
        }
        assert!(a.login("10.10.0.7", "correct-horse").is_ok());
        for _ in 0..MAX_FAILURES - 1 {
            assert_eq!(
                a.login("10.10.0.7", "wrong"),
                Err(LoginError::BadPassphrase),
                "counter must have reset"
            );
        }
    }

    #[test]
    fn unknown_and_logged_out_tokens_fail() {
        let mut a = auth();
        let token = a.login("10.10.0.7", "correct-horse").unwrap();
        a.logout(&token);
        assert!(!a.validate(&token, "10.10.0.7"));
        assert!(!a.validate("never-issued", "10.10.0.7"));
    }

    #[test]
    fn a_session_belongs_to_the_address_it_was_issued_to() {
        let mut a = auth();
        let token = a.login("10.10.0.7", "correct-horse").unwrap();
        assert!(a.validate(&token, "10.10.0.7"));
        // The same cookie from somewhere else is not a login: this is
        // what makes a sniffed cookie useless to another device.
        assert!(!a.validate(&token, "10.10.0.8"));
        assert!(a.validate(&token, "10.10.0.7"), "the real client keeps it");
    }

    #[test]
    fn validate_refreshes_the_idle_clock() {
        let mut a = auth();
        let token = a.login("x", "correct-horse").unwrap();
        // Simulate activity by poking the timestamp.
        {
            let session = a.sessions.get_mut(&token).unwrap();
            session.seen = Instant::now() - SESSION_IDLE + Duration::from_secs(10);
        }
        assert!(a.validate(&token, "x"));
        // An abandoned session ages out.
        let other = a.login("y", "correct-horse").unwrap();
        {
            let session = a.sessions.get_mut(&other).unwrap();
            session.seen = Instant::now() - SESSION_IDLE - Duration::from_secs(1);
        }
        assert!(!a.validate(&other, "y"));
    }

    #[test]
    fn a_session_cannot_outlive_the_absolute_limit() {
        let mut a = auth();
        let token = a.login("x", "correct-horse").unwrap();
        {
            // Active a second ago, but issued longer ago than allowed.
            let session = a.sessions.get_mut(&token).unwrap();
            session.seen = Instant::now() - Duration::from_secs(1);
            session.created = Instant::now() - SESSION_ABSOLUTE - Duration::from_secs(1);
        }
        assert!(
            !a.validate(&token, "x"),
            "activity must not extend a session forever"
        );
        assert_eq!(a.session_count(), 0, "and it is forgotten, not just denied");
    }

    #[test]
    fn the_lockout_map_does_not_grow_forever() {
        let mut a = auth();
        for i in 0..(MAX_LOCKOUT_ENTRIES * 2) {
            let addr = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
            let _ = a.login(&addr, "wrong");
        }
        assert!(
            a.locked.len() <= MAX_LOCKOUT_ENTRIES,
            "{} entries",
            a.locked.len()
        );
        // The budget that matters (recent failures) is bounded too.
        assert!(a.failures.len() <= GLOBAL_FAILURES as usize + 1);
    }

    #[test]
    fn ct_eq_matches_only_exactly() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
        assert!(!ct_eq("", "a"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn generated_secrets_are_unique_and_well_formed() {
        let t1 = new_token();
        let t2 = new_token();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));

        let p = new_passphrase();
        assert_eq!(p.len(), 20);
        assert_ne!(p, new_passphrase());
        // No confusing characters.
        assert!(!p.contains(['0', 'O', '1', 'I']));
    }
}
