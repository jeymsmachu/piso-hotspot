//! Panel login: sessions, lockout, and the effective passphrase.
//!
//! Everything here lives in the daemon's memory: sessions vanish on
//! restart, and a randomly generated passphrase never touches disk.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const SESSION_IDLE: Duration = Duration::from_secs(3600);
pub const MAX_FAILURES: u32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(300);

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

pub struct AuthState {
    /// The passphrase that actually works this run.
    passphrase: String,
    /// token -> last activity
    sessions: HashMap<String, Instant>,
    /// client address -> failure bookkeeping
    locked: HashMap<String, LockoutEntry>,
}

impl AuthState {
    pub fn new(passphrase: String) -> Self {
        Self {
            passphrase,
            sessions: HashMap::new(),
            locked: HashMap::new(),
        }
    }

    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Attempt a login from `addr`. On success, issues a fresh token.
    pub fn login(&mut self, addr: &str, attempt: &str) -> Result<String, LoginError> {
        let now = Instant::now();
        if let Some(entry) = self.locked.get(addr)
            && let Some(until) = entry.locked_until
            && now < until
        {
            return Err(LoginError::LockedOut(
                (until - now).as_secs().saturating_add(1),
            ));
        }

        if ct_eq(attempt, &self.passphrase) {
            self.locked.remove(addr);
            let token = new_token();
            self.sessions.insert(token.clone(), now);
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
        Err(LoginError::BadPassphrase)
    }

    /// Sliding-idle validation: `true` when the token is known; its
    /// activity clock is refreshed.
    pub fn validate(&mut self, token: &str) -> bool {
        let now = Instant::now();
        self.sessions
            .retain(|_, seen| now.duration_since(*seen) < SESSION_IDLE);
        match self.sessions.get_mut(token) {
            Some(seen) => {
                *seen = now;
                true
            }
            None => false,
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
        assert!(a.validate(&token));
    }

    #[test]
    fn bad_passphrase_is_rejected_and_counted() {
        let mut a = auth();
        assert_eq!(
            a.login("10.10.0.7", "wrong"),
            Err(LoginError::BadPassphrase)
        );
        // Still under the limit.
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
        // A different address is unaffected.
        assert!(a.login("10.10.0.8", "correct-horse").is_ok());
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
        let token = a.login("x", "correct-horse").unwrap();
        a.logout(&token);
        assert!(!a.validate(&token));
        assert!(!a.validate("never-issued"));
    }

    #[test]
    fn validate_refreshes_the_idle_clock() {
        let mut a = auth();
        let token = a.login("x", "correct-horse").unwrap();
        // Simulate activity by poking the timestamp.
        {
            let seen = a.sessions.get_mut(&token).unwrap();
            *seen = Instant::now() - SESSION_IDLE + Duration::from_secs(10);
        }
        assert!(a.validate(&token));
        // An abandoned session ages out.
        let other = a.login("y", "correct-horse").unwrap();
        {
            let seen = a.sessions.get_mut(&other).unwrap();
            *seen = Instant::now() - SESSION_IDLE - Duration::from_secs(1);
        }
        assert!(!a.validate(&other));
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
