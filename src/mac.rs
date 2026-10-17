//! MAC address parsing and formatting.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum MacError {
    #[error("{0:?} is not a MAC address")]
    Invalid(String),
}

/// A 48-bit MAC address, stored as raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddr {
    type Err = MacError;

    fn from_str(s: &str) -> Result<Self, MacError> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12
            || s.chars()
                .any(|c| !(c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.')))
        {
            return Err(MacError::Invalid(s.to_string()));
        }
        let mut bytes = [0u8; 6];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let part = std::str::from_utf8(chunk).expect("ascii hex");
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| MacError::Invalid(s.to_string()))?;
        }
        Ok(MacAddr(bytes))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_colon_lowercase() {
        let m: MacAddr = "1c:ce:51:a2:ff:9f".parse().unwrap();
        assert_eq!(m.to_string(), "1c:ce:51:a2:ff:9f");
    }

    #[test]
    fn accepts_dashes_uppercase() {
        let m: MacAddr = "1C-CE-51-A2-FF-9F".parse().unwrap();
        assert_eq!(m.to_string(), "1c:ce:51:a2:ff:9f");
    }

    #[test]
    fn accepts_bare_hex() {
        let m: MacAddr = "1cce51a2ff9f".parse().unwrap();
        assert_eq!(m.to_string(), "1c:ce:51:a2:ff:9f");
    }

    #[test]
    fn rejects_too_short() {
        assert!("1c:ce:51:a2:ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!("".parse::<MacAddr>().is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!("zz:zz:zz:zz:zz:zz".parse::<MacAddr>().is_err());
    }

    #[test]
    fn rejects_garbage_with_hex_digits() {
        // 12 hex digits but also invalid separator characters
        assert!("1cce51a2ff9f??".parse::<MacAddr>().is_err());
    }
}
