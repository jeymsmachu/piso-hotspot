//! Pass definitions: what the operator sells.
//!
//! A pass has a price and a duration. A pass with `duration_secs: None`
//! runs until local midnight (the "day pass").

// First consumed by `grant` and the panel (P1+); already covered by tests.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassDef {
    /// Stable identifier used on the command line and in the database.
    pub id: String,
    /// Human label shown in the panel.
    pub name: String,
    /// Price in the minor unit of [`crate::config::Config::currency`]
    /// (e.g. centavos when the currency is PHP).
    pub price_minor: u32,
    /// Pass length in seconds. Absent/`null` means "until local midnight".
    #[serde(default)]
    pub duration_secs: Option<u64>,
}

impl PassDef {
    pub fn is_until_midnight(&self) -> bool {
        self.duration_secs.is_none()
    }
}

/// The out-of-the-box price list: Quick, Extended, Day.
pub fn default_passes() -> Vec<PassDef> {
    vec![
        PassDef {
            id: "quick".into(),
            name: "Quick".into(),
            price_minor: 300,
            duration_secs: Some(15 * 60),
        },
        PassDef {
            id: "extended".into(),
            name: "Extended".into(),
            price_minor: 500,
            duration_secs: Some(45 * 60),
        },
        PassDef {
            id: "day".into(),
            name: "Day".into(),
            price_minor: 1500,
            duration_secs: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_passes_are_unique_and_sensible() {
        let passes = default_passes();
        let mut ids: Vec<_> = passes.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), passes.len());
        assert!(passes.iter().all(|p| !p.id.is_empty()));
        assert!(passes.iter().all(|p| p.price_minor > 0));
        assert!(passes.iter().any(|p| p.is_until_midnight()));
    }

    #[test]
    fn missing_duration_means_until_midnight() {
        let p: PassDef =
            serde_json::from_str(r#"{"id":"x","name":"X","price_minor":100}"#).unwrap();
        assert!(p.is_until_midnight());
    }
}
