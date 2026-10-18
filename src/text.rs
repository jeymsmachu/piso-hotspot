//! Text hygiene for values that come from one human and are read by
//! another: device labels, friend labels, printed config.
//!
//! Two rules, applied at two different times on purpose:
//!
//! - **Stored values** are validated ([`clean_label`]): labels are
//!   trimmed, capped, and refused if they contain control characters.
//!   The database holds what the operator typed, nothing else.
//! - **Printed values** are escaped ([`sanitize`]): whatever is in the
//!   database — including rows written by an older version, or by hand
//!   with the sqlite3 CLI — must not be able to emit escape sequences
//!   into somebody else's terminal.
//!
//! The panel and the portal build their DOM/text with escaping APIs, so
//! this module is about the CLI and the log.

/// Longest accepted label, in characters. Long enough for
/// "Juan dela Cruz's laptop (2024)", short enough that a label can never
/// be a meaningful amount of data.
pub const MAX_LABEL_CHARS: usize = 50;

/// Validate an operator-supplied label.
///
/// `None` and blank strings mean "no label" (the panel uses that to
/// clear one), leading/trailing whitespace is dropped, and anything
/// longer than [`MAX_LABEL_CHARS`] or carrying control characters is
/// refused rather than silently stored.
pub fn clean_label(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(text) = raw else { return Ok(None) };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(bad) = trimmed.chars().find(|c| c.is_control()) {
        return Err(format!(
            "label must not contain control characters (found {})",
            bad.escape_debug()
        ));
    }
    let len = trimmed.chars().count();
    if len > MAX_LABEL_CHARS {
        return Err(format!(
            "label must be at most {MAX_LABEL_CHARS} characters, got {len}"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// Escape control characters for terminal output, leaving everything
/// else exactly as stored.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_labels_mean_no_label() {
        assert_eq!(clean_label(None).unwrap(), None);
        assert_eq!(clean_label(Some("")).unwrap(), None);
        assert_eq!(clean_label(Some("   \t ")).unwrap(), None);
    }

    #[test]
    fn labels_are_trimmed_not_mangled() {
        assert_eq!(
            clean_label(Some("  Juan's laptop ")).unwrap().as_deref(),
            Some("Juan's laptop")
        );
        // Unicode is fine: characters, not bytes.
        assert_eq!(
            clean_label(Some("Kainan ni Aling Nena 🍜"))
                .unwrap()
                .as_deref(),
            Some("Kainan ni Aling Nena 🍜")
        );
    }

    #[test]
    fn labels_are_capped_at_fifty_characters() {
        let ok = "a".repeat(MAX_LABEL_CHARS);
        assert!(clean_label(Some(&ok)).is_ok());
        let too_long = "a".repeat(MAX_LABEL_CHARS + 1);
        let err = clean_label(Some(&too_long)).unwrap_err();
        assert!(err.contains("at most 50 characters"), "{err}");
        // Multi-byte characters count as one each, not as bytes.
        assert!(clean_label(Some(&"é".repeat(MAX_LABEL_CHARS))).is_ok());
    }

    #[test]
    fn control_characters_are_refused() {
        for bad in ["evil\nlabel", "esc\u{1b}[2J", "bell\u{7}", "tab\there"] {
            assert!(clean_label(Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn printing_escapes_control_characters_only() {
        assert_eq!(sanitize("plain label"), "plain label");
        assert_eq!(sanitize("Juan's laptop"), "Juan's laptop");
        assert_eq!(sanitize("evil\nlabel"), "evil\\nlabel");
        assert_eq!(sanitize("\u{1b}[2J"), "\\u{1b}[2J");
        assert_eq!(sanitize("bell\u{7}"), "bell\\u{7}");
    }
}
