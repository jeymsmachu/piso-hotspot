//! Parser for `iw list` (aka `iw phy`) output.
//!
//! Extracts, per phy: supported interface modes, interface combinations
//! (the kernel's answer to "can this radio be an AP and a station at
//! once?"), operating bands, and current interfaces. Pure string parsing,
//! fixture-tested — no root, no hardware.

use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Combination {
    /// Per-mode limits, e.g. `[("managed", 1), ("ap", 1)]`.
    pub limits: Vec<(String, u32)>,
    /// Maximum number of interfaces across all listed modes.
    pub total_max: u32,
    /// Maximum number of distinct channels the combination may span.
    /// `1` means every interface shares one channel.
    pub max_channels: Option<u32>,
}

impl Combination {
    pub fn limit_for(&self, mode: &str) -> u32 {
        self.limits
            .iter()
            .find(|(m, _)| m.eq_ignore_ascii_case(mode))
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }

    /// True when the combination permits one station + one AP.
    pub fn allows_station_and_ap(&self) -> bool {
        self.total_max >= 2 && self.limit_for("managed") >= 1 && self.limit_for("ap") >= 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhyInterface {
    pub name: String,
    /// Current operating mode reported by `iw list` (e.g. `managed`, `ap`).
    pub iface_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phy {
    /// e.g. `phy0`.
    pub name: String,
    /// Normalized interface modes, lowercase (e.g. `managed`, `ap`).
    pub supported_modes: Vec<String>,
    pub combinations: Vec<Combination>,
    /// Distinct frequency bands in GHz: `"2.4"`, `"5"`, `"6"`.
    pub bands: BTreeSet<String>,
    pub interfaces: Vec<PhyInterface>,
}

impl Phy {
    pub fn supports_mode(&self, mode: &str) -> bool {
        self.supported_modes
            .iter()
            .any(|m| m == &mode.to_ascii_lowercase())
    }

    /// The radio can beacon an AP at all.
    pub fn supports_ap(&self) -> bool {
        self.supports_mode("ap")
    }

    /// The radio can be a station and an AP concurrently (single-radio
    /// uplink). Requires an interface combination, not just both modes.
    pub fn supports_concurrent_station_and_ap(&self) -> bool {
        self.combinations
            .iter()
            .any(Combination::allows_station_and_ap)
    }

    /// True when every concurrent station+AP combination shares one channel.
    pub fn concurrent_combos_share_channel(&self) -> bool {
        let concurrent: Vec<&Combination> = self
            .combinations
            .iter()
            .filter(|c| c.allows_station_and_ap())
            .collect();
        !concurrent.is_empty() && concurrent.iter().all(|c| c.max_channels == Some(1))
    }
}

/// Parse the full `iw list` output into one [`Phy`] per `Wiphy` section.
pub fn parse(output: &str) -> Vec<Phy> {
    let mut phys: Vec<Phy> = Vec::new();
    let mut section = Section::None;
    let mut current_iface: Option<PhyInterface> = None;
    // Combination lines may wrap; the parsed combination is completed
    // when the section closes.
    let mut pending_combination: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        // A new phy closes everything before it.
        if let Some(rest) = trimmed.strip_prefix("Wiphy ") {
            close_pending(&mut phys, &mut pending_combination);
            finish(&mut phys, &mut current_iface);
            phys.push(Phy {
                name: rest.trim().to_string(),
                supported_modes: Vec::new(),
                combinations: Vec::new(),
                bands: BTreeSet::new(),
                interfaces: Vec::new(),
            });
            section = Section::None;
            continue;
        }
        if phys.is_empty() {
            continue;
        }

        // Some iw versions capitalize these headers.
        let explicit_section = if trimmed.eq_ignore_ascii_case("supported interface modes:") {
            Some(Section::SupportedModes)
        } else if trimmed.eq_ignore_ascii_case("valid interface combinations:") {
            Some(Section::Combinations)
        } else {
            None
        };
        let band_section = trimmed
            .strip_prefix("Band ")
            .filter(|rest| rest.trim_end().ends_with(':'))
            .map(|_| Section::Band);
        let iface_header = trimmed
            .strip_prefix("Interface ")
            .map(|rest| rest.trim().to_string());

        // These lines close the blocks currently being read.
        if indent == 0
            || explicit_section.is_some()
            || band_section.is_some()
            || iface_header.is_some()
        {
            close_pending(&mut phys, &mut pending_combination);
            finish(&mut phys, &mut current_iface);
        }
        if indent == 0 {
            section = Section::None;
            continue;
        }
        if let Some(s) = explicit_section.or(band_section) {
            section = s;
            continue;
        }
        if let Some(name) = iface_header {
            current_iface = Some(PhyInterface {
                name,
                iface_type: String::new(),
            });
            section = Section::Iface;
            continue;
        }

        let phy = phys.last_mut().expect("phys is non-empty");
        match section {
            Section::None => {}
            Section::SupportedModes => {
                if let Some(mode) = trimmed.strip_prefix("* ") {
                    phy.supported_modes.push(mode.trim().to_ascii_lowercase());
                } else if !trimmed.is_empty() {
                    section = Section::None;
                }
            }
            Section::Combinations => {
                if trimmed.starts_with('*') && trimmed.contains("#{") {
                    // A new combination line; flush the previous one.
                    if let Some(text) = pending_combination.take()
                        && let Some(comb) = parse_combination(&text)
                    {
                        phy.combinations.push(comb);
                    }
                    pending_combination = Some(trimmed.to_string());
                } else if trimmed.contains("<=") {
                    // Continuation of a wrapped combination line, e.g.
                    // "total <= 2, #channels <= 1".
                    if let Some(pending) = pending_combination.as_mut() {
                        pending.push(' ');
                        pending.push_str(trimmed);
                    }
                } else if !trimmed.is_empty() {
                    if let Some(text) = pending_combination.take()
                        && let Some(comb) = parse_combination(&text)
                    {
                        phy.combinations.push(comb);
                    }
                    section = Section::None;
                }
            }
            Section::Iface => {
                if let Some(rest) = trimmed.strip_prefix("type: ")
                    && let Some(iface) = current_iface.as_mut()
                {
                    iface.iface_type = rest.trim().to_ascii_lowercase();
                }
            }
            Section::Band => {
                if let Some(freq) = parse_band_frequency(trimmed) {
                    phy.bands.insert(classify_frequency(freq));
                }
            }
        }
    }
    close_pending(&mut phys, &mut pending_combination);
    finish(&mut phys, &mut current_iface);
    phys
}

enum Section {
    None,
    SupportedModes,
    Combinations,
    Iface,
    Band,
}

/// Close the interface block currently being read, attaching it to the
/// most recent phy.
fn finish(phys: &mut [Phy], current_iface: &mut Option<PhyInterface>) {
    if let Some(iface) = current_iface.take()
        && let Some(phy) = phys.last_mut()
    {
        phy.interfaces.push(iface);
    }
}

/// Complete and attach a pending combination line, if any.
fn close_pending(phys: &mut [Phy], pending: &mut Option<String>) {
    if let Some(text) = pending.take()
        && let Some(comb) = parse_combination(&text)
        && let Some(phy) = phys.last_mut()
    {
        phy.combinations.push(comb);
    }
}

/// Parse one combination line, e.g.:
/// `* #{ managed } <= 1, #{ AP } <= 1, total <= 2, #channels <= 1`
fn parse_combination(line: &str) -> Option<Combination> {
    let mut limits = Vec::new();
    let mut total_max = 0u32;
    let mut max_channels = None;

    for token in split_top_level(line.trim_start_matches('*').trim()) {
        let token = token.trim();
        if let Some(inner) = token.strip_prefix("#{") {
            let modes_end = inner.find('}')?;
            let modes = &inner[..modes_end];
            let value = inner[modes_end + 1..]
                .split("<=")
                .nth(1)?
                .trim()
                .parse::<u32>()
                .ok()?;
            // Braces may hold several modes: `#{ AP, P2P-client, P2P-GO } <= 1`
            for mode in modes.split([',', '/']) {
                let mode = mode.trim();
                if !mode.is_empty() {
                    limits.push((mode.to_ascii_lowercase(), value));
                }
            }
        } else if let Some(rest) = token.strip_prefix("total") {
            total_max = rest.split("<=").nth(1)?.trim().parse().ok()?;
        } else if let Some(rest) = token.strip_prefix("#channels") {
            max_channels = Some(rest.split("<=").nth(1)?.trim().parse().ok()?);
        }
    }

    if limits.is_empty() {
        None
    } else {
        Some(Combination {
            limits,
            total_max,
            max_channels,
        })
    }
}

/// Split on commas that are outside `{}` braces, so that
/// `#{ P2P-client, P2P-GO }` stays one token.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// `* 5180 MHz [36] (20.0 dBm)` → `5180`
fn parse_band_frequency(line: &str) -> Option<u32> {
    let rest = line.strip_prefix('*')?.trim();
    let mhz = rest.find(" MHz")?;
    rest[..mhz].trim().parse().ok()
}

fn classify_frequency(mhz: u32) -> String {
    match mhz {
        0..=3000 => "2.4".to_string(),
        3001..=5925 => "5".to_string(),
        _ => "6".to_string(),
    }
}

/// IEEE channel number for a frequency in MHz, `None` when the
/// frequency is not a standard wifi channel.
pub fn channel_for_frequency(mhz: u32) -> Option<u8> {
    match mhz {
        2412..=2472 => Some(((mhz - 2407) / 5) as u8),
        2484 => Some(14),
        5000..=5895 => Some(((mhz - 5000) / 5) as u8),
        5955..=7115 => Some(((mhz - 5950) / 5) as u8),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed but structurally faithful `iw list` output for two phys:
    // phy0: a common wifi card with no interface combinations block,
    // phy1: a card advertising STA+AP on one channel.
    const FIXTURE: &str = "\
Wiphy phy0
        max # scan requests: 100
        software interface modes (netdev+mac80211 support AP):
                 * AP
                 * AP/VLAN
        supported interface modes:
                 * IBSS
                 * managed
                 * AP
                 * monitor
                 * mesh point
        Band 1:
                Frequencies:
                        * 2412 MHz [1] (20.0 dBm)
                        * 2437 MHz [6] (20.0 dBm)
                        * 2462 MHz [11] (20.0 dBm)
        Band 2:
                Frequencies:
                        * 5180 MHz [36] (20.0 dBm)
                        * 5745 MHz [149] (20.0 dBm)
        Interface wlan0
                ifindex: 3
                wdev: 0x1
                addr: 1c:ce:51:a2:ff:9f
                type: managed
                channel 1 (2412 MHz), width: 20 MHz, center1: 2412 MHz
Wiphy phy1
        supported interface modes:
                 * IBSS
                 * managed
                 * AP
                 * P2P-client
                 * P2P-GO
        valid interface combinations:
                 * #{ managed } <= 1, #{ AP } <= 1, total <= 2, #channels <= 1
        Band 1:
                Frequencies:
                        * 2412 MHz [1] (30.0 dBm)
                        * 2437 MHz [6] (30.0 dBm)
        Band 2:
                Frequencies:
                        * 5180 MHz [36] (23.0 dBm)
        Interface wlan1
                ifindex: 4
                type: managed
        Interface ap0
                ifindex: 5
                type: AP
";

    // A card that can be AP and station at once, but across two channels,
    // plus a P2P mix that exercises the brace-comma split.
    const TWO_CHANNEL_FIXTURE: &str = "\
Wiphy phy0
        supported interface modes:
                 * managed
                 * AP
                 * P2P-client
                 * P2P-GO
        valid interface combinations:
                 * #{ managed } <= 2, #{ AP, P2P-client, P2P-GO } <= 2, total <= 4, #channels <= 2
                 * #{ AP } <= 1, #{ P2P-client, P2P-GO } <= 2, total <= 3, #channels <= 2
        Band 1:
                Frequencies:
                        * 2412 MHz [1] (20.0 dBm)
";

    #[test]
    fn parses_phys_by_name() {
        let phys = parse(FIXTURE);
        let names: Vec<_> = phys.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["phy0", "phy1"]);
    }

    #[test]
    fn supported_modes_are_lowercased() {
        let phys = parse(FIXTURE);
        assert!(phys[0].supports_mode("ap"));
        assert!(phys[0].supports_mode("managed"));
        assert!(phys[0].supports_mode("monitor"));
        assert!(!phys[0].supports_mode("p2p-go"));
    }

    #[test]
    fn no_combination_block_means_no_concurrent_ap_sta() {
        let phys = parse(FIXTURE);
        assert!(phys[0].supports_ap());
        assert!(!phys[0].supports_concurrent_station_and_ap());
    }

    #[test]
    fn single_channel_combo_detected() {
        let phys = parse(FIXTURE);
        assert!(phys[1].supports_concurrent_station_and_ap());
        assert!(phys[1].concurrent_combos_share_channel());
    }

    #[test]
    fn multi_channel_combo_is_not_single_channel() {
        let phys = parse(TWO_CHANNEL_FIXTURE);
        assert!(phys[0].supports_concurrent_station_and_ap());
        assert!(!phys[0].concurrent_combos_share_channel());
    }

    #[test]
    fn brace_commas_do_not_break_parsing() {
        let phys = parse(TWO_CHANNEL_FIXTURE);
        let comb = &phys[0].combinations[0];
        assert_eq!(comb.limit_for("p2p-client"), 2);
        assert_eq!(comb.limit_for("p2p-go"), 2);
        assert_eq!(comb.limit_for("ap"), 2);
        assert_eq!(comb.total_max, 4);
        assert_eq!(comb.max_channels, Some(2));
        // The second combination has AP but no managed: not STA+AP.
        assert!(!phys[0].combinations[1].allows_station_and_ap());
    }

    #[test]
    fn bands_are_classified() {
        let phys = parse(FIXTURE);
        let bands: Vec<_> = phys[0].bands.iter().map(String::as_str).collect();
        assert_eq!(bands, ["2.4", "5"]);
    }

    #[test]
    fn interfaces_are_attached_to_their_phy() {
        let phys = parse(FIXTURE);
        let ifaces: Vec<_> = phys[0]
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i.iface_type.as_str()))
            .collect();
        assert_eq!(ifaces, [("wlan0", "managed")]);
        let ifaces: Vec<_> = phys[1]
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i.iface_type.as_str()))
            .collect();
        assert_eq!(ifaces, [("wlan1", "managed"), ("ap0", "ap")]);
    }

    #[test]
    fn empty_input_yields_no_phys() {
        assert!(parse("").is_empty());
        assert!(parse("garbage\nnot iw output\n").is_empty());
    }

    #[test]
    fn combination_line_parsing_direct() {
        let c = parse_combination(
            "* #{ managed } <= 1, #{ AP, mesh point } <= 1, total <= 3, #channels <= 1",
        )
        .unwrap();
        assert_eq!(c.limit_for("managed"), 1);
        assert_eq!(c.limit_for("ap"), 1);
        assert_eq!(c.limit_for("mesh point"), 1);
        assert_eq!(c.total_max, 3);
        assert_eq!(c.max_channels, Some(1));
    }

    #[test]
    fn channel_numbering() {
        assert_eq!(channel_for_frequency(2412), Some(1));
        assert_eq!(channel_for_frequency(2437), Some(6));
        assert_eq!(channel_for_frequency(2484), Some(14));
        assert_eq!(channel_for_frequency(5180), Some(36));
        assert_eq!(channel_for_frequency(5745), Some(149));
        assert_eq!(channel_for_frequency(5955), Some(1));
        assert_eq!(channel_for_frequency(1234), None);
    }

    // Captured from a real iw (1.9) on an RTL8821CE with the multivif
    // patch: capitalized header, combination wrapped over two lines.
    const WRAPPED_FIXTURE: &str = "\
Wiphy phy0
	wiphy index: 0
	max # scan SSIDs: 4
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * AP/VLAN
		 * monitor
	Band 1:
		Capabilities: 0x196e
			HT20/HT40
		* 2412 MHz [1] (20.0 dBm)
		* 2437 MHz [6] (20.0 dBm)
	valid interface combinations:
		 * #{ managed } <= 1, #{ AP } <= 1,
		   total <= 2, #channels <= 1
	HT Capability overrides:
		 * MCS: ff ff ff ff ff ff ff ff ff ff
";

    #[test]
    fn capitalized_header_is_recognized() {
        let phys = parse(WRAPPED_FIXTURE);
        assert!(phys[0].supports_mode("ap"));
        assert!(phys[0].supports_mode("managed"));
    }

    #[test]
    fn wrapped_combination_line_is_joined() {
        let phys = parse(WRAPPED_FIXTURE);
        assert_eq!(phys[0].combinations.len(), 1);
        let comb = &phys[0].combinations[0];
        assert_eq!(comb.limit_for("managed"), 1);
        assert_eq!(comb.limit_for("ap"), 1);
        assert_eq!(comb.total_max, 2);
        assert_eq!(comb.max_channels, Some(1));
        assert!(phys[0].supports_concurrent_station_and_ap());
        assert!(phys[0].concurrent_combos_share_channel());
        // "HT Capability overrides:" closes the section without parsing junk.
        assert_eq!(phys[0].combinations.len(), 1);
    }

    #[test]
    fn bands_parse_below_ht_capabilities() {
        let phys = parse(WRAPPED_FIXTURE);
        let bands: Vec<_> = phys[0].bands.iter().map(String::as_str).collect();
        assert_eq!(bands, ["2.4"]);
    }
}
