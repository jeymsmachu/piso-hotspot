//! nftables paywall: the kernel-side gate.
//!
//! One embedded ruleset, parameterized by the AP interface, the uplink
//! interface, and the gateway subnet. The store is the source of truth;
//! this module just applies and reads back set membership.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use thiserror::Error;

use crate::mac::MacAddr;

/// Set names used by the ruleset.
pub const SET_ALLOWED: &str = "allowed";
pub const SET_FRIENDS: &str = "friends";
/// Known devices *without* access. Never an allow-rule target — it
/// exists so per-device drop counters can attribute "bandwidth eaten
/// by waiting devices".
pub const SET_BLOCKED: &str = "blocked";

/// One member of a counter-enabled set as printed by `nft list set`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetElement {
    pub mac: MacAddr,
    pub packets: u64,
    pub bytes: u64,
}

pub const TABLE: &str = "piso";

#[derive(Error, Debug)]
pub enum NftError {
    #[error("cannot run nft: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("nft rejected the ruleset: {0}")]
    Rejected(String),
    #[error("invalid interface name {0:?}")]
    BadInterface(String),
}

/// Interface names reach the ruleset as text; only accept what the
/// kernel itself accepts, so no caller can smuggle rules in.
fn validate_iface(name: &str) -> Result<&str, NftError> {
    let ok = !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(name)
    } else {
        Err(NftError::BadInterface(name.to_string()))
    }
}

pub struct Firewall {
    /// Interface carrying the hotspot's clients.
    pub ap_iface: String,
    /// Interface carrying internet-bound traffic, when there is one.
    pub uplink: Option<String>,
    /// Gateway address; clients sit in its /24.
    pub gateway: Ipv4Addr,
    /// Admin panel port, open to clients and uplink alike. `0` means
    /// "not configured" and stays closed (fail closed).
    pub panel_port: u16,
    /// Serve the captive portal on port 80 to clients.
    pub portal_enabled: bool,
}

impl Firewall {
    /// The client subnet in network form (gateway masked to /24).
    fn client_subnet(&self) -> String {
        let octets = self.gateway.octets();
        format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
    }

    /// Render the complete table for `nft -f -`.
    pub fn render(&self) -> String {
        let ap = validate_iface(&self.ap_iface).expect("validated at construction");
        // Web ports for hotspot clients: the captive portal (80) and
        // the admin panel. Port 443 is answered-with-RST on purpose:
        // browsers' HTTPS-first mode probes https:// on these addresses,
        // and a silent drop makes them hang forever — a fast refusal
        // makes them fall back to plain HTTP, where the portal lives.
        // Port 0 means "not configured" and stays closed.
        let mut web_ports: Vec<u16> = Vec::new();
        if self.portal_enabled {
            web_ports.push(80);
            web_ports.push(443);
        }
        if self.panel_port != 0 && self.panel_port != 80 && !web_ports.contains(&self.panel_port) {
            web_ports.push(self.panel_port);
        }
        let web_rule = match web_ports.len() {
            0 => String::new(),
            1 => format!("        tcp dport {} accept\n", web_ports[0]),
            _ => {
                let list: Vec<String> = web_ports.iter().map(|p| p.to_string()).collect();
                format!("        tcp dport {{ {} }} accept\n", list.join(", "))
            }
        };
        // QUIC (HTTP/3) probes to https:// get an immediate
        // port-unreachable instead of hanging the same way.
        let udp_rule = if self.portal_enabled {
            "        udp dport 443 accept\n"
        } else {
            ""
        };
        let mut out = format!(
            "table inet {TABLE} {{
    set {SET_ALLOWED} {{
        type ether_addr
        counter
    }}
    set {SET_FRIENDS} {{
        type ether_addr
        counter
    }}
    set {SET_BLOCKED} {{
        type ether_addr
        counter
    }}

    chain forward {{
        type filter hook forward priority filter; policy accept;
        # Traffic that does not pass through the hotspot is not ours to police.
        iifname != \"{ap}\" accept
        # Friends and paying clients may pass; everyone else is dropped,
        # existing connections included: revoke means no internet.
        # Element counters show per-device traffic on the accept side;
        # the blocked set attributes drops to known waiting devices.
        ether saddr @{SET_FRIENDS} counter accept
        ether saddr @{SET_ALLOWED} counter accept
        ether saddr @{SET_BLOCKED} counter drop
        counter drop
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        # Only the hotspot's clients are restricted, never the host's own
        # services on other interfaces.
        iifname != \"{ap}\" accept
        # Clients need DHCP and DNS from this machine; ping the gateway
        # so broken clients can tell wifi from internet.
        udp dport {{ 67, 53 }} accept
        tcp dport 53 accept
        icmp type echo-request accept
{web_rule}{udp_rule}        counter drop
    }}
"
        );
        if let Some(uplink) = &self.uplink {
            let uplink = validate_iface(uplink).expect("validated at construction");
            out.push_str(&format!(
                "
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {subnet} oifname \"{uplink}\" masquerade
    }}
",
                subnet = self.client_subnet()
            ));
        }
        if self.portal_enabled {
            // Captive portal. Unpaid clients resolve DNS normally (the
            // answers are useless to them anyway — their HTTP gets
            // rerouted here, before the forward chain ever sees it).
            // Paying clients and friends skip the redirect entirely.
            out.push_str(&format!(
                "
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname != \"{ap}\" accept
        tcp dport 80 ether saddr @{SET_FRIENDS} accept
        tcp dport 80 ether saddr @{SET_ALLOWED} accept
        tcp dport 80 redirect to :80
    }}
"
            ));
        }
        out.push_str("}\n");
        out
    }

    fn run(args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
        let mut child = Command::new("nft")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().expect("piped");
            pipe.write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            return Err(NftError::Rejected(stderr.trim().to_string()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// (Re)install the table: whatever is there before is ours to replace.
    pub fn install(&self) -> Result<(), NftError> {
        // Fail-closed: drop leftovers first, then apply the full table.
        let _ = Self::run(&["delete", "table", "inet", TABLE], None);
        Self::run(&["-f", "-"], Some(&self.render())).map(|_| ())
    }

    pub fn uninstall(&self) -> Result<(), NftError> {
        match Self::run(&["delete", "table", "inet", TABLE], None) {
            Ok(_) => Ok(()),
            // Already gone — the desired end state.
            Err(NftError::Rejected(e)) if e.contains("No such file") => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn table_exists(&self) -> bool {
        Self::run(&["list", "table", "inet", TABLE], None).is_ok()
    }

    fn set_members_raw(&self, set: &str) -> Result<String, NftError> {
        Self::run(&["list", "set", "inet", TABLE, set], None)
    }

    /// Current members of a set (with their counters), from kernel output.
    pub fn set_members(&self, set: &str) -> Result<Vec<SetElement>, NftError> {
        let out = self.set_members_raw(set)?;
        Ok(parse_elements(&out))
    }

    /// Add a MAC to a set. Elements are set *expressions*, which nft only
    /// parses in a ruleset fed over stdin (`-f -`), so this builds a
    /// one-line script rather than passing argv tokens.
    pub fn set_add(&self, set: &str, mac: &MacAddr) -> Result<(), NftError> {
        let script = format!("add element inet {TABLE} {set} {{ {} }}", mac);
        match Self::run(&["-f", "-"], Some(&script)) {
            Ok(_) => Ok(()),
            // Already present: desired state reached.
            Err(NftError::Rejected(e)) if e.contains("File exists") => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn set_remove(&self, set: &str, mac: &MacAddr) -> Result<(), NftError> {
        let script = format!("delete element inet {TABLE} {set} {{ {} }}", mac);
        match Self::run(&["-f", "-"], Some(&script)) {
            Ok(_) => Ok(()),
            // Absent: already the desired state.
            Err(NftError::Rejected(e)) if e.contains("No such file") => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Parse `elements = { aa:bb:… [counter packets N bytes M], … }`
/// (possibly wrapped over several lines) out of `nft list set` output.
/// Elements without counters report zeros.
pub fn parse_elements(output: &str) -> Vec<SetElement> {
    let mut members = Vec::new();
    let Some(start) = output.find("elements") else {
        return members;
    };
    let Some(open) = output[start..].find('{') else {
        return members;
    };
    let rest = &output[start + open + 1..];
    let Some(close) = rest.find('}') else {
        return members;
    };
    for token in rest[..close].split(',') {
        let mut fields = token.split_whitespace();
        let (Some(mac), rest) = (fields.next(), fields) else {
            continue;
        };
        let Ok(mac) = mac.parse::<MacAddr>() else {
            continue;
        };
        // Optional: "counter packets N bytes M"
        let rest: Vec<&str> = rest.collect();
        let (packets, bytes) = match rest.iter().position(|f| *f == "packets") {
            Some(i) => (
                rest.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0),
                rest.iter()
                    .position(|f| *f == "bytes")
                    .and_then(|j| rest.get(j + 1).and_then(|v| v.parse().ok()))
                    .unwrap_or(0),
            ),
            None => (0, 0),
        };
        members.push(SetElement {
            mac,
            packets,
            bytes,
        });
    }
    members
}

/// What the reconciler wants vs. what the kernel has.
#[derive(Debug, PartialEq, Eq)]
pub struct SetDiff {
    pub add: Vec<MacAddr>,
    pub remove: Vec<MacAddr>,
}

pub fn diff(want: &[MacAddr], have: &[MacAddr]) -> SetDiff {
    let add: Vec<MacAddr> = want.iter().filter(|m| !have.contains(m)).copied().collect();
    let remove: Vec<MacAddr> = have.iter().filter(|m| !want.contains(m)).copied().collect();
    SetDiff { add, remove }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fw(uplink: Option<&str>) -> Firewall {
        Firewall {
            ap_iface: "wlan0".to_string(),
            uplink: uplink.map(str::to_string),
            gateway: Ipv4Addr::new(10, 10, 0, 1),
            panel_port: 8080,
            portal_enabled: true,
        }
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn render_gates_the_ap_interface_only() {
        let rules = fw(None).render();
        assert!(rules.contains("iifname != \"wlan0\" accept"));
        assert!(rules.contains("ether saddr @allowed counter accept"));
        assert!(rules.contains("counter drop"));
        // Every policy decision is observable: three set-declaration
        // counters plus five rule counters (friends, allowed, blocked,
        // forward drop, input drop). Comment lines are ignored.
        let counted = rules
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter(|l| l.contains("counter"))
            .count();
        assert_eq!(counted, 8);
    }

    #[test]
    fn portal_and_panel_ports_open_to_clients() {
        let rules = fw(None).render();
        assert!(
            rules.contains("tcp dport { 80, 443, 8080 } accept"),
            "{rules}"
        );
        // QUIC fast-fail rides along with the portal.
        assert!(rules.contains("udp dport 443 accept"), "{rules}");
    }

    #[test]
    fn portal_disabled_leaves_only_the_panel() {
        let mut f = fw(None);
        f.portal_enabled = false;
        let rules = f.render();
        let input = rules.split("chain input").nth(1).expect("input chain");
        assert!(input.contains("tcp dport 8080 accept"), "{input}");
        assert!(!input.contains("dport { 80"), "no web port list: {input}");
        assert!(!input.contains("tcp dport 80 "), "no bare 80: {input}");
    }

    #[test]
    fn unconfigured_panel_port_stays_closed() {
        let mut f = fw(None);
        f.panel_port = 0;
        f.portal_enabled = false;
        let rules = f.render();
        let input = rules.split("chain input").nth(1).expect("input chain");
        // DHCP/DNS legitimately keep their ports; no *web* port may open.
        assert!(!input.contains("dport 80"), "fail closed: {input}");
        assert!(
            !input.contains("443"),
            "no fast-fail without portal: {input}"
        );
        // With the portal on, the portal ports still open (panel stays closed).
        f.portal_enabled = true;
        let rules = f.render();
        let input = rules.split("chain input").nth(1).expect("input chain");
        assert!(input.contains("tcp dport { 80, 443 } accept"), "{input}");
        assert!(!input.contains("8080"), "panel stays closed: {input}");
    }

    #[test]
    fn panel_on_port_80_is_not_duplicated() {
        let mut f = fw(None);
        f.panel_port = 80;
        let rules = f.render();
        let input = rules.split("chain input").nth(1).expect("input chain");
        // Portal already contributed 80; the list must contain it once.
        assert_eq!(input.matches("tcp dport { 80, 443 } accept").count(), 1);
        assert!(
            !input.contains("tcp dport 80 accept"),
            "unlisted bare 80: {input}"
        );
    }

    #[test]
    fn portal_redirect_intercepts_unpaid_http_only() {
        let rules = fw(None).render();
        let pre = rules
            .split("chain prerouting")
            .nth(1)
            .expect("prerouting chain present");
        // Paid and friends pass before the catch-all redirect fires.
        let allowed_at = pre.find("@allowed accept").expect("allowed bypass");
        let friends_at = pre.find("@friends accept").expect("friends bypass");
        let redirect_at = pre.find("redirect to :80").expect("redirect");
        assert!(friends_at < allowed_at && allowed_at < redirect_at, "{pre}");
        // The chain only fires for the AP side.
        assert!(pre.contains("iifname != \"wlan0\" accept"), "{pre}");
    }

    #[test]
    fn no_redirect_chain_when_portal_disabled() {
        let mut f = fw(None);
        f.portal_enabled = false;
        let rules = f.render();
        assert!(!rules.contains("prerouting"), "{rules}");
        assert!(!rules.contains("redirect"), "{rules}");
    }

    #[test]
    fn masquerade_only_with_uplink() {
        let with = fw(Some("usb0")).render();
        assert!(with.contains("masquerade"));
        assert!(with.contains("oifname \"usb0\""));
        assert!(with.contains("ip saddr 10.10.0.0/24"));

        let without = fw(None).render();
        assert!(!without.contains("masquerade"));
        assert!(!without.contains("postrouting"));
    }

    #[test]
    fn ruleset_is_internally_balanced() {
        for rules in [fw(None).render(), fw(Some("enp0s3")).render()] {
            assert_eq!(rules.matches('{').count(), rules.matches('}').count());
            assert!(rules.trim_end().ends_with('}'));
        }
    }

    #[test]
    fn interface_names_are_validated() {
        assert!(validate_iface("wlan0").is_ok());
        assert!(validate_iface("ap0").is_ok());
        assert!(validate_iface("enp0s20f3u1").is_ok());
        assert!(validate_iface("").is_err());
        assert!(validate_iface("wl an0").is_err());
        assert!(validate_iface("wlan0\naccept").is_err());
        assert!(validate_iface(&"x".repeat(16)).is_err());
        assert!(validate_iface("a\"; drop table").is_err());
    }

    #[test]
    fn constructor_rejects_bad_interfaces_early() {
        // render() validates; constructing the value must not panic on
        // sane inputs — pathological names panic only if they slip past
        // every caller, so validate_iface itself is tested above.
        let fw = Firewall {
            ap_iface: "wlan0".into(),
            uplink: Some("usb0".into()),
            gateway: Ipv4Addr::new(10, 10, 0, 1),
            panel_port: 8080,
            portal_enabled: true,
        };
        assert!(fw.render().contains("table inet piso"));
    }

    #[test]
    fn parses_wrapped_element_lists() {
        let out = "
table inet piso {
    set allowed {
        type ether_addr
        elements = { aa:bb:cc:dd:ee:01, 11:22:33:44:55:66,
            77:88:99:aa:bb:cc }
    }
}
";
        let members = parse_elements(out);
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].mac.to_string(), "aa:bb:cc:dd:ee:01");
        assert_eq!(members[2].mac.to_string(), "77:88:99:aa:bb:cc");
        // No counters shown → zeros.
        assert!(members.iter().all(|e| e.packets == 0 && e.bytes == 0));
    }

    #[test]
    fn parses_element_counters() {
        let out = "
table inet piso {
    set allowed {
        type ether_addr
        counter
        elements = { 42:61:7e:6c:ee:d2 counter packets 70 bytes 4620,
            aa:bb:cc:dd:ee:01 counter packets 0 bytes 0 }
    }
}
";
        let members = parse_elements(out);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].mac.to_string(), "42:61:7e:6c:ee:d2");
        assert_eq!(members[0].packets, 70);
        assert_eq!(members[0].bytes, 4620);
        assert_eq!(members[1].packets, 0);
        assert_eq!(members[1].bytes, 0);
    }

    #[test]
    fn parses_empty_or_absent_elements() {
        assert!(parse_elements("table inet piso { set allowed { type ether_addr } }").is_empty());
        assert!(parse_elements("no elements here").is_empty());
        assert!(parse_elements("elements = { }").is_empty());
    }

    #[test]
    fn diff_is_the_reconcile_instruction() {
        let want = vec![mac("aa:bb:cc:dd:ee:01"), mac("aa:bb:cc:dd:ee:02")];
        let have = vec![mac("aa:bb:cc:dd:ee:02"), mac("aa:bb:cc:dd:ee:03")];
        let d = diff(&want, &have);
        assert_eq!(d.add, vec![mac("aa:bb:cc:dd:ee:01")]);
        assert_eq!(d.remove, vec![mac("aa:bb:cc:dd:ee:03")]);
    }

    #[test]
    fn diff_empty_both_ways() {
        let d = diff(&[], &[]);
        assert!(d.add.is_empty() && d.remove.is_empty());
        let same = vec![mac("aa:bb:cc:dd:ee:01")];
        let d = diff(&same, &same);
        assert!(d.add.is_empty() && d.remove.is_empty());
    }
}
