//! nftables paywall: the kernel-side gate.
//!
//! One embedded ruleset, parameterized by the AP interface, the uplink
//! interface, and the gateway subnet. The store is the source of truth;
//! this module just applies and reads back set membership.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::Arc;

use thiserror::Error;

use crate::log_warn;
use crate::mac::MacAddr;

/// Set names used by the ruleset.
pub const SET_ALLOWED: &str = "allowed";
pub const SET_FRIENDS: &str = "friends";
/// Known devices *without* access. Never an allow-rule target — it
/// exists so per-device drop counters can attribute "bandwidth eaten
/// by waiting devices".
pub const SET_BLOCKED: &str = "blocked";
/// The same idea for the download direction, keyed by the address a
/// client currently holds: by the time a packet is being forwarded *to*
/// a client, its destination MAC is this machine's, so MAC matching
/// cannot see it. These sets are accounting and attribution — they
/// never *grant* anything.
pub const SET_ALLOWED_V4: &str = "allowed_v4";
pub const SET_BLOCKED_V4: &str = "blocked_v4";

/// One member of a counter-enabled set as printed by `nft list set`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetElement {
    pub mac: MacAddr,
    pub packets: u64,
    pub bytes: u64,
}

/// One address member of a v4 set, with its counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V4Element {
    pub addr: Ipv4Addr,
    pub packets: u64,
    pub bytes: u64,
}

/// Every set of our table, in one read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableSnapshot {
    pub allowed: Vec<SetElement>,
    pub friends: Vec<SetElement>,
    pub blocked: Vec<SetElement>,
    pub allowed_v4: Vec<V4Element>,
    pub blocked_v4: Vec<V4Element>,
}

impl TableSnapshot {
    /// MAC members of one of the address sets; empty for v4 sets.
    pub fn macs(&self, set: SetName) -> &[SetElement] {
        match set {
            SetName::Allowed => &self.allowed,
            SetName::Friends => &self.friends,
            SetName::Blocked => &self.blocked,
            SetName::AllowedV4 | SetName::BlockedV4 => &[],
        }
    }

    /// Address members of one of the v4 sets; empty for MAC sets.
    pub fn addresses(&self, set: SetName) -> &[V4Element] {
        match set {
            SetName::AllowedV4 => &self.allowed_v4,
            SetName::BlockedV4 => &self.blocked_v4,
            _ => &[],
        }
    }
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
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(name)
    } else {
        Err(NftError::BadInterface(name.to_string()))
    }
}

/// Everything the paywall asks of the kernel goes through one trait, so
/// the reconciler can be exercised against a fake kernel (unit tests)
/// or a real one inside a network namespace (integration tests) rather
/// than against whatever the developer's laptop happens to have loaded.
pub trait NftBackend: Send + Sync {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftError>;
}

/// The real thing: the `nft` binary.
pub struct SystemNft;

impl NftBackend for SystemNft {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
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
    backend: Arc<dyn NftBackend>,
}

impl Firewall {
    /// A firewall that talks to this machine's kernel.
    pub fn system(
        ap_iface: impl Into<String>,
        uplink: Option<String>,
        gateway: Ipv4Addr,
        panel_port: u16,
        portal_enabled: bool,
    ) -> Self {
        Self {
            ap_iface: ap_iface.into(),
            uplink,
            gateway,
            panel_port,
            portal_enabled,
            backend: Arc::new(SystemNft),
        }
    }

    /// Same, with a caller-supplied kernel (tests).
    #[cfg(test)]
    pub(crate) fn with_backend(
        backend: Arc<dyn NftBackend>,
        ap_iface: impl Into<String>,
        uplink: Option<String>,
        gateway: Ipv4Addr,
        panel_port: u16,
        portal_enabled: bool,
    ) -> Self {
        Self {
            ap_iface: ap_iface.into(),
            uplink,
            gateway,
            panel_port,
            portal_enabled,
            backend,
        }
    }

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
    set {SET_ALLOWED_V4} {{
        type ipv4_addr
        counter
    }}
    set {SET_BLOCKED_V4} {{
        type ipv4_addr
        counter
    }}

    chain forward {{
        type filter hook forward priority filter; policy accept;
        # Downloads are attributed by the address the client holds: the
        # frame's destination MAC belongs to this machine by now, so the
        # client's own MAC is not in the packet any more. The allow-set
        # rule counts and falls through; it grants nothing.
        ip daddr @{SET_BLOCKED_V4} counter drop
        ip daddr @{SET_ALLOWED_V4} counter
        # Traffic that does not pass through the hotspot is not ours to police.
        iifname != \"{ap}\" accept
        # Friends and paying clients may pass; everyone else is dropped,
        # existing connections included: revoke means no internet.
        # Element counters show per-device traffic on the accept side;
        # the blocked set attributes drops to known waiting devices.
        ether saddr @{SET_FRIENDS} counter accept
        ether saddr @{SET_ALLOWED} counter accept
        ether saddr @{SET_BLOCKED} counter drop
        # HTTPS-first browsers probe :443 before they try :80; a silent
        # drop leaves them waiting about six seconds per attempt. A
        # refusal is instant, and it is also what their captive-portal
        # detection notices (#25).
        tcp dport 443 counter reject with tcp reset
        udp dport 443 counter reject
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

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
        self.backend.run(args, stdin)
    }

    /// (Re)install the table: whatever is there before is ours to replace.
    pub fn install(&self) -> Result<(), NftError> {
        // Fail-closed: drop leftovers first, then apply the full table.
        let _ = self.run(&["delete", "table", "inet", TABLE], None);
        self.run(&["-f", "-"], Some(&self.render())).map(|_| ())
    }

    pub fn uninstall(&self) -> Result<(), NftError> {
        match self.run(&["delete", "table", "inet", TABLE], None) {
            Ok(_) => Ok(()),
            // Already gone — the desired end state.
            Err(NftError::Rejected(e)) if e.contains("No such file") => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn table_exists(&self) -> bool {
        self.run(&["list", "table", "inet", TABLE], None).is_ok()
    }

    /// Is the installed table still *ours*, and still loaded?
    ///
    /// `table_exists` answers "does the kernel know a table by this
    /// name", which stays true after `nft flush table inet piso` — a
    /// table with the right name, no rules, and no enforcement. This
    /// compares the listed ruleset against the rules the paywall
    /// depends on, so a flushed or foreign table reads as broken and is
    /// reinstalled instead of being trusted.
    ///
    /// Reading is separate from interpreting so a caller can do both in
    /// one `nft` call (see [`Firewall::inspect`]).
    pub fn list_table(&self) -> Result<Option<String>, NftError> {
        match self.run(&["list", "table", "inet", TABLE], None) {
            Ok(listed) => Ok(Some(listed)),
            // Missing is a state, not an error: the caller will install.
            Err(NftError::Rejected(reason)) if reason.contains("No such file") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// One read for the whole tick: `None` when the table is missing,
    /// flushed, or somebody else's; otherwise every set it holds.
    pub fn inspect(&self) -> Result<Option<TableSnapshot>, NftError> {
        let Some(listed) = self.list_table()? else {
            return Ok(None);
        };
        if !self.ruleset_is_ours(&listed) {
            return Ok(None);
        }
        Ok(Some(parse_table_listing(&listed)))
    }

    /// The rules a listed table must contain to count as enforcing.
    fn ruleset_is_ours(&self, listed: &str) -> bool {
        let ap = self.ap_iface.as_str();
        let mut required: Vec<String> = vec![
            format!("iifname != \"{ap}\" accept"),
            format!("ether saddr @{SET_FRIENDS} counter accept"),
            format!("ether saddr @{SET_ALLOWED} counter accept"),
            format!("ether saddr @{SET_BLOCKED} counter drop"),
            // The catch-all: unknown devices are dropped, not passed.
            "counter drop".to_string(),
        ];
        if self.uplink.is_some() {
            required.push("masquerade".to_string());
        }
        if self.portal_enabled {
            required.push("redirect to :80".to_string());
        }
        // `nft list table` normalizes whitespace and prints counter
        // values inline (`counter packets 3 bytes 252 accept`), so both
        // sides are reduced to the rule text alone before comparing.
        let listed = normalize_ruleset(listed);
        required
            .iter()
            .all(|rule| listed.contains(&normalize_ruleset(rule)))
    }

    /// Apply set changes in one `nft` run. Every call costs a process
    /// spawn and a ruleset transaction, so a reconcile tick that changes
    /// 40 devices used to mean 40 of them; this makes it one, and the
    /// transaction is atomic — a revoked device is never briefly in no
    /// set at all, and a granted one never waits for the next tick.
    ///
    /// If one element turns out to be stale, `nft` aborts the whole
    /// script; that case replays the changes one by one so the rest of
    /// the batch still takes effect.
    pub fn apply_batch(&self, changes: &[SetChange]) -> Result<(), NftError> {
        if changes.is_empty() {
            return Ok(());
        }
        let script: String = changes
            .iter()
            .map(|change| format!("{}\n", change.render()))
            .collect();
        match self.run(&["-f", "-"], Some(&script)) {
            Ok(_) => Ok(()),
            Err(err) => {
                // A stale element aborts the whole script; that case is
                // worth a retry element by element, anything else is not.
                let stale = matches!(
                    &err,
                    NftError::Rejected(reason)
                        if reason.contains("File exists") || reason.contains("No such file")
                );
                if !stale {
                    return Err(err);
                }
                log_warn!("nft rejected a batch ({err}); applying element by element");
                self.apply_one_by_one(changes)
            }
        }
    }

    /// The slow, tolerant path: one element per `nft` run, where "already
    /// there" and "already gone" are the desired state rather than
    /// errors.
    fn apply_one_by_one(&self, changes: &[SetChange]) -> Result<(), NftError> {
        for change in changes {
            let script = format!("{}\n", change.render());
            match self.run(&["-f", "-"], Some(&script)) {
                Ok(_) => {}
                Err(NftError::Rejected(e))
                    if e.contains("File exists") || e.contains("No such file") => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// One set change, with the set named by type rather than by string:
/// set names reach the ruleset script, so they never come from input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetName {
    Allowed,
    Friends,
    Blocked,
    AllowedV4,
    BlockedV4,
}

impl SetName {
    pub fn name(self) -> &'static str {
        match self {
            SetName::Allowed => SET_ALLOWED,
            SetName::Friends => SET_FRIENDS,
            SetName::Blocked => SET_BLOCKED,
            SetName::AllowedV4 => SET_ALLOWED_V4,
            SetName::BlockedV4 => SET_BLOCKED_V4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetChange {
    AddMac(SetName, MacAddr),
    DelMac(SetName, MacAddr),
    AddV4(SetName, Ipv4Addr),
    DelV4(SetName, Ipv4Addr),
}

impl SetChange {
    fn render(self) -> String {
        let (verb, set, element) = match self {
            SetChange::AddMac(set, mac) => ("add", set, mac.to_string()),
            SetChange::DelMac(set, mac) => ("delete", set, mac.to_string()),
            SetChange::AddV4(set, addr) => ("add", set, addr.to_string()),
            SetChange::DelV4(set, addr) => ("delete", set, addr.to_string()),
        };
        format!("{verb} element inet {TABLE} {} {{ {element} }}", set.name())
    }
}

/// Rule text with counter values removed: `counter packets 3 bytes 252`
/// and `counter` both become `counter`, which is what rule comparison
/// cares about.
fn normalize_ruleset(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut skip_value = false;
    for token in text.split_whitespace() {
        if skip_value {
            skip_value = false;
            continue;
        }
        if token == "packets" || token == "bytes" {
            skip_value = true;
            continue;
        }
        out.push(token);
    }
    out.join(" ")
}

/// Parse the counters from one element token: everything after the
/// element is optional, and the shape is `[counter packets N bytes M]`.
fn token_counters(rest: &[&str]) -> (u64, u64) {
    match rest.iter().position(|f| *f == "packets") {
        Some(i) => (
            rest.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0),
            rest.iter()
                .position(|f| *f == "bytes")
                .and_then(|j| rest.get(j + 1).and_then(|v| v.parse().ok()))
                .unwrap_or(0),
        ),
        None => (0, 0),
    }
}

/// The element list of one set block (`elements = { … }`, possibly
/// wrapped over several lines), or `""` when the set has none.
fn element_list(block: &str) -> &str {
    let Some(start) = block.find("elements") else {
        return "";
    };
    let Some(open) = block[start..].find('{') else {
        return "";
    };
    let rest = &block[start + open + 1..];
    match rest.find('}') {
        Some(close) => &rest[..close],
        None => rest,
    }
}

/// Split `nft list table` output into `(set name, block text)` pairs.
fn set_blocks(output: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, usize, String)> = None;
    for line in output.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if let Some((_, set_indent, text)) = current.as_mut() {
            if indent <= *set_indent && trimmed.starts_with('}') {
                let (name, _, text) = current.take().expect("checked above");
                blocks.push((name, text));
                continue;
            }
            text.push_str(line);
            text.push('\n');
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("set ")
            && trimmed.ends_with('{')
        {
            let name = rest.trim_end_matches('{').trim().to_string();
            current = Some((name, indent, String::new()));
        }
    }
    if let Some((name, _, text)) = current {
        blocks.push((name, text));
    }
    blocks
}

/// Parse `nft list table inet piso`: every set of our table, in one pass.
///
/// Elements without counters report zeros. Anything unparseable is
/// skipped rather than guessed at: this output is the reconciler's view
/// of the kernel, and a half-written line must not invent membership.
pub fn parse_table_listing(output: &str) -> TableSnapshot {
    let mut snapshot = TableSnapshot::default();
    for (name, block) in set_blocks(output) {
        let elements = element_list(&block);
        if elements.trim().is_empty() {
            continue;
        }
        for token in elements.split(',') {
            let mut fields = token.split_whitespace();
            let Some(first) = fields.next() else { continue };
            let rest: Vec<&str> = fields.collect();
            let (packets, bytes) = token_counters(&rest);
            match name.as_str() {
                SET_ALLOWED | SET_FRIENDS | SET_BLOCKED => {
                    if let Ok(mac) = first.parse::<MacAddr>() {
                        let element = SetElement {
                            mac,
                            packets,
                            bytes,
                        };
                        match name.as_str() {
                            SET_ALLOWED => snapshot.allowed.push(element),
                            SET_FRIENDS => snapshot.friends.push(element),
                            _ => snapshot.blocked.push(element),
                        }
                    }
                }
                SET_ALLOWED_V4 | SET_BLOCKED_V4 => {
                    if let Ok(addr) = first.parse::<Ipv4Addr>() {
                        let element = V4Element {
                            addr,
                            packets,
                            bytes,
                        };
                        match name.as_str() {
                            SET_ALLOWED_V4 => snapshot.allowed_v4.push(element),
                            _ => snapshot.blocked_v4.push(element),
                        }
                    }
                }
                // Our table, a set we do not know about: not ours to read.
                _ => {}
            }
        }
    }
    snapshot
}

/// What the reconciler wants vs. what the kernel has: set membership of
/// any element type (device MACs, client addresses).
#[derive(Debug, PartialEq, Eq)]
pub struct SetDiff<T> {
    pub add: Vec<T>,
    pub remove: Vec<T>,
}

pub fn diff<T: PartialEq + Copy>(want: &[T], have: &[T]) -> SetDiff<T> {
    let add: Vec<T> = want.iter().filter(|m| !have.contains(m)).copied().collect();
    let remove: Vec<T> = have.iter().filter(|m| !want.contains(m)).copied().collect();
    SetDiff { add, remove }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fw(uplink: Option<&str>) -> Firewall {
        Firewall::system(
            "wlan0",
            uplink.map(str::to_string),
            Ipv4Addr::new(10, 10, 0, 1),
            8080,
            true,
        )
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
        // Every policy decision is observable: five set declarations
        // carry counters, plus nine rule counters (blocked downloads,
        // allowed downloads, friends, allowed, blocked uploads, the two
        // HTTPS refusals, forward drop, input drop). Comments are
        // ignored.
        let counted = rules
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter(|l| l.contains("counter"))
            .count();
        assert_eq!(counted, 14);
    }

    #[test]
    fn download_attribution_never_grants_anything() {
        let rules = fw(None).render();
        let forward = rules.split("chain forward").nth(1).expect("forward chain");
        // The allow-set rule counts and falls through: no verdict.
        let allowed_at = forward.find("ip daddr @allowed_v4 counter").expect("count");
        let rules_after = &forward[allowed_at..];
        assert!(
            !rules_after
                .lines()
                .next()
                .unwrap_or_default()
                .contains("accept"),
            "the download counter must not accept: {rules_after}"
        );
        // Blocked addresses are dropped, and before the foreign-traffic
        // escape hatch, or downloads would never reach the rule.
        let drop_at = forward
            .find("ip daddr @blocked_v4 counter drop")
            .expect("drop");
        let gate_at = forward.find("iifname != \"wlan0\" accept").expect("gate");
        assert!(drop_at < gate_at, "{forward}");
    }

    /// One chain's text, without the chains that follow it.
    fn chain<'a>(rules: &'a str, name: &str) -> &'a str {
        let start = rules.find(&format!("chain {name}")).expect("chain present");
        let rest = &rules[start..];
        match rest[1..].find("\n    chain ") {
            Some(offset) => &rest[..offset + 1],
            None => rest,
        }
    }

    #[test]
    fn unpaid_https_is_refused_instead_of_dropped() {
        let rules = fw(None).render();
        let forward = chain(&rules, "forward");
        let reset_at = forward.find("reject with tcp reset").expect("tcp reset");
        let quic_at = forward
            .find("udp dport 443 counter reject")
            .expect("udp reject");
        let drop_at = forward
            .rfind("counter drop")
            .expect("the catch-all drop is last");
        assert!(reset_at < drop_at && quic_at < drop_at, "{forward}");
        // The refusal comes after the allowed sets, so paying clients are
        // unaffected: their traffic was accepted before this point.
        let allowed_at = forward
            .find("ether saddr @allowed counter accept")
            .expect("allowed");
        assert!(allowed_at < reset_at, "{forward}");
        // Refusing is not granting: nothing in this chain may accept
        // after the refusal, or an unpaid device would get through.
        assert!(
            !forward[reset_at..].contains("accept"),
            "the refusal must not open anything: {forward}"
        );
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
        let fw = Firewall::system(
            "wlan0",
            Some("usb0".into()),
            Ipv4Addr::new(10, 10, 0, 1),
            8080,
            true,
        );
        assert!(fw.render().contains("table inet piso"));
    }

    /// A `nft list table inet piso` capture: three MAC sets with
    /// counters, two address sets, and a foreign set we must ignore.
    const LISTED: &str = "
table inet piso {
\tset allowed {
\t\ttype ether_addr
\t\tcounter
\t\telements = { 42:61:7e:6c:ee:d2 counter packets 70 bytes 4620,
\t\t\taa:bb:cc:dd:ee:01 counter packets 0 bytes 0 }
\t}

\tset friends {
\t\ttype ether_addr
\t\tcounter
\t}

\tset blocked {
\t\ttype ether_addr
\t\tcounter
\t\telements = { 11:22:33:44:55:66 counter packets 3 bytes 252 }
\t}

\tset allowed_v4 {
\t\ttype ipv4_addr
\t\tcounter
\t\telements = { 10.10.0.5 counter packets 12 bytes 900 }
\t}

\tset blocked_v4 {
\t\ttype ipv4_addr
\t\tcounter
\t}

\tset somebody_elses {
\t\ttype inet_service
\t\telements = { 999 }
\t}

\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname != \"wlan0\" accept
\t\tether saddr @friends counter accept
\t\tether saddr @blocked counter drop
\t}
}
";

    #[test]
    fn parses_every_set_of_the_table_in_one_pass() {
        let snapshot = parse_table_listing(LISTED);
        assert_eq!(snapshot.allowed.len(), 2);
        assert_eq!(snapshot.allowed[0].mac.to_string(), "42:61:7e:6c:ee:d2");
        assert_eq!(snapshot.allowed[0].packets, 70);
        assert_eq!(snapshot.allowed[0].bytes, 4620);
        assert_eq!(snapshot.allowed[1].bytes, 0, "no counters means zeros");
        assert!(snapshot.friends.is_empty(), "an empty set has no elements");
        assert_eq!(snapshot.blocked.len(), 1);
        assert_eq!(snapshot.blocked[0].bytes, 252);
        assert_eq!(snapshot.allowed_v4.len(), 1);
        assert_eq!(snapshot.allowed_v4[0].addr.to_string(), "10.10.0.5");
        assert_eq!(snapshot.allowed_v4[0].bytes, 900);
        assert!(snapshot.blocked_v4.is_empty());
        // A set we do not know about is not ours to read.
        assert_eq!(snapshot.macs(SetName::Allowed).len(), 2);
    }

    #[test]
    fn parses_empty_or_absent_elements() {
        let snapshot = parse_table_listing("table inet piso { set allowed { type ether_addr } }");
        assert!(snapshot.allowed.is_empty());
        assert!(parse_table_listing("no sets here").allowed.is_empty());
        assert!(
            parse_table_listing("set allowed {\n elements = { }\n}")
                .allowed
                .is_empty()
        );
        // Half-written lines are skipped, never guessed at.
        let half =
            "set allowed {\n type ether_addr\n elements = { aa:bb:cc:dd:ee:01,\n junk\n }\n}";
        assert_eq!(parse_table_listing(half).allowed.len(), 1);
    }

    #[test]
    fn integrity_check_notices_a_flushed_or_foreign_table() {
        let fw = fw(None);
        let installed = fw.render();
        // `nft list table` prints rules with counter values inline; that
        // is the spelling the check has to accept.
        let listed = installed.replace("counter", "counter packets 3 bytes 252");
        assert!(fw.ruleset_is_ours(&listed), "our own ruleset must pass");
        assert!(
            fw.ruleset_is_ours(&installed),
            "and so must the un-instrumented text"
        );

        // Flushed: same table, same sets, no rules.
        let flushed = "table inet piso {\n\tset allowed {\n\t\ttype ether_addr\n\t}\n\tchain forward {\n\t}\n}";
        assert!(
            !fw.ruleset_is_ours(flushed),
            "a table without the enforcing rules is not intact"
        );

        // Foreign: right name, someone else's rules.
        let foreign =
            "table inet piso {\n\tchain forward {\n\t\tcounter packets 1 bytes 60 accept\n\t}\n}";
        assert!(!fw.ruleset_is_ours(foreign));
        assert!(!fw.ruleset_is_ours(""));
    }

    #[test]
    fn integrity_check_follows_the_configured_shape() {
        // With an uplink and the portal on, the NAT and redirect rules are
        // part of what makes the table ours.
        let fw = fw(Some("usb0"));
        let listed = fw.render();
        assert!(fw.ruleset_is_ours(&listed));
        let without_masquerade = listed.replace("masquerade", "");
        assert!(!fw.ruleset_is_ours(&without_masquerade));
        let without_redirect = listed.replace("redirect to :80", "");
        assert!(!fw.ruleset_is_ours(&without_redirect));
    }

    #[test]
    fn batch_scripts_are_one_script_with_typed_set_names() {
        let changes = [
            SetChange::AddMac(SetName::Allowed, mac("aa:bb:cc:dd:ee:01")),
            SetChange::DelMac(SetName::Blocked, mac("aa:bb:cc:dd:ee:01")),
            SetChange::AddV4(SetName::AllowedV4, Ipv4Addr::new(10, 10, 0, 5)),
            SetChange::DelV4(SetName::BlockedV4, Ipv4Addr::new(10, 10, 0, 6)),
        ];
        let script: String = changes
            .iter()
            .map(|c| format!("{}\n", c.render()))
            .collect();
        assert_eq!(
            script,
            "add element inet piso allowed { aa:bb:cc:dd:ee:01 }\n\
             delete element inet piso blocked { aa:bb:cc:dd:ee:01 }\n\
             add element inet piso allowed_v4 { 10.10.0.5 }\n\
             delete element inet piso blocked_v4 { 10.10.0.6 }\n"
        );
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
        let d = diff::<MacAddr>(&[], &[]);
        assert!(d.add.is_empty() && d.remove.is_empty());
        let same = vec![mac("aa:bb:cc:dd:ee:01")];
        let d = diff(&same, &same);
        assert!(d.add.is_empty() && d.remove.is_empty());
    }
}
