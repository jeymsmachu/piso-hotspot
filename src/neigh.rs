//! Who is at an address right now, according to the kernel.
//!
//! The portal used to identify its visitor by looking their source
//! address up in the DHCP lease file. A device that statically takes an
//! address dnsmasq leased to somebody else was then shown *that* device's
//! page — its paid state, its MAC, its pass name.
//!
//! The kernel keeps a better answer: the neighbour table records which
//! MAC actually holds each address, updated from the traffic itself. A
//! request that reaches the portal came from a device whose address has
//! been resolved, so this is the device to describe — and if the kernel
//! does not know the address, the honest answer is "no idea", which the
//! portal renders as the generic unpaid page.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::mac::MacAddr;

/// `/proc/net/arp`, as the kernel writes it:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 10.10.0.50       0x1         0x2         aa:bb:cc:dd:ee:ff     *        ap0
/// ```
///
/// Only complete entries (`0x2`) count: the rest are in-flight or stale.
pub fn parse_arp(content: &str) -> HashMap<Ipv4Addr, MacAddr> {
    let mut table = HashMap::new();
    for line in content.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(ip), Some(_hw), Some(flags), Some(mac)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !flags.starts_with("0x2") {
            continue;
        }
        if let (Ok(ip), Ok(mac)) = (ip.parse::<Ipv4Addr>(), mac.parse::<MacAddr>()) {
            table.insert(ip, mac);
        }
    }
    table
}

/// The device holding `addr`, or `None` when the kernel has no complete
/// neighbour entry for it.
pub fn holder(addr: Ipv4Addr) -> Option<MacAddr> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp(&content).get(&addr).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
10.10.0.50       0x1         0x2         aa:bb:cc:dd:ee:01     *        ap0
10.10.0.51       0x1         0x0         00:00:00:00:00:00     *        ap0
10.10.0.52       0x1         0x2         aa:bb:cc:dd:ee:02     *        ap0
malformed line
10.10.0.53       0x1         0x2         not-a-mac             *        ap0
";

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_complete_entries_are_trusted() {
        let table = parse_arp(ARP);
        assert_eq!(table.len(), 2, "{table:?}");
        assert_eq!(
            table.get(&Ipv4Addr::new(10, 10, 0, 50)),
            Some(&mac("aa:bb:cc:dd:ee:01"))
        );
        assert_eq!(
            table.get(&Ipv4Addr::new(10, 10, 0, 52)),
            Some(&mac("aa:bb:cc:dd:ee:02"))
        );
        // An incomplete entry is not an answer.
        assert!(!table.contains_key(&Ipv4Addr::new(10, 10, 0, 51)));
        // Nor is a malformed one.
        assert!(!table.contains_key(&Ipv4Addr::new(10, 10, 0, 53)));
    }

    #[test]
    fn empty_or_headerless_input_is_no_answer() {
        assert!(parse_arp("").is_empty());
        assert!(parse_arp("IP address HW type Flags HW address Mask Device\n").is_empty());
    }
}
