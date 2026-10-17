#!/usr/bin/env python3
"""Minimal DHCP client for the hwsim harnesses.

isc-dhclient 4.4.3-P1 (and builds like it) emits DHCP packets with an
invalid IP checksum: it relies on TX checksum offload, which veth and
mac80211_hwsim do not provide, so the kernel drops every DISCOVER in
ip_rcv and counts it as InHdrErrors. This client runs over AF_PACKET
with scapy, which computes checksums in software.

Usage: dhcp-client.py <iface> [wait_seconds]
Prints "LEASE ip=... mask=... gw=..." and exits 0, or NOLEASE on stderr."""
import sys, socket, time

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, conf
except ImportError:
    sys.path.insert(0, "/tmp/dcvenv/lib/python3.14/site-packages")
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, conf

IFACE = sys.argv[1]
WAIT = float(sys.argv[2]) if len(sys.argv) > 2 else 25
MAC = open(f"/sys/class/net/{IFACE}/address").read().strip()
MACB = bytes.fromhex(MAC.replace(":", ""))
XID = 0x12345678
conf.verb = 0


def bootp(msg_type, req_ip=None, sid=None):
    # Options 50/54 take 4 packed bytes (inet_aton) in this scapy build;
    # dotted strings raise TypeError while building the field.
    opts = [(53, bytes([msg_type]))]
    if req_ip:
        opts.append((50, socket.inet_aton(req_ip)))
    if sid:
        opts.append((54, socket.inet_aton(sid)))
    opts.append((55, bytes([1, 3, 6, 15, 28, 51])))
    opts.append("end")
    return BOOTP(op=1, xid=XID, chaddr=MACB, ciaddr="0.0.0.0", flags=0x8000) / DHCP(
        options=opts
    )


DISCOVER = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src=MAC)
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / bootp(1)
)

got = {}


def handler(pkt):
    boot = pkt.getlayer(BOOTP)
    dhcp = pkt.getlayer(DHCP)
    if boot is None or dhcp is None or boot.xid != XID or boot.op != 2:
        return
    msg = next((v for k, v in dhcp.options if k in ("message-type", 53)), None)
    if msg == 2 and "req" not in got:
        offer_ip = boot.yiaddr
        sid = next((v for k, v in dhcp.options if k in ("server_id", 54)), None)
        if not offer_ip:
            return
        got["req"] = True
        req = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=MAC)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp(3, req_ip=offer_ip, sid=sid)
        )
        sendp(req, iface=IFACE, verbose=0)
    elif msg == 5:
        got["ip"] = boot.yiaddr
        gw = next((v for k, v in dhcp.options if k in ("router", 3)), None)
        mask = next((v for k, v in dhcp.options if k in ("subnet_mask", 1)), None)
        if gw:
            got["gw"] = gw
        if mask:
            got["mask"] = mask
    elif msg == 6:
        got.pop("req", None)


for _ in range(2):
    sendp(DISCOVER, iface=IFACE, verbose=0)
    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        timeout=max(2.0, WAIT / 2),
        prn=handler,
        stop_filter=lambda p: "ip" in got,
    )
    if "ip" in got:
        print(f"LEASE ip={got['ip']} mask={got.get('mask', '')} gw={got.get('gw', '')}")
        sys.exit(0)

print("NOLEASE", file=sys.stderr)
print("(if the server is dnsmasq: it must send broadcast replies, see dhcp-broadcast)",
      file=sys.stderr)
sys.exit(1)
