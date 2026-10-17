#!/usr/bin/env bash
# End-to-end matrix on virtual radios — no hardware needed, safe to run
# on a laptop whose only wifi card is the internet link.
#
# One hwsim radio beacons the AP (ap.interface), a second radio is a
# client moved into a network namespace, and a veth pair in a second
# namespace is the "internet". Covers: bring-up, association over the
# air, DHCP, portal interception, panel reachability, unpaid blocking,
# grant through the paywall with NAT, kernel byte counters, instant
# revoke, and lease-driven device identity.
#
#   sudo scripts/hwsim-matrix.sh
#
# Requires: mac80211_hwsim, hostapd, dnsmasq, nft, iw, tc, curl, and the
# scapy venv created by scripts/hwsim-setup.sh.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/piso-hotspot"
DHCPC="$ROOT/scripts/dhcp-client.py"
LOG=/run/piso-hotspot/daemon.log
CNS=piso-client
INS=piso-uplink
FAKE=198.51.100.1
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
section() { echo; echo "===== $* ====="; }
vcurl() { : > /tmp/vc.body; local c; c=$(ip netns exec $CNS curl -s -o /tmp/vc.body -w '%{http_code}' --max-time "${2:-6}" "$1" 2>/dev/null); echo "${c:-000}"; }

[ -x "$BIN" ] || { echo "build first: cargo build" >&2; exit 2; }
[ -f "$DHCPC" ] || { echo "missing $DHCPC" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 2; }

cleanup() {
    [ -n "${HPID:-}" ] && kill "$HPID" 2>/dev/null
    "$BIN" stop >/dev/null 2>&1
    ip netns del $CNS 2>/dev/null
    ip netns del $INS 2>/dev/null
    ip link del ve-host 2>/dev/null
    ip route del "${FAKE}/32" 2>/dev/null
    ip route del default dev ve-host metric 6000 2>/dev/null
    rmmod mac80211_hwsim 2>/dev/null
    nmcli device set wlan0 managed yes 2>/dev/null
    [ -f "$LOG" ] && { echo "--- daemon.log tail:"; tail -12 "$LOG"; }
    rm -f /etc/piso-hotspot/config.json /etc/piso-hotspot/state.db*
    "$BIN" status >/dev/null 2>&1 && echo "WARNING: daemon still answers" || rm -rf /run/piso-hotspot
    echo; echo "===== summary: $PASS passed, $FAIL failed ====="
}
trap cleanup EXIT
trap 'FAIL=99; exit 130' INT TERM

section "1. simulated internet + two simulated radios"
ip netns del $CNS 2>/dev/null; ip netns del $INS 2>/dev/null; ip link del ve-host 2>/dev/null
ip netns add $INS
ip link add ve-host type veth peer name ve-peer
ip link set ve-peer netns $INS
ip link set ve-host up
ip addr replace 192.168.77.1/24 dev ve-host
ip netns exec $INS ip link set lo up
ip netns exec $INS ip link set ve-peer up
ip netns exec $INS ip addr replace 192.168.77.2/24 dev ve-peer
ip netns exec $INS ip addr replace ${FAKE}/32 dev ve-peer
ip route replace ${FAKE}/32 dev ve-host
ip route replace default dev ve-host metric 6000
ip netns exec $INS python3 -m http.server 8000 --bind ${FAKE} >/tmp/fakeinet.log 2>&1 &
HPID=$!
sleep 0.7

rmmod mac80211_hwsim 2>/dev/null; sleep 1
BEFORE=$(ls /sys/class/net)
modprobe mac80211_hwsim channels=2 radios=2 || { bad "modprobe hwsim"; exit 1; }
sleep 1
NEW=()
for n in /sys/class/net/*; do
    b=$(basename "$n"); case "$BEFORE" in *"$b"*) continue ;; esac
    [ -e "$n/phy80211" ] && NEW+=("$b")
done
[ "${#NEW[@]}" -ge 2 ] || { bad "need 2 new radios, got ${#NEW[@]}"; exit 1; }
CLIENT="${NEW[0]}"; AP="${NEW[1]}"
echo "ap radio: $AP   client radio: $CLIENT"
nmcli device set "$AP" managed no 2>/dev/null
nmcli device set "$CLIENT" managed no 2>/dev/null

section "2. start hotspot with AP forced onto $AP"
mkdir -p /etc/piso-hotspot
printf '{"ap":{"interface":"%s"},"bandwidth":{"max_down_bytes_per_sec":5000000}}' "$AP" > /etc/piso-hotspot/config.json
"$BIN" start || { bad "start"; exit 1; }
iw dev "$AP" info | grep -q "type AP" && ok "$AP is AP" || bad "$AP not in AP mode"
tc qdisc show dev "$AP" | grep -q tbf && ok "download cap installed" || bad "no tbf on $AP"

section "3. client joins via nl80211 wiphy move"
PHY=$(basename "$(readlink -f "/sys/class/net/$CLIENT/phy80211")")
ip netns add $CNS
if iw phy "$PHY" set netns name "$CNS" 2>/tmp/netns-move.err; then
    ok "radio moved via iw phy (nl80211)"
else
    cat /tmp/netns-move.err; bad "cannot move client radio"; exit 1
fi
ip netns exec $CNS ip link set lo up
ip netns exec $CNS ip link set "$CLIENT" up
CMAC=$(ip netns exec $CNS cat "/sys/class/net/$CLIENT/address")
echo "client MAC (post-move): $CMAC"
if ip netns exec $CNS iw dev "$CLIENT" scan 2>/dev/null | grep -q "SSID: piso-hotspot"; then
    ok "client scans and sees piso-hotspot over the air"
else
    bad "client cannot see the SSID — hwsim medium not shared"
fi
ip netns exec $CNS iw dev "$CLIENT" connect piso-hotspot || { bad "connect trigger failed"; exit 1; }
ASSOC=""
for i in $(seq 1 20); do
    ip netns exec $CNS iw dev "$CLIENT" link 2>/dev/null | grep -q "Connected to" && { ASSOC=1; break; }
    sleep 1
done
if [ -n "$ASSOC" ]; then
    ok "client reports associated"
    ip netns exec $CNS iw dev "$CLIENT" link | head -2
else
    bad "client-side association never confirmed"
    iw dev "$AP" station dump 2>/dev/null | head -6 || echo "  (no stations)"
    exit 1
fi
# isc-dhclient emits bogus IP checksums on this class of setup (it relies
# on TX offload that veth/hwsim do not provide), so use the scapy client.
if ip netns exec $CNS python3 "$DHCPC" "$CLIENT" 25 >/tmp/lease.out 2>&1; then
    LEASE=$(grep -oE 'ip=[0-9.]+' /tmp/lease.out | cut -d= -f2)
    ip netns exec $CNS ip addr replace "$LEASE/24" dev "$CLIENT"
    ip netns exec $CNS ip route replace default via 10.10.0.1 2>/dev/null
    ok "DHCP lease ($LEASE)"
else
    bad "DHCP failed"
fi
if ! ip netns exec $CNS ip -4 addr show "$CLIENT" | grep -q 'inet '; then
    echo "  DHCP fallback: static 10.10.0.5/24 + default route"
    ip netns exec $CNS ip addr replace 10.10.0.5/24 dev "$CLIENT"
    ip netns exec $CNS ip route replace default via 10.10.0.1
    printf '%s %s 10.10.0.5 vclient\n' \
        "$(($(date +%s) + 3600))" "$CMAC" > /run/piso-hotspot/dnsmasq.leases
fi
ip netns exec $CNS ping -c2 -W2 10.10.0.1 >/dev/null && ok "pings gateway" || bad "gateway unreachable"
APSTA=$(iw dev "$AP" station dump 2>/dev/null | awk '/^Station/{print $2}' | head -1)
echo "AP sees station: ${APSTA:-none}   grant will use: $CMAC"
for i in $(seq 1 22); do
    "$BIN" list 2>/dev/null | grep -qi "$CMAC" && break
    sleep 1
done
"$BIN" list | grep -qi "$CMAC" && ok "device row appeared from lease" || bad "no device row for $CMAC"

section "4. UNPAID: portal + panel + blocking"
P=$(vcurl "http://10.10.0.1:80/")
[ "$P" = 200 ] && ok "local portal page" || bad "portal: $P"
grep -q "powered by" /tmp/vc.body && ok "powered-by footer" || bad "footer missing"
PN=$(vcurl "http://10.10.0.1:8080/")
[ "$PN" = 200 ] && ok "panel answers client subnet (200)" || bad "panel: $PN"
I=$(vcurl "http://93.184.216.34/")
[ "$I" = 200 ] && ok "unpaid HTTP ANYWHERE → portal (interception)" || bad "interception: $I"
grep -q "piso-hotspot" /tmp/vc.body && ok "portal body served to unpaid" || bad "portal body not served"
HT=$(ip netns exec $CNS curl -s -o /dev/null -w '%{time_total}' --max-time 3 https://10.10.0.1/ 2>/dev/null || echo 9)
awk -v t="$HT" 'BEGIN{exit !(t<1.0)}' && ok "https to gateway refuses FAST (${HT}s)" || bad "https hangs (${HT}s)"
F=$(vcurl "http://${FAKE}:8000/" 3)
[ "$F" = 000 ] && ok "unpaid cannot reach fake internet" || bad "unpaid reached fake internet: $F"

section "5. GRANT: paid path"
"$BIN" grant "$CMAC" quick >/tmp/grant.out 2>&1 && ok "grant" || { bad "grant"; cat /tmp/grant.out; }
sed 's/^/  /' /tmp/grant.out
P=$(vcurl "http://${FAKE}:8000/")
[ "$P" = 200 ] && ok "granted client reaches fake internet THROUGH the paywall+NAT" || bad "paid path: $P"
CNT=$(nft list set inet piso allowed 2>/dev/null | grep -oE 'counter packets [0-9]+ bytes [0-9]+' | head -1)
echo "  allowed-set kernel counter: ${CNT:-none}"
echo "$CNT" | grep -qE 'packets [1-9]' && ok "kernel per-device bytes counted" || bad "counters did not move"
P=$(vcurl "http://10.10.0.1:80/")
[ "$P" = 200 ] && ok "paid portal page" || bad "paid portal: $P"
grep -qE "You're online|expires|until" /tmp/vc.body && ok "countdown present" || bad "countdown missing"

section "6. REVOKE: instant cut"
"$BIN" revoke "$CMAC" >/tmp/revoke.out 2>&1 && ok "revoke" || { bad "revoke"; cat /tmp/revoke.out; }
sed 's/^/  /' /tmp/revoke.out
F=$(vcurl "http://${FAKE}:8000/" 3)
[ "$F" = 000 ] && ok "revoked client cut off again" || bad "still online after revoke: $F"
P=$(vcurl "http://10.10.0.1:80/")
[ "$P" = 200 ] && ok "back to unpaid portal" || bad "expected unpaid, got $P"

section "7. logs"
HITS=$(grep -c "portal hit" "$LOG" 2>/dev/null || echo 0)
[ "$HITS" -ge 2 ] && ok "portal logged $HITS hits" || bad "only $HITS portal hits"
