#!/usr/bin/env bash
# Dual-radio mode on virtual radios. Safe on any host: the real card and
# the host routing table are never touched — ap.interface and ap.uplink
# pin both ends of the hotspot.
#
#   wlan1: upstream AP (schoolnet) in netns "upns", with a fake-internet
#          HTTP server bound to 198.51.100.1
#   wlan2: station uplink, joins schoolnet
#   wlan3: piso AP
#   wlan4: client, moved into netns "piso-client"
#
#   sudo scripts/hwsim-dual-radio.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/piso-hotspot"
DHCPC="$ROOT/scripts/dhcp-client.py"
CNS=piso-client
FAKE=198.51.100.1
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
section() { echo; echo "===== $* ====="; }

[ -x "$BIN" ] || { echo "build first: cargo build" >&2; exit 2; }
[ -f "$DHCPC" ] || { echo "missing $DHCPC" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 2; }

cleanup() {
    [ -n "${UPPID:-}" ] && kill "$UPPID" 2>/dev/null
    [ -n "${HPID:-}" ] && kill "$HPID" 2>/dev/null
    "$BIN" stop >/dev/null 2>&1
    ip netns del $CNS 2>/dev/null
    ip netns del upns 2>/dev/null
    rm -f /etc/piso-hotspot/config.json /etc/piso-hotspot/state.db*
    rmmod mac80211_hwsim 2>/dev/null
    nmcli device set wlan0 managed yes 2>/dev/null
    "$BIN" status >/dev/null 2>&1 && echo "WARNING: daemon still answers" || rm -rf /run/piso-hotspot
    echo; echo "===== summary: $PASS passed, $FAIL failed ====="
}
trap cleanup EXIT
trap 'FAIL=99; exit 130' INT TERM

section "1. four virtual radios (real card untouched)"
rmmod mac80211_hwsim 2>/dev/null; sleep 1
BEFORE=$(ls /sys/class/net)
modprobe mac80211_hwsim radios=4 || { bad "modprobe"; exit 1; }
sleep 1
NEW=()
for n in /sys/class/net/*; do
    b=$(basename "$n"); case "$BEFORE" in *"$b"*) continue ;; esac
    [ -e "$n/phy80211" ] && NEW+=("$b")
done
[ "${#NEW[@]}" -ge 4 ] || { bad "need 4 radios, got ${#NEW[@]}"; exit 1; }
UP="${NEW[0]}"; STA="${NEW[1]}"; AP="${NEW[2]}"; CLI="${NEW[3]}"
echo "upstream=$UP station=$STA piso-ap=$AP client=$CLI"
for i in "$UP" "$STA" "$AP" "$CLI"; do nmcli device set "$i" managed no 2>/dev/null; done

section "2. upstream AP with fake internet (netns upns)"
ip netns del upns 2>/dev/null
ip netns add upns
UP_PHY=$(basename "$(readlink -f "/sys/class/net/$UP/phy80211")")
iw phy "$UP_PHY" set netns name upns || { bad "cannot move upstream phy"; exit 1; }
ip netns exec upns ip link set lo up
ip netns exec upns ip link set "$UP" up
ip netns exec upns ip addr replace 192.168.90.1/24 dev "$UP"
ip netns exec upns ip addr replace ${FAKE}/32 dev lo
ip netns exec upns python3 -m http.server 8000 --bind ${FAKE} >/tmp/fakeinet.log 2>&1 &
HPID=$!
sleep 0.7
cat > /tmp/upstream-ap.conf <<EOF
interface=$UP
driver=nl80211
ssid=schoolnet
hw_mode=g
channel=6
EOF
ip netns exec upns hostapd /tmp/upstream-ap.conf >/tmp/upstream-ap.log 2>&1 &
UPPID=$!
sleep 2
if ip netns exec upns iw dev "$UP" info 2>/dev/null | grep -q "type AP"; then
    ok "upstream AP is beaconing"
else
    bad "upstream AP failed"; tail -5 /tmp/upstream-ap.log; exit 1
fi
ip netns exec upns sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

section "3. station uplink joins the upstream"
ip link set "$STA" up
iw dev "$STA" connect schoolnet 2>/tmp/sta-connect.err || { bad "station connect"; cat /tmp/sta-connect.err; exit 1; }
for i in $(seq 1 15); do iw dev "$STA" link 2>/dev/null | grep -q "Connected to" && break; sleep 1; done
if iw dev "$STA" link 2>/dev/null | grep -q "Connected to"; then
    ok "station joined the upstream over the air"
else
    bad "station never associated"; exit 1
fi
ip addr replace 192.168.90.50/24 dev "$STA"
# Only a route to the fake internet; the host default route is untouched.
ip route replace ${FAKE}/32 dev "$STA" src 192.168.90.50
C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://${FAKE}:8000/)
[ "$C" = 200 ] && ok "uplink reaches the fake internet" || bad "uplink broken: $C"

section "4. start --dual-radio (ap.uplink pins the uplink)"
mkdir -p /etc/piso-hotspot
cat > /etc/piso-hotspot/config.json <<EOF
{"ap":{"interface":"$AP","uplink":"$STA"},"bandwidth":{"max_down_bytes_per_sec":5000000}}
EOF
"$BIN" start --dual-radio || { bad "start --dual-radio"; tail -20 /run/piso-hotspot/daemon.log 2>/dev/null; exit 1; }
iw dev "$AP" info | grep -q "type AP" && ok "$AP beacons the hotspot" || bad "$AP not in AP mode"
"$BIN" status | grep -qE "mode +dual-radio" && ok "status reports dual-radio" || bad "wrong mode in status"
"$BIN" status | grep -qE "uplink +$STA" && ok "status: uplink is $STA" || bad "wrong uplink"
ip route show default | grep -q "dev wlan0" && ok "host default route untouched (wlan0)" || bad "host default route changed!"

section "5. client: unpaid, paid, revoked"
CLI_PHY=$(basename "$(readlink -f "/sys/class/net/$CLI/phy80211")")
ip netns add $CNS
iw phy "$CLI_PHY" set netns name $CNS || { bad "cannot move client phy"; exit 1; }
ip netns exec $CNS ip link set lo up
ip netns exec $CNS ip link set "$CLI" up
CMAC=$(ip netns exec $CNS cat "/sys/class/net/$CLI/address")
ip netns exec $CNS iw dev "$CLI" connect piso-hotspot >/dev/null 2>&1
for i in $(seq 1 15); do ip netns exec $CNS iw dev "$CLI" link 2>/dev/null | grep -q "Connected to" && break; sleep 1; done
ip netns exec $CNS iw dev "$CLI" link 2>/dev/null | grep -q "Connected to" && ok "client associated" || bad "client cannot associate"
if ip netns exec $CNS python3 "$DHCPC" "$CLI" 25 >/tmp/lease.out 2>&1; then
    LEASE=$(grep -oE 'ip=[0-9.]+' /tmp/lease.out | cut -d= -f2)
    ip netns exec $CNS ip addr replace "$LEASE/24" dev "$CLI"
    ip netns exec $CNS ip route replace default via 10.10.0.1
    ok "DHCP lease ($LEASE)"
else
    bad "DHCP failed"; cat /tmp/lease.out
fi
sleep 3
F=$(ip netns exec $CNS curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://${FAKE}:8000/ 2>/dev/null)
[ "$F" = 000 ] && ok "unpaid client blocked" || bad "unpaid reached internet: $F"
"$BIN" grant "$CMAC" quick >/dev/null 2>&1 && ok "grant" || bad "grant failed"
F=$(ip netns exec $CNS curl -s -o /dev/null -w '%{http_code}' --max-time 6 http://${FAKE}:8000/ 2>/dev/null)
[ "$F" = 200 ] && ok "paid client reaches the internet through station uplink + NAT" || bad "paid path broken: $F"
"$BIN" revoke "$CMAC" >/dev/null 2>&1
F=$(ip netns exec $CNS curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://${FAKE}:8000/ 2>/dev/null)
[ "$F" = 000 ] && ok "revoke cuts instantly" || bad "still online: $F"
