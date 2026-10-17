#!/usr/bin/env bash
# P1 live smoke, offline edition — no netns, no fake uplink, no NAT.
#
# `start --offline` brings up AP + DHCP + the paywall with the gateway
# address on the AP interface itself. A real client proves the gate by
# DHCP/DNS/ping behavior; we prove enforcement by deleting the paywall
# table out from under the daemon and watching the reconciler reinstall
# it (the fail-closed property). Wifi drops mid-run; step 5 stops and
# restores before exit.

# Resolve the binary next to this script (repo layout), so the script
# works regardless of where the repo is cloned.
BIN="$(cd "$(dirname "$0")" && pwd)/target/debug/piso-hotspot"
PASS=0; FAIL=0
ok()  { echo "PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }
section() { echo; echo "===== $* ====="; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
clean() {
    "$BIN" stop >/dev/null 2>&1
    rm -f /etc/piso-hotspot/config.json \
          /etc/piso-hotspot/state.db /etc/piso-hotspot/state.db-wal /etc/piso-hotspot/state.db-shm
    rm -rf /run/piso-hotspot
    [ -f /run/piso-hotspot/daemon.log ] && { echo "--- daemon.log tail ---"; tail -40 /run/piso-hotspot/daemon.log; }
    exit "$1"
}
echo "pre-test ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)  ssid-was-configured"

section "1. start --offline"
"$BIN" start --offline || clean 1
check "hostapd running"      pgrep -x hostapd
check "dnsmasq running"      pgrep -x dnsmasq
check "paywall table exists" nft list table inet piso
check "wlan0 is AP"          sh -c 'iw dev wlan0 info | grep -q "type AP"'
check "gateway address set"  sh -c 'ip -4 addr show wlan0 | grep -q 10.10.0.1'
check "ip_forward=1"         sh -c 'grep -qx 1 /proc/sys/net/ipv4/ip_forward'
echo "--- forward chain:"
nft list chain inet piso forward 2>/dev/null || bad "cannot list forward chain"

section "2. client connected?"
echo "Connect a phone/wifi client to the 'piso-hotspot' network now."
echo "(paywall drops its forwarded traffic; DHCP/DNS/ping-gateway still work)"
CLIENT_MAC=""
for i in $(seq 1 90); do
    [ -s /run/piso-hotspot/dnsmasq.leases ] && { CLIENT_MAC=$(awk 'NR==1{print $2}' /run/piso-hotspot/dnsmasq.leases); break; }
    sleep 1
done
if [ -n "$CLIENT_MAC" ]; then
    ok "client got a DHCP lease: $CLIENT_MAC"
    # The reconciler ingests leases once per tick (15s); give it time.
    TRACKED=""
    for i in $(seq 1 25); do
        if "$BIN" list 2>/dev/null | grep -qiF "$CLIENT_MAC"; then TRACKED=1; break; fi
        sleep 1
    done
    if [ -n "$TRACKED" ]; then ok "device tracked in store"; else bad "device never appeared in list"; fi
else
    bad "no client leased an address in 90s (skipping client assertions)"
fi

section "3. fail-closed reconciliation"
nft delete table inet piso && echo "deleted paywall table out from under the daemon"
sleep 20   # one reconcile tick (15s) + margin
check "reconciler reinstalled the table" nft list table inet piso
if [ -n "$CLIENT_MAC" ]; then
    check "client is NOT in the allowed set (still unpaid)" \
        sh -c "! nft list set inet piso allowed | grep -qi '$CLIENT_MAC'"
fi

section "4. grant + revoke reflected in the kernel set"
if [ -n "$CLIENT_MAC" ]; then
    "$BIN" grant "$CLIENT_MAC" quick   && ok "grant command succeeded" || bad "grant failed"
    check "client now in allowed set"  sh -c "nft list set inet piso allowed | grep -qiF '$CLIENT_MAC'"
    "$BIN" revoke "$CLIENT_MAC"        && ok "revoke command succeeded" || bad "revoke failed"
    check "client removed from allowed set" sh -c "! nft list set inet piso allowed | grep -qiF '$CLIENT_MAC'"
    echo "--- piso-hotspot list:"
    "$BIN" list || bad "list failed"
else
    echo "skipping: no client"
fi

section "5. stop and restore"
"$BIN" stop || bad "stop failed"
sleep 1
check "hostapd gone"     sh -c '! pgrep -x hostapd'
check "dnsmasq gone"     sh -c '! pgrep -x dnsmasq'
nft list table inet piso >/dev/null 2>&1 && bad "paywall table still present" || ok "paywall table removed"
check "ip_forward restored" sh -c 'grep -qx 0 /proc/sys/net/ipv4/ip_forward'
nmcli -t -f GENERAL.NM-MANAGED device show wlan0 2>/dev/null | grep -q ':yes$' \
    && ok "NM manages wlan0 again" || bad "wlan0 still unmanaged"
for i in $(seq 1 45); do
    ip -4 addr show wlan0 | grep -q '192.168' && break
    sleep 1
done
ip -4 addr show wlan0 | grep -q '192.168' && ok "wlan0 reconnected to home wifi" || bad "wlan0 did not reconnect"
ping -c2 -W2 1.1.1.1 >/dev/null 2>&1 && ok "real internet restored" || echo "WARN: real internet not back yet"

echo; echo "===== summary ====="; echo "$PASS passed, $FAIL failed"
clean "$FAIL"
