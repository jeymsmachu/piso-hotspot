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
    # Keep the log's last words before the run dir goes away.
    [ -f /run/piso-hotspot/daemon.log ] && { echo "--- daemon.log tail ---"; tail -40 /run/piso-hotspot/daemon.log; }
    rm -f /etc/piso-hotspot/config.json \
          /etc/piso-hotspot/state.db /etc/piso-hotspot/state.db-wal /etc/piso-hotspot/state.db-shm
    rm -rf /run/piso-hotspot
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

section "6. wifi-uplink: wifi stays, the AP rides beside it"
echo "Waiting for the station side to (re)connect..."
STATION_OK=""
for i in $(seq 1 45); do
    iw dev wlan0 link 2>/dev/null | grep -q "Connected to" && { STATION_OK=1; break; }
    sleep 1
done
if [ -z "$STATION_OK" ]; then
    bad "station not connected; wifi-uplink cannot be tested"
else
    ok "station connected before start"
    if "$BIN" start --wifi-uplink; then
        sleep 2
        check "station STILL connected while AP is up" sh -c 'iw dev wlan0 link | grep -q "Connected to"'
        check "ap0 exists as an AP interface" sh -c 'iw dev ap0 info | grep -q "type AP"'
        check "ap0 has the gateway address" sh -c 'ip -4 addr show ap0 | grep -q 10.10.0.1'
        check "hostapd running" pgrep -x hostapd
        ping -c2 -W2 1.1.1.1 >/dev/null 2>&1 \
            && ok "laptop KEEPS its own internet during the hotspot" \
            || bad "laptop lost internet in wifi-uplink mode"
        FREQ_ST=$(iw dev wlan0 link 2>/dev/null | awk '/freq:/{print int($2); exit}')
        FREQ_AP=$(iw dev ap0 info 2>/dev/null | sed -n 's/.*(\([0-9]\+\) MHz).*/\1/p' | head -1)
        if [ -n "$FREQ_ST" ] && [ -n "$FREQ_AP" ]; then
            [ "$FREQ_ST" = "$FREQ_AP" ] \
                && ok "ap0 beacons on the station's channel ($FREQ_ST MHz)" \
                || bad "channel mismatch: station=$FREQ_ST ap0=$FREQ_AP MHz"
        else
            echo "INFO: could not read both frequencies (station='$FREQ_ST' ap0='$FREQ_AP'); channel check skipped"
        fi

        echo ">>> Connect your phone to 'piso-hotspot' now (it may auto-reconnect by itself)"
        WIFI_CLIENT=""; WIFI_IP=""
        for i in $(seq 1 90); do
            if [ -s /run/piso-hotspot/dnsmasq.leases ]; then
                WIFI_CLIENT=$(awk 'NR==1{print $2}' /run/piso-hotspot/dnsmasq.leases)
                WIFI_IP=$(awk 'NR==1{print $3}' /run/piso-hotspot/dnsmasq.leases)
                break
            fi
            sleep 1
        done
        if [ -n "$WIFI_CLIENT" ]; then
            ok "phone leased an address on ap0: $WIFI_CLIENT ($WIFI_IP)"
            TRACKED=""
            for i in $(seq 1 25); do
                "$BIN" list 2>/dev/null | grep -qiF "$WIFI_CLIENT" && { TRACKED=1; break; }
                sleep 1
            done
            [ -n "$TRACKED" ] && ok "phone tracked in store" || bad "phone never appeared in list"

            "$BIN" grant "$WIFI_CLIENT" quick && ok "grant succeeded" || bad "grant failed"
            check "phone in allowed set" sh -c "nft list set inet piso allowed | grep -qiF '$WIFI_CLIENT'"
            echo ">>> OPEN ANY WEBSITE ON YOUR PHONE NOW — waiting up to 60s for its traffic"
            echo ">>> to cross the paywall and reach the real internet..."
            ALLOWED=0
            for i in $(seq 1 60); do
                N=$(nft list chain inet piso forward 2>/dev/null \
                    | awk '/@allowed/{for(j=1;j<=NF;j++) if($j=="packets"){print $(j+1); exit}}')
                [ "${N:-0}" -gt 0 ] && { ALLOWED=1; break; }
                sleep 1
            done
            if [ "$ALLOWED" = 1 ]; then
                ok "granted phone traffic reached the real internet (allowed counter > 0)"
            else
                bad "no traffic crossed the allowed rule in 60s"
            fi
        else
            bad "no phone connected within 90s; wifi-uplink client checks skipped"
        fi
    else
        bad "start --wifi-uplink failed"
    fi
fi

section "7. stop from wifi-uplink"
"$BIN" stop || bad "stop failed"
sleep 1
check "ap0 removed"        sh -c '! iw dev ap0 info 2>/dev/null'
check "hostapd gone"       sh -c '! pgrep -x hostapd'
check "dnsmasq gone"       sh -c '! pgrep -x dnsmasq'
nft list table inet piso >/dev/null 2>&1 && bad "paywall table still present" || ok "paywall table removed"
check "ip_forward restored" sh -c 'grep -qx 0 /proc/sys/net/ipv4/ip_forward'
check "station never lost its connection" sh -c 'iw dev wlan0 link | grep -q "Connected to"'
ping -c2 -W2 1.1.1.1 >/dev/null 2>&1 && ok "internet intact after wifi-uplink stop" || echo "WARN: internet not up yet"

echo; echo "===== summary ====="; echo "$PASS passed, $FAIL failed"
clean "$FAIL"
