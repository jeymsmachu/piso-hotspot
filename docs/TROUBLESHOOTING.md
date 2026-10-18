# Troubleshooting

Start with `piso-hotspot doctor` — it is read-only and tells you what
your hardware can do before you change anything.

## `doctor` reports no AP-capable radio

- Most laptops' built-in adapters can beacon; many cheap USB dongles
  cannot (or cannot reliably). Try a different adapter or a wired→AP
  setup.
- Drivers matter: check your kernel/module (`lspci`, `dmesg | grep -i
  firmware`). A patched driver is sometimes required — the `--wifi-uplink`
  support used to depend on one for the RTL8821CE.
- If `doctor` shows AP mode but no mode is *selectable* because the
  uplink radio and AP radio would collide, you need a second radio
  (`--dual-radio`) or a client+AP-capable one (`--wifi-uplink`).

## The hotspot starts but my machine's Wi-Fi drops

Expected with one radio: it is busy being the AP. Use `--dual-radio`
(two radios) or `--wifi-uplink` (one driver that supports both at
once).

## Clients can't reach the portal / panel

- Check the gateway: the panel answers on `http://10.10.0.1:8080` by
  default. `sudo piso-hotspot status` prints the addresses and the
  admin passphrase.
- Is UFW active? piso-hotspot opens exactly the ports it needs on the
  AP interface at start, but only if it detects UFW. `sudo ufw status`
  — restart the hotspot after changing UFW.
- Disable other DHCP/DNS servers on the same interface (systemd-resolved
  with dnsmasq, other hostapd instances). Two servers on one interface
  means nobody gets a lease.

## A client connects but HTTPS just hangs

Normal. The portal refuses HTTPS probes immediately so browsers fall
back to HTTP and the portal — DNS is never tampered with. If the browser
keeps trying HTTPS, it is showing a stale connection; reconnect the
client.

## Everything worked, then stopped at midnight / after a time

Passes have expiries (`duration_secs`, or until local midnight). Check
`sudo piso-hotspot list` and re-grant if needed.

## The laptop suspends and everything dies

A suspended host drops all associations and stops enforcing the
paywall. Do not sleep while the hotspot runs: on AC power, or
`systemctl mask sleep.target suspend.target` (see docs/INSTALL.md).

## Logs

The daemon logs to `/run/piso-hotspot/daemon.log` while running. All
state (sold passes, devices, friends) is in
`/etc/piso-hotspot/state.db`.

## Nothing else helped

Open an issue with the bug template: distro + `uname -r`, adapter
chipset, `piso-hotspot doctor` output, the exact start command, and the
daemon log tail. Hardware bugs without `doctor` output are very hard to
triage.