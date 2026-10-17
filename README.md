# piso-hotspot

Pay-per-usage wifi hotspot for Linux. Students connect, the operator sells
timed passes, and only paying devices get internet — enforced in the kernel
firewall, per MAC address.

Works with whatever uplink you have: a USB-tethered phone, an ethernet cable,
a second wifi radio, or — on radios whose driver advertises station+AP
concurrency — the same wifi card that carries the internet.

## Status

Early development. The only command today is `doctor` (below); the hotspot
itself, the paywall, and the admin panel are being rebuilt here.

## Requirements

- Linux with `iw`, `hostapd`, `dnsmasq`, and `nft` (nftables) installed
- A wifi radio that supports AP mode (`piso-hotspot doctor` tells you)
- Root, for starting the hotspot (not needed for `doctor`)

## `piso-hotspot doctor`

Inspects the machine and reports what could work. Changes nothing.

```console
$ piso-hotspot doctor
Host
  hostname   school-laptop
  kernel     6.12.9-arch1-1
  root       no (starting the hotspot will need sudo)

Dependencies
  iw             ok       /usr/bin/iw
  hostapd        ok       /usr/bin/hostapd
  dnsmasq        missing  required by: hotspot, dual-radio, wifi-uplink
  nft            ok       /usr/bin/nft
  bluetoothctl   ok       /usr/bin/bluetoothctl

Radios
  wlan0  (phy0, rtw88_8821ce)
         bands: 2.4 GHz, 5 GHz
         AP mode: yes   station+AP: yes (shares one channel)
         station: connected to "SchoolNet" on channel 36

Uplinks
  usb0       usb-tether default route

Modes
  hotspot      available   uplink usb0 (UsbTether)
  dual-radio   unavailable only one radio present
  wifi-uplink  available   single radio wlan0 does both; the AP follows the station's channel and band; station connected
  bluetooth    available   phone must be paired with Bluetooth tethering switched on
  offline      available   no internet; paywall and panel can be tested

State
  config     /etc/piso-hotspot/config.json (not created yet; defaults apply)
  state.db   /etc/piso-hotspot/state.db (not created yet)

verdict: ok — at least one hotspot mode is available
```

- Exit code `0` when at least one mode is available, `1` when none is.
- `--json` prints the same report as JSON, for scripts.

### The modes

| Mode | Uplink | Needs |
|---|---|---|
| `hotspot` | USB-tethered phone or ethernet | Any AP-capable radio |
| `dual-radio` | Wifi (station) | Two wifi radios |
| `wifi-uplink` | Same wifi card, simultaneously | Driver advertising station+AP concurrency |
| `bluetooth` | Paired phone, Bluetooth tethering | `bluetoothctl`, a paired phone |
| `offline` | None | Nothing; tests the paywall |

`wifi-uplink` is available when the kernel reports the right interface
combination (`iw list` → "valid interface combinations"). Most stock laptop
cards do not; some Realtek cards do after a driver patch, and some cards
advertise it out of the box. The doctor reads what the kernel actually
offers — it does not care which driver or patch produced it.

## Development

```console
cargo test          # unit tests, no root or hardware needed
cargo run -- doctor # inspect this machine
```

## License

MIT OR Apache-2.0.
