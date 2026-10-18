<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="packaging/assets/logo-white.png">
  <img src="packaging/assets/logo.png" alt="piso-hotspot logo" width="240">
</picture>

# piso-hotspot

**Turn your Linux machine into a hotspot, sell time-limited internet passes, and manage access from your phone or the command line—yay!**

[![CI](https://github.com/jeymsmachu/piso-hotspot/actions/workflows/ci.yml/badge.svg)](https://github.com/jeymsmachu/piso-hotspot/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jeymsmachu/piso-hotspot)](https://github.com/jeymsmachu/piso-hotspot/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

[Installation](#installation) · [Usage](#usage) · [Configuration](#making-it-yours) · [Contributing](CONTRIBUTING.md) · [FAQ](#faq)

</div>

---

## Why "piso"?

In the Philippines, *piso* is the peso coin — and "piso wifi" is the coin-operated Wi-Fi vending machine you'll find outside sari-sari stores, in waiting sheds, and along busy streets: insert ₱1, get minutes of internet. piso-hotspot is that idea, running on a laptop you already own: share your connection, sell time-limited passes, and keep it all under your control.

> **Tiny but important detail:** piso-hotspot manages access and pass sales; it doesn't collect or process the payment for you. That's still between you and your customer.

## How does it work?

1. A device connects to the hotspot's Wi-Fi. It can associate, get an address, and resolve names — but the kernel firewall drops its internet traffic.
2. Any web page it tries to open lands on **your captive portal**: your message, your payment instructions, the pass menu. (DNS is never tampered with; HTTPS probes are refused immediately so browsers fall back instead of hanging.)
3. The customer pays you — cash, GCash, however you do it — and you grant a pass from your phone or the command line.
4. The pass lands in the firewall's allow-list, keyed by MAC address, and their traffic flows through NAT to the internet. When time is up, the same packet-level gate cuts them off.

Every step above is enforced in-kernel, per device: joining the Wi-Fi is not enough to get online, and one payer can't smuggle a friend's traffic through their own connection.

## Status and caution

This project is still in **beta!** It contains LLM-generated and LLM-assisted code, so bugs—and, yes, potential security holes—are possible. Starting the hotspot changes network and firewall settings and requires root/`sudo` privileges. Try it only on a machine and network you control, and use it at your own discretion!

## Installation

### Prerequisites

- A Linux machine with a Wi-Fi adapter that supports **access-point mode** (`piso-hotspot doctor` tells you)
- An internet connection to share: a USB-tethered phone or ethernet by default; a second Wi-Fi radio (`--dual-radio`), or one special radio that can do client+AP at once (`--wifi-uplink`)
- `iw`, `hostapd`, `dnsmasq`, `nftables`, and `iproute2` (the commands `iw`, `hostapd`, `dnsmasq`, `nft`, `ip`)

| Distribution | Command |
| --- | --- |
| Debian / Ubuntu | `sudo apt update && sudo apt install -y iw hostapd dnsmasq nftables iproute2` |
| Arch / Manjaro | `sudo pacman -S iw hostapd dnsmasq nftables iproute2` |
| Fedora | `sudo dnf install iw hostapd dnsmasq nftables iproute` |
| openSUSE | `sudo zypper install iw hostapd dnsmasq nftables iproute2` |
| Alpine | `sudo apk add iw hostapd dnsmasq nftables iproute2` |

### One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/jeymsmachu/piso-hotspot/main/install.sh | bash
```

It detects your architecture, shows a progress bar, verifies the checksum, checks the dependencies, and installs to `/usr/local/bin`. Add `--nightly` for the freshest build (and potentially fresher bugs). Prefer not to pipe curl into bash? [Read the script first](install.sh) — it's short.

### Packages and manual install

**x86-64 (most Intel/AMD PCs)**

- **Release** — [binary](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64-unknown-linux-gnu) · [.deb](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-amd64.deb) · [.rpm](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64.rpm) · [AppImage](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64.AppImage)
- **Nightly** — [binary](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64-unknown-linux-gnu) · [.deb](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-amd64.deb) · [.rpm](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64.rpm) · [AppImage](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64.AppImage)

**ARM64 / AArch64**

- **Release** — [binary](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64-unknown-linux-gnu) · [.deb](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-arm64.deb) · [.rpm](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64.rpm) · [AppImage](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64.AppImage)
- **Nightly** — [binary](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64-unknown-linux-gnu) · [.deb](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-arm64.deb) · [.rpm](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64.rpm) · [AppImage](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64.AppImage)

Debian / Ubuntu:

```bash
sudo apt install ./piso-hotspot-amd64.deb
```

Fedora / RHEL:

```bash
sudo dnf install ./piso-hotspot-x86_64.rpm
```

Raw binary or AppImage:

```bash
chmod +x piso-hotspot-x86_64.AppImage        # or the raw binary
sudo install -Dm755 piso-hotspot-x86_64.AppImage /usr/local/bin/piso-hotspot
```

Arch users: build from the release tag so it links against your system correctly — `packaging/aur/PKGBUILD` is in the repo, `makepkg -si` from `packaging/aur/` after checking out the tag.

Build from source instead? You'll need Git and the stable Rust toolchain from [rustup.rs](https://rustup.rs/):

```bash
git clone https://github.com/jeymsmachu/piso-hotspot.git
cd piso-hotspot
cargo build --release --locked
sudo install -Dm755 target/release/piso-hotspot /usr/local/bin/piso-hotspot
```

Then check the machine:

```bash
piso-hotspot doctor
```

`doctor` only inspects your system; it changes nothing. It reports the radios it found, whether each supports AP mode (and whether one radio can do client+AP at once), the uplinks it can share, and which modes are available. If no hotspot mode is available, it says what's missing — and exits non-zero, so scripts can rely on it.

## Usage

### Fire it up

```bash
sudo piso-hotspot start    # AP + DHCP + paywall, sharing the default route
sudo piso-hotspot stop     # tear everything down, hand the radio back
```

`start` refuses before touching anything when no uplink is available, and installs the paywall *before* forwarding is enabled so no device ever sees ungated internet.

Three more ways to start it:

| Mode | Use when | Needs |
| --- | --- | --- |
| `sudo piso-hotspot start --dual-radio` | You have two radios and want the laptop to stay online over Wi-Fi while the other beacons | Two radios, one connected as a Wi-Fi client |
| `sudo piso-hotspot start --wifi-uplink` | One radio whose driver supports client+AP at once | A driver advertising that combination (`doctor` says) |
| `sudo piso-hotspot start --offline` | Testing the paywall and panel without internet | Nothing — but see the warning |

**Wi-Fi heads-up:** in the default mode the hotspot radio is busy being an access point, so the machine's own Wi-Fi connection may drop. `--dual-radio` and `--wifi-uplink` exist to avoid that.

**Offline warning:** `--offline` still spends an AP-capable radio. On a laptop where that's the same radio carrying your internet, you'll lose connectivity for the duration.

Several radios or uplinks? Pin them in the config (`ap.interface`, `ap.uplink`) instead of relying on auto-selection — with two connected Wi-Fi stations and nothing pinned, `--dual-radio` refuses rather than guessing.

### Open the admin panel

```bash
sudo piso-hotspot status
```

It prints the mode, the gateway, the panel addresses, and the admin passphrase. The panel answers on the gateway (`http://10.10.0.1:8080`), on the machine itself, and on the uplink address — so a phone on *either* side of the link can run it. Open one of those addresses and sign in.

From the panel you can see devices and active passes, watch traffic and sales, sell passes with one tap, revoke access, rename devices, and give trusted devices free access. The panel is plain HTTP on your local network; treat the passphrase as a local credential, not an internet-facing one.

If you haven't set an admin passphrase in `/etc/piso-hotspot/config.json`, a fresh one is generated at every start and shown by `sudo piso-hotspot status`.

### Sell a pass

Out of the box, the pass menu looks like this:

| Pass | Price | Internet time |
| --- | ---: | --- |
| `quick` | ₱3 | 15 minutes |
| `extended` | ₱5 | 45 minutes |
| `day` | ₱15 | Until midnight |

Sell from the panel, or from the command line. Replace the example MAC address with your customer's device address:

```bash
sudo piso-hotspot grant AA:BB:CC:DD:EE:FF quick
```

A few other handy commands (all need root: the control socket is root-only):

```bash
sudo piso-hotspot list                         # devices, pass state, expiry
sudo piso-hotspot revoke AA:BB:CC:DD:EE:FF     # cut off internet access
sudo piso-hotspot friend AA:BB:CC:DD:EE:FF     # unlimited free access
sudo piso-hotspot unfriend AA:BB:CC:DD:EE:FF   # remove free access
sudo piso-hotspot friends                      # list free-access devices
piso-hotspot --help                            # every command
```

## Keeping it running

The daemon survives a closed terminal, so the panel and paywall keep working. **A suspended machine does not:** it drops every connection and stops enforcing the paywall. Disable sleep while the hotspot runs (on AC power), or mask the sleep targets. A systemd unit and more install notes live in [docs/INSTALL.md](docs/INSTALL.md).

If UFW is active, piso-hotspot opens exactly the ports the hotspot needs — DHCP, DNS, portal, and panel — scoped to the AP interface, and removes them at stop. Without that, UFW's INPUT chain silently eats those packets before the paywall rules ever see them.

## Making it yours

The optional configuration file lives at `/etc/piso-hotspot/config.json`. You can customize the hotspot name and password, pass prices and durations, the portal message and payment instructions, the admin passphrase, traffic caps, and which radio and uplink to use. If the file doesn't exist, defaults apply.

```json
{
  "ap": {
    "ssid": "Piso Hotspot",
    "passphrase": "change-this-wifi-password"
  },
  "admin": {
    "passphrase": "change-this-admin-password"
  },
  "blocked_page": {
    "payment_instructions": "Pay the operator to get a pass."
  }
}
```

Change both example passwords before using it. The Wi-Fi password must be 8–63 characters; the admin passphrase must be at least 8. An empty Wi-Fi password means the network is open to join — the paywall still controls internet access.

Every field is documented in [docs/CONFIG.md](docs/CONFIG.md), with a complete starting point in [docs/config.example.json](docs/config.example.json). Apply changes by restarting the hotspot; passes already sold keep their stored price and expiry.

## Hacking on it

The full workflow lives in [CONTRIBUTING.md](CONTRIBUTING.md); the short version:

```bash
cargo test                          # unit tests, no root or hardware needed
cargo run -- doctor                 # inspect this machine
```

## FAQ

**Will it work with my Wi-Fi adapter?**

Run `piso-hotspot doctor`. It only inspects; it tells you which radios
can beacon, whether one can do client+AP at once, and which start modes
your machine supports.

**Can it run on a Raspberry Pi?**

Yes — ARM64/AArch64 builds ship with every release and nightly, and the
daemon manages the radio and firewall exactly as on x86.

**Does it need an internet connection?**

Only to be useful. `start --offline` brings up the AP, paywall, and
panel without any uplink.

**Does it take payments?**

No. piso-hotspot manages access and pass sales; the money part stays
between you and your customer.

## Credits

Logo built with icons from [Icons8](https://icons8.com): [Hotspot](https://icons8.com/icon/OnFteDC8fjB4/hotspot) and [Peso symbol](https://icons8.com/icon/119775/peso-symbol).

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
