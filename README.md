# piso-hotspot

**Turn your Linux machine into a hotspot, sell time-limited internet passes, and manage access from your phone or the command line—yay!**

Connect a device, collect payment, grant a pass, and let the internet party begin. Devices without an active pass see your captive portal and payment instructions instead of getting online.

> **Tiny but important detail:** piso-hotspot manages access and pass sales; it doesn't collect or process the payment for you. That's still between you and your customer.

You'll need a Linux machine with a Wi-Fi adapter that supports access-point mode, plus an internet connection to share. (Offline mode is available for testing.)

## Status and caution

This project is still in **beta!** It contains LLM-generated and LLM-assisted code, so bugs—and, yes, potential security holes—are possible. Starting the hotspot changes network and firewall settings and requires root/`sudo` privileges. Try it only on a machine and network you control, and use it at your own discretion!

## Installation

### 1. Install the dependencies

`iw`, `hostapd`, `dnsmasq`, `nft` (nftables), and `ip` (iproute2) are required. Bluetooth tethering works through a normal network interface, so it needs no extra package.

| Distribution | Command |
| --- | --- |
| Debian / Ubuntu | `sudo apt update && sudo apt install -y iw hostapd dnsmasq nftables iproute2` |
| Arch / Manjaro | `sudo pacman -S iw hostapd dnsmasq nftables iproute2` |
| Fedora | `sudo dnf install iw hostapd dnsmasq nftables iproute` |
| openSUSE | `sudo zypper install iw hostapd dnsmasq nftables iproute2` |
| Alpine | `sudo apk add iw hostapd dnsmasq nftables iproute2` |

### 2. Install piso-hotspot

Pick the artifact for your machine and distribution:

| Architecture | Binary | Debian / Ubuntu | Fedora / RHEL | AppImage |
| --- | --- | --- | --- | --- |
| x86-64 (most Intel/AMD PCs) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64-unknown-linux-gnu) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64-unknown-linux-gnu) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-amd64.deb) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-amd64.deb) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64.rpm) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64.rpm) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-x86_64.AppImage) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-x86_64.AppImage) |
| ARM64 / AArch64 | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64-unknown-linux-gnu) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64-unknown-linux-gnu) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-arm64.deb) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-arm64.deb) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64.rpm) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64.rpm) | [stable](https://github.com/jeymsmachu/piso-hotspot/releases/latest/download/piso-hotspot-aarch64.AppImage) · [nightly](https://github.com/jeymsmachu/piso-hotspot/releases/download/nightly/piso-hotspot-aarch64.AppImage) |

**Stable** is the sensible pick for everyday use; **nightly** is rebuilt from `main` and is for trying the freshest changes (and potentially fresher bugs). Every release ships a `sha256sums.txt`.

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

Arch users should build the package from the release tag instead of using a hosted binary, so it links against the local system correctly:

```bash
git clone https://github.com/jeymsmachu/piso-hotspot.git
cd piso-hotspot/packaging/aur && makepkg -si
```

### 3. Check the machine

```bash
piso-hotspot doctor
```

`doctor` only inspects your system; it changes nothing. It reports the radios it found, whether each supports AP mode (and whether one radio can be a client and an AP at the same time), the uplinks it can share, and which modes are available. If no hotspot mode is available, it says what is missing. It exits non-zero in that case, so scripts can rely on it.

### Or, build it yourself

You'll need Git and the stable Rust toolchain. Get Rust from [rustup.rs](https://rustup.rs/), then:

```bash
git clone https://github.com/jeymsmachu/piso-hotspot.git
cd piso-hotspot
cargo build --release --locked
sudo install -Dm755 target/release/piso-hotspot /usr/local/bin/piso-hotspot
```

## Usage

### Fire it up

```bash
sudo piso-hotspot start    # AP + DHCP + paywall, sharing the default route
sudo piso-hotspot stop     # tear everything down, hand the radio back
```

`start` refuses before touching anything when no uplink is available, and installs the paywall *before* forwarding is enabled so no device ever sees ungated internet.

There are three more ways to start it:

| Mode | Use when | Needs |
| --- | --- | --- |
| `sudo piso-hotspot start --dual-radio` | You have two radios and want the laptop to stay online over Wi-Fi while the other radio beacons | Two radios, one connected as a Wi-Fi client |
| `sudo piso-hotspot start --wifi-uplink` | You have one radio whose driver supports client+AP at the same time | A driver advertising that combination (`doctor` says) |
| `sudo piso-hotspot start --offline` | You want to test the paywall and panel without internet | Nothing — but see the warning below |

**Wi-Fi heads-up:** in the default mode the radio used for the hotspot is busy being an access point, so the machine's own Wi-Fi connection may drop. `--dual-radio` and `--wifi-uplink` exist to avoid that.

**Offline warning:** `--offline` still spends an AP-capable radio. On a laptop where that is the same radio carrying your internet, you will lose connectivity for the duration.

If several radios or uplinks are available, pin them in the config (`ap.interface`, `ap.uplink`) instead of relying on auto-selection. With two connected Wi-Fi stations and no pinned uplink, `--dual-radio` refuses rather than guessing.

### Open the admin panel

```bash
sudo piso-hotspot status
```

It prints the mode, the gateway, the panel addresses, and the admin passphrase. The panel answers on the gateway (`http://10.10.0.1:8080`), on the machine itself, and on the uplink address — so a phone on either side of the link can run it. Open one of those addresses and sign in.

From the panel you can see devices and active passes, watch traffic and sales, sell passes with one tap, revoke access, rename devices, and give trusted devices free access. The panel is plain HTTP on your local network; the passphrase is a local credential, not an internet-facing one.

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

Enforcement is per MAC address in the kernel firewall: joining the Wi-Fi is not enough to get online, and `revoke` cuts existing connections on the next packet.

### What students see

Unpaid devices get any HTTP address redirected to the portal, which shows your message, payment instructions, and the pass list. DNS is not tampered with, and HTTPS is refused immediately rather than dropped, so browsers fall back to the portal instead of hanging.

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

## Keeping it running

The daemon survives a closed terminal, so the panel and paywall keep working. **A suspended machine does not:** it drops every connection and stops enforcing the paywall. Disable sleep while the hotspot runs (on AC power), or mask the sleep targets. A systemd unit and install notes are in [docs/INSTALL.md](docs/INSTALL.md).

If UFW is active, piso-hotspot opens exactly the ports the hotspot needs — DHCP, DNS, portal, and panel — scoped to the AP interface, and removes them at stop. Without that, UFW's INPUT chain silently eats those packets before the paywall rules ever see them.

## Hacking on it

```bash
cargo test                          # unit tests, no root or hardware needed
cargo run -- doctor                 # inspect this machine
```

The paywall, portal, panel, DHCP, and NAT path are exercised end to end on virtual radios, so the real card is never touched:

```bash
scripts/hwsim-setup.sh              # once: venv with scapy for the DHCP client
sudo scripts/hwsim-matrix.sh        # 24 checks, two radios + veth "internet"
sudo scripts/hwsim-dual-radio.sh    # dual-radio mode, four radios
```

`piso-smoke.sh` is the interactive hardware counterpart; it refuses to run when the chosen AP interface carries the default route, because that would disconnect the machine mid-test.

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
