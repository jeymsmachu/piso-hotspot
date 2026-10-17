# Install

Three paths, depending on what you want.

## From source

```console
cargo build --release
sudo install -m755 target/release/piso-hotspot /usr/local/bin/
```

Runtime dependencies (package names on Arch, equivalents elsewhere):

```console
sudo pacman -S iw hostapd dnsmasq nftables
```

That is the whole install: there is no service, daemon user, or state
directory to create. `piso-hotspot start` is the program.

## systemd

The unit expects the binary at `/usr/bin/piso-hotspot` (the packaging
convention). Either install there, or edit `ExecStart`/`ExecStop` to
match `/usr/local/bin`.

```console
sudo install -m755 target/release/piso-hotspot /usr/bin/
sudo install -m644 packaging/piso-hotspot.service /etc/systemd/system/
sudo install -D -m644 docs/config.example.json /etc/piso-hotspot/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now piso-hotspot
```

`systemctl start` runs `piso-hotspot start` (which forks the daemon and
returns once it answers on the control socket); `systemctl stop` runs
`piso-hotspot stop`, which tears down the AP, DHCP, NAT rules, and UFW
rules it added, then hands the radio back to NetworkManager.

Notes:

- **Never suspend while the hotspot runs.** A suspended host drops
  every association and stops enforcing the paywall. Mask sleep targets
  (`systemctl mask sleep.target suspend.target`) or set the unit's
  suspend behaviour to refuse.
- The unit sets `Restart=no` on purpose: a half-applied teardown is
  worse than a stopped hotspot, and `start` re-runs cleanup for a
  crashed previous run before it brings anything up.
- The panel listens on the gateway address (and the uplink address when
  one exists); there is no TLS. Treat the admin passphrase as a LAN
  credential, not an internet one.

## AUR

Not published yet. The packaging above is enough for a PKGBUILD:
`depends=(iw hostapd dnsmasq nftables)`, `install -Dm755` the binary,
`install -Dm644` the unit and example config.

# Updating

State lives in `/etc/piso-hotspot/state.db` (SQLite). The binary
migrates its schema on open; keep a copy before a major upgrade if the
sales history matters:

```console
sudo sqlite3 /etc/piso-hotspot/state.db ".backup /root/piso-state-backup.db"
```

# Uninstalling

```console
sudo piso-hotspot stop
sudo systemctl disable --now piso-hotspot   # if the unit was used
sudo rm -f /usr/local/bin/piso-hotspot
sudo rm -rf /etc/piso-hotspot /etc/systemd/system/piso-hotspot.service
```

`stop` already removed every firewall rule, address, and interface the
program created.
