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

- **Suspend kills the wifi session.** A suspended host drops every
  association. The daemon notices the resume (a wall-clock jump), logs
  it, re-asserts the access point and the firewall, and the hotspot
  serves again — but clients have to rejoin the wifi either way. To
  avoid the gap entirely, mask sleep targets
  (`systemctl mask sleep.target suspend.target`) while the hotspot runs.
- The unit sets `Restart=on-failure` with a burst limit: a crashed run
  is brought back by systemd (after `start` re-ran cleanup for its
  predecessor), while a crash loop stops after three tries instead of
  hammering the radio.
- The panel listens on the gateway address (and the uplink address when
  one exists). It serves HTTPS by default (a generated self-signed
  certificate; `http` and a certificate file are options in the
  config). Treat the admin passphrase as a LAN credential, not an
  internet one.

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
sudo piso-hotspot wipe-data                 # deletes config, state, unit, run files; asks for confirmation
sudo rm -f /usr/local/bin/piso-hotspot
```

`stop` already removed every firewall rule, address, and interface the
program created. `wipe-data` never touches the binary itself or files
in the config directory it did not create.
