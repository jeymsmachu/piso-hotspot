# Releasing

## Channels

| Channel | Source | Where it lands |
| --- | --- | --- |
| `release` | Tag `vX.Y.Z` on `main` | `/releases/latest/download/...` (default `install.sh` channel) |
| `nightly` | Every push to `main` + daily | `/releases/download/nightly/...` (`install.sh --nightly`) |

Asset names are a **public contract** — never add version numbers to
them; README and the installer link by name.

## Cut a release

1. Bump `version` in `Cargo.toml` (e.g. `0.1.0` → `0.1.1`), commit, push.
   CI must be green on `main`.
2. Tag it — the tag *must* equal `v<Cargo.toml version>`; the release
   workflow refuses otherwise:
   ```bash
   git tag v0.1.1 && git push origin v0.1.1
   ```
3. `release.yml` builds all formats, generates release notes
   (categorized by labels), uploads assets + `sha256sums.txt`, and
   marks the release `latest`.
4. Verify on a clean machine: `curl -fsSL ... | bash` (the release
   channel), then the manual hardware gate below.

## Manual hardware gate (no CI runs this)

The unit suite needs no hardware; this checklist does. Run it against
the **release artifacts**, not a debug build:

- [ ] `doctor` reports the expected modes
- [ ] `start` brings up AP + DHCP + paywall; portal shows for a fresh
      client; HTTPS probes fail fast
- [ ] `grant`/`revoke`/`friend` work; expiry cuts the device off
- [ ] Panel reachable, login works, pass sale shows up
- [ ] `stop` tears everything down; radio handed back to NetworkManager
- [ ] Repeat with UFW active

Empirically: the paywall, portal, panel, DHCP, and NAT paths were
developed against virtual radios (`mac80211_hwsim`). Those harnesses
are throwaway — kept in `/tmp`, not the tree — so restore them from git
history if you need them again.

## Version policy

Stay `0.x` while the beta warning is in the README. Bump: patch for
fixes, minor for breaking config/CLI changes. Pre-release suffixes are
available (`v0.2.0-beta.1`) if a release candidate is ever needed;
they do **not** take `latest`.