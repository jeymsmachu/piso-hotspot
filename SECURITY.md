# Security

piso-hotspot runs as **root**, brings up network interfaces, and edits
the firewall. Treat anything in that path as security-sensitive.

## Report a vulnerability

Use GitHub's **private vulnerability reporting** — it goes to the
maintainer and stays hidden until publish:

<https://github.com/jeymsmachu/piso-hotspot/security/advisories/new>

Do **not** open a public issue for suspected security problems.

## Scope

In scope: the daemon and its root privileges, the nftables paywall and
NAT rules, DHCP/DNS handling, the admin panel and its session auth, the
captive portal (including HTML escaping), and config/state parsing.

Out of scope: threats requiring local access to the host, and the
business trust decision between you and your customer (who you hand
passes to is yours to manage).

## Supported builds

- The latest tagged release (`vX.Y.Z`).
- `nightly` and `main` are supported on a best-effort basis.

This is a beta, largely-solo project: expect best-effort response times
and a warning that unfixed bugs (including security ones) are possible.