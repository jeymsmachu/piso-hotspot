# Contributing

Thanks for looking. This is a small, beta, mostly-solo project, so
conventions lean toward boring and reviewable.

## What kind of change

- **Bug** — fix it, add a regression test if one is practical, note the
  hardware it reproduced on.
- **Enhancement** — open an issue first for anything non-trivial; a
  design note beats a surprise PR.
- **Docs** — do it in the same PR as the code change, not after.

Label unclear? Use the issue forms; they apply the right labels.

## Setup

Rust stable + `cargo test` is all you need for the unit suite — no root
and no radio hardware required:

```bash
cargo test                      # unit tests
cargo run -- doctor             # inspect this machine (needs no root)
```

To exercise the real thing you need root and an AP-capable radio.
`doctor` tells you what your machine can do before you start anything.

## Building and installing

```bash
cargo build --release --locked
sudo install -Dm755 target/release/piso-hotspot /usr/local/bin/piso-hotspot
piso-hotspot doctor
```

## Development rules

- **No throwaway scripts in the tree.** Harnesses, smoke tests, and
  other one-shot helpers belong in `/tmp`, not under `scripts/` or the
  repo root. If a pull request adds one, expect a request to move it.
- **Never version release asset names.** README and the installer link
  to stable, human names (`/releases/latest/download/...`); version
  numbers live in the tag, not the file.
- **Docs move with code.** User-visible changes (flags, config, error
  messages) update `README.md`, `docs/`, and the man/completion output
  in the same commit.

## Committing

- Imperative subject line, `scope:` prefix when it helps:
  `ci: pin actions to full SHAs`, `panel: show tomorrow's expiry`.
- One logical change per commit. Rebase and squash locally; the repo
  merges squashed anyway.

## Pull requests

1. Fork, branch off `main`, push.
2. Open the PR against `main`. CI runs format, clippy `-D warnings`,
   tests, a release build, and package inspection; **main requires all
   checks to pass** before anything merges.
3. Note in the description which labels to apply and any hardware you
   verified against (issue forms ask for `piso-hotspot doctor` output —
   include it for bug fixes touching radio/AP paths).

## Reporting security issues

Do **not** open a public issue. piso-hotspot runs as root and edits the
firewall, so treat any bug there as security-sensitive. Use GitHub's
private vulnerability reporting — see `SECURITY.md`.

## Labels

The glossary, roughly: `bug` / `enhancement` / `documentation` /
`security` / `performance` / `dependencies` say what kind of work it is;
`area: …` (`daemon`, `radio`, `firewall`, `portal`, `panel`, `passes`,
`cli`, `packaging`, `ci`) say where. `question`, `good first issue`,
`help wanted`, `duplicate`, `invalid`, `wontfix` are triage helpers.