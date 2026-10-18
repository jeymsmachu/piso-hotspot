#!/usr/bin/env bash
# piso-hotspot installer.
#
#   curl -fsSL https://raw.githubusercontent.com/jeymsmachu/piso-hotspot/main/install.sh | bash
#
# Options (pass after `bash install.sh`, or as env vars when piping):
#   --nightly      install the nightly build instead of the latest release
#   --prefix DIR   install location (default: /usr/local/bin)
#   PISO_CHANNEL / PISO_PREFIX env equivalents for the curl | bash case.
#
# Works without prompting: safe to pipe. sudo (if needed) is invoked on
# the single install step only.
set -euo pipefail

CHANNEL="${PISO_CHANNEL:-release}"
PREFIX="${PISO_PREFIX:-/usr/local/bin}"
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly)  CHANNEL=nightly ;;
        --prefix)   PREFIX="${2:?--prefix needs a directory}"; shift ;;
        --prefix=*) PREFIX="${1#*=}" ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

REPO="jeymsmachu/piso-hotspot"
case "$CHANNEL" in
    release) BASE="https://github.com/$REPO/releases/latest/download" ;;
    nightly) BASE="https://github.com/$REPO/releases/download/nightly" ;;
    *) echo "unknown channel: $CHANNEL" >&2; exit 2 ;;
esac

step() { printf '\n==> %s\n' "$*"; }

# ------------------------------------------------------------- architecture
case "$(uname -m)" in
    x86_64|amd64)          TARGET="x86_64-unknown-linux-gnu";  ARCH_LABEL="x86-64" ;;
    aarch64|arm64)         TARGET="aarch64-unknown-linux-gnu"; ARCH_LABEL="ARM64 (AArch64)" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
ASSET="piso-hotspot-$TARGET"
printf 'Detecting system architecture... %s detected!\n' "$ARCH_LABEL"

# ------------------------------------------------------------- fetch binary
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step "Installing ($ASSET)..."
URL="$BASE/$ASSET"
# curl's meter is noisy; drive the bar ourselves off Content-Length.
# The probe must not kill the script (pipefail + 404 would abort here
# before the friendly message below ever runs).
SIZE=$( { curl -fsIL "$URL" 2>/dev/null || true; } \
        | tr -d '\r' \
        | awk 'tolower($1)=="content-length:"{print $2}' \
        | tail -1 )
case "$SIZE" in ''|*[!0-9]*) SIZE="" ;; esac
if [ -n "$SIZE" ] && [ "$SIZE" -gt 0 ] 2>/dev/null; then
    curl -fL -o "$TMP/$ASSET" "$URL" 2>/dev/null &
    DL=$!
    while kill -0 "$DL" 2>/dev/null; do
        GOT=$(stat -c%s "$TMP/$ASSET" 2>/dev/null || echo 0)
        PCT=$((GOT * 100 / SIZE))
        BAR=$((PCT / 5))
        printf '\rInstalling (%s)... [%-20s] %3d%%' "$ASSET" \
            "$(printf '#%.0s' $(seq 1 $BAR))" "$PCT"
        sleep 0.2
    done
    wait "$DL" || { echo; echo "download failed: $URL" >&2; exit 1; }
    printf '\rInstalling (%s)... [%-20s] 100%%\n' "$ASSET" "$(printf '#%.0s' $(seq 1 20))"
else
    # No Content-Length (or HEAD blocked): plain download.
    curl -fL -o "$TMP/$ASSET" "$URL" || { echo "download failed: $URL" >&2; exit 1; }
    echo "done."
fi

# Checksum, when the release publishes one. Missing sums file or missing
# entry is tolerated (older releases); a mismatching entry is fatal.
if curl -fsSL -o "$TMP/sha256sums.txt" "$BASE/sha256sums.txt" 2>/dev/null; then
    WANT="$(grep " $ASSET\$" "$TMP/sha256sums.txt" | awk '{print $1}')"
    GOT="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
    if [ -n "$WANT" ] && [ "$WANT" != "$GOT" ]; then
        echo "checksum mismatch for $ASSET" >&2
        echo "  want $WANT" >&2
        echo "  got  $GOT" >&2
        exit 1
    fi
    if [ -n "$WANT" ]; then
        echo "checksum ok"
    fi
fi

# ------------------------------------------------------------- dependencies
step "Checking runtime dependencies..."
MISSING=""
for tool in iw hostapd dnsmasq nft ip; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    echo "  missing:$MISSING"
    echo "  install them with:"
    if   command -v apt-get >/dev/null 2>&1; then echo "    sudo apt install iw hostapd dnsmasq nftables iproute2"
    elif command -v pacman  >/dev/null 2>&1; then echo "    sudo pacman -S iw hostapd dnsmasq nftables iproute2"
    elif command -v dnf     >/dev/null 2>&1; then echo "    sudo dnf install iw hostapd dnsmasq nftables iproute"
    elif command -v zypper  >/dev/null 2>&1; then echo "    sudo zypper install iw hostapd dnsmasq nftables iproute2"
    elif command -v apk     >/dev/null 2>&1; then echo "    sudo apk add iw hostapd dnsmasq nftables iproute2"
    fi
    echo "  (they are only needed when the hotspot runs; installing now is up to you)"
else
    echo "  all present"
fi

# ------------------------------------------------------------- install
step "Placing binary in $PREFIX..."
SUDO=""
if [ "$(id -u)" != 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO=sudo
    else
        echo "not root and no sudo available" >&2
        echo "re-run with a writable --prefix, e.g. --prefix ~/.local/bin" >&2
        exit 1
    fi
fi
if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    echo "sudo needs your password; if piping this script, run it on a terminal"
fi
$SUDO install -Dm755 "$TMP/$ASSET" "$PREFIX/piso-hotspot"

"$PREFIX/piso-hotspot" --version
step "Done. Run 'piso-hotspot doctor' to see what your machine can do."
