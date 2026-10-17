#!/usr/bin/env bash
# Prepare the Python environment the hwsim harnesses use for DHCP.
# scapy is not packaged for every distro; a throwaway venv keeps it out
# of the system Python (Arch refuses pip installs outside a venv).
#
#   scripts/hwsim-setup.sh
set -eu
command -v uv >/dev/null 2>&1 || {
    echo "uv is required (https://docs.astral.sh/uv/): pacman -S uv" >&2
    exit 2
}
uv venv /tmp/dcvenv -q
uv pip install --python /tmp/dcvenv/bin/python scapy -q
/tmp/dcvenv/bin/python -c 'import scapy; print("scapy", scapy.__version__)'
echo "ready: /tmp/dcvenv/bin/python"
