# Configuration

`/etc/piso-hotspot/config.json` — `$PISO_HOTSPOT_CONFIG_DIR` overrides
the directory. Strict JSON: no comments, no trailing commas. Every
field is optional; anything omitted takes the default shown in
[`config.example.json`](config.example.json), and no file at all means
all defaults. The program never writes this file.

State (sold passes, device labels, friends) lives beside it in
`state.db` and is written by the program.

## `ap`

| Field | Default | Meaning |
|---|---|---|
| `ssid` | `piso-hotspot` | Name clients see, 1–32 bytes. No control characters, quotes, or backslashes. |
| `passphrase` | `""` | WPA2 passphrase, 8–63 printable ASCII characters. Empty means an open network (the paywall is the gate). |
| `channel` | `6` | 1–14 is 2.4 GHz, above that 5 GHz. Ignored in `wifi-uplink`, where the AP follows the station. |
| `max_clients` | `12` | Driver-level station cap. |
| `port` | `8080` | Admin panel port. `0` keeps the panel closed. |
| `isolate_clients` | `true` | Clients cannot reach each other directly. |
| `ieee80211n` | `true` | Advertise 802.11n rates. |
| `country_code` | `null` | Two-letter ISO code (`"PH"`). Unset lets the kernel decide. |
| `interface` | `null` | Force the beaconing radio (hosts with several). Must be AP-capable. |
| `uplink` | `null` | Force the internet egress. Unset uses the default route. |

## Money and passes

| Field | Default | Meaning |
|---|---|---|
| `gateway` | `10.10.0.1` | Hotspot gateway address; clients sit in its /24. |
| `currency` | `PHP` | ISO code used for display and stored with each sale. |
| `passes` | Quick/Extended/Day | What you sell. `price_minor` is the minor unit (centavos); `duration_secs: null` means until local midnight. |

## `blocked_page`

Unpaid clients see these on the portal. All fields are escaped before
rendering.

| Field | Default |
|---|---|
| `title` | `No internet yet` |
| `message` | `See the operator to buy a pass.` |
| `footer` | empty |
| `payment_instructions` | empty — e.g. your GCash number |
| `show_prices` | `true` |

## `admin`

| Field | Default | Meaning |
|---|---|---|
| `passphrase` | `""` | Panel login. Empty generates a random one each start; `piso-hotspot status` prints it. At least 8 characters when set. |

## `portal` and `ui`

| Field | Default | Meaning |
|---|---|---|
| `portal.enabled` | `true` | Redirect unpaid HTTP to the notice page. |
| `ui.theme` | `auto` | `auto`, `light`, or `dark`; the panel's default appearance. |

## `bandwidth`

Client traffic caps, applied in-kernel. `null` is unlimited; `0` is
rejected (say what you mean).

| Field | Default |
|---|---|
| `max_down_bytes_per_sec` | `null` |
| `max_up_bytes_per_sec` | `null` |

## Applying changes

`piso-hotspot stop && sudo piso-hotspot start`. Selling prices and the
portal text are read at start; passes already sold keep their stored
price and expiry.
