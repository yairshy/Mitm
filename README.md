# MITM TV Sync

Make two smart TVs appear as the same device to a TV app's backend servers. Runs on your MacBook to intercept and rewrite network traffic from TV2, replacing its device identifiers with those captured from TV1.

## How It Works

```
TV1 (Samsung) ──────────────────────> App Server
                                         │
TV2 (LG) ──> MacBook (MITM proxy) ──────┘
              Rewrites TV2's device ID
              with TV1's device ID
```

1. **Sniff** - Passively observe TV1's network traffic to discover which servers the app talks to
2. **Learn** - Intercept TV1's traffic and capture its device fingerprint (device ID, serial, headers, etc.)
3. **Clone** - Intercept TV2's traffic and rewrite its device identifiers with TV1's

## Requirements

- macOS (MacBook on the same network as both TVs)
- Python 3.10+
- Both TVs on the same local network
- Root/sudo access (for network interception)

## Install

```bash
./setup.sh
source venv/bin/activate
```

## Quick Start

### Step 1: Check your network

```bash
sudo mitm-tv info
```

This shows your MacBook's IP, gateway, and network interface.

### Step 2: Discover TV1's traffic (passive, no interception)

```bash
sudo mitm-tv sniff --target 192.168.1.100 --duration 120
```

Watch DNS queries and connections while using the TV app. This helps you identify which API servers the app communicates with.

### Step 3: Capture TV1's device fingerprint

```bash
sudo mitm-tv learn --target 192.168.1.100 --name "Samsung TV"
```

This ARP-spoofs TV1's traffic through your MacBook, runs a transparent proxy, and captures all device-identifying fields from HTTP requests. Use the TV app normally while this runs.

Press Ctrl+C when done. The fingerprint is saved automatically.

### Step 4: Clone TV1's identity onto TV2

```bash
sudo mitm-tv clone --target 192.168.1.101 --source "Samsung TV"
```

This intercepts TV2's traffic and rewrites outgoing requests, replacing TV2's device identifiers with TV1's captured values. The app server now thinks TV2 is TV1.

### Step 5 (if needed): Use the verbose flag to watch rewrites

```bash
sudo mitm-tv clone --target 192.168.1.101 --source "Samsung TV" --verbose
```

## Alternative: DNS-Based Interception

If ARP spoofing doesn't work well on your network, you can use DNS-based interception instead:

### Discover which domains the TV app uses

```bash
sudo mitm-tv dns --discover
```

Then set your TV's DNS server to your MacBook's IP in the TV's network settings.

### Spoof specific domains

```bash
sudo mitm-tv dns -d api.tvapp.com -d auth.tvapp.com
```

## Managing Fingerprints

```bash
mitm-tv fp list                    # List saved fingerprints
mitm-tv fp show "Samsung TV"      # Show fingerprint details
mitm-tv fp export "Samsung TV"    # Export as JSON
mitm-tv fp delete "Samsung TV"    # Delete a fingerprint
```

## Configuration

Default rewrite rules are in `config/default_rules.yaml`. This defines which HTTP headers, JSON body fields, and query parameters are tracked and rewritten.

After discovery, you can customize rules:

```bash
# Copy default rules to your home directory for customization
cp config/default_rules.yaml ~/.mitm_tv_sync/rules.yaml
# Edit as needed - add app-specific headers, target domains, etc.
```

You can also pass custom rules directly:

```bash
sudo mitm-tv learn --target 192.168.1.100 --name "Samsung TV" --rules my_rules.yaml
```

## HTTPS Strategy

Most TV app traffic is HTTPS. There are three strategies depending on whether the app uses certificate pinning:

### Strategy 1: Direct interception (no cert pinning)

Most third-party TV apps do NOT enforce cert pinning. The transparent proxy intercepts HTTPS by generating certificates signed by mitmproxy's CA. This works when:
- The app doesn't pin certificates (most third-party apps)
- You install the mitmproxy CA cert on the TV (Samsung dev mode / LG developer portal)

```bash
sudo mitm-tv learn --target <TV_IP> --name "Samsung TV"
```

### Strategy 2: iPad-first capture (recommended for HTTPS apps)

Since you likely have the same app on an iPad/iPhone, and iOS does NOT enforce cert pinning for third-party apps, use the iPad as your capture device:

```bash
# 1. Start the capture proxy (no sudo needed)
mitm-tv capture -n "ipad-session" -f "iPad"

# 2. On iPad: WiFi Settings → HTTP Proxy → Manual
#    Server: <mac-ip>  Port: 8080

# 3. On iPad: visit http://mitm.it to install mitmproxy CA cert
#    (Settings → General → VPN & Device Mgmt → install the profile)

# 4. Use the app on the iPad - the proxy captures the registration handshake

# 5. Ctrl+C when done. Review what was captured:
mitm-tv replay -n "ipad-session" --show

# 6. Clone the captured identity onto TV2:
sudo mitm-tv clone --target <TV2_IP> --source "iPad"
```

This captures the FULL registration flow (request + response), including:
- The device ID sent to the server
- Any tokens returned by the server
- All headers the app sends

### Strategy 3: Registration replay (cert pinning on TV)

If the TV's HTTPS is cert-pinned and you can't intercept it at all, you can **replay** the registration request directly from your MacBook:

```bash
# 1. Capture the registration from iPad first (Strategy 2)
mitm-tv capture -n "ipad-session"

# 2. Review the captured registration request
mitm-tv replay -n "ipad-session" --show

# 3. Replay it to re-register with TV1's device ID
mitm-tv replay -n "ipad-session" --dry-run

# 4. Or replay with a different device ID
mitm-tv replay -n "ipad-session" -d "<tv2-device-id>"
```

### Strategy 4: Manual fingerprint (you already know the device ID)

If you already have the device ID (e.g. from the iPad app, dev tools, or logs):

```bash
mitm-tv fp create -n "iPad" -d "-VUHXoGHr45MABV8Up0evXcA..."
sudo mitm-tv clone --target <TV2_IP> --source "iPad"
```

### How the app handshake typically works

```
App Boot → POST /device/register
           Body: { "deviceId": "...", "model": "...", "platform": "..." }
                          ↓
           Server: { "token": "...", "accountId": "..." }
                          ↓
All subsequent requests use: Authorization: Bearer <token>
```

The critical moment is the registration POST. If we can capture that from the iPad
and replay it (or rewrite TV2's version of it), we control the device identity.

## No-ARP Mode

If you can configure the TV's HTTP proxy settings directly (some Samsung/LG TVs allow this):

```bash
sudo mitm-tv learn --target 192.168.1.100 --name "Samsung TV" --no-arp
# Then set the TV's HTTP proxy to <your-mac-ip>:8080
```

This avoids ARP spoofing entirely and is more reliable.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| ARP spoof not working | Try `--no-arp` mode and configure TV proxy manually |
| No traffic captured | Check that the TV and MacBook are on the same subnet |
| HTTPS connections failing | The TV likely uses cert pinning - try HTTP-only or DNS mode |
| Permission denied | Run with `sudo` |
| TV app still sees different device | Check `mitm-tv fp show` - you may need to add custom body fields |

## Project Structure

```
mitm_tv_sync/
├── __init__.py          # Package init
├── cli.py               # CLI entry point (click-based)
├── arp_spoof.py         # ARP spoofing for traffic interception
├── sniffer.py           # Traffic capture and fingerprint learning
├── proxy.py             # mitmproxy addon for request rewriting
├── dns_spoof.py         # DNS-based interception alternative
├── fingerprint.py       # Device fingerprint storage
├── handshake.py         # Registration capture and replay
├── config.py            # Configuration management
└── utils.py             # Network utilities
config/
└── default_rules.yaml   # Default rewrite rules
```
