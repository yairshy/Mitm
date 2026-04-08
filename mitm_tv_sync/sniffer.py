"""Traffic sniffer for learning a TV's device fingerprint.

Operates in two modes:
1. Passive sniff (no ARP spoof) - just watches traffic on the network
2. Active learn (with ARP spoof) - intercepts and inspects traffic via mitmproxy

The sniffer identifies device-identifying fields in HTTP headers, JSON bodies,
query parameters, and cookies by matching against known field name patterns.
"""

import json
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from mitmproxy import http, ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

import yaml

from .fingerprint import DeviceFingerprint, FingerprintStore


# Patterns that look like device identifiers (case-insensitive)
DEVICE_ID_PATTERNS = [
    re.compile(r"device.?id", re.IGNORECASE),
    re.compile(r"serial.?(number|no)?", re.IGNORECASE),
    re.compile(r"mac.?addr", re.IGNORECASE),
    re.compile(r"hardware.?id", re.IGNORECASE),
    re.compile(r"client.?id", re.IGNORECASE),
    re.compile(r"udid", re.IGNORECASE),
    re.compile(r"uuid", re.IGNORECASE),
    re.compile(r"device.?model", re.IGNORECASE),
    re.compile(r"device.?name", re.IGNORECASE),
    re.compile(r"device.?type", re.IGNORECASE),
    re.compile(r"platform.?id", re.IGNORECASE),
    re.compile(r"advertising.?id", re.IGNORECASE),
    re.compile(r"samsung", re.IGNORECASE),
    re.compile(r"lg.?device", re.IGNORECASE),
    re.compile(r"tizen", re.IGNORECASE),
    re.compile(r"webos", re.IGNORECASE),
    # Samsung DUID (Device Unique ID) - primary Samsung TV identifier (MAC hash)
    re.compile(r"\bduid\b", re.IGNORECASE),
    # LG LGUDID - factory-assigned LG TV identifier
    re.compile(r"lgudid", re.IGNORECASE),
    # ESN (Electronic Serial Number) - used by Netflix and similar apps
    re.compile(r"\besn\b", re.IGNORECASE),
    re.compile(r"firmware.?ver", re.IGNORECASE),
    re.compile(r"model.?name", re.IGNORECASE),
]


def _looks_like_device_field(name: str) -> bool:
    """Check if a field name looks like it could be a device identifier."""
    return any(p.search(name) for p in DEVICE_ID_PATTERNS)


# Pattern for base64url-encoded SHA-256 hashes (Samsung DUID format):
# 43 chars from the base64url alphabet, no padding
_BASE64URL_SHA256 = re.compile(r"^[A-Za-z0-9\-_]{43}$")

# Other value patterns that look like device identifiers
_DEVICE_VALUE_PATTERNS = [
    _BASE64URL_SHA256,                                      # SHA-256 base64url (Samsung DUID)
    re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE),          # SHA-256 hex
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"    # UUID
               r"[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),
    re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"),   # MAC address
]


def _looks_like_device_value(value: Any) -> bool:
    """Check if a value looks like a device identifier (hash, UUID, MAC, etc.)."""
    if not isinstance(value, str) or len(value) < 12:
        return False
    return any(p.match(value) for p in _DEVICE_VALUE_PATTERNS)


def _extract_json_fields(data: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively extract fields from JSON that look like device identifiers.

    Matches on both field names (e.g. 'deviceId') AND field values
    (e.g. a base64url SHA-256 hash like Samsung DUID).
    """
    results = {}
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (dict, list)):
                results.update(_extract_json_fields(value, full_key))
            elif _looks_like_device_field(key) or _looks_like_device_value(value):
                results[full_key] = value
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.update(_extract_json_fields(item, f"{prefix}[{i}]"))
    return results


class LearnAddon:
    """mitmproxy addon that captures device fingerprint fields from traffic."""

    def __init__(
        self,
        fingerprint: DeviceFingerprint,
        rules: dict,
        on_update=None,
    ):
        self.fingerprint = fingerprint
        self.rules = rules
        self.on_update = on_update  # callback for real-time UI updates
        self.request_count = 0

    def _get_tracked_header_names(self) -> set[str]:
        """Get the set of header names we're tracking (case-insensitive keys)."""
        names = set()
        for h in self.rules.get("headers", []):
            if h.get("enabled", True):
                names.add(h["name"].lower())
        return names

    def _get_tracked_body_fields(self) -> set[str]:
        names = set()
        for f in self.rules.get("body_fields", []):
            if f.get("enabled", True):
                names.add(f["name"])
        return names

    def _get_tracked_query_params(self) -> set[str]:
        names = set()
        for p in self.rules.get("query_params", []):
            if p.get("enabled", True):
                names.add(p["name"])
        return names

    def _should_ignore_domain(self, domain: str) -> bool:
        for ignored in self.rules.get("ignore_domains", []):
            if domain.endswith(ignored):
                return True
        return False

    def _should_target_domain(self, domain: str) -> bool:
        targets = self.rules.get("target_domains", [])
        if not targets:
            return True  # No filter = target everything
        return any(domain.endswith(t) for t in targets)

    def request(self, flow: http.HTTPFlow) -> None:
        """Inspect each request for device fingerprint fields."""
        host = flow.request.pretty_host
        if self._should_ignore_domain(host):
            return
        if not self._should_target_domain(host):
            return

        self.request_count += 1
        self.fingerprint.add_domain(host)

        # Check headers
        tracked_headers = self._get_tracked_header_names()
        for name, value in flow.request.headers.items():
            if name.lower() in tracked_headers or _looks_like_device_field(name):
                self.fingerprint.update_header(name, value)

        # Always capture User-Agent
        ua = flow.request.headers.get("User-Agent", "")
        if ua:
            self.fingerprint.update_header("User-Agent", ua)

        # Capture Authorization header (device-bound tokens from registration)
        auth = flow.request.headers.get("Authorization", "")
        if auth:
            self.fingerprint.update_header("Authorization", auth)

        # Check query parameters
        parsed = urlparse(flow.request.url)
        tracked_params = self._get_tracked_query_params()
        for name, values in parse_qs(parsed.query).items():
            if name in tracked_params or _looks_like_device_field(name):
                self.fingerprint.update_query_param(name, values[0])

        # Check JSON body
        content_type = flow.request.headers.get("Content-Type", "")
        body_text = flow.request.get_text()
        if body_text and "json" in content_type.lower():
            try:
                body_json = json.loads(body_text)
                tracked_fields = self._get_tracked_body_fields()

                # Check explicitly tracked fields
                if isinstance(body_json, dict):
                    for field_name in tracked_fields:
                        if field_name in body_json:
                            self.fingerprint.update_body_field(
                                field_name, body_json[field_name]
                            )

                # Auto-detect device-looking fields
                auto_fields = _extract_json_fields(body_json)
                for field_name, value in auto_fields.items():
                    self.fingerprint.update_body_field(field_name, value)

            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Check cookies
        for cookie_name, cookie_value in flow.request.cookies.items():
            if _looks_like_device_field(cookie_name):
                self.fingerprint.cookies[cookie_name] = cookie_value

        # Store sample request
        self.fingerprint.add_sample_request(
            method=flow.request.method,
            url=flow.request.url,
            headers=dict(flow.request.headers),
            body=body_text[:500] if body_text else None,
        )

        if self.on_update:
            self.on_update(self.fingerprint, self.request_count)


class PassiveSniffer:
    """Passive network sniffer using scapy to observe traffic without interception.

    Useful for initial discovery when you can't yet MITM the connection
    (e.g., due to HTTPS cert pinning). Captures DNS queries, connection
    destinations, and unencrypted HTTP traffic.
    """

    def __init__(self, target_ip: str, interface: str):
        self.target_ip = target_ip
        self.interface = interface
        self.dns_queries: list[dict] = []
        self.connections: list[dict] = []
        self._running = False

    def start(self, duration: int = 60) -> dict:
        """Sniff traffic for the given duration and return a summary."""
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

        self._running = True
        packets = sniff(
            iface=self.interface,
            filter=f"host {self.target_ip}",
            timeout=duration,
            store=True,
        )
        self._running = False

        seen_hosts = set()
        dns_names = set()

        for pkt in packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                remote = dst if src == self.target_ip else src

                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport if src == self.target_ip else pkt[TCP].sport
                    seen_hosts.add(f"{remote}:{dport}")

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                dns_names.add(qname)
                self.dns_queries.append({
                    "name": qname,
                    "timestamp": datetime.now().isoformat(),
                })

        return {
            "packet_count": len(packets),
            "unique_destinations": sorted(seen_hosts),
            "dns_queries": sorted(dns_names),
            "duration_seconds": duration,
        }
