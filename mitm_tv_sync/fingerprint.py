"""Device fingerprint capture and storage.

Stores the identity fields captured from TV1 so they can be replayed onto TV2's
traffic. Fingerprints are saved as YAML files for easy inspection and editing.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class DeviceFingerprint:
    """Captured device identity from a TV's network traffic."""

    device_name: str  # User-friendly label, e.g. "Samsung TV (Living Room)"
    ip_address: str
    mac_address: str = ""
    captured_at: str = ""

    # Captured identity fields
    headers: dict[str, str] = field(default_factory=dict)
    body_fields: dict[str, Any] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Domains this device talks to (discovered during sniffing)
    observed_domains: list[str] = field(default_factory=list)

    # Raw captured requests for analysis
    sample_requests: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.captured_at:
            self.captured_at = datetime.now().isoformat()

    def update_header(self, name: str, value: str) -> None:
        """Record a header value seen in traffic."""
        self.headers[name] = value

    def update_body_field(self, name: str, value: Any) -> None:
        """Record a JSON body field value seen in traffic."""
        self.body_fields[name] = value

    def update_query_param(self, name: str, value: str) -> None:
        """Record a query parameter value seen in traffic."""
        self.query_params[name] = value

    def add_domain(self, domain: str) -> None:
        """Track a domain this device communicates with."""
        if domain not in self.observed_domains:
            self.observed_domains.append(domain)

    def add_sample_request(
        self, method: str, url: str, headers: dict, body: Optional[str] = None
    ) -> None:
        """Store a sample request for later analysis."""
        sample = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "timestamp": datetime.now().isoformat(),
        }
        if body:
            sample["body"] = body[:2000]  # Truncate large bodies
        # Keep last 50 samples
        self.sample_requests.append(sample)
        if len(self.sample_requests) > 50:
            self.sample_requests = self.sample_requests[-50:]

    def to_dict(self) -> dict:
        return {
            "device_name": self.device_name,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "captured_at": self.captured_at,
            "headers": self.headers,
            "body_fields": self.body_fields,
            "query_params": self.query_params,
            "cookies": self.cookies,
            "observed_domains": self.observed_domains,
            "sample_requests": self.sample_requests,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceFingerprint":
        return cls(**data)


class FingerprintStore:
    """Manages saved device fingerprints on disk."""

    def __init__(self, store_dir: Optional[str] = None):
        if store_dir:
            self.store_dir = Path(store_dir)
        else:
            self.store_dir = Path.home() / ".mitm_tv_sync" / "fingerprints"
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _filename(self, name: str) -> Path:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        return self.store_dir / f"{safe_name}.yaml"

    def save(self, fingerprint: DeviceFingerprint) -> Path:
        """Save a fingerprint to disk."""
        path = self._filename(fingerprint.device_name)
        with open(path, "w") as f:
            yaml.dump(fingerprint.to_dict(), f, default_flow_style=False, sort_keys=False)
        return path

    def load(self, name: str) -> DeviceFingerprint:
        """Load a fingerprint by device name."""
        path = self._filename(name)
        if not path.exists():
            raise FileNotFoundError(f"No fingerprint found for '{name}' at {path}")
        with open(path) as f:
            data = yaml.safe_load(f)
        return DeviceFingerprint.from_dict(data)

    def list_fingerprints(self) -> list[str]:
        """List all saved fingerprint names."""
        results = []
        for path in self.store_dir.glob("*.yaml"):
            with open(path) as f:
                data = yaml.safe_load(f)
            if data and "device_name" in data:
                results.append(data["device_name"])
        return results

    def delete(self, name: str) -> bool:
        """Delete a saved fingerprint."""
        path = self._filename(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def export_json(self, name: str) -> str:
        """Export a fingerprint as JSON for debugging."""
        fp = self.load(name)
        return json.dumps(fp.to_dict(), indent=2)
