"""Registration replay and handshake capture tools.

When HTTPS certificate pinning prevents mitmproxy from intercepting the app's
TLS traffic on the TV, we need alternative approaches:

1. **iPad-first capture**: Proxy the iPad (no cert pinning issues on iOS for
   third-party apps) to capture the full registration handshake, then replay
   it for the TV.

2. **Registration replay**: Send the registration/login request directly from
   the MacBook to the app server, using TV1's device ID but from TV2's context.

3. **TLS passthrough with selective intercept**: Let cert-pinned connections
   pass through untouched, but intercept the ones that aren't pinned.

This module handles capturing the handshake from a device you CAN proxy (iPad),
saving it, and replaying it to register a second device with the same identity.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml
from mitmproxy import http, ctx

from .fingerprint import DeviceFingerprint, FingerprintStore


@dataclass
class CapturedHandshake:
    """A captured registration/login handshake (request + response pair)."""

    # Request
    method: str = ""
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None

    # Response
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None

    # Metadata
    captured_at: str = ""
    host: str = ""
    path: str = ""
    tags: list[str] = field(default_factory=list)  # e.g. ["registration", "login", "token"]

    def __post_init__(self):
        if not self.captured_at:
            self.captured_at = datetime.now().isoformat()
        if self.url and not self.host:
            parsed = urlparse(self.url)
            self.host = parsed.hostname or ""
            self.path = parsed.path or ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "captured_at": self.captured_at,
            "host": self.host,
            "path": self.path,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CapturedHandshake":
        return cls(**data)

    def get_response_json(self) -> Optional[dict]:
        """Parse the response body as JSON."""
        if self.response_body:
            try:
                return json.loads(self.response_body)
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def get_request_json(self) -> Optional[dict]:
        """Parse the request body as JSON."""
        if self.request_body:
            try:
                return json.loads(self.request_body)
            except (json.JSONDecodeError, TypeError):
                pass
        return None


class HandshakeStore:
    """Saves and loads captured handshakes."""

    def __init__(self, store_dir: Optional[str] = None):
        if store_dir:
            self.store_dir = Path(store_dir)
        else:
            self.store_dir = Path.home() / ".mitm_tv_sync" / "handshakes"
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, handshakes: list[CapturedHandshake]) -> Path:
        path = self.store_dir / f"{name}.yaml"
        data = [h.to_dict() for h in handshakes]
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        return path

    def load(self, name: str) -> list[CapturedHandshake]:
        path = self.store_dir / f"{name}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"No handshake capture found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or []
        return [CapturedHandshake.from_dict(d) for d in data]

    def list_captures(self) -> list[str]:
        return [p.stem for p in self.store_dir.glob("*.yaml")]


# ---------------------------------------------------------------------------
# Heuristics to detect registration/login requests
# ---------------------------------------------------------------------------

_REGISTRATION_PATH_KEYWORDS = [
    "register", "device", "activate", "provision", "enroll",
    "auth", "login", "signin", "sign-in", "token", "oauth",
    "pair", "link", "handshake", "init", "setup", "onboard",
]

_REGISTRATION_BODY_KEYWORDS = [
    "deviceId", "device_id", "deviceID", "duid", "DUID",
    "serialNumber", "serial_number", "macAddress", "mac_address",
    "lgudid", "LGUDID", "udid", "clientId", "client_id",
    "grant_type", "device_code",
]


def _looks_like_registration(flow: http.HTTPFlow) -> float:
    """Score how likely a request is a registration/login handshake (0-1)."""
    score = 0.0

    # Check URL path
    path = flow.request.path.lower()
    for keyword in _REGISTRATION_PATH_KEYWORDS:
        if keyword in path:
            score += 0.3
            break

    # Check if it's a POST (registrations are almost always POST)
    if flow.request.method == "POST":
        score += 0.1

    # Check request body for device ID fields
    body_text = flow.request.get_text() or ""
    content_type = flow.request.headers.get("Content-Type", "")
    if "json" in content_type.lower() and body_text:
        try:
            body = json.loads(body_text)
            if isinstance(body, dict):
                for keyword in _REGISTRATION_BODY_KEYWORDS:
                    if keyword in body:
                        score += 0.2
                        break
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Check if response contains a token (registration responses usually do)
    if flow.response and flow.response.status_code in (200, 201):
        resp_text = flow.response.get_text() or ""
        resp_ct = flow.response.headers.get("Content-Type", "")
        if "json" in resp_ct.lower() and resp_text:
            try:
                resp = json.loads(resp_text)
                if isinstance(resp, dict):
                    token_keys = {"token", "access_token", "accessToken", "auth_token",
                                  "authToken", "session", "sessionId", "session_id",
                                  "refresh_token", "refreshToken", "bearer", "jwt"}
                    if token_keys & set(resp.keys()):
                        score += 0.3
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    return min(score, 1.0)


class HandshakeCaptureAddon:
    """mitmproxy addon that identifies and captures registration/login handshakes.

    Use this when proxying the iPad to capture the full request/response
    exchange for the app's device registration flow.
    """

    def __init__(
        self,
        capture_all: bool = False,
        score_threshold: float = 0.3,
        on_capture=None,
    ):
        """
        Args:
            capture_all: If True, capture ALL requests (not just registration-like ones).
            score_threshold: Minimum registration-likeness score to auto-capture.
            on_capture: Callback(handshake, score) for UI updates.
        """
        self.capture_all = capture_all
        self.score_threshold = score_threshold
        self.on_capture = on_capture
        self.handshakes: list[CapturedHandshake] = []
        self.all_flows: list[CapturedHandshake] = []
        self.request_count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        """Capture completed request/response pairs."""
        self.request_count += 1

        # Build handshake record
        handshake = CapturedHandshake(
            method=flow.request.method,
            url=flow.request.url,
            request_headers=dict(flow.request.headers),
            request_body=flow.request.get_text(),
            status_code=flow.response.status_code if flow.response else 0,
            response_headers=dict(flow.response.headers) if flow.response else {},
            response_body=flow.response.get_text() if flow.response else None,
        )

        # Always record for full capture
        self.all_flows.append(handshake)

        # Check if it looks like a registration
        score = _looks_like_registration(flow)

        if self.capture_all or score >= self.score_threshold:
            if score >= 0.5:
                handshake.tags.append("registration")
            if score >= 0.3:
                handshake.tags.append("auth-related")
            self.handshakes.append(handshake)

            if self.on_capture:
                self.on_capture(handshake, score)

            ctx.log.info(
                f"[handshake] Captured {flow.request.method} {flow.request.url} "
                f"(score: {score:.1f}, tags: {handshake.tags})"
            )


class TLSPassthroughAddon:
    """mitmproxy addon that passes through cert-pinned connections instead of failing.

    When a TLS handshake fails (likely due to cert pinning), this addon
    adds the domain to a passthrough list so subsequent connections to that
    domain go through without interception. Non-pinned connections are
    still intercepted normally.

    This way the app keeps working (pinned connections pass through)
    while we intercept everything we can (non-pinned connections).
    """

    def __init__(self, on_pinning_detected=None):
        self.pinned_domains: set[str] = set()
        self.intercepted_domains: set[str] = set()
        self.on_pinning_detected = on_pinning_detected

    def tls_clienthello(self, data) -> None:
        """Inspect TLS ClientHello to extract SNI for logging."""
        # mitmproxy provides SNI through the data object
        pass

    def tls_established_client(self, data) -> None:
        """Track successfully intercepted TLS connections."""
        conn = data.context.client
        sni = getattr(data.context, "server", None)
        if sni and hasattr(sni, "address"):
            domain = sni.address[0] if sni.address else ""
            if domain:
                self.intercepted_domains.add(domain)

    def tls_failed_client(self, data) -> None:
        """Detect cert pinning failures and add to passthrough list."""
        sni = getattr(data.context, "server", None)
        if sni and hasattr(sni, "address"):
            domain = sni.address[0] if sni.address else ""
            if domain and domain not in self.pinned_domains:
                self.pinned_domains.add(domain)
                ctx.log.warn(
                    f"[tls] Certificate pinning detected for {domain} - "
                    f"adding to passthrough list"
                )
                if self.on_pinning_detected:
                    self.on_pinning_detected(domain)


def replay_registration(
    handshake: CapturedHandshake,
    new_device_id: Optional[str] = None,
    device_id_field: str = "deviceId",
    extra_overrides: Optional[dict] = None,
    timeout: int = 30,
) -> dict:
    """Replay a captured registration request, optionally with a different device ID.

    This sends the exact same HTTP request that was captured from the iPad/TV1,
    but can substitute the device ID field. Useful when you want to register
    a new device with the server using the same identity.

    Args:
        handshake: The captured registration handshake to replay.
        new_device_id: If provided, replace the device ID in the request body.
        device_id_field: The JSON field name containing the device ID.
        extra_overrides: Additional body fields to override.
        timeout: Request timeout in seconds.

    Returns:
        Dict with 'status_code', 'headers', 'body' of the server's response.
    """
    import urllib.request
    import ssl

    # Prepare request body
    body = handshake.request_body
    if body and new_device_id:
        try:
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                # Replace device ID
                if device_id_field in body_json:
                    body_json[device_id_field] = new_device_id
                # Also try common variants
                for variant in ("deviceId", "device_id", "deviceID"):
                    if variant in body_json:
                        body_json[variant] = new_device_id
                # Apply extra overrides
                if extra_overrides:
                    body_json.update(extra_overrides)
                body = json.dumps(body_json)
        except (json.JSONDecodeError, TypeError):
            pass

    # Build the request
    body_bytes = body.encode("utf-8") if body else None
    req = urllib.request.Request(
        handshake.url,
        data=body_bytes,
        method=handshake.method,
    )

    # Copy original headers (skip hop-by-hop headers)
    skip_headers = {"host", "content-length", "transfer-encoding", "connection"}
    for name, value in handshake.request_headers.items():
        if name.lower() not in skip_headers:
            req.add_header(name, value)

    if body_bytes:
        req.add_header("Content-Length", str(len(body_bytes)))

    # Send the request (allow self-signed certs for testing)
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = True
    ctx_ssl.verify_mode = ssl.CERT_REQUIRED

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx_ssl) as resp:
            return {
                "status_code": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read().decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as e:
        return {
            "status_code": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": e.read().decode("utf-8", errors="replace") if e.fp else "",
            "error": str(e),
        }
    except Exception as e:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "error": str(e),
        }
