"""mitmproxy addon for rewriting TV2's requests with TV1's device identity.

This is the core "clone" functionality. It intercepts outgoing requests from
TV2 and replaces device-identifying fields with the values captured from TV1.
"""

import json
import re
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from mitmproxy import http, ctx

from .fingerprint import DeviceFingerprint


class IdentityCloneAddon:
    """mitmproxy addon that rewrites requests to clone one device's identity onto another."""

    def __init__(
        self,
        source_fingerprint: DeviceFingerprint,
        rules: dict,
        log_rewrites: bool = True,
        on_rewrite=None,
    ):
        """
        Args:
            source_fingerprint: The captured fingerprint from TV1 to clone.
            rules: Rewrite rules from config (which fields to replace).
            log_rewrites: Whether to log each rewrite operation.
            on_rewrite: Optional callback(flow, changes) for UI updates.
        """
        self.source = source_fingerprint
        self.rules = rules
        self.log_rewrites = log_rewrites
        self.on_rewrite = on_rewrite
        self.rewrite_count = 0
        self.request_count = 0

    def _should_ignore_domain(self, domain: str) -> bool:
        for ignored in self.rules.get("ignore_domains", []):
            if domain.endswith(ignored):
                return True
        return False

    def _should_target_domain(self, domain: str) -> bool:
        targets = self.rules.get("target_domains", [])
        if not targets:
            # If no target filter, use the domains observed in the source fingerprint
            if self.source.observed_domains:
                return any(domain.endswith(d) for d in self.source.observed_domains)
            return True
        return any(domain.endswith(t) for t in targets)

    def _rewrite_headers(self, flow: http.HTTPFlow) -> list[str]:
        """Replace tracked headers with source fingerprint values."""
        changes = []
        for header_name, source_value in self.source.headers.items():
            current = flow.request.headers.get(header_name)
            if current is not None and current != source_value:
                flow.request.headers[header_name] = source_value
                changes.append(f"Header {header_name}: {current!r} -> {source_value!r}")
            elif current is None:
                # Header exists in source but not in this request - check if
                # it's a known identity header we should inject
                tracked = {
                    h["name"].lower()
                    for h in self.rules.get("headers", [])
                    if h.get("enabled")
                }
                if header_name.lower() in tracked:
                    flow.request.headers[header_name] = source_value
                    changes.append(f"Header {header_name}: (added) {source_value!r}")
        return changes

    def _rewrite_query_params(self, flow: http.HTTPFlow) -> list[str]:
        """Replace tracked query parameters with source fingerprint values."""
        changes = []
        if not self.source.query_params:
            return changes

        parsed = urlparse(flow.request.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        modified = False

        for param_name, source_value in self.source.query_params.items():
            if param_name in params:
                old_val = params[param_name][0]
                if old_val != source_value:
                    params[param_name] = [source_value]
                    modified = True
                    changes.append(
                        f"Query {param_name}: {old_val!r} -> {source_value!r}"
                    )

        if modified:
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            flow.request.url = new_url

        return changes

    def _rewrite_json_body(self, flow: http.HTTPFlow) -> list[str]:
        """Replace tracked JSON body fields with source fingerprint values."""
        changes = []
        if not self.source.body_fields:
            return changes

        content_type = flow.request.headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            return changes

        body_text = flow.request.get_text()
        if not body_text:
            return changes

        try:
            body = json.loads(body_text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return changes

        if not isinstance(body, dict):
            return changes

        modified = False
        for field_path, source_value in self.source.body_fields.items():
            # Handle nested paths like "device.info.id"
            if "." in field_path and "[" not in field_path:
                parts = field_path.split(".")
                obj = body
                for part in parts[:-1]:
                    if isinstance(obj, dict) and part in obj:
                        obj = obj[part]
                    else:
                        obj = None
                        break
                if isinstance(obj, dict) and parts[-1] in obj:
                    old_val = obj[parts[-1]]
                    if old_val != source_value:
                        obj[parts[-1]] = source_value
                        modified = True
                        changes.append(
                            f"Body {field_path}: {old_val!r} -> {source_value!r}"
                        )
            else:
                # Top-level field
                clean_name = field_path.split("[")[0]  # Strip array indices
                if clean_name in body:
                    old_val = body[clean_name]
                    if old_val != source_value:
                        body[clean_name] = source_value
                        modified = True
                        changes.append(
                            f"Body {clean_name}: {old_val!r} -> {source_value!r}"
                        )

        if modified:
            flow.request.set_text(json.dumps(body))
            # Update content-length
            flow.request.headers["Content-Length"] = str(len(flow.request.get_content()))

        return changes

    def _rewrite_cookies(self, flow: http.HTTPFlow) -> list[str]:
        """Replace tracked cookies with source fingerprint values."""
        changes = []
        for cookie_name, source_value in self.source.cookies.items():
            current = flow.request.cookies.get(cookie_name)
            if current is not None and current != source_value:
                flow.request.cookies[cookie_name] = source_value
                changes.append(
                    f"Cookie {cookie_name}: {current!r} -> {source_value!r}"
                )
        return changes

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and rewrite each request."""
        host = flow.request.pretty_host
        if self._should_ignore_domain(host):
            return
        if not self._should_target_domain(host):
            return

        self.request_count += 1

        all_changes = []
        all_changes.extend(self._rewrite_headers(flow))
        all_changes.extend(self._rewrite_query_params(flow))
        all_changes.extend(self._rewrite_json_body(flow))
        all_changes.extend(self._rewrite_cookies(flow))

        if all_changes:
            self.rewrite_count += 1
            if self.log_rewrites:
                ctx.log.info(
                    f"[clone] Rewrote {len(all_changes)} fields in "
                    f"{flow.request.method} {flow.request.url}"
                )
                for change in all_changes:
                    ctx.log.info(f"  {change}")

            if self.on_rewrite:
                self.on_rewrite(flow, all_changes)

    def response(self, flow: http.HTTPFlow) -> None:
        """Optionally inspect responses for device-specific tokens that may need cloning."""
        # Some apps return device-specific tokens in responses that then get
        # sent back in subsequent requests. We log these for manual inspection.
        host = flow.request.pretty_host
        if self._should_ignore_domain(host):
            return

        content_type = flow.response.headers.get("Content-Type", "") if flow.response else ""
        if flow.response and "json" in content_type.lower():
            body_text = flow.response.get_text()
            if body_text:
                try:
                    body = json.loads(body_text)
                    # Check if response contains device-related fields
                    from .sniffer import _extract_json_fields
                    device_fields = _extract_json_fields(body)
                    if device_fields and self.log_rewrites:
                        ctx.log.info(
                            f"[clone] Response from {host} contains device fields: "
                            f"{list(device_fields.keys())}"
                        )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
