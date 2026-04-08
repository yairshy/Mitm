"""DNS spoofing module for redirecting TV traffic to the proxy.

Alternative to ARP spoofing. Runs a local DNS server that responds to queries
for targeted domains with the MacBook's IP, forcing the TV to connect to our
proxy instead of the real server. The proxy then forwards to the real server.

This approach works well when:
- You configure the TV to use your MacBook as its DNS server
  (possible on most Samsung/LG TVs via network settings)
- Or you ARP spoof just the DNS traffic
- Avoids full traffic interception, only redirects specific domains

Limitation: Does NOT help with certificate pinning since the TV will still
validate the server's TLS certificate against the real domain.
"""

import socket
import struct
import threading
from typing import Optional


class DNSSpoofer:
    """Simple DNS server that spoofs responses for targeted domains.

    For non-targeted domains, forwards the query to the real DNS server
    and passes the response back to the client.
    """

    def __init__(
        self,
        spoof_ip: str,
        interface_ip: str,
        upstream_dns: str = "8.8.8.8",
        port: int = 53,
        target_domains: Optional[list[str]] = None,
    ):
        """
        Args:
            spoof_ip: IP to return for spoofed domains (usually the MacBook's IP).
            interface_ip: IP of the interface to bind to (0.0.0.0 for all).
            upstream_dns: Real DNS server for non-spoofed queries.
            port: Port to listen on (53 for standard DNS).
            target_domains: Domains to spoof. If empty, nothing is spoofed
                           (pass-through mode for discovery).
        """
        self.spoof_ip = spoof_ip
        self.interface_ip = interface_ip
        self.upstream_dns = upstream_dns
        self.port = port
        self.target_domains = set(target_domains or [])
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self.query_log: list[dict] = []

    def _should_spoof(self, domain: str) -> bool:
        """Check if a domain should be spoofed."""
        if not self.target_domains:
            return False
        domain = domain.rstrip(".")
        for target in self.target_domains:
            if domain == target or domain.endswith("." + target):
                return True
        return False

    def _parse_dns_query(self, data: bytes) -> tuple[str, int, int]:
        """Parse a DNS query and extract the domain name, query type, and query class."""
        # Skip header (12 bytes)
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            pos += 1
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        domain = ".".join(labels)
        qtype = struct.unpack("!H", data[pos:pos + 2])[0] if pos + 2 <= len(data) else 1
        qclass = struct.unpack("!H", data[pos + 2:pos + 4])[0] if pos + 4 <= len(data) else 1
        return domain, qtype, qclass

    def _build_spoof_response(self, query_data: bytes, domain: str) -> bytes:
        """Build a DNS response that points the domain to our spoof IP."""
        # Copy transaction ID from query
        transaction_id = query_data[:2]

        # Flags: standard response, no error
        flags = struct.pack("!H", 0x8180)

        # Counts: 1 question, 1 answer, 0 authority, 0 additional
        counts = struct.pack("!HHHH", 1, 1, 0, 0)

        # Question section (copy from query)
        question_start = 12
        pos = question_start
        while pos < len(query_data) and query_data[pos] != 0:
            pos += query_data[pos] + 1
        pos += 5  # null byte + qtype(2) + qclass(2)
        question = query_data[question_start:pos]

        # Answer section
        # Name pointer to question
        answer_name = struct.pack("!H", 0xC00C)
        # Type A, Class IN
        answer_type = struct.pack("!HH", 1, 1)
        # TTL: 60 seconds
        answer_ttl = struct.pack("!I", 60)
        # RDATA: 4 bytes for IPv4
        ip_parts = self.spoof_ip.split(".")
        rdata = struct.pack("!BBBB", *[int(p) for p in ip_parts])
        answer_rdlen = struct.pack("!H", 4)

        answer = answer_name + answer_type + answer_ttl + answer_rdlen + rdata

        return transaction_id + flags + counts + question + answer

    def _forward_query(self, data: bytes) -> Optional[bytes]:
        """Forward a DNS query to the upstream server and return the response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(data, (self.upstream_dns, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
        except (socket.timeout, OSError):
            return None

    def _serve_loop(self) -> None:
        """Main DNS server loop."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._socket.bind((self.interface_ip, self.port))
        except PermissionError:
            raise PermissionError(
                f"Cannot bind to port {self.port}. Run with sudo or use a port > 1024."
            )

        self._socket.settimeout(1.0)

        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
            except socket.timeout:
                continue

            try:
                domain, qtype, _ = self._parse_dns_query(data)
            except Exception:
                continue

            # Log the query
            entry = {"domain": domain, "type": qtype, "from": addr[0], "spoofed": False}

            if self._should_spoof(domain) and qtype == 1:  # Only spoof A records
                response = self._build_spoof_response(data, domain)
                entry["spoofed"] = True
            else:
                response = self._forward_query(data)

            self.query_log.append(entry)

            if response:
                self._socket.sendto(response, addr)

        self._socket.close()

    def start(self) -> None:
        """Start the DNS spoof server."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the DNS spoof server."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def add_domain(self, domain: str) -> None:
        """Add a domain to the spoof list."""
        self.target_domains.add(domain.rstrip("."))

    def remove_domain(self, domain: str) -> None:
        """Remove a domain from the spoof list."""
        self.target_domains.discard(domain.rstrip("."))

    def get_observed_domains(self) -> list[str]:
        """Get unique domains seen in queries."""
        return sorted(set(e["domain"] for e in self.query_log))

    @property
    def is_running(self) -> bool:
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
