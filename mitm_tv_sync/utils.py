"""Network utility functions."""

import re
import socket
import subprocess
import sys


def get_default_interface() -> str:
    """Get the default network interface name on macOS."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split("interface:")[-1].strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    # Fallback: try common macOS interfaces
    for iface in ("en0", "en1", "eth0"):
        try:
            import netifaces
            if iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return iface
        except ImportError:
            pass
    return "en0"


def get_interface_ip(interface: str) -> str:
    """Get the IP address of a network interface."""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET][0]["addr"]
    except (ImportError, KeyError, IndexError):
        pass
    # Fallback
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, check=True,
        )
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    raise RuntimeError(f"Could not determine IP for interface {interface}")


def get_mac_address(interface: str) -> str:
    """Get the MAC address of a network interface."""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_LINK][0]["addr"]
    except (ImportError, KeyError, IndexError):
        pass
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, check=True,
        )
        match = re.search(r"ether ([0-9a-f:]{17})", result.stdout)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    raise RuntimeError(f"Could not determine MAC for interface {interface}")


def get_gateway_ip() -> str:
    """Get the default gateway IP address."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.splitlines():
            if "gateway:" in line:
                return line.split("gateway:")[-1].strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    # Linux fallback
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True,
        )
        parts = result.stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    raise RuntimeError("Could not determine default gateway")


def resolve_ip(target: str) -> str:
    """Resolve a hostname or IP to an IP address."""
    try:
        socket.inet_aton(target)
        return target  # Already an IP
    except socket.error:
        return socket.gethostbyname(target)


def enable_ip_forwarding() -> None:
    """Enable IP forwarding on the system (requires root)."""
    if sys.platform == "darwin":
        subprocess.run(
            ["sysctl", "-w", "net.inet.ip.forwarding=1"],
            check=True, capture_output=True,
        )
    else:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True,
        )


def disable_ip_forwarding() -> None:
    """Disable IP forwarding on the system (requires root)."""
    if sys.platform == "darwin":
        subprocess.run(
            ["sysctl", "-w", "net.inet.ip.forwarding=0"],
            check=True, capture_output=True,
        )
    else:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True, capture_output=True,
        )


def setup_iptables_redirect(interface: str, src_ip: str, proxy_port: int = 8080) -> None:
    """Set up iptables/pf rules to redirect HTTP(S) traffic to the proxy."""
    if sys.platform == "darwin":
        # macOS uses pf (packet filter)
        pf_rules = (
            f"rdr on {interface} proto tcp from {src_ip} to any "
            f"port 80 -> 127.0.0.1 port {proxy_port}\n"
            f"rdr on {interface} proto tcp from {src_ip} to any "
            f"port 443 -> 127.0.0.1 port {proxy_port}\n"
        )
        rules_file = "/tmp/mitm_tv_pf.conf"
        with open(rules_file, "w") as f:
            f.write(pf_rules)
        subprocess.run(["pfctl", "-ef", rules_file], capture_output=True)
    else:
        # Linux uses iptables
        for port in (80, 443):
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", interface, "-s", src_ip,
                "-p", "tcp", "--dport", str(port),
                "-j", "REDIRECT", "--to-port", str(proxy_port),
            ], capture_output=True)


def teardown_iptables_redirect(interface: str, src_ip: str, proxy_port: int = 8080) -> None:
    """Remove iptables/pf redirect rules."""
    if sys.platform == "darwin":
        subprocess.run(["pfctl", "-d"], capture_output=True)
        try:
            import os
            os.remove("/tmp/mitm_tv_pf.conf")
        except FileNotFoundError:
            pass
    else:
        for port in (80, 443):
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-i", interface, "-s", src_ip,
                "-p", "tcp", "--dport", str(port),
                "-j", "REDIRECT", "--to-port", str(proxy_port),
            ], capture_output=True)
