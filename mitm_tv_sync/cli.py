"""CLI interface for MITM TV Sync.

Provides three main workflows:
  1. sniff  - Passive observation of a TV's network traffic (discovery)
  2. learn  - Active interception to capture TV1's device fingerprint
  3. clone  - Rewrite TV2's traffic using TV1's captured fingerprint

Plus utility commands for managing fingerprints and configuration.
"""

import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import load_rules, save_rules, get_data_dir
from .fingerprint import DeviceFingerprint, FingerprintStore
from .utils import (
    get_default_interface,
    get_gateway_ip,
    get_interface_ip,
    get_mac_address,
    enable_ip_forwarding,
    disable_ip_forwarding,
    setup_iptables_redirect,
    teardown_iptables_redirect,
)

console = Console()


@click.group()
@click.version_option(version=__version__)
def main():
    """MITM TV Sync - Clone TV app identity across smart TVs.

    Run on your MacBook to make TV2 appear as TV1 to app backend servers.
    Requires root/sudo for network interception.

    Typical workflow:

      1. mitm-tv sniff --target <TV1_IP>        # Discover what servers the app talks to
      2. mitm-tv learn --target <TV1_IP> --name "Samsung TV"  # Capture TV1's fingerprint
      3. mitm-tv clone --target <TV2_IP> --source "Samsung TV" # Clone onto TV2
    """
    pass


# ---------------------------------------------------------------------------
# sniff - Passive traffic observation
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", "-t", required=True, help="IP address of the TV to observe")
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
@click.option("--duration", "-d", default=120, help="Sniff duration in seconds (default: 120)")
@click.option("--output", "-o", default=None, help="Save results to JSON file")
def sniff(target: str, interface: Optional[str], duration: int, output: Optional[str]):
    """Passively observe a TV's network traffic to discover API endpoints.

    This does NOT intercept or modify traffic. It watches DNS queries and
    TCP connections to identify which servers the TV app communicates with.

    Use this first to understand the traffic before attempting interception.
    """
    if not interface:
        interface = get_default_interface()

    console.print(f"[bold]Passive sniff[/bold] on [cyan]{interface}[/cyan]")
    console.print(f"Target: [yellow]{target}[/yellow]")
    console.print(f"Duration: {duration}s")
    console.print()

    from .sniffer import PassiveSniffer

    sniffer = PassiveSniffer(target_ip=target, interface=interface)

    console.print("[dim]Sniffing... press Ctrl+C to stop early[/dim]")
    try:
        results = sniffer.start(duration=duration)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped early[/yellow]")
        results = {
            "packet_count": 0,
            "unique_destinations": [],
            "dns_queries": sorted(set(e["name"] for e in sniffer.dns_queries)),
            "duration_seconds": duration,
        }

    # Display results
    console.print()
    console.print(Panel("[bold]Sniff Results[/bold]"))
    console.print(f"Packets captured: {results['packet_count']}")
    console.print()

    if results["dns_queries"]:
        table = Table(title="DNS Queries (domains the TV looked up)")
        table.add_column("Domain", style="cyan")
        for domain in results["dns_queries"]:
            table.add_row(domain)
        console.print(table)
    else:
        console.print("[dim]No DNS queries captured[/dim]")

    console.print()
    if results["unique_destinations"]:
        table = Table(title="TCP Connections (IP:Port)")
        table.add_column("Destination", style="green")
        for dest in results["unique_destinations"]:
            table.add_row(dest)
        console.print(table)
    else:
        console.print("[dim]No TCP connections captured[/dim]")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\nResults saved to [green]{output}[/green]")

    # Suggest next steps
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(
        f'  mitm-tv learn --target {target} --name "My TV"  '
        "[dim]# Capture device fingerprint[/dim]"
    )


# ---------------------------------------------------------------------------
# learn - Active fingerprint capture via mitmproxy
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", "-t", required=True, help="IP address of the TV to learn from")
@click.option("--name", "-n", required=True, help='Friendly name for this device (e.g. "Samsung TV")')
@click.option("--gateway", "-g", default=None, help="Gateway IP (default: auto-detect)")
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
@click.option("--port", "-p", default=8080, help="Proxy port (default: 8080)")
@click.option("--duration", "-d", default=0, help="Auto-stop after N seconds (0 = manual stop)")
@click.option("--rules", "-r", default=None, help="Path to custom rules YAML")
@click.option("--no-arp", is_flag=True, help="Skip ARP spoofing (configure TV proxy manually)")
def learn(
    target: str,
    name: str,
    gateway: Optional[str],
    interface: Optional[str],
    port: int,
    duration: int,
    rules: Optional[str],
    no_arp: bool,
):
    """Capture a TV's device fingerprint by intercepting its traffic.

    This uses ARP spoofing to redirect the TV's traffic through mitmproxy,
    then inspects HTTP requests for device-identifying fields.

    The captured fingerprint is saved and can be used with the 'clone' command.

    Note: HTTPS interception requires the TV to accept our CA certificate.
    Smart TVs with certificate pinning will only allow HTTP traffic inspection.
    """
    if not interface:
        interface = get_default_interface()
    if not gateway:
        gateway = get_gateway_ip()

    my_ip = get_interface_ip(interface)
    rewrite_rules = load_rules(rules)

    console.print(Panel("[bold]Learn Mode - Capturing Device Fingerprint[/bold]"))
    console.print(f"Target TV:  [yellow]{target}[/yellow]")
    console.print(f"Device name: [cyan]{name}[/cyan]")
    console.print(f"Gateway:    [green]{gateway}[/green]")
    console.print(f"Interface:  {interface} ({my_ip})")
    console.print(f"Proxy port: {port}")
    console.print()

    # Create fingerprint object
    try:
        mac = get_mac_address(interface)
    except RuntimeError:
        mac = ""

    fingerprint = DeviceFingerprint(
        device_name=name,
        ip_address=target,
        mac_address=mac,
    )

    store = FingerprintStore()
    arp_spoofer = None

    def _on_update(fp: DeviceFingerprint, count: int):
        """Called by the sniffer on each captured request."""
        # Auto-save periodically
        if count % 10 == 0:
            store.save(fp)

    try:
        # Start ARP spoofing
        if not no_arp:
            from .arp_spoof import ARPSpoofer

            console.print("[dim]Starting ARP spoof...[/dim]")
            arp_spoofer = ARPSpoofer(
                target_ip=target,
                gateway_ip=gateway,
                interface=interface,
            )
            arp_spoofer.start()
            console.print("[green]ARP spoofing active[/green]")

            # Set up traffic redirect to proxy
            setup_iptables_redirect(interface, target, port)
            console.print(f"[green]Traffic redirect active (port {port})[/green]")
        else:
            console.print(
                "[yellow]ARP spoofing disabled. Configure the TV to use "
                f"{my_ip}:{port} as HTTP proxy.[/yellow]"
            )

        console.print()
        console.print("[bold]Capturing traffic... press Ctrl+C to stop[/bold]")
        console.print("[dim]Use the TV app normally to generate traffic[/dim]")
        console.print()

        # Start mitmproxy with our learn addon
        from .sniffer import LearnAddon

        addon = LearnAddon(
            fingerprint=fingerprint,
            rules=rewrite_rules,
            on_update=_on_update,
        )

        _run_mitmproxy(port=port, addons=[addon], mode="transparent")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping...[/yellow]")
    finally:
        # Cleanup
        if arp_spoofer:
            console.print("[dim]Restoring ARP tables...[/dim]")
            arp_spoofer.stop()
            teardown_iptables_redirect(interface, target, port)

        # Save final fingerprint
        path = store.save(fingerprint)
        console.print()
        console.print(Panel("[bold green]Fingerprint Captured[/bold green]"))
        console.print(f"Saved to: [cyan]{path}[/cyan]")
        console.print(f"Requests analyzed: {getattr(addon, 'request_count', 0) if 'addon' in dir() else 'N/A'}")

        if fingerprint.headers:
            table = Table(title="Captured Headers")
            table.add_column("Header", style="cyan")
            table.add_column("Value", style="green")
            for h, v in fingerprint.headers.items():
                table.add_row(h, v[:80])
            console.print(table)

        if fingerprint.body_fields:
            table = Table(title="Captured Body Fields")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            for f, v in fingerprint.body_fields.items():
                table.add_row(f, str(v)[:80])
            console.print(table)

        if fingerprint.observed_domains:
            table = Table(title="Observed Domains")
            table.add_column("Domain", style="cyan")
            for d in fingerprint.observed_domains:
                table.add_row(d)
            console.print(table)

        console.print()
        console.print("[bold]Next steps:[/bold]")
        console.print(
            f'  mitm-tv clone --target <TV2_IP> --source "{name}"  '
            "[dim]# Clone this identity onto TV2[/dim]"
        )


# ---------------------------------------------------------------------------
# clone - Rewrite TV2's traffic with TV1's identity
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", "-t", required=True, help="IP address of TV2 (the one to disguise)")
@click.option("--source", "-s", required=True, help='Name of the source fingerprint (e.g. "Samsung TV")')
@click.option("--gateway", "-g", default=None, help="Gateway IP (default: auto-detect)")
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
@click.option("--port", "-p", default=8080, help="Proxy port (default: 8080)")
@click.option("--rules", "-r", default=None, help="Path to custom rules YAML")
@click.option("--no-arp", is_flag=True, help="Skip ARP spoofing (configure TV proxy manually)")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed rewrite logs")
def clone(
    target: str,
    source: str,
    gateway: Optional[str],
    interface: Optional[str],
    port: int,
    rules: Optional[str],
    no_arp: bool,
    verbose: bool,
):
    """Rewrite TV2's traffic to use TV1's device identity.

    Loads a previously captured fingerprint and rewrites TV2's outgoing
    requests to use TV1's device identifiers, making the app server
    think TV2 is TV1.

    Example:
      mitm-tv clone --target 192.168.1.101 --source "Samsung TV"
    """
    if not interface:
        interface = get_default_interface()
    if not gateway:
        gateway = get_gateway_ip()

    my_ip = get_interface_ip(interface)
    rewrite_rules = load_rules(rules)

    # Load source fingerprint
    store = FingerprintStore()
    try:
        source_fp = store.load(source)
    except FileNotFoundError:
        console.print(f"[red]Fingerprint '{source}' not found.[/red]")
        available = store.list_fingerprints()
        if available:
            console.print("Available fingerprints:")
            for name in available:
                console.print(f"  - {name}")
        else:
            console.print("No fingerprints saved. Run 'mitm-tv learn' first.")
        sys.exit(1)

    console.print(Panel("[bold]Clone Mode - Rewriting Device Identity[/bold]"))
    console.print(f"Target TV (TV2): [yellow]{target}[/yellow]")
    console.print(f"Source identity:  [cyan]{source}[/cyan] (captured from {source_fp.ip_address})")
    console.print(f"Gateway:         [green]{gateway}[/green]")
    console.print(f"Interface:       {interface} ({my_ip})")
    console.print(f"Proxy port:      {port}")
    console.print()

    # Show what will be cloned
    if source_fp.headers:
        table = Table(title="Identity to Clone - Headers")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="green")
        for h, v in source_fp.headers.items():
            table.add_row(h, v[:80])
        console.print(table)

    if source_fp.body_fields:
        table = Table(title="Identity to Clone - Body Fields")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        for f, v in source_fp.body_fields.items():
            table.add_row(f, str(v)[:80])
        console.print(table)

    console.print()

    arp_spoofer = None

    def _on_rewrite(flow, changes):
        if verbose:
            console.print(f"[green]Rewrote[/green] {flow.request.method} {flow.request.url}")
            for c in changes:
                console.print(f"  {c}")

    try:
        if not no_arp:
            from .arp_spoof import ARPSpoofer

            console.print("[dim]Starting ARP spoof...[/dim]")
            arp_spoofer = ARPSpoofer(
                target_ip=target,
                gateway_ip=gateway,
                interface=interface,
            )
            arp_spoofer.start()
            console.print("[green]ARP spoofing active[/green]")

            setup_iptables_redirect(interface, target, port)
            console.print(f"[green]Traffic redirect active (port {port})[/green]")
        else:
            console.print(
                f"[yellow]ARP spoofing disabled. Configure TV2 to use "
                f"{my_ip}:{port} as HTTP proxy.[/yellow]"
            )

        console.print()
        console.print("[bold]Cloning active... press Ctrl+C to stop[/bold]")
        console.print("[dim]TV2 traffic will be rewritten with TV1's identity[/dim]")
        console.print()

        from .proxy import IdentityCloneAddon

        addon = IdentityCloneAddon(
            source_fingerprint=source_fp,
            rules=rewrite_rules,
            log_rewrites=verbose,
            on_rewrite=_on_rewrite,
        )

        _run_mitmproxy(port=port, addons=[addon], mode="transparent")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping...[/yellow]")
    finally:
        if arp_spoofer:
            console.print("[dim]Restoring ARP tables...[/dim]")
            arp_spoofer.stop()
            teardown_iptables_redirect(interface, target, port)

        if 'addon' in dir():
            console.print()
            console.print(
                f"Requests processed: {addon.request_count}, "
                f"Rewrites made: {addon.rewrite_count}"
            )


# ---------------------------------------------------------------------------
# dns - DNS spoofing mode (alternative to ARP)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
@click.option("--domains", "-d", multiple=True, help="Domains to spoof (repeat for multiple)")
@click.option("--discover", is_flag=True, help="Discovery mode - log all queries without spoofing")
@click.option("--port", default=53, help="DNS port (default: 53)")
def dns(interface: Optional[str], domains: tuple, discover: bool, port: int):
    """Run a DNS spoof server to redirect TV traffic.

    Alternative to ARP spoofing. Set the TV's DNS server to your MacBook's IP,
    then this redirects targeted domains to the proxy.

    Discovery mode (--discover) logs all DNS queries without modification,
    useful for finding which domains the TV app uses.

    Example:
      mitm-tv dns --discover                    # See what domains the TV queries
      mitm-tv dns -d api.tvapp.com -d auth.tvapp.com  # Spoof specific domains
    """
    if not interface:
        interface = get_default_interface()

    my_ip = get_interface_ip(interface)

    from .dns_spoof import DNSSpoofer

    target_domains = list(domains) if not discover else []

    console.print(Panel("[bold]DNS Spoof Server[/bold]"))
    console.print(f"Listening on: [cyan]{my_ip}:{port}[/cyan]")

    if discover:
        console.print("Mode: [yellow]Discovery (no spoofing)[/yellow]")
        console.print("[dim]Set your TV's DNS server to this IP to see queries[/dim]")
    else:
        console.print(f"Spoofing {len(target_domains)} domain(s) -> {my_ip}")
        for d in target_domains:
            console.print(f"  [cyan]{d}[/cyan]")

    console.print()

    spoofer = DNSSpoofer(
        spoof_ip=my_ip,
        interface_ip="0.0.0.0",
        port=port,
        target_domains=target_domains,
    )

    try:
        spoofer.start()
        console.print("[green]DNS server running. Press Ctrl+C to stop.[/green]")
        console.print()

        # Live display of queries
        seen = 0
        while True:
            time.sleep(1)
            if len(spoofer.query_log) > seen:
                for entry in spoofer.query_log[seen:]:
                    status = "[red]SPOOFED[/red]" if entry["spoofed"] else "[dim]forwarded[/dim]"
                    console.print(
                        f"  {entry['from']:>15s}  {status}  [cyan]{entry['domain']}[/cyan]"
                    )
                seen = len(spoofer.query_log)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping DNS server...[/yellow]")
    finally:
        spoofer.stop()

        if spoofer.query_log:
            domains_seen = spoofer.get_observed_domains()
            console.print(f"\nTotal queries: {len(spoofer.query_log)}")
            console.print(f"Unique domains: {len(domains_seen)}")

            if discover:
                console.print("\n[bold]Discovered domains:[/bold]")
                for d in domains_seen:
                    console.print(f"  [cyan]{d}[/cyan]")
                console.print()
                console.print("[bold]Next steps:[/bold]")
                console.print(
                    "  mitm-tv dns -d <domain1> -d <domain2>  "
                    "[dim]# Spoof specific domains[/dim]"
                )


# ---------------------------------------------------------------------------
# fingerprints - Manage saved fingerprints
# ---------------------------------------------------------------------------

@main.group()
def fp():
    """Manage saved device fingerprints."""
    pass


@fp.command("list")
def fp_list():
    """List all saved fingerprints."""
    store = FingerprintStore()
    names = store.list_fingerprints()
    if not names:
        console.print("[dim]No fingerprints saved. Run 'mitm-tv learn' first.[/dim]")
        return
    table = Table(title="Saved Fingerprints")
    table.add_column("Name", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("Headers", justify="right")
    table.add_column("Body Fields", justify="right")
    table.add_column("Domains", justify="right")
    for name in names:
        fp = store.load(name)
        table.add_row(
            name,
            fp.ip_address,
            str(len(fp.headers)),
            str(len(fp.body_fields)),
            str(len(fp.observed_domains)),
        )
    console.print(table)


@fp.command("show")
@click.argument("name")
def fp_show(name: str):
    """Show details of a saved fingerprint."""
    store = FingerprintStore()
    try:
        fingerprint = store.load(name)
    except FileNotFoundError:
        console.print(f"[red]Fingerprint '{name}' not found.[/red]")
        return

    console.print(Panel(f"[bold]Fingerprint: {name}[/bold]"))
    console.print(f"IP: {fingerprint.ip_address}")
    console.print(f"MAC: {fingerprint.mac_address or 'N/A'}")
    console.print(f"Captured: {fingerprint.captured_at}")
    console.print()

    if fingerprint.headers:
        table = Table(title="Headers")
        table.add_column("Name", style="cyan")
        table.add_column("Value", style="green")
        for h, v in fingerprint.headers.items():
            table.add_row(h, v)
        console.print(table)

    if fingerprint.body_fields:
        table = Table(title="Body Fields")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        for f, v in fingerprint.body_fields.items():
            table.add_row(f, str(v))
        console.print(table)

    if fingerprint.query_params:
        table = Table(title="Query Parameters")
        table.add_column("Param", style="cyan")
        table.add_column("Value", style="green")
        for p, v in fingerprint.query_params.items():
            table.add_row(p, v)
        console.print(table)

    if fingerprint.cookies:
        table = Table(title="Cookies")
        table.add_column("Name", style="cyan")
        table.add_column("Value", style="green")
        for c, v in fingerprint.cookies.items():
            table.add_row(c, v)
        console.print(table)

    if fingerprint.observed_domains:
        table = Table(title="Observed Domains")
        table.add_column("Domain", style="cyan")
        for d in fingerprint.observed_domains:
            table.add_row(d)
        console.print(table)


@fp.command("create")
@click.option("--name", "-n", required=True, help='Device name (e.g. "iPad")')
@click.option("--device-id", "-d", required=True, help="The app's device ID value")
@click.option(
    "--field", "-f", multiple=True,
    help='Additional field as name=value (e.g. -f "User-Agent=MyApp/1.0" -f "modelName=iPad")',
)
@click.option("--ip", default="manual", help="Source device IP (default: 'manual')")
def fp_create(name: str, device_id: str, field: tuple, ip: str):
    """Manually create a fingerprint from a known device ID.

    Use this when you already know the device ID (e.g. from an iPad, browser
    dev tools, or another device you can inspect). Skips the learn phase entirely.

    The device ID is stored in common field names so it gets matched during
    cloning regardless of what the app calls it.

    Examples:
      mitm-tv fp create -n "iPad" -d "-VUHXoGHr45MABV8Up0evXcA..."
      mitm-tv fp create -n "iPad" -d "abc123" -f "User-Agent=MyApp/2.0 iPad"
    """
    fingerprint = DeviceFingerprint(
        device_name=name,
        ip_address=ip,
    )

    # Store the device ID under all common field names so it matches
    # whatever the app actually sends
    fingerprint.update_body_field("deviceId", device_id)
    fingerprint.update_body_field("device_id", device_id)
    fingerprint.update_body_field("deviceID", device_id)
    fingerprint.update_header("X-Device-Id", device_id)
    fingerprint.update_header("X-Device-ID", device_id)

    # Parse additional fields
    for f in field:
        if "=" not in f:
            console.print(f"[red]Invalid field format '{f}', use name=value[/red]")
            continue
        fname, fvalue = f.split("=", 1)
        # Guess if it's a header (has - or uppercase start) or body field
        if "-" in fname or fname[0].isupper():
            fingerprint.update_header(fname, fvalue)
        else:
            fingerprint.update_body_field(fname, fvalue)

    store = FingerprintStore()
    path = store.save(fingerprint)

    console.print(Panel("[bold green]Fingerprint Created[/bold green]"))
    console.print(f"Name: [cyan]{name}[/cyan]")
    console.print(f"Device ID: [yellow]{device_id}[/yellow]")
    console.print(f"Saved to: {path}")

    if fingerprint.headers:
        table = Table(title="Headers")
        table.add_column("Name", style="cyan")
        table.add_column("Value", style="green")
        for h, v in fingerprint.headers.items():
            table.add_row(h, v[:80])
        console.print(table)

    if fingerprint.body_fields:
        table = Table(title="Body Fields")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        for f, v in fingerprint.body_fields.items():
            table.add_row(f, str(v)[:80])
        console.print(table)

    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(
        f'  mitm-tv clone --target <TV2_IP> --source "{name}"  '
        "[dim]# Clone this identity onto TV2[/dim]"
    )
    console.print(
        f'  mitm-tv fp show "{name}"  '
        "[dim]# Review the fingerprint[/dim]"
    )
    console.print(
        f'  mitm-tv fp edit "{name}"  '
        "[dim]# Add more fields if needed[/dim]"
    )


@fp.command("edit")
@click.argument("name")
@click.option("--set-header", "-H", multiple=True, help="Set header: name=value")
@click.option("--set-field", "-F", multiple=True, help="Set body field: name=value")
@click.option("--set-param", "-P", multiple=True, help="Set query param: name=value")
@click.option("--set-domain", "-D", multiple=True, help="Add an observed domain")
@click.option("--set-device-id", help="Update the device ID across all common fields")
def fp_edit(
    name: str,
    set_header: tuple,
    set_field: tuple,
    set_param: tuple,
    set_domain: tuple,
    set_device_id: Optional[str],
):
    """Edit an existing fingerprint by adding or updating fields.

    Examples:
      mitm-tv fp edit "iPad" -H "User-Agent=NewAgent" -F "modelName=iPad Pro"
      mitm-tv fp edit "iPad" --set-device-id "newDeviceIdValue"
    """
    store = FingerprintStore()
    try:
        fingerprint = store.load(name)
    except FileNotFoundError:
        console.print(f"[red]Fingerprint '{name}' not found.[/red]")
        return

    changes = 0

    if set_device_id:
        for field_name in ("deviceId", "device_id", "deviceID"):
            fingerprint.update_body_field(field_name, set_device_id)
        for header_name in ("X-Device-Id", "X-Device-ID"):
            fingerprint.update_header(header_name, set_device_id)
        changes += 1

    for h in set_header:
        if "=" in h:
            hname, hval = h.split("=", 1)
            fingerprint.update_header(hname, hval)
            changes += 1

    for f in set_field:
        if "=" in f:
            fname, fval = f.split("=", 1)
            fingerprint.update_body_field(fname, fval)
            changes += 1

    for p in set_param:
        if "=" in p:
            pname, pval = p.split("=", 1)
            fingerprint.update_query_param(pname, pval)
            changes += 1

    for d in set_domain:
        fingerprint.add_domain(d)
        changes += 1

    if changes:
        path = store.save(fingerprint)
        console.print(f"[green]Updated {changes} field(s) in '{name}'[/green]")
        console.print(f"Saved to: {path}")
    else:
        console.print("[yellow]No changes specified[/yellow]")


@fp.command("export")
@click.argument("name")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
def fp_export(name: str, output: Optional[str]):
    """Export a fingerprint as JSON."""
    store = FingerprintStore()
    try:
        data = store.export_json(name)
    except FileNotFoundError:
        console.print(f"[red]Fingerprint '{name}' not found.[/red]")
        return

    if output:
        with open(output, "w") as f:
            f.write(data)
        console.print(f"Exported to [green]{output}[/green]")
    else:
        console.print(data)


@fp.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Are you sure?")
def fp_delete(name: str):
    """Delete a saved fingerprint."""
    store = FingerprintStore()
    if store.delete(name):
        console.print(f"[green]Deleted fingerprint '{name}'[/green]")
    else:
        console.print(f"[red]Fingerprint '{name}' not found.[/red]")


# ---------------------------------------------------------------------------
# capture - Capture app handshake from iPad/other proxy-able device
# ---------------------------------------------------------------------------

@main.command()
@click.option("--port", "-p", default=8080, help="Proxy port (default: 8080)")
@click.option("--name", "-n", required=True, help='Capture name (e.g. "ipad-session")')
@click.option("--capture-all", is_flag=True, help="Capture all requests (not just registration-like ones)")
@click.option("--fingerprint", "-f", default=None, help="Also save a fingerprint with this name")
def capture(port: int, name: str, capture_all: bool, fingerprint: Optional[str]):
    """Capture the app's registration handshake from an iPad or other device.

    This runs a regular (non-transparent) HTTP proxy. Point the iPad's WiFi
    proxy settings to your MacBook's IP and this port. The proxy captures
    the full request/response exchange, focusing on registration and login
    flows where the device ID is sent.

    NO ARP spoofing or root required - the iPad connects to the proxy voluntarily.

    This is the recommended first step when the TV app has HTTPS cert pinning,
    because iOS does NOT enforce cert pinning for third-party apps.

    Example:
      mitm-tv capture -n "ipad-session" -f "iPad"
      # Then set iPad WiFi proxy to <mac-ip>:8080 and use the app
    """
    from .handshake import HandshakeCaptureAddon, HandshakeStore, TLSPassthroughAddon

    handshake_addon = HandshakeCaptureAddon(
        capture_all=capture_all,
        on_capture=lambda h, s: console.print(
            f"  [green]Captured[/green] {h.method} {h.url} "
            f"(score: {s:.1f}, tags: {h.tags})"
        ),
    )
    tls_addon = TLSPassthroughAddon(
        on_pinning_detected=lambda d: console.print(
            f"  [yellow]Cert pinning detected:[/yellow] {d} (passing through)"
        ),
    )

    console.print(Panel("[bold]Handshake Capture Mode[/bold]"))
    console.print(f"Proxy listening on: [cyan]0.0.0.0:{port}[/cyan]")
    console.print()
    console.print("[bold]Setup:[/bold]")
    console.print(f"  1. On your iPad, go to WiFi settings")
    console.print(f"  2. Set HTTP Proxy to Manual")
    console.print(f"  3. Server: [cyan]<your-mac-ip>[/cyan]  Port: [cyan]{port}[/cyan]")
    console.print(f"  4. Open the TV app on the iPad and use it normally")
    console.print(f"  5. Press Ctrl+C when done")
    console.print()
    console.print(
        "[dim]For HTTPS: visit http://mitm.it on the iPad to install the "
        "mitmproxy CA cert[/dim]"
    )
    console.print()
    console.print("[bold]Capturing... press Ctrl+C to stop[/bold]")
    console.print()

    try:
        # Run as regular proxy (not transparent) since iPad is configured manually
        _run_mitmproxy(port=port, addons=[handshake_addon, tls_addon], mode="regular")
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping...[/yellow]")

    # Save captured handshakes
    hs_store = HandshakeStore()
    if handshake_addon.handshakes:
        path = hs_store.save(name, handshake_addon.handshakes)
        console.print()
        console.print(Panel("[bold green]Handshake Capture Complete[/bold green]"))
        console.print(f"Saved to: [cyan]{path}[/cyan]")
        console.print(
            f"Total requests: {handshake_addon.request_count}, "
            f"Registration-like: {len(handshake_addon.handshakes)}"
        )

        # Show captured handshakes
        table = Table(title="Captured Handshakes")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Method", style="cyan")
        table.add_column("URL", style="green", max_width=60)
        table.add_column("Status", justify="right")
        table.add_column("Tags", style="yellow")
        for i, h in enumerate(handshake_addon.handshakes):
            table.add_row(
                str(i),
                h.method,
                h.url[:60],
                str(h.status_code),
                ", ".join(h.tags),
            )
        console.print(table)

        # Also create a fingerprint if requested
        if fingerprint:
            from .sniffer import LearnAddon, _extract_json_fields
            from .config import load_rules

            fp_obj = DeviceFingerprint(
                device_name=fingerprint,
                ip_address="ipad-capture",
            )

            # Extract identity fields from all captured handshakes
            for h in handshake_addon.handshakes:
                # Headers
                for hdr_name, hdr_val in h.request_headers.items():
                    lower = hdr_name.lower()
                    if any(k in lower for k in (
                        "device", "client", "auth", "user-agent",
                        "samsung", "lg", "x-"
                    )):
                        fp_obj.update_header(hdr_name, hdr_val)

                # Body fields
                req_json = h.get_request_json()
                if req_json and isinstance(req_json, dict):
                    fields = _extract_json_fields(req_json)
                    for field_name, value in fields.items():
                        fp_obj.update_body_field(field_name, value)

                # Response tokens
                resp_json = h.get_response_json()
                if resp_json and isinstance(resp_json, dict):
                    for key in ("token", "access_token", "accessToken",
                                "auth_token", "authToken", "sessionId"):
                        if key in resp_json:
                            fp_obj.update_header("Authorization",
                                                 f"Bearer {resp_json[key]}")

                fp_obj.add_domain(h.host)

            fp_store = FingerprintStore()
            fp_path = fp_store.save(fp_obj)
            console.print(f"\nFingerprint saved as: [cyan]{fingerprint}[/cyan] at {fp_path}")

        # Report cert pinning
        if tls_addon.pinned_domains:
            console.print()
            console.print("[yellow]Cert-pinned domains (could not intercept):[/yellow]")
            for d in sorted(tls_addon.pinned_domains):
                console.print(f"  [red]{d}[/red]")

        if tls_addon.intercepted_domains:
            console.print()
            console.print("[green]Successfully intercepted domains:[/green]")
            for d in sorted(tls_addon.intercepted_domains):
                console.print(f"  [green]{d}[/green]")

    else:
        console.print()
        console.print("[yellow]No registration-like requests captured.[/yellow]")
        console.print(
            "Try --capture-all to see everything, or make sure the app "
            "performed a login/registration."
        )

    # Save full capture too
    if handshake_addon.all_flows:
        full_path = hs_store.save(f"{name}_full", handshake_addon.all_flows)
        console.print(f"\nFull capture ({len(handshake_addon.all_flows)} requests): {full_path}")

    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(
        f'  mitm-tv replay -n "{name}" --show   '
        "[dim]# Review the captured handshake[/dim]"
    )
    if fingerprint:
        console.print(
            f'  mitm-tv clone --target <TV2_IP> --source "{fingerprint}"  '
            "[dim]# Clone identity onto TV2[/dim]"
        )


# ---------------------------------------------------------------------------
# replay - Replay a captured registration request
# ---------------------------------------------------------------------------

@main.command()
@click.option("--name", "-n", required=True, help="Name of the captured handshake")
@click.option("--show", is_flag=True, help="Just show the captured handshake (don't replay)")
@click.option("--index", default=0, help="Which captured request to replay (default: 0)")
@click.option("--device-id", "-d", default=None, help="Override the device ID in the request")
@click.option("--device-id-field", default="deviceId", help="JSON field name for device ID")
@click.option("--dry-run", is_flag=True, help="Show what would be sent without sending")
def replay(name: str, show: bool, index: int, device_id: Optional[str],
           device_id_field: str, dry_run: bool):
    """Replay a captured registration handshake to the app server.

    Use this to re-register a device with the same identity, or to register
    a new device using a captured device ID.

    Example:
      mitm-tv replay -n "ipad-session" --show          # Review what was captured
      mitm-tv replay -n "ipad-session" --dry-run       # See what would be sent
      mitm-tv replay -n "ipad-session"                  # Actually replay it
      mitm-tv replay -n "ipad-session" -d "new-id"      # Replay with different device ID
    """
    from .handshake import HandshakeStore, replay_registration

    hs_store = HandshakeStore()
    try:
        handshakes = hs_store.load(name)
    except FileNotFoundError:
        console.print(f"[red]Capture '{name}' not found.[/red]")
        available = hs_store.list_captures()
        if available:
            console.print("Available captures:")
            for n in available:
                console.print(f"  - {n}")
        return

    if show:
        console.print(Panel(f"[bold]Captured Handshake: {name}[/bold]"))
        for i, h in enumerate(handshakes):
            console.print(f"\n[bold]--- Request #{i} ---[/bold]")
            console.print(f"[cyan]{h.method} {h.url}[/cyan]")
            console.print(f"Status: {h.status_code}")
            console.print(f"Tags: {', '.join(h.tags) or 'none'}")
            console.print(f"Captured: {h.captured_at}")

            if h.request_headers:
                console.print("\n[dim]Request Headers:[/dim]")
                for k, v in h.request_headers.items():
                    console.print(f"  {k}: {v[:100]}")

            if h.request_body:
                console.print("\n[dim]Request Body:[/dim]")
                try:
                    pretty = json.dumps(json.loads(h.request_body), indent=2)
                    console.print(pretty[:2000])
                except (json.JSONDecodeError, TypeError):
                    console.print(h.request_body[:2000])

            if h.response_body:
                console.print(f"\n[dim]Response ({h.status_code}):[/dim]")
                try:
                    pretty = json.dumps(json.loads(h.response_body), indent=2)
                    console.print(pretty[:2000])
                except (json.JSONDecodeError, TypeError):
                    console.print(h.response_body[:2000])
        return

    # Replay
    if index >= len(handshakes):
        console.print(f"[red]Index {index} out of range (0-{len(handshakes)-1})[/red]")
        return

    h = handshakes[index]
    console.print(Panel("[bold]Replay Registration[/bold]"))
    console.print(f"Target: [cyan]{h.method} {h.url}[/cyan]")

    if device_id:
        console.print(f"Override device ID field '{device_id_field}': [yellow]{device_id}[/yellow]")

    if dry_run:
        console.print("\n[yellow]DRY RUN - showing what would be sent:[/yellow]")
        body = h.request_body or ""
        if device_id and body:
            try:
                body_json = json.loads(body)
                if isinstance(body_json, dict):
                    for variant in (device_id_field, "deviceId", "device_id", "deviceID"):
                        if variant in body_json:
                            body_json[variant] = device_id
                    body = json.dumps(body_json, indent=2)
            except (json.JSONDecodeError, TypeError):
                pass
        console.print(f"\n{h.method} {h.url}")
        for k, v in h.request_headers.items():
            console.print(f"  {k}: {v[:100]}")
        console.print(f"\n{body[:2000]}")
        return

    console.print("\n[dim]Sending...[/dim]")
    result = replay_registration(
        handshake=h,
        new_device_id=device_id,
        device_id_field=device_id_field,
    )

    console.print(f"\nStatus: [{'green' if result['status_code'] == 200 else 'red'}]"
                  f"{result['status_code']}[/]")

    if result.get("error"):
        console.print(f"Error: [red]{result['error']}[/red]")

    if result["body"]:
        console.print("\n[dim]Response:[/dim]")
        try:
            pretty = json.dumps(json.loads(result["body"]), indent=2)
            console.print(pretty[:3000])
        except (json.JSONDecodeError, TypeError):
            console.print(result["body"][:3000])


# ---------------------------------------------------------------------------
# network info helper
# ---------------------------------------------------------------------------

@main.command()
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
def info(interface: Optional[str]):
    """Show network information useful for setup."""
    if not interface:
        interface = get_default_interface()

    console.print(Panel("[bold]Network Information[/bold]"))
    console.print(f"Interface: [cyan]{interface}[/cyan]")

    try:
        ip = get_interface_ip(interface)
        console.print(f"IP Address: [green]{ip}[/green]")
    except RuntimeError as e:
        console.print(f"IP Address: [red]{e}[/red]")

    try:
        mac = get_mac_address(interface)
        console.print(f"MAC Address: [green]{mac}[/green]")
    except RuntimeError as e:
        console.print(f"MAC Address: [red]{e}[/red]")

    try:
        gw = get_gateway_ip()
        console.print(f"Gateway: [green]{gw}[/green]")
    except RuntimeError as e:
        console.print(f"Gateway: [red]{e}[/red]")

    console.print()
    console.print(f"Config dir: {get_data_dir()}")

    store = FingerprintStore()
    fps = store.list_fingerprints()
    console.print(f"Saved fingerprints: {len(fps)}")
    for name in fps:
        console.print(f"  - {name}")


# ---------------------------------------------------------------------------
# Helper: run mitmproxy inline
# ---------------------------------------------------------------------------

def _run_mitmproxy(port: int, addons: list, mode: str = "transparent") -> None:
    """Run mitmproxy with the given addons.

    This starts mitmproxy's event loop and blocks until interrupted.
    """
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    opts = Options(
        listen_port=port,
        mode=[mode] if mode else [],
    )

    async def _start():
        master = DumpMaster(opts)
        for addon in addons:
            master.addons.add(addon)
        try:
            await master.run()
        except KeyboardInterrupt:
            master.shutdown()

    try:
        asyncio.run(_start())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
