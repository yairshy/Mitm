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
