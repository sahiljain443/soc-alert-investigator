#!/usr/bin/env python3
"""List DataDog security signals with full details including IDs."""

import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from datadog_connector import DataDogClient
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def format_time_ago(timestamp):
    """Format timestamp as relative time."""
    if timestamp is None:
        return "unknown"

    if isinstance(timestamp, (int, float)):
        if timestamp > 1e12:
            timestamp = timestamp / 1000
        dt = datetime.utcfromtimestamp(timestamp)
    elif isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            dt = dt.replace(tzinfo=None)
        except ValueError:
            return timestamp
    else:
        return str(timestamp)

    now = datetime.utcnow()
    delta = now - dt

    if delta.days > 0:
        return f"{delta.days}d ago"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        return f"{hours}h ago"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        return f"{minutes}m ago"
    else:
        return "just now"

def main():
    console = Console()

    # Fetch signals
    client = DataDogClient()
    from_time = datetime.utcnow() - timedelta(hours=24)
    signals = client.list_signals_by_severity(severity="high", from_time=from_time, limit=5)

    if not signals:
        console.print("[yellow]No high severity signals found.[/yellow]")
        return

    console.print(f"\n[bold cyan]Found {len(signals)} high severity signals:[/bold cyan]\n")

    # Display each signal with details
    for idx, signal in enumerate(signals, 1):
        attrs = signal.get("attributes", {})
        signal_attrs = attrs.get("attributes", {})

        signal_id = signal.get("id", "unknown")
        severity = str(attrs.get("severity", "unknown"))
        status = attrs.get("status", "unknown")
        timestamp = attrs.get("timestamp")

        # Get title from rule
        rule = attrs.get("rule", {})
        title = rule.get("name", "Untitled")

        # Get message
        message = attrs.get("message", "")

        # Get IP and user
        network = signal_attrs.get("network", {})
        client_data = network.get("client", {})
        source_ip = client_data.get("ip", "-")

        usr = signal_attrs.get("usr", {})
        user_email = usr.get("email", "-")

        # Format severity label
        severity_labels = {"4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
        severity_label = severity_labels.get(severity, severity.upper())

        # Build detail text
        detail_text = f"""[bold]#{idx} - {title}[/bold]

[bold]Signal ID:[/bold] {signal_id}
[bold]Severity:[/bold] {severity_label}
[bold]Status:[/bold] {status}
[bold]Time:[/bold] {format_time_ago(timestamp)}
[bold]Source IP:[/bold] {source_ip}
[bold]User:[/bold] {user_email}

[bold]Message:[/bold]
{message[:300]}{'...' if len(message) > 300 else ''}
"""

        panel = Panel(detail_text, border_style="cyan")
        console.print(panel)
        console.print()

    console.print("\n[bold green]To investigate a signal, use:[/bold green]")
    console.print("[dim]python3 main.py --datadog-id <SIGNAL_ID>[/dim]\n")

if __name__ == "__main__":
    main()
