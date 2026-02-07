"""Interactive CLI for selecting DataDog security signals."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel

from .client import DataDogClient, DataDogClientError
from .signal_mapper import SignalMapper


class SignalSelector:
    """Interactive CLI for browsing and selecting DataDog security signals."""

    SEVERITY_COLORS = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
        # Numeric severity mapping (DataDog API returns integers)
        "4": "red bold",
        "3": "red",
        "2": "yellow",
        "1": "blue",
        "0": "dim",
    }

    # Map numeric severity to string labels
    SEVERITY_LABELS = {
        "4": "CRITICAL",
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "INFO",
    }

    def __init__(self, client: Optional[DataDogClient] = None):
        """Initialize signal selector.

        Args:
            client: DataDog client instance. Creates one if not provided.
        """
        self.client = client or DataDogClient()
        self.console = Console()
        self._cached_signals: List[Dict[str, Any]] = []

    def _format_time_ago(self, timestamp: Any) -> str:
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
        elif isinstance(timestamp, datetime):
            dt = timestamp
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

    def _get_severity_style(self, severity) -> str:
        """Get Rich style for severity level."""
        severity_str = str(severity).lower()
        return self.SEVERITY_COLORS.get(severity_str, "white")

    def fetch_signals(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch security signals from DataDog.

        Args:
            hours: Number of hours to look back.
            severity: Filter by severity (optional).
            limit: Maximum number of signals to fetch.
            open_only: Only fetch open (untriaged) signals.

        Returns:
            List of signal dictionaries.
        """
        from_time = datetime.utcnow() - timedelta(hours=hours)

        try:
            if open_only:
                signals = self.client.list_open_signals(from_time=from_time, limit=limit)
            elif severity:
                signals = self.client.list_signals_by_severity(
                    severity=severity, from_time=from_time, limit=limit
                )
            else:
                signals = self.client.list_security_signals(
                    from_time=from_time, limit=limit
                )

            self._cached_signals = signals
            return signals

        except DataDogClientError as e:
            self.console.print(f"[red]Error fetching signals: {e}[/red]")
            return []

    def display_signals(self, signals: Optional[List[Dict[str, Any]]] = None) -> None:
        """Display signals in a formatted table.

        Args:
            signals: List of signals to display. Uses cached signals if not provided.
        """
        if signals is None:
            signals = self._cached_signals

        if not signals:
            self.console.print("[yellow]No signals found.[/yellow]")
            return

        # Display summary banner
        total = len(signals)
        severity_counts = {}
        status_counts = {}

        for signal in signals:
            attrs = signal.get("attributes", {})
            severity = str(attrs.get("severity", "unknown"))
            status = str(attrs.get("status", "unknown"))

            severity_label = self.SEVERITY_LABELS.get(severity, severity.upper())
            severity_counts[severity_label] = severity_counts.get(severity_label, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1

        summary_text = f"[bold]Total Signals:[/bold] {total}  "
        if severity_counts:
            summary_text += "[bold]Severity:[/bold] "
            for sev, count in sorted(severity_counts.items()):
                color = self._get_severity_style(sev)
                summary_text += f"[{color}]{sev}: {count}[/{color}]  "

        summary_panel = Panel(
            summary_text,
            title="[bold cyan]DataDog Security Signals Summary[/bold cyan]",
            border_style="cyan",
            padding=(0, 2)
        )
        self.console.print(summary_panel)
        self.console.print()

        # Main signals table
        table = Table(
            title="[bold]Select a Signal to Investigate[/bold]",
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            padding=(0, 1)
        )

        table.add_column("#", justify="right", style="cyan bold", width=4)
        table.add_column("Severity", width=12, justify="center")
        table.add_column("Title", width=45, overflow="ellipsis")
        table.add_column("Status", width=10, justify="center")
        table.add_column("Source IP", width=15, overflow="ellipsis")
        table.add_column("User", width=20, overflow="ellipsis")
        table.add_column("Time", width=12, justify="right")

        for idx, signal in enumerate(signals, 1):
            attrs = signal.get("attributes", {})
            signal_attrs = attrs.get("attributes", {})

            severity = str(attrs.get("severity", "unknown"))
            title = self._extract_title(attrs)
            status = str(attrs.get("status", "unknown"))
            timestamp = attrs.get("timestamp")

            # Extract IP and user from nested attributes
            network = signal_attrs.get("network", {})
            client = network.get("client", {})
            source_ip = client.get("ip", "-")

            usr = signal_attrs.get("usr", {})
            user_email = usr.get("email", "-")
            if user_email != "-" and len(user_email) > 20:
                user_email = user_email[:17] + "..."

            severity_style = self._get_severity_style(severity)
            severity_label = self.SEVERITY_LABELS.get(severity, severity.upper())

            # Enhanced status styling with icons
            if status == "closed":
                status_display = "[green]✓ Closed[/green]"
            elif status == "open":
                status_display = "[red]● Open[/red]"
            elif status == "under_review":
                status_display = "[yellow]◐ Review[/yellow]"
            else:
                status_display = f"[dim]{status}[/dim]"

            # Add severity icon
            severity_icons = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪"
            }
            severity_icon = severity_icons.get(severity_label, "")
            severity_display = f"{severity_icon} [{severity_style}]{severity_label}[/{severity_style}]"

            table.add_row(
                str(idx),
                severity_display,
                title[:45],
                status_display,
                f"[dim]{source_ip}[/dim]",
                f"[dim]{user_email}[/dim]",
                self._format_time_ago(timestamp),
            )

        self.console.print(table)

    def _extract_title(self, attrs: Dict[str, Any]) -> str:
        """Extract title from signal attributes."""
        # Check nested attributes first (DataDog Security Signal structure)
        nested_attrs = attrs.get("attributes", {})

        # Title is often in nested attributes
        if "title" in nested_attrs:
            return nested_attrs["title"]

        # Or in workflow.rule.name
        workflow = nested_attrs.get("workflow", {})
        rule = workflow.get("rule", {})
        if isinstance(rule, dict) and "name" in rule:
            return rule["name"]

        # Fallback to top-level title
        if "title" in attrs:
            return attrs["title"]

        # Try rule at top level
        if "rule" in attrs:
            rule = attrs["rule"]
            if isinstance(rule, dict):
                return rule.get("name", "Untitled")

        # Use message first line as last resort (skip %%% placeholders)
        if "message" in attrs:
            message = attrs["message"]
            if isinstance(message, str) and not message.startswith("%%%"):
                return message.split("\n")[0][:50]

        return "Untitled Signal"

    def select_signal(
        self, signals: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """Interactively select a signal from the list.

        Args:
            signals: List of signals to select from. Uses cached signals if not provided.

        Returns:
            Selected signal dictionary, or None if cancelled.
        """
        if signals is None:
            signals = self._cached_signals

        if not signals:
            self.console.print("[yellow]No signals available to select.[/yellow]")
            return None

        self.console.print()
        try:
            selection = IntPrompt.ask(
                "Select signal to investigate (0 to cancel)",
                default=0,
            )

            if selection == 0:
                return None

            if 1 <= selection <= len(signals):
                return signals[selection - 1]
            else:
                self.console.print(f"[red]Invalid selection. Choose 1-{len(signals)}[/red]")
                return None

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Selection cancelled.[/yellow]")
            return None

    def get_mapped_alert(
        self, signal: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get a signal mapped to DataDogAlert format.

        Args:
            signal: Signal to map. Prompts for selection if not provided.

        Returns:
            Mapped alert dictionary ready for DataDogAlert.from_raw().
        """
        if signal is None:
            signal = self.select_signal()

        if signal is None:
            return None

        return SignalMapper.map_signal(signal)

    def show_signal_details(self, signal: Dict[str, Any]) -> None:
        """Display detailed information about a signal.

        Args:
            signal: Signal dictionary to display.
        """
        attrs = signal.get("attributes", {})
        signal_attrs = attrs.get("attributes", {})

        title = self._extract_title(attrs)
        severity = str(attrs.get("severity", "unknown"))
        severity_label = self.SEVERITY_LABELS.get(severity, severity.upper())
        status = str(attrs.get("status", "unknown"))
        timestamp = attrs.get("timestamp")
        message = attrs.get("message", "No message")
        # Use nested title in message if main message is just "%%%"
        if message.strip().replace("%", "").replace("\n", "").strip() == "":
            message = signal_attrs.get("title", "No message")

        # Build detail panel
        details = f"""[bold]Title:[/bold] {title}
[bold]Severity:[/bold] [{self._get_severity_style(severity)}]{severity_label}[/{self._get_severity_style(severity)}]
[bold]Status:[/bold] {status}
[bold]Time:[/bold] {self._format_time_ago(timestamp)}
[bold]Signal ID:[/bold] {signal.get('id', 'unknown')}

[bold]Message:[/bold]
{message[:500]}{'...' if len(message) > 500 else ''}
"""

        # Add network info if present
        network = signal_attrs.get("network", {})
        if network:
            client = network.get("client", {})
            if client.get("ip"):
                details += f"\n[bold]Source IP:[/bold] {client.get('ip')}"

        # Add user info if present
        usr = signal_attrs.get("usr", {})
        if usr:
            if usr.get("email"):
                details += f"\n[bold]User:[/bold] {usr.get('email')}"

        panel = Panel(details, title="Signal Details", border_style="cyan")
        self.console.print(panel)

    # ------------------------------------------------------------------
    # Non-interactive helpers (used by auto-pilot workflow)
    # ------------------------------------------------------------------

    def fetch_and_format_signals(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch signals and return structured summaries without any stdin interaction.

        Returns:
            List of dicts with keys: index, id, title, severity, status,
            source_ip, user, time_ago.
        """
        signals = self.fetch_signals(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

        formatted: List[Dict[str, Any]] = []
        for idx, signal in enumerate(signals, 1):
            attrs = signal.get("attributes", {})
            signal_attrs = attrs.get("attributes", {})

            severity_val = str(attrs.get("severity", "unknown"))
            severity_label = self.SEVERITY_LABELS.get(severity_val, severity_val.upper())
            title = self._extract_title(attrs)
            status = str(attrs.get("status", "unknown"))
            timestamp = attrs.get("timestamp")

            network = signal_attrs.get("network", {})
            client = network.get("client", {})
            source_ip = client.get("ip", "-")

            usr = signal_attrs.get("usr", {})
            user_email = usr.get("email", "-")

            formatted.append({
                "index": idx,
                "id": signal.get("id", "unknown"),
                "title": title,
                "severity": severity_label,
                "status": status,
                "source_ip": source_ip if isinstance(source_ip, str) else str(source_ip),
                "user": user_email,
                "time_ago": self._format_time_ago(timestamp),
            })

        return formatted

    def select_by_index(
        self,
        index: int,
        signals: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Select a signal by 1-based index and return a mapped alert dict.

        Args:
            index: 1-based position in the signal list.
            signals: Raw signal list. Uses cached signals if not provided.

        Returns:
            Mapped alert dict ready for ``DataDogAlert.from_raw()``, or None.
        """
        if signals is None:
            signals = self._cached_signals

        if not signals or index < 1 or index > len(signals):
            return None

        return SignalMapper.map_signal(signals[index - 1])

    # ------------------------------------------------------------------
    # Interactive flow (original CLI mode)
    # ------------------------------------------------------------------

    def interactive_select(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Run full interactive selection flow.

        Fetches signals, displays them, and prompts for selection.

        Args:
            hours: Number of hours to look back.
            severity: Filter by severity (optional).
            limit: Maximum number of signals to fetch.
            open_only: Only fetch open (untriaged) signals.

        Returns:
            Mapped alert dictionary ready for investigation, or None if cancelled.
        """
        self.console.print("[cyan]Fetching security signals from DataDog...[/cyan]")

        signals = self.fetch_signals(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

        if not signals:
            return None

        self.console.print()
        self.display_signals(signals)

        selected = self.select_signal(signals)
        if selected is None:
            return None

        self.console.print()
        self.show_signal_details(selected)

        # Confirm selection
        self.console.print()
        confirm = Prompt.ask(
            "Proceed with investigation?",
            choices=["y", "n"],
            default="y",
        )

        if confirm.lower() != "y":
            self.console.print("[yellow]Investigation cancelled.[/yellow]")
            return None

        return SignalMapper.map_signal(selected)
