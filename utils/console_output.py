"""Console output formatting using Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich import box

from models.alert import DataDogAlert
from models.ioc import IOC, IOCType
from models.finding import Finding, RiskLevel


class ConsoleOutput:
    """Rich console output for investigation reports."""

    def __init__(self):
        self.console = Console()

    def print_header(self, title: str) -> None:
        """Print a styled header."""
        self.console.print()
        self.console.rule(f"[bold blue]{title}[/bold blue]")
        self.console.print()

    def print_alert_summary(self, alert: DataDogAlert) -> None:
        """Print alert summary panel."""
        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
        }
        color = severity_colors.get(alert.severity, "white")

        content = f"""[bold]ID:[/bold] {alert.id}
[bold]Title:[/bold] {alert.title}
[bold]Severity:[/bold] [{color}]{alert.severity.upper()}[/{color}]
[bold]Source:[/bold] {alert.source}
[bold]Timestamp:[/bold] {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
[bold]Host:[/bold] {alert.host or 'N/A'}
[bold]Service:[/bold] {alert.service or 'N/A'}

[bold]Message:[/bold]
{alert.message[:500] + '...' if len(alert.message) > 500 else alert.message}"""

        panel = Panel(
            content,
            title="[bold]Alert Summary[/bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
        self.console.print(panel)

    def print_iocs(self, iocs: list[IOC]) -> None:
        """Print IOC table."""
        if not iocs:
            self.console.print("[dim]No IOCs extracted[/dim]")
            return

        table = Table(
            title="Extracted IOCs",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="white")
        table.add_column("Internal", justify="center")
        table.add_column("Context", style="dim", max_width=40)

        # Sort by type
        sorted_iocs = sorted(iocs, key=lambda x: x.type.value)

        for ioc in sorted_iocs:
            internal_marker = "[green]Yes[/green]" if ioc.is_internal else "[red]No[/red]"
            context = ioc.context[:40] + "..." if len(ioc.context) > 40 else ioc.context
            table.add_row(
                ioc.type.value,
                ioc.value,
                internal_marker,
                context,
            )

        self.console.print(table)

    def print_ip_threat_intel_table(self, ip_threat_intel: list[dict]) -> None:
        """
        Print IP threat intelligence table in Key Findings.

        This table is ALWAYS included when IPs are relevant to the alert investigation.
        """
        if not ip_threat_intel:
            self.console.print("[dim]No IP addresses to analyze[/dim]")
            return

        risk_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        table = Table(
            title="IP Threat Intelligence Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Location", style="white")
        table.add_column("Reputation", style="white")
        table.add_column("Blocklists", justify="center")
        table.add_column("Known Activity", style="dim", max_width=35)
        table.add_column("Risk", justify="center")

        for ip_data in ip_threat_intel:
            risk_level = ip_data.get("risk_level", "info")
            color = risk_colors.get(risk_level, "white")

            # Format blocklist status
            blocklist_status = ip_data.get("blocklists", "No")
            if blocklist_status == "Yes":
                blocklist_display = "[red]Yes[/red]"
            else:
                blocklist_display = "[green]No[/green]"

            # Format reputation
            reputation = ip_data.get("reputation", "Unknown")
            if "malicious" in reputation.lower():
                reputation_display = f"[red]{reputation}[/red]"
            elif "suspicious" in reputation.lower() or "flagged" in reputation.lower():
                reputation_display = f"[yellow]{reputation}[/yellow]"
            elif "clean" in reputation.lower():
                reputation_display = f"[green]{reputation}[/green]"
            else:
                reputation_display = reputation

            # Format risk badge
            risk_badge = f"[{color}]{risk_level.upper()}[/{color}]"

            # Truncate known activity
            known_activity = ip_data.get("known_activity", "None identified")
            if len(known_activity) > 35:
                known_activity = known_activity[:32] + "..."

            table.add_row(
                ip_data.get("ip", "N/A"),
                ip_data.get("location", "Unknown"),
                reputation_display,
                blocklist_display,
                known_activity,
                risk_badge,
            )

        self.console.print(table)

    def print_findings(self, findings: list[Finding]) -> None:
        """Print investigation findings."""
        if not findings:
            self.console.print("[dim]No findings[/dim]")
            return

        risk_colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "orange1",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.INFO: "blue",
        }

        # Group by source
        by_source: dict[str, list[Finding]] = {}
        for finding in findings:
            source = finding.source.value
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(finding)

        for source, source_findings in by_source.items():
            self.console.print(f"\n[bold cyan]{source.upper()} Findings[/bold cyan]")

            for finding in source_findings:
                color = risk_colors.get(finding.risk_level, "white")
                risk_badge = f"[{color}][{finding.risk_level.value.upper()}][/{color}]"

                self.console.print(f"  {risk_badge} [bold]{finding.title}[/bold]")
                self.console.print(f"    [dim]{finding.description}[/dim]")
                if finding.ioc_value:
                    self.console.print(f"    [dim]IOC: {finding.ioc_value}[/dim]")
                self.console.print()

    def print_risk_assessment(
        self,
        overall_risk: RiskLevel,
        risk_score: float,
        summary: str,
        recommendations: list[str],
    ) -> None:
        """Print overall risk assessment panel."""
        risk_colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "orange1",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.INFO: "blue",
        }
        color = risk_colors.get(overall_risk, "white")

        # Build recommendations text
        rec_text = "\n".join(f"  {i+1}. {rec}" for i, rec in enumerate(recommendations))

        content = f"""[bold]Overall Risk Level:[/bold] [{color}]{overall_risk.value.upper()}[/{color}]
[bold]Risk Score:[/bold] {risk_score:.0%}

[bold]Summary:[/bold]
{summary}

[bold]Recommendations:[/bold]
{rec_text}"""

        panel = Panel(
            content,
            title="[bold]Risk Assessment[/bold]",
            border_style=color,
            box=box.DOUBLE,
        )
        self.console.print(panel)

    def print_report(
        self,
        alert: DataDogAlert,
        iocs: list[IOC],
        findings: list[Finding],
        overall_risk: RiskLevel,
        risk_score: float,
        summary: str,
        recommendations: list[str],
    ) -> None:
        """Print complete investigation report."""
        self.print_header("SOC Alert Investigation Report")
        self.print_alert_summary(alert)
        self.console.print()

        self.print_header("Indicators of Compromise")
        self.print_iocs(iocs)

        self.print_header("Investigation Findings")
        self.print_findings(findings)

        self.print_header("Risk Assessment")
        self.print_risk_assessment(overall_risk, risk_score, summary, recommendations)

        self.console.print()
        self.console.rule("[bold blue]End of Report[/bold blue]")
        self.console.print()

    def print_progress(self, message: str) -> None:
        """Print a progress message."""
        self.console.print(f"[dim][*][/dim] {message}")

    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[green][+][/green] {message}")

    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[red][!][/red] {message}")

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[yellow][!][/yellow] {message}")
