"""Rich CLI presentation for investigation results with colors and emojis."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.padding import Padding
from rich.align import Align


class Verdict(Enum):
    """Investigation verdict categories."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Evidence:
    """Evidence supporting a verdict."""
    description: str
    source: str
    severity: Severity = Severity.INFO
    data: Optional[Dict[str, Any]] = None


@dataclass
class Recommendation:
    """Action recommendation."""
    action: str
    priority: Severity
    rationale: Optional[str] = None


@dataclass
class TimelineEvent:
    """Event in investigation timeline."""
    timestamp: str
    event_type: str
    description: str
    ip: Optional[str] = None
    status: str = "info"  # success, failed, info


@dataclass
class DeviceFingerprint:
    """Device fingerprint data."""
    ip: str
    device_type: str
    ja4: Optional[str] = None
    ja3: Optional[str] = None
    user_agent: Optional[str] = None
    event_count: int = 0
    status: str = "unknown"


class InvestigationPresenter:
    """Rich CLI presenter for investigation results with colors and emojis."""

    # Verdict configurations with emojis and colors
    VERDICT_CONFIG = {
        Verdict.MALICIOUS: {
            "emoji": "🚨",
            "color": "red",
            "label": "MALICIOUS - CONFIRMED THREAT",
            "icon": "❌",
        },
        Verdict.SUSPICIOUS: {
            "emoji": "⚠️",
            "color": "yellow",
            "label": "SUSPICIOUS - REQUIRES ATTENTION",
            "icon": "⚠️",
        },
        Verdict.BENIGN: {
            "emoji": "✅",
            "color": "green",
            "label": "BENIGN - NO THREAT DETECTED",
            "icon": "✅",
        },
        Verdict.FALSE_POSITIVE: {
            "emoji": "✅",
            "color": "cyan",
            "label": "FALSE POSITIVE - BENIGN ACTIVITY",
            "icon": "✅",
        },
        Verdict.INCONCLUSIVE: {
            "emoji": "❓",
            "color": "white",
            "label": "INCONCLUSIVE - MORE DATA NEEDED",
            "icon": "❓",
        },
    }

    # Severity configurations
    SEVERITY_CONFIG = {
        Severity.CRITICAL: {"emoji": "🔴", "color": "red bold", "label": "CRITICAL"},
        Severity.HIGH: {"emoji": "🟠", "color": "red", "label": "HIGH"},
        Severity.MEDIUM: {"emoji": "🟡", "color": "yellow", "label": "MEDIUM"},
        Severity.LOW: {"emoji": "🟢", "color": "green", "label": "LOW"},
        Severity.INFO: {"emoji": "🔵", "color": "blue", "label": "INFO"},
    }

    # Section emojis
    SECTION_EMOJIS = {
        "banner": "🛡️",
        "alert": "📋",
        "timeline": "🕐",
        "fingerprint": "🔍",
        "risk": "⚖️",
        "verdict": "🎯",
        "evidence": "📝",
        "recommendations": "💡",
        "iocs": "🔗",
        "footer": "🏁",
    }

    # Field emojis
    FIELD_EMOJIS = {
        "alert_id": "🔖",
        "title": "📌",
        "severity": "⚠️",
        "locations": "🌍",
        "user": "👤",
        "time": "🕐",
        "ip": "🌐",
        "device": "📱",
        "fingerprint": "🔑",
        "events": "📊",
        "status": "✓",
        "domain": "🔗",
        "email": "📧",
        "hash": "🔢",
    }

    # Status emojis
    STATUS_EMOJIS = {
        "success": "✅",
        "failed": "❌",
        "warning": "⚠️",
        "info": "ℹ️",
        "known": "✅",
        "unknown": "❓",
        "suspicious": "🚨",
        "pass": "✅",
        "fail": "❌",
    }

    def __init__(self, use_emojis: bool = True):
        """Initialize presenter.

        Args:
            use_emojis: Whether to use emojis in output (default: True)
        """
        self.console = Console()
        self.use_emojis = use_emojis

    def _emoji(self, key: str, category: str = "section") -> str:
        """Get emoji if enabled, otherwise empty string."""
        if not self.use_emojis:
            return ""

        if category == "section":
            return self.SECTION_EMOJIS.get(key, "") + "  "
        elif category == "field":
            return self.FIELD_EMOJIS.get(key, "") + " "
        elif category == "status":
            return self.STATUS_EMOJIS.get(key, "")
        return ""

    def _severity_display(self, severity: Severity) -> str:
        """Get formatted severity display."""
        config = self.SEVERITY_CONFIG.get(severity, self.SEVERITY_CONFIG[Severity.INFO])
        emoji = config["emoji"] + " " if self.use_emojis else ""
        return f"[{config['color']}]{emoji}{config['label']}[/{config['color']}]"

    def _status_display(self, status: str, text: Optional[str] = None) -> str:
        """Get formatted status display."""
        status_lower = status.lower()
        emoji = self.STATUS_EMOJIS.get(status_lower, "") + " " if self.use_emojis else ""

        colors = {
            "success": "green",
            "pass": "green",
            "known": "green",
            "failed": "red",
            "fail": "red",
            "suspicious": "red",
            "warning": "yellow",
            "unknown": "yellow",
            "info": "blue",
        }
        color = colors.get(status_lower, "white")
        display_text = text or status.title()
        return f"[{color}]{emoji}{display_text}[/{color}]"

    def print_banner(self, title: str = "SOC Alert Investigation Report") -> None:
        """Print investigation report banner."""
        emoji = self._emoji("banner", "section").strip()
        display_title = f"{emoji}  {title}  {emoji}" if emoji else title

        banner = Panel(
            Align.center(Text(display_title, style="bold white")),
            box=box.DOUBLE,
            style="bold blue",
            padding=(1, 2),
        )
        self.console.print()
        self.console.print(banner)
        self.console.print()

    def print_section_header(self, title: str, section_type: str = "alert") -> None:
        """Print a section header with emoji and color."""
        emoji = self._emoji(section_type, "section")

        colors = {
            "alert": "cyan",
            "timeline": "yellow",
            "fingerprint": "green",
            "risk": "yellow",
            "verdict": "green",
            "evidence": "cyan",
            "recommendations": "magenta",
            "iocs": "blue",
        }
        color = colors.get(section_type, "blue")

        self.console.print()
        self.console.print("━" * 80, style=color)
        self.console.print(f"{emoji}[bold {color}]{title.upper()}[/bold {color}]")
        self.console.print("━" * 80, style=color)
        self.console.print()

    def print_alert_summary(
        self,
        alert_id: str,
        title: str,
        severity: str,
        source_ips: List[str],
        target_user: Optional[str] = None,
        timestamp: Optional[str] = None,
        additional_fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """Print alert summary section."""
        self.print_section_header("Alert Summary", "alert")

        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }
        sev_color = severity_colors.get(severity.lower(), "white")
        sev_emoji = "🔴" if severity.lower() in ["critical", "high"] else "🟡" if severity.lower() == "medium" else "🟢"
        sev_display = f"[bold {sev_color}]{sev_emoji} {severity.upper()}[/bold {sev_color}]" if self.use_emojis else f"[bold {sev_color}]{severity.upper()}[/bold {sev_color}]"

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold white")
        table.add_column("Value")

        table.add_row(
            f"{self._emoji('alert_id', 'field')}Alert ID",
            f"[dim]{alert_id[:50]}{'...' if len(alert_id) > 50 else ''}[/dim]"
        )
        table.add_row(f"{self._emoji('title', 'field')}Title", f"[bold]{title}[/bold]")
        table.add_row(f"{self._emoji('severity', 'field')}Severity", sev_display)

        if source_ips:
            ips_display = ", ".join(source_ips[:2])
            if len(source_ips) > 2:
                ips_display += f" (+{len(source_ips) - 2} more)"
            table.add_row(f"{self._emoji('locations', 'field')}Source IPs", f"[cyan]{ips_display}[/cyan]")

        if target_user:
            table.add_row(f"{self._emoji('user', 'field')}Target User", f"[bold magenta]{target_user}[/bold magenta]")

        if timestamp:
            table.add_row(f"{self._emoji('time', 'field')}Time", f"[dim]{timestamp}[/dim]")

        if additional_fields:
            for key, value in additional_fields.items():
                table.add_row(f"  {key}", str(value))

        self.console.print(table)

    def print_timeline(self, events: List[TimelineEvent], title: str = "Timeline Analysis") -> None:
        """Print timeline of events."""
        if not events:
            return

        self.print_section_header(title, "timeline")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column(f"{self._emoji('time', 'field')}Time", style="dim", width=20)
        table.add_column("Event", width=12)
        table.add_column("Description", style="white")
        table.add_column(f"{self._emoji('ip', 'field')}IP", style="dim", width=20)

        for event in events:
            status_emoji = self._emoji(event.status, "status")
            status_colors = {"success": "green", "failed": "red", "info": "blue"}
            color = status_colors.get(event.status, "white")
            event_display = f"[{color}]{status_emoji} {event.event_type}[/{color}]"

            table.add_row(
                event.timestamp,
                event_display,
                event.description,
                event.ip or "-",
            )

        self.console.print(table)

    def print_device_fingerprints(
        self,
        fingerprints: List[DeviceFingerprint],
        title: str = "Device Fingerprint Analysis",
    ) -> None:
        """Print device fingerprint analysis table."""
        if not fingerprints:
            return

        self.print_section_header(title, "fingerprint")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green",
            expand=True,
        )
        table.add_column(f"{self._emoji('ip', 'field')}IP Address", style="cyan", no_wrap=True)
        table.add_column(f"{self._emoji('device', 'field')}Device", style="white")
        table.add_column(f"{self._emoji('fingerprint', 'field')}JA4 Fingerprint", style="dim", max_width=25, overflow="ellipsis")
        table.add_column(f"{self._emoji('events', 'field')}Events", justify="center")
        table.add_column(f"{self._emoji('status', 'field')}Status", justify="center")

        for fp in fingerprints:
            status_display = self._status_display(fp.status, fp.status.title())
            ja4_display = fp.ja4[:22] + "..." if fp.ja4 and len(fp.ja4) > 25 else (fp.ja4 or "-")

            table.add_row(
                fp.ip,
                fp.device_type,
                ja4_display,
                f"[bold]{fp.event_count}[/bold]",
                status_display,
            )

        self.console.print(table)

    def print_key_finding(
        self,
        title: str,
        findings: List[str],
        finding_type: str = "success",  # success, warning, error
    ) -> None:
        """Print a key finding panel."""
        type_config = {
            "success": {"color": "green", "emoji": "✅", "border": "green"},
            "warning": {"color": "yellow", "emoji": "⚠️", "border": "yellow"},
            "error": {"color": "red", "emoji": "🚨", "border": "red"},
            "info": {"color": "cyan", "emoji": "ℹ️", "border": "cyan"},
        }
        config = type_config.get(finding_type, type_config["info"])

        emoji = config["emoji"] + " " if self.use_emojis else ""

        content = f"[bold {config['color']}]{emoji}{title}[/bold {config['color']}]\n\n"
        for finding in findings:
            bullet = "   🔹 " if self.use_emojis else "   • "
            content += f"{bullet}{finding}\n"

        self.console.print(Panel(
            content,
            title=f"[bold]{self._emoji('fingerprint', 'section')}Key Finding[/bold]",
            border_style=config["border"],
            box=box.DOUBLE,
        ))

    def print_risk_assessment(
        self,
        risk_factors: List[Dict[str, str]],
        title: str = "Risk Assessment",
    ) -> None:
        """Print risk assessment section."""
        if not risk_factors:
            return

        self.print_section_header(title, "risk")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("Risk Factor", style="white")
        table.add_column("Assessment", style="white")
        table.add_column("Status", justify="center")

        for factor in risk_factors:
            name = factor.get("name", "Unknown")
            assessment = factor.get("assessment", "-")
            status = factor.get("status", "info")

            status_display = self._status_display(status, factor.get("status_text", status.upper()))

            table.add_row(name, assessment, status_display)

        self.console.print(table)

    def print_verdict(
        self,
        verdict: Verdict,
        confidence: str = "HIGH",
        summary: Optional[str] = None,
    ) -> None:
        """Print the investigation verdict."""
        self.print_section_header("Investigation Verdict", "verdict")

        config = self.VERDICT_CONFIG[verdict]
        emoji = config["emoji"] + "  " if self.use_emojis else ""

        # Confidence bar
        conf_bars = {"HIGH": "●●●●●", "MEDIUM": "●●●○○", "LOW": "●○○○○"}
        conf_bar = conf_bars.get(confidence.upper(), "●●●○○")

        verdict_text = Text()
        verdict_text.append("\n")
        verdict_text.append(f"   {emoji}", style=f"bold {config['color']}")
        verdict_text.append(config["label"], style=f"bold {config['color']}")
        verdict_text.append("\n\n")
        verdict_text.append("   Confidence: ", style="white")
        verdict_text.append(f"{conf_bar} {confidence}", style=f"bold {config['color']}")
        verdict_text.append("\n")

        if summary:
            verdict_text.append(f"\n   {summary}\n", style="white")

        panel = Panel(
            verdict_text,
            title=f"[bold]{self._emoji('verdict', 'section')}INVESTIGATION VERDICT[/bold]",
            border_style=f"bold {config['color']}",
            box=box.DOUBLE,
        )
        self.console.print(panel)

    def print_evidence(self, evidence_list: List[Evidence], title: str = "Evidence") -> None:
        """Print evidence supporting the verdict."""
        if not evidence_list:
            return

        self.print_section_header(title, "evidence")

        tree = Tree(f"[bold cyan]{self._emoji('evidence', 'section')}Supporting Evidence[/bold cyan]")

        for i, evidence in enumerate(evidence_list, 1):
            check = self._emoji("pass", "status") + " " if self.use_emojis else "• "

            evidence_node = tree.add(f"[green]{check}[/green]{evidence.description}")
            evidence_node.add(f"[dim]Source: {evidence.source}[/dim]")

            if evidence.data:
                for key, value in evidence.data.items():
                    evidence_node.add(f"[dim]{key}: [cyan]{value}[/cyan][/dim]")

        self.console.print(tree)

    def print_recommendations(
        self,
        recommendations: List[Recommendation],
        title: str = "Recommendations",
    ) -> None:
        """Print action recommendations."""
        if not recommendations:
            return

        self.print_section_header(title, "recommendations")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Priority", justify="center", width=14)
        table.add_column("Action", style="white")
        table.add_column("Rationale", style="dim", max_width=35)

        for rec in recommendations:
            priority_display = self._severity_display(rec.priority)

            table.add_row(
                priority_display,
                rec.action,
                rec.rationale or "-",
            )

        self.console.print(table)

    def print_ip_threat_intel_table(self, ip_threat_intel: List[Dict[str, Any]]) -> None:
        """Print IP threat intelligence table with emojis and colors."""
        if not ip_threat_intel:
            return

        self.print_section_header("IP Threat Intelligence", "iocs")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold blue",
            expand=True,
        )
        table.add_column(f"{self._emoji('ip', 'field')}IP Address", style="cyan", no_wrap=True)
        table.add_column(f"{self._emoji('locations', 'field')}Location", style="white")
        table.add_column("Reputation", justify="center")
        table.add_column("Blocklisted", justify="center")
        table.add_column("Known Activity", style="dim", max_width=30)
        table.add_column("Risk", justify="center")

        risk_styles = {
            "critical": ("red bold", "🔴"),
            "high": ("red", "🟠"),
            "medium": ("yellow", "🟡"),
            "low": ("green", "🟢"),
            "info": ("blue", "🔵"),
        }

        reputation_styles = {
            "malicious": ("red", "🚨"),
            "suspicious": ("yellow", "⚠️"),
            "flagged": ("yellow", "⚠️"),
            "clean": ("green", "✅"),
            "unknown": ("dim", "❓"),
        }

        for entry in ip_threat_intel:
            risk_level = entry.get("risk_level", "info").lower()
            risk_color, risk_emoji = risk_styles.get(risk_level, ("white", ""))
            risk_display = f"[{risk_color}]{risk_emoji} {risk_level.upper()}[/{risk_color}]" if self.use_emojis else f"[{risk_color}]{risk_level.upper()}[/{risk_color}]"

            rep = entry.get("reputation", "Unknown").lower()
            rep_color, rep_emoji = reputation_styles.get(rep, ("white", ""))
            rep_display = f"[{rep_color}]{rep_emoji} {entry.get('reputation', 'Unknown')}[/{rep_color}]" if self.use_emojis else f"[{rep_color}]{entry.get('reputation', 'Unknown')}[/{rep_color}]"

            blocklisted = entry.get("blocklists", "No")
            bl_display = self._status_display("fail", "Yes") if blocklisted == "Yes" else self._status_display("pass", "No")

            table.add_row(
                entry.get("ip", "-"),
                entry.get("location", "Unknown"),
                rep_display,
                bl_display,
                entry.get("known_activity", "-"),
                risk_display,
            )

        self.console.print(table)

    def print_findings_table(self, findings_by_source: Dict[str, List[Dict[str, Any]]]) -> None:
        """Print findings grouped by source in a Rich Table with risk level emoji badges."""
        if not findings_by_source:
            return

        self.print_section_header("Investigation Findings", "evidence")

        risk_badges = {
            "critical": ("red bold", "🔴"),
            "high": ("red", "🟠"),
            "medium": ("yellow", "🟡"),
            "low": ("green", "🟢"),
            "info": ("blue", "🔵"),
        }

        for source, findings in findings_by_source.items():
            if not findings:
                continue

            source_emoji = {
                "splunk": "🔍",
                "virustotal": "🛡️",
                "abuseipdb": "🌐",
                "ipinfo": "📍",
                "spur": "🕵️",
                "shodan": "🔌",
                "talos": "🐟",
                "otx": "👽",
                "rhisac": "🏢",
                "threat_intel": "⚡",
                "device_fingerprint": "📱",
                "analysis": "📊",
                "ioc_extraction": "🔗",
            }
            emoji = source_emoji.get(source.lower(), "📋") + " " if self.use_emojis else ""

            table = Table(
                title=f"{emoji}[bold]{source.upper()}[/bold] ({len(findings)} findings)",
                box=box.SIMPLE_HEAVY,
                show_header=True,
                header_style="bold cyan",
                expand=True,
            )
            table.add_column("Risk", justify="center", width=12)
            table.add_column("Title", style="white")
            table.add_column("IOC", style="dim", max_width=25, overflow="ellipsis")
            table.add_column("Confidence", justify="center", width=12)

            for finding in findings:
                risk = finding.get("risk_level", "info").lower()
                risk_color, risk_emoji_char = risk_badges.get(risk, ("white", ""))
                risk_display = f"[{risk_color}]{risk_emoji_char} {risk.upper()}[/{risk_color}]" if self.use_emojis else f"[{risk_color}]{risk.upper()}[/{risk_color}]"

                confidence = finding.get("confidence", 0.5)
                conf_pct = f"{confidence:.0%}"
                conf_color = "green" if confidence >= 0.8 else "yellow" if confidence >= 0.5 else "dim"

                table.add_row(
                    risk_display,
                    finding.get("title", "-"),
                    finding.get("ioc_value", "-") or "-",
                    f"[{conf_color}]{conf_pct}[/{conf_color}]",
                )

            self.console.print(table)
            self.console.print()

    def print_ioc_summary(self, iocs: Dict[str, List[str]]) -> None:
        """Print IOC summary by type."""
        if not any(iocs.values()):
            return

        self.print_section_header("IOC Summary", "iocs")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold blue",
        )

        type_emojis = {
            "IP": "🌐",
            "IP Addresses": "🌐",
            "Domain": "🔗",
            "Domains": "🔗",
            "Email": "📧",
            "Emails": "📧",
            "Hash": "🔢",
            "Hashes": "🔢",
            "URL": "🔗",
            "URLs": "🔗",
            "Hostname": "🖥️",
            "Hostnames": "🖥️",
        }

        table.add_column("Type", style="cyan", width=18)
        table.add_column("Count", justify="center", width=8)
        table.add_column("Values", style="white")

        for ioc_type, values in iocs.items():
            if values:
                emoji = type_emojis.get(ioc_type, "🔹") + " " if self.use_emojis else ""
                display_values = ", ".join(values[:3])
                if len(values) > 3:
                    display_values += f" (+{len(values) - 3} more)"

                table.add_row(
                    f"{emoji}{ioc_type}",
                    f"[bold]{len(values)}[/bold]",
                    display_values
                )

        self.console.print(table)

    def print_divider(self) -> None:
        """Print a simple divider."""
        self.console.print()
        self.console.rule(style="dim")
        self.console.print()

    def print_footer(self, message: str = "Investigation Complete") -> None:
        """Print report footer."""
        emoji = self._emoji("footer", "section").strip()
        display_msg = f"{emoji} {message} {emoji}" if emoji else message

        self.console.print()
        self.console.print("═" * 80, style="blue")
        self.console.print(Align.center(f"[bold blue]{display_msg}[/bold blue]"))
        self.console.print("═" * 80, style="blue")
        self.console.print()

    def print_full_report(
        self,
        alert_id: str,
        title: str,
        severity: str,
        source_ips: List[str],
        target_user: Optional[str],
        timeline: List[TimelineEvent],
        fingerprints: List[DeviceFingerprint],
        risk_factors: List[Dict[str, str]],
        verdict: Verdict,
        verdict_confidence: str,
        verdict_summary: str,
        evidence_list: List[Evidence],
        recommendations: List[Recommendation],
        iocs: Optional[Dict[str, List[str]]] = None,
        key_finding: Optional[Dict[str, Any]] = None,
        ip_threat_intel: Optional[List[Dict[str, Any]]] = None,
        findings_by_source: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> None:
        """Print a complete investigation report."""
        # Banner
        self.print_banner()

        # Alert Summary
        self.print_alert_summary(
            alert_id=alert_id,
            title=title,
            severity=severity,
            source_ips=source_ips,
            target_user=target_user,
        )

        # IP Threat Intelligence (after alert summary)
        if ip_threat_intel:
            self.print_ip_threat_intel_table(ip_threat_intel)

        # Timeline
        if timeline:
            self.print_timeline(timeline)

        # Device Fingerprints
        if fingerprints:
            self.print_device_fingerprints(fingerprints)

        # Key Finding
        if key_finding:
            self.print_key_finding(
                title=key_finding.get("title", "Key Finding"),
                findings=key_finding.get("findings", []),
                finding_type=key_finding.get("type", "info"),
            )

        # Investigation Findings (after key finding)
        if findings_by_source:
            self.print_findings_table(findings_by_source)

        # Risk Assessment
        if risk_factors:
            self.print_risk_assessment(risk_factors)

        # Verdict
        self.print_verdict(verdict, verdict_confidence, verdict_summary)

        # Evidence
        if evidence_list:
            self.print_evidence(evidence_list)

        # Recommendations
        if recommendations:
            self.print_recommendations(recommendations)

        # IOCs
        if iocs:
            self.print_ioc_summary(iocs)

        # Footer
        self.print_footer()


# Convenience function for quick reports
def present_investigation(
    verdict: str,
    evidence: List[str],
    recommendations: List[str],
    alert_title: str = "Security Alert",
    severity: str = "medium",
    use_emojis: bool = True,
) -> None:
    """Quick convenience function to present investigation results."""
    presenter = InvestigationPresenter(use_emojis=use_emojis)

    # Map string verdict to enum
    verdict_map = {
        "malicious": Verdict.MALICIOUS,
        "suspicious": Verdict.SUSPICIOUS,
        "benign": Verdict.BENIGN,
        "false_positive": Verdict.FALSE_POSITIVE,
        "inconclusive": Verdict.INCONCLUSIVE,
    }
    verdict_enum = verdict_map.get(verdict.lower(), Verdict.INCONCLUSIVE)

    presenter.print_banner()
    presenter.print_verdict(verdict_enum)

    if evidence:
        evidence_list = [
            Evidence(description=e, source="Investigation", severity=Severity.INFO)
            for e in evidence
        ]
        presenter.print_evidence(evidence_list)

    if recommendations:
        rec_list = [
            Recommendation(action=r, priority=Severity.LOW)
            for r in recommendations
        ]
        presenter.print_recommendations(rec_list)

    presenter.print_footer()
