"""Investigation Protocol - Ensures complete investigation execution."""

from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from models.alert import DataDogAlert
from models.finding import Finding
from models.ioc import IOC
from utils.alert_classifier import is_account_takeover_alert


class InvestigationState(str, Enum):
    """Investigation execution states."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class InvestigationStep:
    """Definition of an investigation step."""
    id: str
    name: str
    tier: int
    agent: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    validates: Optional[Callable[[Dict[str, Any]], bool]] = None
    conditional: Optional[Callable[[DataDogAlert], bool]] = None
    critical: bool = False  # If True, investigation cannot proceed if this fails

    # Runtime state
    state: InvestigationState = InvestigationState.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class InvestigationProtocol:
    """
    Enforces complete investigation execution with validation gates.

    This protocol ensures that all required investigation steps are executed
    in the correct sequence with proper validation between tiers.
    """

    def __init__(self):
        """Initialize the investigation protocol."""
        self.steps = self._define_steps()
        self.context: Dict[str, Any] = {}

    def _define_steps(self) -> List[InvestigationStep]:
        """Define the complete investigation workflow."""
        return [
            # Tier 0: Signal Acquisition
            InvestigationStep(
                id="tier0_acquisition",
                name="Acquire Alert Signal",
                tier=0,
                agent="SignalAcquisitionAgent",
                description="Acquire alert from DataDog, file, stdin, or raw dict",
                validates=lambda ctx: ctx.get("alert_data") is not None,
                critical=True,
            ),

            # Tier 1: Orchestration
            InvestigationStep(
                id="tier1_parse",
                name="Parse Alert & Extract IOCs",
                tier=1,
                agent="Orchestrator",
                description="Parse alert structure and extract all IOCs",
                depends_on=["tier0_acquisition"],
                validates=lambda ctx: (
                    ctx.get("alert") is not None and
                    ctx.get("iocs") is not None and
                    len(ctx.get("iocs", [])) > 0
                ),
                critical=True,
            ),

            InvestigationStep(
                id="tier1_splunk_queries",
                name="Prepare Splunk Investigation Queries",
                tier=1,
                agent="Orchestrator",
                description="Generate Splunk queries based on IOCs and alert type",
                depends_on=["tier1_parse"],
                validates=lambda ctx: (
                    ctx.get("splunk_queries") is not None and
                    len(ctx.get("splunk_queries", [])) > 0
                ),
                critical=True,
            ),

            # Tier 2: Investigation (Splunk)
            InvestigationStep(
                id="tier2_execute_splunk_queries",
                name="Execute Splunk Queries via MCP",
                tier=2,
                agent="Claude (MCP)",
                description="Execute all prepared Splunk queries and collect results",
                depends_on=["tier1_splunk_queries"],
                validates=lambda ctx: ctx.get("splunk_query_results") is not None,
                critical=True,
            ),

            InvestigationStep(
                id="tier2_analyze_splunk_results",
                name="Analyze Splunk Results & Create Findings",
                tier=2,
                agent="SplunkInvestigator",
                description="Convert Splunk query results into Finding objects with risk assessment",
                depends_on=["tier2_execute_splunk_queries"],
                validates=lambda ctx: ctx.get("splunk_findings") is not None,
                critical=True,
            ),

            # Tier 2: Investigation (Device Fingerprints for ATO alerts)
            InvestigationStep(
                id="tier2_device_fingerprint",
                name="Device Fingerprint Analysis (ATO alerts)",
                tier=2,
                agent="SplunkInvestigator",
                description="Execute comprehensive device fingerprint query and analyze for ATO indicators",
                depends_on=["tier2_analyze_splunk_results"],
                conditional=lambda alert: is_account_takeover_alert(alert.title, alert.message),
                validates=lambda ctx: (
                    not ctx.get("is_ato_alert") or
                    ctx.get("device_fingerprint_findings") is not None
                ),
                critical=False,  # Only required if ATO alert
            ),

            # Tier 2: Investigation (Threat Intel)
            InvestigationStep(
                id="tier2_threat_intel",
                name="Enrich IOCs with Threat Intelligence",
                tier=2,
                agent="ThreatIntelEnricher",
                description="Enrich external IOCs using 8 threat intel sources",
                depends_on=["tier1_parse"],
                validates=lambda ctx: ctx.get("threat_intel_findings") is not None,
                critical=False,  # Can proceed without threat intel if APIs fail
            ),

            # Tier 3: Reporting
            InvestigationStep(
                id="tier3_consolidate_findings",
                name="Consolidate All Findings",
                tier=3,
                agent="Reporter",
                description="Merge Splunk, threat intel, and device fingerprint findings",
                depends_on=["tier2_analyze_splunk_results", "tier2_threat_intel"],
                validates=lambda ctx: (
                    ctx.get("all_findings") is not None and
                    len(ctx.get("all_findings", [])) >= len(ctx.get("splunk_findings", [])) +
                                                          len(ctx.get("threat_intel_findings", []))
                ),
                critical=True,
            ),

            InvestigationStep(
                id="tier3_generate_report",
                name="Generate Investigation Report",
                tier=3,
                agent="Reporter",
                description="Calculate risk, generate recommendations, and format report",
                depends_on=["tier3_consolidate_findings"],
                validates=lambda ctx: (
                    ctx.get("final_report") is not None and
                    ctx.get("final_report").get("overall_risk_level") is not None
                ),
                critical=True,
            ),
        ]

    def get_next_steps(self) -> List[InvestigationStep]:
        """
        Get the next steps that should be executed.

        Returns steps whose dependencies are completed and are ready to run.
        """
        next_steps = []

        for step in self.steps:
            # Skip if already completed or in progress
            if step.state in (InvestigationState.COMPLETED, InvestigationState.IN_PROGRESS):
                continue

            # Check if conditional (skip if condition not met)
            if step.conditional:
                alert = self.context.get("alert")
                if alert and not step.conditional(alert):
                    step.state = InvestigationState.SKIPPED
                    continue

            # Check dependencies
            dependencies_met = all(
                self._get_step_by_id(dep_id).state == InvestigationState.COMPLETED
                for dep_id in step.depends_on
            )

            if dependencies_met:
                next_steps.append(step)

        return next_steps

    def _get_step_by_id(self, step_id: str) -> Optional[InvestigationStep]:
        """Get a step by its ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def mark_step_started(self, step_id: str):
        """Mark a step as started."""
        step = self._get_step_by_id(step_id)
        if step:
            step.state = InvestigationState.IN_PROGRESS
            step.started_at = datetime.now()

    def mark_step_completed(self, step_id: str, validation_context: Optional[Dict[str, Any]] = None):
        """
        Mark a step as completed after validation.

        Args:
            step_id: The step ID
            validation_context: Context data to validate against

        Raises:
            ValueError: If validation fails
        """
        step = self._get_step_by_id(step_id)
        if not step:
            raise ValueError(f"Unknown step ID: {step_id}")

        # Update context if provided
        if validation_context:
            self.context.update(validation_context)

        # Validate if validator exists
        if step.validates and not step.validates(self.context):
            error_msg = f"Step '{step.name}' validation failed"
            step.state = InvestigationState.FAILED
            step.error_message = error_msg

            if step.critical:
                raise ValueError(f"CRITICAL STEP FAILED: {error_msg}")
            else:
                print(f"WARNING: {error_msg} (non-critical, continuing)")
                return

        step.state = InvestigationState.COMPLETED
        step.completed_at = datetime.now()

    def mark_step_failed(self, step_id: str, error_message: str):
        """Mark a step as failed."""
        step = self._get_step_by_id(step_id)
        if step:
            step.state = InvestigationState.FAILED
            step.error_message = error_message

            if step.critical:
                raise ValueError(f"CRITICAL STEP FAILED: {step.name} - {error_message}")

    def get_progress_summary(self) -> Dict[str, Any]:
        """Get a summary of investigation progress."""
        total = len(self.steps)
        completed = sum(1 for s in self.steps if s.state == InvestigationState.COMPLETED)
        failed = sum(1 for s in self.steps if s.state == InvestigationState.FAILED)
        in_progress = sum(1 for s in self.steps if s.state == InvestigationState.IN_PROGRESS)
        skipped = sum(1 for s in self.steps if s.state == InvestigationState.SKIPPED)

        return {
            "total_steps": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "skipped": skipped,
            "pending": total - completed - failed - in_progress - skipped,
            "progress_percent": int((completed / total) * 100) if total > 0 else 0,
            "critical_failures": [
                {"step": s.name, "error": s.error_message}
                for s in self.steps if s.state == InvestigationState.FAILED and s.critical
            ],
        }

    def is_complete(self) -> bool:
        """Check if investigation is complete (all critical steps done)."""
        return all(
            s.state in (InvestigationState.COMPLETED, InvestigationState.SKIPPED)
            for s in self.steps
            if s.critical or not s.conditional
        )

    def print_status(self):
        """Print current investigation status."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()

        # Progress summary
        summary = self.get_progress_summary()
        console.print(Panel(
            f"Investigation Progress: {summary['completed']}/{summary['total_steps']} steps completed "
            f"({summary['progress_percent']}%)",
            title="📊 Investigation Status",
            border_style="cyan"
        ))

        # Steps table
        table = Table(title="Investigation Steps", show_header=True, header_style="bold magenta")
        table.add_column("Tier", justify="center", width=6)
        table.add_column("Step", style="cyan", width=40)
        table.add_column("Agent", style="yellow", width=20)
        table.add_column("Status", justify="center", width=12)

        for step in self.steps:
            status_emoji = {
                InvestigationState.COMPLETED: "✅",
                InvestigationState.IN_PROGRESS: "🔄",
                InvestigationState.FAILED: "❌",
                InvestigationState.PENDING: "⏳",
                InvestigationState.SKIPPED: "⏭️",
            }.get(step.state, "❓")

            status_color = {
                InvestigationState.COMPLETED: "green",
                InvestigationState.IN_PROGRESS: "yellow",
                InvestigationState.FAILED: "red",
                InvestigationState.PENDING: "white",
                InvestigationState.SKIPPED: "dim",
            }.get(step.state, "white")

            table.add_row(
                f"T{step.tier}",
                step.name + (" *" if step.critical else ""),
                step.agent,
                f"[{status_color}]{status_emoji} {step.state.value}[/{status_color}]"
            )

        console.print(table)
        console.print("\n[dim]* = Critical step (investigation cannot proceed if failed)[/dim]\n")
