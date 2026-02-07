#!/usr/bin/env python3
"""
SOC Alert Investigation Module

This module provides functions for investigating security alerts.
It's designed to be used by Claude Code session which acts as the
orchestrating "brain" and executes Splunk queries via MCP.

Usage from Claude Code:
    1. Load this module
    2. Call parse_and_plan(alert_json) to get investigation plan
    3. Execute Splunk queries via MCP
    4. Create findings from results
    5. Run threat intel enrichment
    6. Generate final report
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add the project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from models.alert import DataDogAlert
from models.ioc import IOC
from models.finding import Finding
from agents.orchestrator import Orchestrator
from agents.signal_acquisition import SignalAcquisitionAgent, SignalAcquisitionError
from agents.splunk_investigator import SplunkInvestigator
from agents.threat_intel import ThreatIntelEnricher
from agents.reporter import Reporter
from utils.console_output import ConsoleOutput


# Sample alert for testing
SAMPLE_ALERT = {
    "id": "alert-2024-001",
    "title": "Suspicious Login Activity Detected",
    "message": """Multiple failed login attempts detected from external IP 185.220.101.45
targeting user account admin@example.com. Source IP is associated with known TOR exit node.
Additional suspicious activity from IP 45.33.32.156 attempting to access /api/admin endpoint.
File hash detected in request payload: 44d88612fea8a8f36de82e1278abb02f (MD5).
Affected host: web-server-prod-01.internal.corp""",
    "severity": "high",
    "status": "triggered",
    "source": "datadog",
    "tags": ["security", "authentication", "brute-force", "tor"],
    "timestamp": "2024-02-03T10:30:00Z",
    "host": "web-server-prod-01",
    "service": "auth-api",
    "attributes": {
        "source_ips": ["185.220.101.45", "45.33.32.156"],
        "target_user": "admin@example.com",
        "failed_attempts": 47,
    },
}


def parse_and_plan(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse an alert and create an investigation plan.

    Args:
        alert_data: Raw alert JSON data

    Returns:
        Investigation plan with:
        - alert: Parsed DataDogAlert
        - iocs: List of extracted IOCs
        - splunk_queries: List of queries to execute via MCP
        - enrichable_iocs: IOCs that can be enriched with threat intel
        - summary: Quick summary of extracted data
    """
    orchestrator = Orchestrator()
    alert = orchestrator.parse_alert(alert_data)
    return orchestrator.get_investigation_plan(alert)


def create_finding_from_splunk_result(
    query: str,
    description: str,
    result: Dict[str, Any],
    ioc_value: Optional[str] = None,
) -> Finding:
    """
    Create a finding from Splunk query results.

    Args:
        query: The SPL query that was executed
        description: What the query was searching for
        result: The Splunk query result
        ioc_value: Associated IOC value if any

    Returns:
        Finding object
    """
    investigator = SplunkInvestigator()
    return investigator.create_finding_from_result(query, description, result, ioc_value)


async def run_threat_intel_enrichment(iocs: List[IOC]) -> List[Finding]:
    """
    Run threat intelligence enrichment on IOCs.

    Args:
        iocs: List of IOCs to enrich

    Returns:
        List of findings from threat intel lookups
    """
    enricher = ThreatIntelEnricher()
    return await enricher.enrich_iocs(iocs)


def generate_investigation_report(
    alert: DataDogAlert,
    iocs: List[IOC],
    findings: List[Finding],
) -> Dict[str, Any]:
    """
    Generate the final investigation report with Rich-formatted output.

    Args:
        alert: The original alert
        iocs: Extracted IOCs
        findings: All investigation findings

    Returns:
        Report dictionary
    """
    reporter = Reporter()
    return reporter.generate_report(alert, iocs, findings)


def get_sample_alert() -> Dict[str, Any]:
    """Get a sample alert for testing."""
    return SAMPLE_ALERT.copy()


def print_investigation_plan(plan: Dict[str, Any]) -> None:
    """Print investigation plan summary to console."""
    console = ConsoleOutput()

    console.print_header("Investigation Plan")

    # Print alert summary
    alert = plan["alert"]
    console.console.print(f"[bold]Alert:[/bold] {alert.title}")
    console.console.print(f"[bold]Severity:[/bold] {alert.severity}")
    console.console.print(f"[bold]Host:[/bold] {alert.host or 'N/A'}")
    console.console.print()

    # Print IOC summary
    summary = plan["summary"]
    console.console.print("[bold]IOCs Extracted:[/bold]")
    console.console.print(f"  - External IPs: {summary['external_ips']}")
    console.console.print(f"  - Internal IPs: {summary['internal_ips']}")
    console.console.print(f"  - Domains: {summary['domains']}")
    console.console.print(f"  - File Hashes: {summary['hashes']}")
    console.console.print(f"  - Emails: {summary['emails']}")
    console.console.print(f"  - Usernames: {summary['usernames']}")
    console.console.print(f"  - Hostnames: {summary['hostnames']}")
    console.console.print()

    # Print Splunk queries
    console.console.print(f"[bold]Splunk Queries to Execute:[/bold] {summary['splunk_queries_count']}")
    for i, query in enumerate(plan["splunk_queries"][:5], 1):
        console.console.print(f"  {i}. {query['description']}")
    if len(plan["splunk_queries"]) > 5:
        console.console.print(f"  ... and {len(plan['splunk_queries']) - 5} more")
    console.console.print()

    # Print enrichable IOCs
    console.console.print(f"[bold]IOCs for Threat Intel Enrichment:[/bold] {summary['enrichable_iocs_count']}")
    for ioc in plan["enrichable_iocs"][:5]:
        console.console.print(f"  - [{ioc.type.value}] {ioc.value}")
    if len(plan["enrichable_iocs"]) > 5:
        console.console.print(f"  ... and {len(plan['enrichable_iocs']) - 5} more")


def acquire_alert_from_file(file_path: str) -> Dict[str, Any]:
    """Acquire an alert from a JSON file via Tier 0 agent.

    Args:
        file_path: Path to the JSON alert file.

    Returns:
        Alert dictionary ready for investigation.

    Raises:
        SignalAcquisitionError: If the file is missing or contains invalid JSON.
    """
    agent = SignalAcquisitionAgent()
    return agent.acquire_from_file(file_path)


def acquire_alert_from_datadog_id(signal_id: str) -> Dict[str, Any]:
    """Acquire a specific DataDog signal by ID via Tier 0 agent.

    Args:
        signal_id: The DataDog signal ID.

    Returns:
        Alert dictionary ready for investigation.

    Raises:
        SignalAcquisitionError: If the signal cannot be fetched.
    """
    agent = SignalAcquisitionAgent()
    return agent.acquire_from_datadog_id(signal_id)


def acquire_and_plan(
    file_path: Optional[str] = None,
    signal_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Acquire an alert and generate an investigation plan in one step.

    Provide exactly one of file_path or signal_id. If neither is given,
    the sample alert is used.

    Args:
        file_path: Path to a JSON alert file.
        signal_id: DataDog signal ID to fetch.

    Returns:
        Investigation plan dictionary (same as parse_and_plan output).

    Raises:
        SignalAcquisitionError: If acquisition fails.
    """
    agent = SignalAcquisitionAgent()

    if file_path:
        alert_data = agent.acquire_from_file(file_path)
    elif signal_id:
        alert_data = agent.acquire_from_datadog_id(signal_id)
    else:
        alert_data = agent.acquire_from_dict(SAMPLE_ALERT)

    return parse_and_plan(alert_data)


# For direct execution / testing
if __name__ == "__main__":
    import asyncio

    print("SOC Alert Investigation Module")
    print("=" * 50)
    print()

    # Parse sample alert
    plan = parse_and_plan(SAMPLE_ALERT)
    print_investigation_plan(plan)

    print()
    print("To use this module from Claude Code:")
    print("  1. plan = parse_and_plan(alert_json)")
    print("  2. Execute Splunk queries via MCP")
    print("  3. findings = await run_threat_intel_enrichment(plan['enrichable_iocs'])")
    print("  4. report = generate_investigation_report(plan['alert'], plan['iocs'], findings)")
