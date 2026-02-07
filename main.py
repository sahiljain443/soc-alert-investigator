#!/usr/bin/env python3
"""
SOC Alert Investigator - Multi-tier Agent Application

A prototype application for investigating security alerts using:
- Claude Code as the orchestrating LLM (via existing session)
- Splunk MCP for log analysis
- VirusTotal and AbuseIPDB for threat intelligence

This application is designed to be used from within a Claude Code session.
Claude acts as the "brain" and executes the investigation plan.

Usage:
    python main.py --sample           Show investigation plan for sample alert
    python main.py --file alert.json  Show investigation plan for alert file
    python main.py --datadog          Fetch and select signals from DataDog
    python main.py                    Interactive mode (paste JSON)
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.signal_acquisition import SignalAcquisitionAgent, SignalAcquisitionError
from config import Config
from investigate import (
    parse_and_plan,
    print_investigation_plan,
    SAMPLE_ALERT,
)
from utils.console_output import ConsoleOutput


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SOC Alert Investigator - Multi-tier Agent Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This application generates investigation plans that can be executed
by Claude Code using Splunk MCP for log analysis.

Examples:
  python main.py --sample           Show plan for sample alert
  python main.py --file alert.json  Show plan for custom alert
  python main.py --datadog          Fetch and select signals from DataDog
  python main.py --datadog --datadog-severity high  Filter by high severity
  python main.py --datadog --datadog-list           List signals only
  python main.py --datadog-id <signal_id>           Investigate specific signal
  python main.py                    Interactive mode (paste JSON)

To execute the investigation from Claude Code:
  1. Run this script to see the investigation plan
  2. Ask Claude to execute the Splunk queries via MCP
  3. Claude will enrich IOCs with threat intel APIs
  4. Claude generates the final report
        """,
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="Path to alert JSON file",
    )
    parser.add_argument(
        "--sample", "-s",
        action="store_true",
        help="Use sample alert for testing",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output investigation plan as JSON",
    )
    # DataDog integration arguments
    parser.add_argument(
        "--datadog", "-d",
        action="store_true",
        help="Fetch and select security signals from DataDog",
    )
    parser.add_argument(
        "--datadog-hours",
        type=int,
        default=24,
        help="Hours to look back for DataDog signals (default: 24)",
    )
    parser.add_argument(
        "--datadog-severity",
        type=str,
        choices=["info", "low", "medium", "high", "critical"],
        help="Filter DataDog signals by severity",
    )
    parser.add_argument(
        "--datadog-limit",
        type=int,
        default=25,
        help="Maximum number of DataDog signals to fetch (default: 25)",
    )
    parser.add_argument(
        "--datadog-open",
        action="store_true",
        help="Only show open (untriaged) DataDog signals",
    )
    parser.add_argument(
        "--datadog-list",
        action="store_true",
        help="List DataDog signals without selecting (use with --datadog)",
    )
    parser.add_argument(
        "--datadog-id",
        type=str,
        help="Directly investigate a specific DataDog signal by ID",
    )

    args = parser.parse_args()

    # Initialize console output
    console = ConsoleOutput()

    # Print banner
    console.print_header("SOC Alert Investigator")
    console.console.print("[dim]Multi-tier Agent Application for Security Alert Investigation[/dim]")
    console.console.print("[dim]Designed to work with Claude Code session[/dim]")
    console.console.print()

    # Load configuration and show warnings
    try:
        config = Config.from_env()
        warnings = config.validate()
        for warning in warnings:
            console.print_warning(warning)
    except Exception as e:
        console.print_warning(f"Config warning: {e}")

    # Initialize signal acquisition agent
    agent = SignalAcquisitionAgent(config=config, console=console)

    # Get alert data
    try:
        if args.datadog_list:
            # Display-only listing, then exit
            agent.list_datadog_signals(
                hours=args.datadog_hours,
                severity=args.datadog_severity,
                limit=args.datadog_limit,
                open_only=args.datadog_open,
            )
            sys.exit(0)
        elif args.datadog_id:
            alert_data = agent.acquire_from_datadog_id(args.datadog_id)
        elif args.datadog:
            alert_data = agent.acquire_from_datadog(
                hours=args.datadog_hours,
                severity=args.datadog_severity,
                limit=args.datadog_limit,
                open_only=args.datadog_open,
            )
        elif args.sample:
            console.print_progress("Using sample alert...")
            alert_data = agent.acquire_from_dict(SAMPLE_ALERT)
        elif args.file:
            console.print_progress(f"Loading alert from {args.file}...")
            alert_data = agent.acquire_from_file(args.file)
        else:
            alert_data = agent.acquire_from_stdin()
    except SignalAcquisitionError as e:
        console.print_error(str(e))
        sys.exit(1)

    # Generate investigation plan
    try:
        plan = parse_and_plan(alert_data)

        if args.json:
            # Output as JSON for programmatic use
            output = {
                "alert": {
                    "id": plan["alert"].id,
                    "title": plan["alert"].title,
                    "severity": plan["alert"].severity,
                    "host": plan["alert"].host,
                    "message": plan["alert"].message[:500],
                },
                "iocs": [
                    {"type": ioc.type.value, "value": ioc.value, "internal": ioc.is_internal}
                    for ioc in plan["iocs"]
                ],
                "splunk_queries": plan["splunk_queries"],
                "enrichable_iocs": [
                    {"type": ioc.type.value, "value": ioc.value}
                    for ioc in plan["enrichable_iocs"]
                ],
                "summary": plan["summary"],
            }
            print(json.dumps(output, indent=2))
        else:
            # Print human-readable plan
            print_investigation_plan(plan)

            console.console.print()
            console.console.print("[bold cyan]Next Steps:[/bold cyan]")
            console.console.print("  1. Execute the Splunk queries above via MCP")
            console.console.print("  2. Run threat intel enrichment on external IOCs")
            console.console.print("  3. Generate the investigation report")
            console.console.print()
            console.console.print("[dim]Use 'python investigate.py' to see the module API[/dim]")

    except Exception as e:
        console.print_error(f"Failed to create investigation plan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
