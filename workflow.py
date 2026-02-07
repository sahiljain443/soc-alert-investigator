"""Auto-pilot investigation workflow for Claude Code sessions.

This module provides the ``InvestigationWorkflow`` class which breaks the
full investigation into five discrete steps.  Between steps 2 and 3 the
Claude session is expected to execute the prepared Splunk queries via MCP
(``mcp__splunk__run_splunk_query``) and feed the results back into step 3.

Usage inside a Claude Code session::

    from workflow import InvestigationWorkflow

    wf = InvestigationWorkflow()

    # Step 1 -- list DataDog signals (no stdin prompts)
    signals = wf.step_1_list_signals(hours=24, severity="high")

    # Claude presents signals to user; user picks an index
    plan = wf.step_2_select_and_plan(signals["raw_signals"], index=1)

    # Claude executes each query in plan["queries"] via MCP and collects
    # raw results into a list aligned by index.
    splunk_raw_results = [...]  # list of MCP responses

    findings = wf.step_3_process_splunk_results(plan, splunk_raw_results)

    # Step 4 -- threat intel enrichment (async)
    ti_findings = wf.step_4_enrich_iocs_sync(plan)
    # -- or --
    ti_findings = await wf.step_4_enrich_iocs(plan)

    all_findings = findings + ti_findings

    # Step 5 -- generate and print report
    report = wf.step_5_generate_report(plan, all_findings)
"""

import asyncio
from typing import Any, Dict, List, Optional

from config import Config
from agents.orchestrator import Orchestrator
from agents.signal_acquisition import SignalAcquisitionAgent, SignalAcquisitionError
from models.alert import DataDogAlert
from models.finding import Finding
from models.ioc import IOC
from utils.mcp_normalizer import normalize_mcp_splunk_result


class InvestigationWorkflow:
    """Five-step auto-pilot investigation workflow.

    All methods are non-interactive (no stdin prompts).  The only
    human-in-the-loop is signal selection (step 2) and Splunk query
    execution via MCP (between steps 2 and 3), both orchestrated by the
    surrounding Claude session.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.from_env()
        self.orchestrator = Orchestrator(config=self.config)
        self.signal_acquisition = SignalAcquisitionAgent(config=self.config)

    # ------------------------------------------------------------------
    # Step 1: List signals
    # ------------------------------------------------------------------

    def step_1_list_signals(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> Dict[str, Any]:
        """Fetch DataDog signals and return a structured list.

        Returns:
            Dict with keys ``signals`` (formatted list of dicts),
            ``raw_signals`` (raw API responses), and ``count``.

        Raises:
            SignalAcquisitionError: If DataDog API fails or no signals found.
        """
        return self.signal_acquisition.list_signals_for_selection(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

    # ------------------------------------------------------------------
    # Step 2: Select signal and build investigation plan
    # ------------------------------------------------------------------

    def step_2_select_and_plan(
        self,
        raw_signals: List[Dict[str, Any]],
        index: int,
    ) -> Dict[str, Any]:
        """Select a signal by index and return a full investigation plan.

        Args:
            raw_signals: The ``raw_signals`` list from step 1.
            index: 1-based position of the chosen signal.

        Returns:
            Dict with keys: ``alert`` (DataDogAlert), ``iocs`` (list),
            ``queries`` (list of Splunk query specs), ``enrichable_iocs``
            (list), ``summary`` (dict of counts).
        """
        alert_data = self.signal_acquisition.select_signal(raw_signals, index)
        alert = self.orchestrator.parse_alert(alert_data)
        plan = self.orchestrator.get_investigation_plan(alert)
        return {
            "alert": plan["alert"],
            "iocs": plan["iocs"],
            "queries": plan["splunk_queries"],
            "enrichable_iocs": plan["enrichable_iocs"],
            "summary": plan["summary"],
        }

    # ------------------------------------------------------------------
    # Step 2b: Build plan from existing alert data (file, dict, ID)
    # ------------------------------------------------------------------

    def step_2_plan_from_alert_data(
        self,
        alert_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build an investigation plan from already-acquired alert data.

        Use this when the alert was loaded from a file, raw dict, or
        DataDog signal ID (instead of interactive list selection).

        Args:
            alert_data: Raw alert dict compatible with ``DataDogAlert.from_raw()``.

        Returns:
            Same structure as ``step_2_select_and_plan``.
        """
        alert = self.orchestrator.parse_alert(alert_data)
        plan = self.orchestrator.get_investigation_plan(alert)
        return {
            "alert": plan["alert"],
            "iocs": plan["iocs"],
            "queries": plan["splunk_queries"],
            "enrichable_iocs": plan["enrichable_iocs"],
            "summary": plan["summary"],
        }

    # ------------------------------------------------------------------
    # Step 3: Process Splunk MCP results into findings
    # ------------------------------------------------------------------

    def step_3_process_splunk_results(
        self,
        plan: Dict[str, Any],
        splunk_raw_results: List[Any],
    ) -> List[Finding]:
        """Convert raw MCP Splunk responses into Finding objects.

        Args:
            plan: Investigation plan from step 2.
            splunk_raw_results: List of raw MCP responses, one per query
                in ``plan["queries"]``.  Missing entries may be ``None``.

        Returns:
            List of Splunk-sourced Finding objects.
        """
        queries = plan["queries"]
        findings: List[Finding] = []

        for i, query_spec in enumerate(queries):
            raw = splunk_raw_results[i] if i < len(splunk_raw_results) else None
            normalised = normalize_mcp_splunk_result(raw)

            finding = self.orchestrator.splunk_investigator.create_finding_from_result(
                query=query_spec["query"],
                description=query_spec.get("description", ""),
                result=normalised,
                ioc_value=query_spec.get("ioc_value"),
                analysis_type=query_spec.get("analysis_type"),
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Step 4: Threat intel enrichment
    # ------------------------------------------------------------------

    async def step_4_enrich_iocs(
        self,
        plan: Dict[str, Any],
    ) -> List[Finding]:
        """Enrich IOCs with threat intelligence (async).

        Args:
            plan: Investigation plan from step 2.

        Returns:
            List of threat-intel-sourced Finding objects.
        """
        iocs: List[IOC] = plan["iocs"]
        return await self.orchestrator.threat_intel_enricher.enrich_iocs(iocs)

    def step_4_enrich_iocs_sync(
        self,
        plan: Dict[str, Any],
    ) -> List[Finding]:
        """Synchronous wrapper around :meth:`step_4_enrich_iocs`.

        Uses ``asyncio.run()`` internally so it works in non-async contexts.
        """
        return asyncio.run(self.step_4_enrich_iocs(plan))

    # ------------------------------------------------------------------
    # Step 5: Generate report
    # ------------------------------------------------------------------

    def step_5_generate_report(
        self,
        plan: Dict[str, Any],
        all_findings: List[Finding],
    ) -> Dict[str, Any]:
        """Generate the investigation report with Rich-formatted output.

        Args:
            plan: Investigation plan from step 2.
            all_findings: Combined Splunk + threat intel findings.

        Returns:
            Report data dict.
        """
        alert: DataDogAlert = plan["alert"]
        iocs: List[IOC] = plan["iocs"]

        return self.orchestrator.reporter.generate_report(alert, iocs, all_findings)
