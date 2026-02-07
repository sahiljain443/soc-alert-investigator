"""Orchestrator - Tier 1: Coordinates the investigation workflow."""

from typing import Any, Dict, List, Optional

from config import Config
from models.alert import DataDogAlert
from models.ioc import IOC, IOCType
from models.finding import Finding
from utils.ioc_extractor import IOCExtractor
from utils.console_output import ConsoleOutput

from .signal_acquisition import SignalAcquisitionAgent
from .splunk_investigator import SplunkInvestigator
from .threat_intel import ThreatIntelEnricher
from .reporter import Reporter


class Orchestrator:
    """
    Tier 1 Orchestrator.

    Coordinates the investigation workflow by:
    - Parsing alerts and extracting IOCs
    - Preparing Splunk queries for MCP execution
    - Running threat intelligence enrichment
    - Generating investigation reports

    This orchestrator is designed to work with the current Claude Code session
    as the "brain" - it prepares data and queries but lets Claude execute
    the actual Splunk MCP queries.
    """

    def __init__(self, config: Optional[Config] = None, console: Optional[ConsoleOutput] = None):
        """Initialize the Orchestrator."""
        self.config = config or Config.from_env()
        self.console = console or ConsoleOutput()
        self.ioc_extractor = IOCExtractor()

        # Initialize components
        self.signal_acquisition = SignalAcquisitionAgent(config=self.config, console=self.console)
        self.splunk_investigator = SplunkInvestigator(console)
        self.threat_intel_enricher = ThreatIntelEnricher(self.config, console)
        self.reporter = Reporter()

    def parse_alert(self, alert_data: Dict[str, Any]) -> DataDogAlert:
        """Parse raw alert data into a DataDogAlert object."""
        return DataDogAlert.from_raw(alert_data)

    def extract_iocs(self, alert: DataDogAlert) -> List[IOC]:
        """Extract all IOCs from an alert."""
        text = alert.get_searchable_text()

        # Extract standard IOCs
        iocs = self.ioc_extractor.extract(text, include_internal=True)

        # Extract hostnames and usernames
        hostnames = self.ioc_extractor.extract_hostnames(text)
        usernames = self.ioc_extractor.extract_usernames(text)

        # Combine and deduplicate
        all_iocs = list(set(iocs + hostnames + usernames))

        # Add alert host if specified
        if alert.host:
            host_ioc = IOC(
                type=IOCType.HOSTNAME,
                value=alert.host,
                context="Alert host field",
                is_internal=True,
            )
            if host_ioc not in all_iocs:
                all_iocs.append(host_ioc)

        return all_iocs

    def get_splunk_queries(self, iocs: List[IOC], alert: Optional[DataDogAlert] = None) -> List[Dict[str, str]]:
        """Get Splunk queries for investigation."""
        return self.splunk_investigator.get_queries_for_investigation(iocs, alert)

    def create_splunk_finding(
        self,
        query: str,
        description: str,
        result: Dict[str, Any],
        ioc_value: Optional[str] = None,
    ) -> Finding:
        """Create a finding from Splunk query results."""
        return self.splunk_investigator.create_finding_from_result(
            query, description, result, ioc_value
        )

    async def enrich_iocs(self, iocs: List[IOC]) -> List[Finding]:
        """Enrich IOCs with threat intelligence."""
        return await self.threat_intel_enricher.enrich_iocs(iocs)

    def generate_report(
        self,
        alert: DataDogAlert,
        iocs: List[IOC],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Generate investigation report."""
        return self.reporter.generate_report(alert, iocs, findings)

    def get_investigation_plan(self, alert: DataDogAlert) -> Dict[str, Any]:
        """
        Get a complete investigation plan for an alert.

        This returns all the data needed for the Claude session to
        execute the investigation.

        Returns:
            Dictionary with:
            - alert: Parsed alert object
            - iocs: Extracted IOCs
            - splunk_queries: Queries to execute via MCP
            - enrichable_iocs: IOCs that can be enriched with threat intel
        """
        # Parse and extract
        iocs = self.extract_iocs(alert)

        # Get Splunk queries
        splunk_queries = self.get_splunk_queries(iocs, alert)

        # Get enrichable IOCs
        enrichable_iocs = self.threat_intel_enricher.get_enrichable_iocs(iocs)

        return {
            "alert": alert,
            "iocs": iocs,
            "splunk_queries": splunk_queries,
            "enrichable_iocs": enrichable_iocs,
            "summary": {
                "total_iocs": len(iocs),
                "external_ips": len([i for i in iocs if i.type == IOCType.IP_ADDRESS and not i.is_internal]),
                "internal_ips": len([i for i in iocs if i.type == IOCType.IP_ADDRESS and i.is_internal]),
                "domains": len([i for i in iocs if i.type == IOCType.DOMAIN]),
                "hashes": len([i for i in iocs if i.is_hash]),
                "emails": len([i for i in iocs if i.type == IOCType.EMAIL]),
                "usernames": len([i for i in iocs if i.type == IOCType.USERNAME]),
                "hostnames": len([i for i in iocs if i.type == IOCType.HOSTNAME]),
                "splunk_queries_count": len(splunk_queries),
                "enrichable_iocs_count": len(enrichable_iocs),
            },
        }
