"""SOC Alert Investigation Agents."""

from .signal_acquisition import (
    SignalAcquisitionAgent,
    SignalAcquisitionError,
    SignalSource,
    acquire_from_file,
    acquire_from_dict,
    acquire_from_datadog_id,
)
from .orchestrator import Orchestrator
from .splunk_investigator import SplunkInvestigator
from .threat_intel import ThreatIntelEnricher, enrich_iocs
from .reporter import Reporter

__all__ = [
    # Tier 0 - Signal Acquisition
    "SignalAcquisitionAgent",
    "SignalAcquisitionError",
    "SignalSource",
    "acquire_from_file",
    "acquire_from_dict",
    "acquire_from_datadog_id",
    # Tier 1 - Orchestrator
    "Orchestrator",
    # Tier 2 - Investigators
    "SplunkInvestigator",
    "ThreatIntelEnricher",
    "enrich_iocs",
    # Tier 3 - Reporter
    "Reporter",
]
