"""DataDog Security Signal Connector.

This module provides integration with DataDog's Security Monitoring API
to fetch SIEM signals and forward them to soc-alert-investigator.
"""

from .client import DataDogClient
from .signal_mapper import SignalMapper
from .signal_selector import SignalSelector

__all__ = ["DataDogClient", "SignalMapper", "SignalSelector"]
