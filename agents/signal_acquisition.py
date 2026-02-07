"""Signal Acquisition Agent - Tier 0: Acquires alerts from all input sources."""

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import Config
from utils.console_output import ConsoleOutput


class SignalSource(Enum):
    """Enumeration of supported alert input sources."""

    DATADOG = "datadog"
    DATADOG_ID = "datadog_id"
    FILE = "file"
    RAW_DICT = "raw_dict"
    STDIN = "stdin"
    SAMPLE = "sample"


class SignalAcquisitionError(Exception):
    """Exception raised when signal acquisition fails.

    Replaces scattered ValueError/FileNotFoundError across acquisition paths.
    """

    pass


class SignalAcquisitionAgent:
    """Tier 0 agent responsible for acquiring alerts from all input sources.

    Unifies DataDog API, file, stdin, and raw dict inputs behind a single
    agent interface. DataDog imports are lazy so the agent can be instantiated
    without DD_API_KEY/DD_APP_KEY set.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        console: Optional[ConsoleOutput] = None,
    ):
        """Initialize the Signal Acquisition Agent.

        Args:
            config: Application configuration. Loaded from env if not provided.
            console: Console output handler.
        """
        self.config = config or Config.from_env()
        self.console = console or ConsoleOutput()

    # ------------------------------------------------------------------
    # DataDog sources (lazy imports)
    # ------------------------------------------------------------------

    def acquire_from_datadog(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> Dict[str, Any]:
        """Interactively select and acquire a signal from DataDog.

        Args:
            hours: Number of hours to look back.
            severity: Filter by severity level.
            limit: Maximum number of signals to fetch.
            open_only: Only show open (untriaged) signals.

        Returns:
            Alert dictionary ready for investigation.

        Raises:
            SignalAcquisitionError: If no signal is selected or DataDog fails.
        """
        from datadog_connector import DataDogClient, SignalSelector
        from datadog_connector.client import DataDogClientError

        try:
            client = DataDogClient()
        except DataDogClientError as e:
            raise SignalAcquisitionError(f"DataDog client error: {e}")

        selector = SignalSelector(client)

        alert_data = selector.interactive_select(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

        if alert_data is None:
            raise SignalAcquisitionError("No signal selected")

        return alert_data

    def acquire_from_datadog_id(self, signal_id: str) -> Dict[str, Any]:
        """Fetch a specific signal from DataDog by ID.

        Args:
            signal_id: The DataDog signal ID.

        Returns:
            Alert dictionary ready for investigation.

        Raises:
            SignalAcquisitionError: If the signal cannot be fetched.
        """
        from datadog_connector import DataDogClient, SignalSelector, SignalMapper
        from datadog_connector.client import DataDogClientError

        try:
            client = DataDogClient()
        except DataDogClientError as e:
            raise SignalAcquisitionError(f"DataDog client error: {e}")

        selector = SignalSelector(client)

        self.console.print_progress(f"Fetching signal {signal_id}...")
        try:
            signal = client.get_security_signal(signal_id)
            selector.show_signal_details(signal)
            return SignalMapper.map_signal(signal)
        except DataDogClientError as e:
            raise SignalAcquisitionError(f"Failed to fetch signal: {e}")

    # ------------------------------------------------------------------
    # Non-interactive helpers (auto-pilot workflow)
    # ------------------------------------------------------------------

    def list_signals_for_selection(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> Dict[str, Any]:
        """Fetch signals and return structured data without any stdin interaction.

        Returns:
            Dict with keys: signals (formatted list), raw_signals (raw API
            responses for later selection), count (int).

        Raises:
            SignalAcquisitionError: If signals cannot be fetched.
        """
        from datadog_connector import DataDogClient, SignalSelector
        from datadog_connector.client import DataDogClientError

        try:
            client = DataDogClient()
        except DataDogClientError as e:
            raise SignalAcquisitionError(f"DataDog client error: {e}")

        selector = SignalSelector(client)

        formatted = selector.fetch_and_format_signals(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

        if not formatted:
            raise SignalAcquisitionError("No security signals found matching the criteria")

        return {
            "signals": formatted,
            "raw_signals": selector._cached_signals,
            "count": len(formatted),
        }

    def select_signal(
        self,
        raw_signals: List[Dict[str, Any]],
        index: int,
    ) -> Dict[str, Any]:
        """Select a signal by index and return a mapped alert dict.

        Args:
            raw_signals: Raw signal list from ``list_signals_for_selection``.
            index: 1-based position in the list.

        Returns:
            Mapped alert dict ready for ``DataDogAlert.from_raw()``.

        Raises:
            SignalAcquisitionError: If the index is out of range.
        """
        from datadog_connector import SignalMapper

        if not raw_signals or index < 1 or index > len(raw_signals):
            raise SignalAcquisitionError(
                f"Invalid signal index {index}. Must be 1-{len(raw_signals)}."
            )

        return SignalMapper.map_signal(raw_signals[index - 1])

    # ------------------------------------------------------------------
    # DataDog list (original interactive helper)
    # ------------------------------------------------------------------

    def list_datadog_signals(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 25,
        open_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """List DataDog signals without selecting one for investigation.

        Args:
            hours: Number of hours to look back.
            severity: Filter by severity level.
            limit: Maximum number of signals to fetch.
            open_only: Only show open (untriaged) signals.

        Returns:
            List of raw signal dictionaries.

        Raises:
            SignalAcquisitionError: If signals cannot be fetched.
        """
        from datadog_connector import DataDogClient, SignalSelector
        from datadog_connector.client import DataDogClientError

        try:
            client = DataDogClient()
        except DataDogClientError as e:
            raise SignalAcquisitionError(f"DataDog client error: {e}")

        selector = SignalSelector(client)

        signals = selector.fetch_signals(
            hours=hours,
            severity=severity,
            limit=limit,
            open_only=open_only,
        )

        if not signals:
            raise SignalAcquisitionError("No security signals found matching the criteria")

        selector.display_signals(signals)
        return signals

    # ------------------------------------------------------------------
    # File / dict / stdin sources
    # ------------------------------------------------------------------

    def acquire_from_file(self, file_path: str) -> Dict[str, Any]:
        """Load alert JSON from a file.

        Args:
            file_path: Path to the JSON alert file.

        Returns:
            Alert dictionary ready for investigation.

        Raises:
            SignalAcquisitionError: If the file is missing or contains invalid JSON.
        """
        path = Path(file_path)
        if not path.exists():
            raise SignalAcquisitionError(f"Alert file not found: {file_path}")

        try:
            with open(path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise SignalAcquisitionError(f"Invalid JSON in {file_path}: {e}")

    def acquire_from_dict(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Pass-through for programmatic use with a raw dictionary.

        Args:
            alert_data: Alert dictionary.

        Returns:
            The same dictionary (identity operation for interface consistency).

        Raises:
            SignalAcquisitionError: If alert_data is not a dict.
        """
        if not isinstance(alert_data, dict):
            raise SignalAcquisitionError(
                f"Expected dict, got {type(alert_data).__name__}"
            )
        return alert_data

    def acquire_from_stdin(self) -> Dict[str, Any]:
        """Read alert JSON from stdin.

        Prompts the user to paste JSON and reads until EOF (Ctrl+D / Ctrl+Z).

        Returns:
            Alert dictionary ready for investigation.

        Raises:
            SignalAcquisitionError: If the input is not valid JSON.
        """
        self.console.print_progress(
            "Paste your DataDog alert JSON (press Ctrl+D or Ctrl+Z when done):"
        )
        self.console.console.print()

        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass

        json_str = "\n".join(lines)

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise SignalAcquisitionError(f"Invalid JSON: {e}")


# ------------------------------------------------------------------
# Module-level convenience functions
# ------------------------------------------------------------------


def acquire_from_file(file_path: str) -> Dict[str, Any]:
    """Load an alert from a JSON file.

    Convenience wrapper around SignalAcquisitionAgent.acquire_from_file().
    """
    agent = SignalAcquisitionAgent()
    return agent.acquire_from_file(file_path)


def acquire_from_dict(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Pass-through for a raw alert dictionary.

    Convenience wrapper around SignalAcquisitionAgent.acquire_from_dict().
    """
    agent = SignalAcquisitionAgent()
    return agent.acquire_from_dict(alert_data)


def acquire_from_datadog_id(signal_id: str) -> Dict[str, Any]:
    """Fetch a specific signal from DataDog by ID.

    Convenience wrapper around SignalAcquisitionAgent.acquire_from_datadog_id().
    """
    agent = SignalAcquisitionAgent()
    return agent.acquire_from_datadog_id(signal_id)
