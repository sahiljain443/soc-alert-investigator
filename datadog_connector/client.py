"""DataDog Security Monitoring API client."""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx


class DataDogClientError(Exception):
    """Exception raised for DataDog API errors."""

    pass


class DataDogClient:
    """Client for DataDog Security Monitoring API.

    Fetches security signals (SIEM alerts) from DataDog for investigation.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        app_key: Optional[str] = None,
        site: Optional[str] = None,
    ):
        """Initialize DataDog client.

        Args:
            api_key: DataDog API key. Defaults to DD_API_KEY env var.
            app_key: DataDog Application key. Defaults to DD_APP_KEY env var.
            site: DataDog site (e.g., datadoghq.com, datadoghq.eu). Defaults to DD_SITE env var.
        """
        self.api_key = api_key or os.getenv("DD_API_KEY", "")
        self.app_key = app_key or os.getenv("DD_APP_KEY", "")
        self.site = site or os.getenv("DD_SITE", "datadoghq.com")

        if not self.api_key:
            raise DataDogClientError("DD_API_KEY environment variable not set")
        if not self.app_key:
            raise DataDogClientError("DD_APP_KEY environment variable not set")

        self.base_url = f"https://api.{self.site}"
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={
                    "DD-API-KEY": self.api_key,
                    "DD-APPLICATION-KEY": self.app_key,
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "DataDogClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def list_security_signals(
        self,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        query: Optional[str] = None,
        limit: int = 25,
        sort: str = "timestamp",
        sort_order: str = "desc",
    ) -> List[Dict[str, Any]]:
        """List security signals from DataDog SIEM.

        Args:
            from_time: Start time for signal search. Defaults to 24 hours ago.
            to_time: End time for signal search. Defaults to now.
            query: Optional filter query (DataDog query syntax).
            limit: Maximum number of signals to return.
            sort: Field to sort by (timestamp, severity).
            sort_order: Sort order (asc, desc).

        Returns:
            List of security signal dictionaries.

        Raises:
            DataDogClientError: If API request fails.
        """
        if from_time is None:
            from_time = datetime.utcnow() - timedelta(hours=24)
        if to_time is None:
            to_time = datetime.utcnow()

        # Build the request payload for POST /api/v2/security_monitoring/signals/search
        payload: Dict[str, Any] = {
            "filter": {
                "from": from_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": to_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "sort": f"{'-' if sort_order == 'desc' else ''}{sort}",
            "page": {"limit": limit},
        }

        if query:
            payload["filter"]["query"] = query

        try:
            response = self.client.post(
                "/api/v2/security_monitoring/signals/search",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])
        except httpx.HTTPStatusError as e:
            raise DataDogClientError(
                f"Failed to fetch security signals: {e.response.status_code} - {e.response.text}"
            )
        except httpx.RequestError as e:
            raise DataDogClientError(f"Request failed: {e}")

    def get_security_signal(self, signal_id: str) -> Dict[str, Any]:
        """Get a specific security signal by ID.

        Args:
            signal_id: The signal ID to fetch.

        Returns:
            Signal dictionary.

        Raises:
            DataDogClientError: If API request fails or signal not found.
        """
        try:
            response = self.client.get(
                f"/api/v2/security_monitoring/signals/{signal_id}"
            )
            response.raise_for_status()
            data = response.json()
            return data.get("data", {})
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise DataDogClientError(f"Signal not found: {signal_id}")
            raise DataDogClientError(
                f"Failed to fetch signal: {e.response.status_code} - {e.response.text}"
            )
        except httpx.RequestError as e:
            raise DataDogClientError(f"Request failed: {e}")

    def list_signals_by_severity(
        self,
        severity: str,
        from_time: Optional[datetime] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """List security signals filtered by severity.

        Args:
            severity: Severity level (info, low, medium, high, critical).
            from_time: Start time for signal search.
            limit: Maximum number of signals to return.

        Returns:
            List of security signal dictionaries.
        """
        # DataDog uses status for severity in queries
        query = f"status:{severity}"
        return self.list_security_signals(
            from_time=from_time,
            query=query,
            limit=limit,
        )

    def list_open_signals(
        self,
        from_time: Optional[datetime] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """List open (untriaged) security signals.

        Args:
            from_time: Start time for signal search.
            limit: Maximum number of signals to return.

        Returns:
            List of security signal dictionaries.
        """
        query = "signal.status:open"
        return self.list_security_signals(
            from_time=from_time,
            query=query,
            limit=limit,
        )
