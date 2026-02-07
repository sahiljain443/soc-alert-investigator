"""DataDog alert model."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DataDogAlert(BaseModel):
    """Model representing a DataDog security alert."""

    id: str = Field(description="Unique alert identifier")
    title: str = Field(description="Alert title")
    message: str = Field(default="", description="Alert message/description")
    severity: str = Field(default="medium", description="Alert severity (low, medium, high, critical)")
    status: str = Field(default="triggered", description="Alert status")
    source: str = Field(default="datadog", description="Alert source")
    tags: List[str] = Field(default_factory=list, description="Associated tags")
    timestamp: datetime = Field(default_factory=datetime.now, description="Alert timestamp")
    host: Optional[str] = Field(default=None, description="Affected host")
    service: Optional[str] = Field(default=None, description="Affected service")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Additional attributes")

    @classmethod
    def from_raw(cls, data: dict[str, Any]) -> "DataDogAlert":
        """Parse a raw DataDog alert payload into a structured model."""
        # Handle nested DataDog alert structure
        alert_data = data.get("alert", data)

        # Extract timestamp
        ts = alert_data.get("timestamp") or alert_data.get("date") or alert_data.get("created_at")
        if isinstance(ts, (int, float)):
            timestamp = datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts)
        elif isinstance(ts, str):
            try:
                timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()

        # Map severity variations
        severity_map = {
            "P1": "critical",
            "P2": "high",
            "P3": "medium",
            "P4": "low",
            "critical": "critical",
            "error": "high",
            "warning": "medium",
            "info": "low",
        }
        raw_severity = str(alert_data.get("severity", alert_data.get("priority", "medium"))).lower()
        severity = severity_map.get(raw_severity, raw_severity)

        return cls(
            id=str(alert_data.get("id", alert_data.get("alert_id", "unknown"))),
            title=alert_data.get("title", alert_data.get("name", "Untitled Alert")),
            message=alert_data.get("message", alert_data.get("body", alert_data.get("description", ""))),
            severity=severity,
            status=alert_data.get("status", "triggered"),
            source=alert_data.get("source", "datadog"),
            tags=alert_data.get("tags", []),
            timestamp=timestamp,
            host=alert_data.get("host", alert_data.get("hostname")),
            service=alert_data.get("service"),
            attributes=alert_data.get("attributes", {}),
        )

    def get_searchable_text(self) -> str:
        """Get all text content that should be searched for IOCs."""
        parts = [
            self.title,
            self.message,
            self.host or "",
            self.service or "",
            " ".join(self.tags),
        ]
        # Include any string values from attributes
        for value in self.attributes.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(v) for v in value if isinstance(v, str))

        return " ".join(parts)
